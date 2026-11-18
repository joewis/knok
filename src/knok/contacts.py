"""Contact state machine and the inbound gate (SPEC §9).

Contract: a message is admitted only when the sender is an accepted contact, is not blocked, and the
thread it belongs to still expects traffic. Every refusal is a single fixed string so the answer
cannot be used to learn whether a given agent exists.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

REQUEST_TTL = timedelta(days=7)
#: One string for every refusal reason. A distinguishable refusal is an existence oracle
#: however carefully the wording is chosen (SPEC §9).
REFUSED = "refused: delivery not permitted"

STATES = {"requested", "accepted", "refused", "expired"}


class ContactError(ValueError):
    """Raised on a contact transition that the protocol forbids."""


class DuplicateRequest(ContactError):
    """A second request to the same recipient before the first expired."""


def _ts(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _parse(text: str) -> datetime:
    return datetime.fromisoformat(text)


class Contacts:
    """Persistent contact state: ``none → requested → accepted | refused | expired``."""

    def __init__(self, path: str | Path):
        self._conn = sqlite3.connect(str(path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS contacts (peer TEXT PRIMARY KEY, state TEXT NOT NULL,"
            " updated TEXT NOT NULL)"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Contacts":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _row(self, peer: str) -> tuple[str, datetime] | None:
        row = self._conn.execute(
            "SELECT state, updated FROM contacts WHERE peer = ?", (peer,)
        ).fetchone()
        return (row[0], _parse(row[1])) if row else None

    def state(self, peer: str, now: datetime | None = None) -> str:
        """Return the current state, applying the 7-day expiry of a request."""
        moment = now or datetime.now(timezone.utc)
        row = self._row(peer)
        if row is None:
            return "none"
        state, updated = row
        if state == "requested" and moment - updated >= REQUEST_TTL:
            # Persist the expiry rather than recomputing it: a later call must not see the stale
            # request time and resurrect the request.
            self._set(peer, "expired", moment)
            return "expired"
        return state

    def _set(self, peer: str, state: str, now: datetime) -> None:
        self._conn.execute(
            "INSERT INTO contacts (peer, state, updated) VALUES (?, ?, ?)"
            " ON CONFLICT(peer) DO UPDATE SET state = excluded.state, updated = excluded.updated",
            (peer, state, _ts(now)),
        )
        self._conn.commit()

    def request(self, peer: str, now: datetime | None = None) -> str:
        """Record an inbound contact request. Raises DuplicateRequest if one is live."""
        moment = now or datetime.now(timezone.utc)
        current = self.state(peer, moment)
        if current == "requested":
            raise DuplicateRequest(f"{peer} already has a live request")
        if current == "accepted":
            raise DuplicateRequest(f"{peer} is already an accepted contact")
        self._set(peer, "requested", moment)
        return "requested"

    def accept(self, peer: str, now: datetime | None = None) -> None:
        if self.state(peer, now) != "requested":
            raise ContactError(f"{peer} has no live request to accept")
        self._set(peer, "accepted", now or datetime.now(timezone.utc))

    def refuse(self, peer: str, now: datetime | None = None) -> None:
        if self.state(peer, now) not in {"requested", "accepted"}:
            raise ContactError(f"{peer} is not a contact")
        self._set(peer, "refused", now or datetime.now(timezone.utc))

    def accepted(self) -> set[str]:
        rows = self._conn.execute("SELECT peer FROM contacts WHERE state = 'accepted'").fetchall()
        return {row[0] for row in rows}

    def expire(self, now: datetime | None = None) -> int:
        """Mark stale requests as refused. Returns how many changed."""
        moment = now or datetime.now(timezone.utc)
        rows = self._conn.execute("SELECT peer FROM contacts WHERE state = 'requested'").fetchall()
        changed = 0
        for (peer,) in rows:
            if self.state(peer, moment) == "expired":
                changed += 1
        return changed
