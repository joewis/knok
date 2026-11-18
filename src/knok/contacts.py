"""Contact state machine and the request discipline of SPEC §9.

Contract: ``none → requested → accepted | refused | expired (7 days)``. ``refused`` is terminal;
``expired`` may be requested again. A recipient accepts at most three requests in a rolling 30 days —
after that the sender waits out the cooldown. The request text is capped at 280 characters because
the request must not be able to be the spam.
"""

from __future__ import annotations

import functools
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .rates import Rates

REQUEST_TTL = timedelta(days=7)
COOLDOWN = timedelta(days=30)
MAX_REQUESTS = 3
MAX_REQUEST_CHARS = 280

#: One string for every refusal reason: a distinguishable refusal is an existence oracle, however
#: carefully it is worded (§9).
REFUSED = "refused: delivery not permitted"

STATES = {"requested", "accepted", "refused", "expired"}


class ContactError(ValueError):
    """Raised on a contact transition that the protocol forbids."""


class DuplicateRequest(ContactError):
    """A second request to the same recipient before the first expired."""


class Cooldown(ContactError):
    """The sender has used its three requests and is inside the 30-day cooldown."""


def _ts(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _parse(text: str) -> datetime:
    return datetime.fromisoformat(text)


def _locked(method):
    """Run a method with this store's lock held (RLock: nesting is fine).

    The transport serves on its own thread, so every method touching the
    connection must be safe to call from there — same pattern as Queue.
    """

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class Contacts:
    """Persistent contact state and request history."""

    def __init__(self, path: str | Path, rates: Rates | None = None,
                 contact_request_daily_limit: int | None = None):
        self.rates = rates
        self.contact_request_daily_limit = contact_request_daily_limit
        # Same pattern as Queue: the transport serves on its own thread, so
        # the connection must be usable from it, guarded by one lock.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS contacts (peer TEXT PRIMARY KEY, state TEXT NOT NULL,"
            " updated TEXT NOT NULL, requests INTEGER NOT NULL DEFAULT 0,"
            " last_request TEXT)"
        )
        #: The cooldown is a rolling window, so the individual attempt times are what matter; a
        #: lifetime counter with one anchor date throttles a peer forever after three requests.
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS contact_requests (peer TEXT NOT NULL, at TEXT NOT NULL)"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Contacts":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @_locked
    def _row(self, peer: str) -> tuple[str, datetime, int, datetime | None] | None:
        row = self._conn.execute(
            "SELECT state, updated, requests, last_request FROM contacts WHERE peer = ?", (peer,)
        ).fetchone()
        if row is None:
            return None
        return (row[0], _parse(row[1]), row[2], _parse(row[3]) if row[3] else None)

    @_locked
    def state(self, peer: str, now: datetime | None = None) -> str:
        """Current state, applying the 7-day expiry of a request.

        The expiry is written down rather than recomputed on every read: a recomputed expiry would
        resurrect a stale request on the next call.
        """
        return self._state_locked(peer, now or datetime.now(timezone.utc))

    def _state_locked(self, peer: str, moment: datetime) -> str:
        """State lookup with the lock already held (``state`` wraps this)."""
        row = self._row(peer)
        if row is None:
            return "none"
        state, updated = row[0], row[1]
        if state == "requested" and moment - updated >= REQUEST_TTL:
            self._set(peer, "expired", moment)
            return "expired"
        return state

    @_locked
    def requests_since(self, peer: str, moment: datetime) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM contact_requests WHERE peer = ? AND at > ?",
            (peer, _ts(moment - COOLDOWN)),
        ).fetchone()
        return row[0]

    @_locked
    def _set(self, peer: str, state: str, now: datetime, bump: bool = False) -> None:
        if bump:
            self._conn.execute(
                "INSERT INTO contacts (peer, state, updated, requests, last_request)"
                " VALUES (?, ?, ?, 1, ?)"
                " ON CONFLICT(peer) DO UPDATE SET state = excluded.state,"
                " updated = excluded.updated, requests = contacts.requests + 1,"
                " last_request = excluded.last_request",
                (peer, state, _ts(now), _ts(now)),
            )
        else:
            self._conn.execute(
                "INSERT INTO contacts (peer, state, updated) VALUES (?, ?, ?)"
                " ON CONFLICT(peer) DO UPDATE SET state = excluded.state, updated = excluded.updated",
                (peer, state, _ts(now)),
            )
        self._conn.commit()

    @_locked
    def request(self, peer: str, text: str = "", now: datetime | None = None) -> str:
        """Record an inbound contact request.

        Raises ``DuplicateRequest`` for a live or accepted request, ``ContactError`` after a refusal
        (terminal), and ``Cooldown`` once three requests have been used inside the rolling window.
        """
        moment = now or datetime.now(timezone.utc)
        if not isinstance(text, str):
            raise ContactError("a contact request carries text")
        if len(text) > MAX_REQUEST_CHARS:
            raise ContactError(f"a contact request is at most {MAX_REQUEST_CHARS} characters")

        current = self.state(peer, moment)
        if current == "requested":
            raise DuplicateRequest(f"{peer} already has a live request")
        if current == "accepted":
            raise DuplicateRequest(f"{peer} is already an accepted contact")
        if current == "refused":
            raise ContactError(f"{peer} refused; a refusal is terminal")

        if self.requests_since(peer, moment) >= MAX_REQUESTS:
            raise Cooldown(f"{peer} is inside the 30-day cooldown")

        # The daily limit is inbound overall (§9's probation number), not per peer: the per-peer
        # throttle is the three-requests/30-days rule above.
        if self.rates is not None and self.contact_request_daily_limit is not None:
            if self.rates.count("requests", "all", moment, timedelta(days=1)) >= self.contact_request_daily_limit:
                raise Cooldown(f"{peer}: the daily contact-request limit is spent")

        self._set(peer, "requested", moment, bump=True)
        self._conn.execute(
            "INSERT INTO contact_requests (peer, at) VALUES (?, ?)", (peer, _ts(moment))
        )
        self._conn.commit()
        if self.rates is not None:
            self.rates.hit("requests", "all", moment, timedelta(days=1))
        return "requested"

    @_locked
    def accept(self, peer: str, now: datetime | None = None) -> None:
        if self.state(peer, now) != "requested":
            raise ContactError(f"{peer} has no live request to accept")
        self._set(peer, "accepted", now or datetime.now(timezone.utc))

    @_locked
    def refuse(self, peer: str, now: datetime | None = None) -> None:
        """Refuse a live request. Refusal is terminal, and applies only to a request (§9)."""
        if self.state(peer, now) != "requested":
            raise ContactError(f"{peer} has no live request to refuse")
        self._set(peer, "refused", now or datetime.now(timezone.utc))

    @_locked
    def revoke(self, peer: str, now: datetime | None = None) -> None:
        """Withdraw an accepted contact. Local action: the peer is told nothing, and the row is
        removed so the relationship returns to `none` rather than to a terminal refusal."""
        if self.state(peer, now) != "accepted":
            raise ContactError(f"{peer} is not an accepted contact")
        self._conn.execute("DELETE FROM contacts WHERE peer = ?", (peer,))
        self._conn.commit()

    @_locked
    def accepted(self) -> set[str]:
        rows = self._conn.execute("SELECT peer FROM contacts WHERE state = 'accepted'").fetchall()
        return {row[0] for row in rows}

    @_locked
    def expire(self, now: datetime | None = None) -> int:
        """Mark stale requests as expired. Returns how many changed."""
        moment = now or datetime.now(timezone.utc)
        rows = self._conn.execute("SELECT peer FROM contacts WHERE state = 'requested'").fetchall()
        changed = 0
        for (peer,) in rows:
            if self.state(peer, moment) == "expired":
                changed += 1
        return changed
