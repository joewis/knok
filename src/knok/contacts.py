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

#: The states a PEER may see. ``held`` is local and never appears on the wire (§9).
STATES = {"requested", "accepted", "refused", "expired"}
#: A request the owner has been shown but has not decided. Deliberately absent from STATES.
LOCAL_HELD = "held"
#: Presentations per owner per day. The queue is an attack surface; uncapped it is the spam channel.
MAX_PRESENTATIONS_PER_DAY = 5


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
        #: The audit of owner decisions. "The owner approved this key" has to be distinguishable
        #: from "approved this name before the key was rotated", so the fingerprint is recorded.
        #: ``fingerprint`` is what was *presented*; ``decided_fingerprint`` is what the owner was
        #: looking at when they decided (#65). They differ when the peer rotates a key while the
        #: request sits held, and collapsing the two would make "refused this key" and "refused a
        #: key that had already rotated away" the same row.
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS approvals (peer TEXT PRIMARY KEY, text TEXT NOT NULL,"
            " fingerprint TEXT NOT NULL, presented TEXT NOT NULL, decision TEXT,"
            " decided_by TEXT, decided_at TEXT, decided_fingerprint TEXT)"
        )
        # Additive migration: a contacts file created before #65 has no decided_fingerprint.
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(approvals)")}
        if "decided_fingerprint" not in columns:
            self._conn.execute("ALTER TABLE approvals ADD COLUMN decided_fingerprint TEXT")
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
        return self.wire_state(peer, now)

    @_locked
    def wire_state(self, peer: str, now: datetime | None = None) -> str:
        """What the PEER is told. A held request is still `requested` on the wire (§9).

        Publishing `held` would hand a stranger an oracle for whether a human is watching, and
        would break every client that reads the four-state machine.
        """
        raw = self._state_locked(peer, now or datetime.now(timezone.utc))
        return "requested" if raw == LOCAL_HELD else raw

    @_locked
    def local_state(self, peer: str, now: datetime | None = None) -> str:
        """The owner's view: `held` is visible here and nowhere else."""
        return self._state_locked(peer, now or datetime.now(timezone.utc))

    @_locked
    def pending(self) -> list[dict]:
        """Requests waiting on the owner, oldest first, with the text and fingerprint shown."""
        rows = self._conn.execute(
            "SELECT c.peer, c.updated, a.text, a.fingerprint FROM contacts c"
            " JOIN approvals a ON a.peer = c.peer"
            " WHERE c.state = ? AND a.decision IS NULL ORDER BY c.updated",
            (LOCAL_HELD,),
        ).fetchall()
        return [{"peer": r[0], "at": r[1], "text": r[2], "fingerprint": r[3]} for r in rows]

    def _state_locked(self, peer: str, moment: datetime) -> str:
        """State lookup with the lock already held (``state`` wraps this)."""
        row = self._row(peer)
        if row is None:
            return "none"
        state, updated = row[0], row[1]
        if state in ("requested", LOCAL_HELD) and moment - updated >= REQUEST_TTL:
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
    def request(self, peer: str, text: str = "", now: datetime | None = None,
                fingerprint: str = "") -> str:
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

        if self._presentations_today(moment) >= MAX_PRESENTATIONS_PER_DAY:
            # The owner's prompt is the last thing a spammer can reach. Cap the queue, not just the
            # messages: an uncapped approval queue is the spam channel one layer up (§9).
            raise Cooldown(f"{peer}: the owner's approval queue is full for today")

        self._set(peer, LOCAL_HELD, moment, bump=True)
        self._conn.execute(
            "INSERT INTO approvals (peer, text, fingerprint, presented, decision)"
            " VALUES (?, ?, ?, ?, NULL)"
            " ON CONFLICT(peer) DO UPDATE SET text = excluded.text,"
            " fingerprint = excluded.fingerprint, presented = excluded.presented,"
            " decision = NULL, decided_by = NULL, decided_at = NULL",
            (peer, text, fingerprint, _ts(moment)),
        )
        self._conn.execute(
            "INSERT INTO contact_requests (peer, at) VALUES (?, ?)", (peer, _ts(moment))
        )
        self._conn.commit()
        if self.rates is not None:
            self.rates.hit("requests", "all", moment, timedelta(days=1))
        return "requested"   # the peer sees requested; the owner sees held

    @_locked
    def _presentations_today(self, moment: datetime) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM approvals WHERE presented > ?",
            (_ts(moment - timedelta(days=1)),),
        ).fetchone()
        return row[0]

    @_locked
    def approve(self, peer: str, decided_by: str, fingerprint: str = "",
                now: datetime | None = None) -> None:
        """Record the OWNER's approval of a held request. Does not accept it — that is separate.

        ``fingerprint`` is what the owner was shown. If they name one and it is not the one on the
        request, the approval is refused: approving this name while a different key is attached is
        the substitution an approval prompt exists to prevent (§9).
        """
        moment = now or datetime.now(timezone.utc)
        row = self._conn.execute(
            "SELECT fingerprint, decision FROM approvals WHERE peer = ?", (peer,)
        ).fetchone()
        if row is None or self.local_state(peer, moment) != LOCAL_HELD:
            raise ContactError(f"{peer} has no held request to approve")
        if row[1] is not None:
            raise ContactError(f"{peer} has already been {row[1]}")
        if fingerprint and fingerprint != row[0]:
            raise ContactError(f"{peer}: the key shown to the owner is not the key on the request")
        self._conn.execute(
            "UPDATE approvals SET decision = 'approved', decided_by = ?, decided_at = ?,"
            " decided_fingerprint = ? WHERE peer = ?",
            (decided_by, _ts(moment), fingerprint or row[0], peer),
        )
        self._conn.commit()

    @_locked
    def deny(self, peer: str, decided_by: str, fingerprint: str = "",
             now: datetime | None = None) -> None:
        """Record the owner's refusal. Terminal, and delivered as silence like every refusal.

        ``fingerprint`` is the key the owner was shown at the moment they refused. Unlike
        ``approve``, a fingerprint that differs from the presented one is **recorded rather than
        refused**: refusing is safe whatever key is attached, and recording the rotated key is the
        point — it keeps "the owner refused this key" distinguishable from "the owner refused a key
        that had already rotated away" (#65).
        """
        moment = now or datetime.now(timezone.utc)
        row = self._conn.execute(
            "SELECT decision, fingerprint FROM approvals WHERE peer = ?", (peer,)
        ).fetchone()
        if row is None or self.local_state(peer, moment) != LOCAL_HELD:
            raise ContactError(f"{peer} has no held request to deny")
        if row[0] is not None:
            raise ContactError(f"{peer} has already been {row[0]}")
        self._conn.execute(
            "UPDATE approvals SET decision = 'denied', decided_by = ?, decided_at = ?,"
            " decided_fingerprint = ? WHERE peer = ?",
            (decided_by, _ts(moment), fingerprint or row[1], peer),
        )
        self._set(peer, "refused", moment)

    @_locked
    def decision(self, peer: str) -> dict[str, object] | None:
        """The owner's recorded decision, with both fingerprints (#65).

        ``presented`` is when the request was shown; ``decided_fingerprint`` is the key on screen
        when the owner answered. They differ only when the peer rotated a key while held.
        """
        row = self._conn.execute(
            "SELECT peer, text, fingerprint, presented, decision, decided_by, decided_at,"
            " decided_fingerprint FROM approvals WHERE peer = ?",
            (peer,),
        ).fetchone()
        if row is None:
            return None
        keys = ("peer", "text", "presented_fingerprint", "presented", "decision",
                "decided_by", "decided_at", "decided_fingerprint")
        return dict(zip(keys, row))

    @_locked
    def accept(self, peer: str, now: datetime | None = None) -> None:
        """Accept a request — only after the OWNER approved it.

        This is the invariant issue #42 names: no code path may turn a request into a contact on its
        own. The check is here rather than in a caller so there is no second place to forget it.
        """
        row = self._conn.execute(
            "SELECT decision FROM approvals WHERE peer = ?", (peer,)
        ).fetchone()
        if row is None or row[0] != "approved":
            raise ContactError(f"{peer} has not been approved by the owner")
        if self.local_state(peer, now) not in (LOCAL_HELD, "requested"):
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
        # `held` expires on the same clock as `requested`: an owner who never answers is
        # not a yes (§9, issue #42).
        rows = self._conn.execute(
            "SELECT peer FROM contacts WHERE state IN ('requested', ?)", (LOCAL_HELD,)
        ).fetchall()
        changed = 0
        for (peer,) in rows:
            if self.state(peer, moment) == "expired":
                changed += 1
        return changed
