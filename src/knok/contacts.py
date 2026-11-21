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
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS approvals (peer TEXT PRIMARY KEY, text TEXT NOT NULL,"
            " fingerprint TEXT NOT NULL, presented TEXT NOT NULL, decision TEXT,"
            " decided_by TEXT, decided_at TEXT, decided_fingerprint TEXT)"
        )
        # Decisions are APPEND-ONLY (#65). The approvals row above is the *presentation* record:
        # what the owner was shown, and when. Overwriting it with a decision destroyed the one fact
        # an audit needs — whether the key on screen had already rotated away — because a rotating
        # peer re-writes that row and the decision then names whatever key happens to be in it.
        # A decision row is therefore written once and never updated; a later request supersedes
        # it rather than replacing it.
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS decisions (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " peer TEXT NOT NULL, presented_fingerprint TEXT NOT NULL,"
            " decided_fingerprint TEXT, decision TEXT NOT NULL, decided_by TEXT NOT NULL,"
            " decided_at TEXT NOT NULL, superseded_by INTEGER)"
        )
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Bring a store created before append-only decisions up to date.

        ``CREATE TABLE IF NOT EXISTS`` does not add a column to an existing table, so the additive
        column is ALTERed in when absent. Decisions already recorded in the old one-row shape are
        then copied into ``decisions``: on a legacy row, ``approvals.fingerprint`` as it stood when
        the decision was written is the only evidence of what was presented. The legacy row is left
        untouched — this migration adds history, it does not rewrite it.
        """
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(approvals)")}
        if "decided_fingerprint" not in columns:
            self._conn.execute("ALTER TABLE approvals ADD COLUMN decided_fingerprint TEXT")
        pending = self._conn.execute(
            "SELECT peer, fingerprint, decision, decided_by, decided_at, decided_fingerprint"
            " FROM approvals WHERE decision IS NOT NULL AND peer NOT IN"
            " (SELECT peer FROM decisions)"
        ).fetchall()
        for peer, presented, decision, decided_by, decided_at, decided_fp in pending:
            self._conn.execute(
                "INSERT INTO decisions (peer, presented_fingerprint, decided_fingerprint,"
                " decision, decided_by, decided_at) VALUES (?, ?, ?, ?, ?, ?)",
                (peer, presented or "", decided_fp, decision, decided_by or "", decided_at or ""),
            )

    def _record_decision(self, peer: str, presented: str, decided: str | None, decision: str,
                         decided_by: str, moment: datetime) -> None:
        """Append one decision row, superseding any earlier undecided-by-supersession row.

        The row records two keys because they answer different questions: what the request
        presented, and what the owner was looking at when they decided. Equal means the decision
        names the key that asked; different means the peer rotated while the request was held, and
        the decision belongs to the key that was on screen (#65).

        Every earlier un-superseded row for this peer is superseded by the new one. The new row
        does not exist yet, so there is no row to exclude: superseding only rows older than the
        global maximum would leave the peer's latest row current whenever it happened to be the
        most recent decision in the table — the common single-peer case — and the audit would show
        two rows, neither marked superseded.
        """
        self._conn.execute(
            "UPDATE decisions SET superseded_by = (SELECT COALESCE(MAX(id), 0) + 1 FROM decisions)"
            " WHERE peer = ? AND superseded_by IS NULL",
            (peer,),
        )
        self._conn.execute(
            "INSERT INTO decisions (peer, presented_fingerprint, decided_fingerprint, decision,"
            " decided_by, decided_at) VALUES (?, ?, ?, ?, ?, ?)",
            (peer, presented, decided, decision, decided_by, _ts(moment)),
        )

    @_locked
    def decision(self, peer: str) -> dict | None:
        """The latest decision for ``peer``, or ``None`` when the owner has not decided one.

        ``presented_fingerprint`` is the key the request carried, ``decided_fingerprint`` the key
        on screen when the decision was made. ``None`` decision means the request is still held.
        Use ``decision_history`` for the full audit including superseded presentations.
        """
        row = self._conn.execute(
            "SELECT id, presented_fingerprint, decided_fingerprint, decision, decided_by,"
            " decided_at, superseded_by FROM decisions WHERE peer = ?"
            " ORDER BY id DESC LIMIT 1",
            (peer,),
        ).fetchone()
        if row is None:
            return None
        return {"id": row[0], "peer": peer, "presented_fingerprint": row[1],
                "decided_fingerprint": row[2], "decision": row[3], "decided_by": row[4],
                "decided_at": row[5], "superseded_by": row[6]}

    @_locked
    def decision_history(self, peer: str) -> list[dict]:
        """Every decision row for ``peer``, oldest first — the audit #65 exists to make readable."""
        rows = self._conn.execute(
            "SELECT id, presented_fingerprint, decided_fingerprint, decision, decided_by,"
            " decided_at, superseded_by FROM decisions WHERE peer = ? ORDER BY id",
            (peer,),
        ).fetchall()
        return [{"id": r[0], "peer": peer, "presented_fingerprint": r[1],
                 "decided_fingerprint": r[2], "decision": r[3], "decided_by": r[4],
                 "decided_at": r[5], "superseded_by": r[6]} for r in rows]

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
    def _set(self, peer: str, state: str, now: datetime, bump: bool = False,
             commit: bool = True) -> None:
        """Write the contact row. With ``commit=False`` the transaction stays open for a caller
        writing more rows in the same transaction — the caller commits (#121: ``request``
        writes the contact row, the presentation row and the request-history row together,
        so none of them may exist without the others)."""
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
        if commit:
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

        # The contact row, the presentation row and the request-history row are one
        # transaction (#121): a failure after the contact row is written must not strand the
        # peer in `held` with no presentation row for the owner to decide. The rollback
        # matters on this connection too — without it the uncommitted row would still be
        # visible here and the peer's retry would hit DuplicateRequest.
        try:
            self._set(peer, LOCAL_HELD, moment, bump=True, commit=False)
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
        except Exception:
            self._conn.rollback()
            raise
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
    def approve(self, peer: str, decided_by: str, fingerprint: str,
                now: datetime | None = None) -> None:
        """Record the OWNER's approval of a held request. Does not accept it — that is separate.

        ``fingerprint`` is what the owner was shown, and it is REQUIRED: an optional argument that
        defaulted to the presented key let a caller record an approval against a key the owner
        never saw, which is the same substitution the prompt exists to prevent, happening in the
        audit instead of at the gate (§9, #65). If it is not the key on the request, the approval
        is refused — approving this name while a different key is attached is not an approval.
        """
        moment = now or datetime.now(timezone.utc)
        if not isinstance(fingerprint, str):
            raise ContactError("the fingerprint shown to the owner is a string")
        row = self._conn.execute(
            "SELECT fingerprint, decision FROM approvals WHERE peer = ?", (peer,)
        ).fetchone()
        if row is None or self.local_state(peer, moment) != LOCAL_HELD:
            raise ContactError(f"{peer} has no held request to approve")
        if row[1] is not None:
            raise ContactError(f"{peer} has already been {row[1]}")
        if fingerprint != row[0]:
            raise ContactError(f"{peer}: the key shown to the owner is not the key on the request")
        self._conn.execute(
            "UPDATE approvals SET decision = 'approved', decided_by = ?, decided_at = ? WHERE peer = ?",
            (decided_by, _ts(moment), peer),
        )
        self._record_decision(peer, row[0], row[0], "approved", decided_by, moment)
        self._conn.commit()

    @_locked
    def deny(self, peer: str, decided_by: str, fingerprint: str = "",
             now: datetime | None = None) -> None:
        """Record the owner's refusal. Terminal, and delivered as silence like every refusal.

        ``fingerprint`` is the key on screen when the decision was made. Unlike ``approve`` it is
        recorded, not checked: refusing is safe whatever key is attached, and the mismatch between
        the presented key and the one that was shown is precisely the fact the audit must keep
        rather than reject (#65). Omitted, it falls back to the request's current fingerprint,
        which is what the prompt shows — an assertion, not a verification, and the docstring says
        so rather than implying a check that does not happen.
        """
        moment = now or datetime.now(timezone.utc)
        if not isinstance(fingerprint, str):
            raise ContactError("the decided fingerprint is a string, not a moment")
        row = self._conn.execute(
            "SELECT fingerprint, decision FROM approvals WHERE peer = ?", (peer,)
        ).fetchone()
        if row is None or self.local_state(peer, moment) != LOCAL_HELD:
            raise ContactError(f"{peer} has no held request to deny")
        if row[1] is not None:
            raise ContactError(f"{peer} has already been {row[1]}")
        self._conn.execute(
            "UPDATE approvals SET decision = 'denied', decided_by = ?, decided_at = ? WHERE peer = ?",
            (decided_by, _ts(moment), peer),
        )
        self._record_decision(peer, row[0], fingerprint or row[0], "denied", decided_by, moment)
        self._set(peer, "refused", moment)

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
