"""The inbound gate: policy, contacts, limits and turn-taking answer one question together (§9).

Contract: ``Gate.decide(envelope, now)`` returns a Decision and never raises for a malformed or
sealed envelope — it refuses. Every refusal carries the same string, so a caller cannot learn from
the answer whether an agent exists, whether it blocked you, or whether it had already refused you.

``decide`` does not move conversation state. When it admits a reply, the decrement of the thread's
``expects`` counter travels with the answer as a :class:`Receipt`, and the queue applies it inside
the transaction that durably stores the message (#69). Deciding and committing separately let a
retry after a lost ack decrement twice, and let a failed insert leave the counter spent with no
message to show for it. The rate window is the one thing ``decide`` still charges, because it lives
in its own store and a spent slot costs a sender's quota, never the conversation's correctness.

The gate runs **after decryption**. A sealed (form 2) envelope has no ``message`` and therefore no
``contextId``; deciding on it here would put every sealed context in one bucket (§6, v0.5).
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .contacts import REFUSED, Contacts
from .policy import Policy
from .rates import Rates


@dataclass(frozen=True)
class Receipt:
    """The thread-state change an admissible reply would make — not yet made.

    ``decide`` hands one to its caller instead of applying it, because the change must commit in
    the same transaction as the queue insert that caused it (#69). ``Queue.put`` applies it on its
    own connection, inside its own ``BEGIN IMMEDIATE``, so a failed insert rolls the decrement back
    with it and a re-offered envelope cannot decrement the same thread twice.

    Applying is deliberately the caller's job, and ``apply`` never commits: the transaction belongs
    to whoever owns durability, and that is never the gate.
    """

    context: str

    def apply(self, conn: sqlite3.Connection, now: datetime) -> None:
        """Decrement ``expects`` for this context on ``conn``; the caller commits."""
        conn.execute(
            "UPDATE threads SET expects = expects - 1, updated = ? WHERE context = ?",
            (now.isoformat(), self.context),
        )


@dataclass(frozen=True)
class Decision:
    """One answer from the gate: allowed or not, and — for our own records — why.

    ``reason`` is the only thing that may ever reach a stranger, and it is the same string for
    every refusal, so the answer cannot be used as a directory oracle. ``rule`` is the internal
    category (#50): it never leaves this process on the 403 path, and it is only ever quoted in a
    notice to a sender whose key the operator has already pinned in this agent's registry — except
    ``blocked``, which is never quoted anywhere, because a blocked sender gets no notice at all:
    blocking must look like nonexistence.
    Refusals that name a rule: ``blocked``, ``policy``, ``limits``, ``thread``, ``malformed``.

    ``transition`` is the state change this answer requires, for the caller to commit alongside the
    message (#69). It is ``None`` for every refusal and for an admission that changes nothing.
    """

    allowed: bool
    reason: str = ""
    rule: str = ""
    transition: Receipt | None = None


class Threads:
    """Per-context bookkeeping: how many replies are owed, and whether the thread is closed.

    The expectation is a **counter**. Two questions sent in one context before either is answered
    owe two replies; a boolean would refuse the second answer as a protocol error.

    This store lives in the queue's database (the bridge opens it on ``queue.db``), because the
    counter moves in the same transaction as the message that moved it (#69). Opening it elsewhere
    still works for a bare gate — ``apply_receipt`` commits on its own — but a queue handed a
    transition needs the ``threads`` table in its own file, or the atomicity is a fiction.
    """

    def __init__(self, path: str | Path):
        # Same pattern as Queue: the transport serves on its own thread, so
        # the connection must be usable from it, guarded by one lock.
        self._lock = threading.RLock()
        # The queue holds its write lock for as long as a durable put takes, so this connection
        # must wait at least as long: sqlite's 5 s default turned a slow put into a failed
        # note_sent, and the reply credit was lost with it (#72 review, nit 1).
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30.0)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS threads (context TEXT PRIMARY KEY, expects INTEGER NOT NULL,"
            " closed INTEGER NOT NULL, updated TEXT NOT NULL)"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Threads":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def note_sent(self, context: str, expects_reply: bool, closes: bool, now: datetime) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT expects FROM threads WHERE context = ?", (context,)
            ).fetchone()
            expects = (row[0] if row else 0) + (1 if expects_reply else 0)
            self._conn.execute(
                "INSERT INTO threads (context, expects, closed, updated) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(context) DO UPDATE SET expects = excluded.expects,"
                " closed = excluded.closed, updated = excluded.updated",
                (context, expects, int(closes), now.isoformat()),
            )
            self._conn.commit()

    def receipt(self, context: str) -> Decision:
        """Answer whether a reply to ``context`` is admissible, and what it would change.

        Read-only: the counter is not touched here. The answer carries a :class:`Receipt` for
        ``decide``'s caller to commit alongside the message (#69), so asking twice about the same
        reply cannot spend two expectations.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT expects, closed FROM threads WHERE context = ?", (context,)
            ).fetchone()
            if row is None:
                return Decision(True)
            expects, closed = row[0], bool(row[1])
            if closed or expects <= 0:
                # A reply to a message that asked for none, or to a closed thread, is a protocol error.
                # Dropping it is what stops two agents answering each other forever (§6, §2 goal 4).
                return Decision(False, REFUSED, "thread")
            return Decision(True, transition=Receipt(context))

    def apply_receipt(self, decision: Decision, now: datetime) -> Decision:
        """Commit ``decision.transition`` on this store's own connection and return the decision.

        For a gate with no queue in front of it — a unit test, an embedded caller that stores the
        message itself. The bridge and the transport do **not** call this: they hand the receipt to
        ``Queue.put`` so the decrement and the insert commit together (#69).
        """
        if decision.transition is not None:
            with self._lock:
                decision.transition.apply(self._conn, now)
                self._conn.commit()
        return decision


class Gate:
    """One place that answers: may this envelope be delivered to this agent?

    Order: block, then allow-list, then accepted contact, then direct-delivery policy, then limits,
    then thread rules. The allow-list is a *pre-approval*, not a prerequisite: requiring both it and
    a completed handshake made the handshake unable to admit anyone.
    """

    def __init__(self, policy: Policy, contacts: Contacts, threads: Threads, rates: Rates | None = None):
        self.policy = policy
        self.contacts = contacts
        self.threads = threads
        self.rates = rates
        # §9's probation limit is a property of the request, not of delivery, so it lives with the
        # contact store rather than with the message counters. Set only when this gate is given a
        # counter store: a Contacts opened with its own store keeps it rather than losing it here.
        if rates is not None:
            contacts.rates = rates
            if contacts.contact_request_daily_limit is None:
                contacts.contact_request_daily_limit = policy.limits.get("contact_requests_per_day")

    def _within_limits(self, sender: str, moment: datetime) -> bool:
        if self.rates is None:
            return True
        limits = self.policy.limits
        pairs = [
            ("messages", "all", limits.get("messages_per_hour"), timedelta(hours=1)),
            ("sender", sender, limits.get("per_sender_per_hour"), timedelta(hours=1)),
            ("messages", "all-day", limits.get("messages_per_day"), timedelta(days=1)),
        ]
        for scope, key, limit, span in pairs:
            if limit is None:
                continue
            if self.rates.count(scope, key, moment, span) >= limit:
                return False
        for scope, key, limit, span in pairs:
            if limit is not None:
                self.rates.hit(scope, key, moment, span)
        return True

    def decide(self, envelope: object, now: datetime | None = None) -> Decision:
        """Admit or refuse one envelope. Moves no conversation state: see :class:`Receipt`.

        The one store this does write is the rate window, charged only after the envelope passed
        every validation: a refused envelope must not spend a sender's quota, and a retry of an
        already-queued message never reaches here (the bridge checks the queue's durable ``seen``
        set first, #69).
        """
        moment = now or datetime.now(timezone.utc)
        if not isinstance(envelope, dict):
            return Decision(False, REFUSED, "malformed")
        message = envelope.get("message")
        if not isinstance(message, dict):
            # Sealed, or malformed. The gate is the post-decryption decision point (§6 v0.5).
            return Decision(False, REFUSED, "malformed")
        sender = envelope.get("from")
        if not isinstance(sender, str) or not sender:
            return Decision(False, REFUSED, "malformed")

        if sender in self.policy.block:
            return Decision(False, REFUSED, "blocked")
        if sender not in self.policy.allow:
            if self.contacts.state(sender, moment) != "accepted":
                if not self.policy.direct_delivery:
                    return Decision(False, REFUSED, "policy")

        # Validate before charging the budget: a refused envelope must not spend a sender's quota,
        # or one malformed caller can throttle everyone else on the shared window.
        context = message.get("contextId")
        if not isinstance(context, str) or not context:
            return Decision(False, REFUSED, "malformed")

        if not self._within_limits(sender, moment):
            return Decision(False, REFUSED, "limits")

        return self.threads.receipt(context)
