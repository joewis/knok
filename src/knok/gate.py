"""The inbound gate: policy, contacts, limits and turn-taking answer one question together (§9).

Contract: ``Gate.decide(envelope, now)`` returns a Decision and never raises for a malformed or
sealed envelope — it refuses. Every refusal carries the same string, so a caller cannot learn from
the answer whether an agent exists, whether it blocked you, or whether it had already refused you.

The gate runs **after decryption**. A sealed (form 2) envelope has no ``message`` and therefore no
``contextId``; deciding on it here would put every sealed context in one bucket (§6, v0.5).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .contacts import REFUSED, Contacts
from .policy import Policy
from .rates import Rates


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""


class Threads:
    """Per-context bookkeeping: how many replies are owed, and whether the thread is closed.

    The expectation is a **counter**. Two questions sent in one context before either is answered
    owe two replies; a boolean would refuse the second answer as a protocol error.
    """

    def __init__(self, path: str | Path):
        self._conn = sqlite3.connect(str(path))
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

    def note_received(self, context: str, now: datetime) -> Decision:
        row = self._conn.execute(
            "SELECT expects, closed FROM threads WHERE context = ?", (context,)
        ).fetchone()
        if row is None:
            return Decision(True)
        expects, closed = row[0], bool(row[1])
        if closed or expects <= 0:
            # A reply to a message that asked for none, or to a closed thread, is a protocol error.
            # Dropping it is what stops two agents answering each other forever (§6, §2 goal 4).
            return Decision(False, REFUSED)
        self._conn.execute(
            "UPDATE threads SET expects = expects - 1, updated = ? WHERE context = ?",
            (now.isoformat(), context),
        )
        self._conn.commit()
        return Decision(True)


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
        # contact store rather than with the message counters.
        contacts.rates = rates
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
        moment = now or datetime.now(timezone.utc)
        if not isinstance(envelope, dict):
            return Decision(False, REFUSED)
        message = envelope.get("message")
        if not isinstance(message, dict):
            # Sealed, or malformed. The gate is the post-decryption decision point (§6 v0.5).
            return Decision(False, REFUSED)
        sender = envelope.get("from")
        if not isinstance(sender, str) or not sender:
            return Decision(False, REFUSED)

        if sender in self.policy.block:
            return Decision(False, REFUSED)
        if sender not in self.policy.allow:
            if self.contacts.state(sender, moment) != "accepted":
                if not self.policy.direct_delivery:
                    return Decision(False, REFUSED)

        # Validate before charging the budget: a refused envelope must not spend a sender's quota,
        # or one malformed caller can throttle everyone else on the shared window.
        context = message.get("contextId")
        if not isinstance(context, str) or not context:
            return Decision(False, REFUSED)

        if not self._within_limits(sender, moment):
            return Decision(False, REFUSED)

        return self.threads.note_received(context, moment)
