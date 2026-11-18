"""The inbound gate: policy, contacts and turn-taking decide one thing together (SPEC §6, §9).

Contract: ``Gate.decide(envelope, now)`` returns a Decision. Every refusal carries the same reason
string, and a decision never raises on a well-formed envelope.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .contacts import REFUSED, Contacts
from .policy import Policy


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    closes_thread: bool = False


class Threads:
    """Per-context bookkeeping: whether a reply is owed, and whether the thread is closed."""

    def __init__(self, path: str | Path):
        self._conn = sqlite3.connect(str(path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS threads (context TEXT PRIMARY KEY, expects_reply INTEGER NOT NULL,"
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
        self._conn.execute(
            "INSERT INTO threads (context, expects_reply, closed, updated) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(context) DO UPDATE SET expects_reply = excluded.expects_reply,"
            " closed = excluded.closed, updated = excluded.updated",
            (context, int(expects_reply), int(closes), now.isoformat()),
        )
        self._conn.commit()

    def note_received(self, context: str, now: datetime) -> Decision:
        row = self._conn.execute(
            "SELECT expects_reply, closed FROM threads WHERE context = ?", (context,)
        ).fetchone()
        if row is None:
            return Decision(True)
        expects_reply, closed = bool(row[0]), bool(row[1])
        if closed:
            return Decision(False, REFUSED, True)
        if not expects_reply:
            # A reply to a message that asked for none is a protocol error; drop it rather than
            # letting two agents answer each other forever (SPEC §6, §2 goal 4).
            return Decision(False, REFUSED)
        self.note_sent(context, False, False, now)
        return Decision(True)


class Gate:
    """One place that answers: may this envelope be delivered to this agent?"

    ``agent_id`` is the identity this gate protects. The gate is deliberately the only policy
    decision point; the hub is an enforcement point for network-wide abuse and never decides
    content (SPEC §3).
    """

    def __init__(self, policy: Policy, contacts: Contacts, threads: Threads):
        self.policy = policy
        self.contacts = contacts
        self.threads = threads

    def decide(self, envelope: dict, now: datetime | None = None) -> Decision:
        moment = now or datetime.now(timezone.utc)
        sender = envelope.get("from", "")
        context = envelope.get("message", {}).get("contextId", "")

        if sender in self.policy.block:
            return Decision(False, REFUSED)
        if not self.policy.may_send(sender):
            return Decision(False, REFUSED)
        if self.contacts.state(sender, moment) != "accepted":
            return Decision(False, REFUSED)

        return self.threads.note_received(context, moment)
