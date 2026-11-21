"""#69: the thread state and the message that moved it commit together, or neither does.

Two symptoms, one cause — the gate used to decrement ``expects`` and commit, and only then did the
queue try to store the message:

* a retry after a lost ack decremented the counter a second time before the duplicate was spotted;
* a failed insert left the counter spent with nothing to show for it.

The fix is the shape of the production path: ``Gate.decide`` answers with a receipt, and only
``Queue.put`` applies it, inside the transaction that stores the message. These tests drive the
transport's real ``deliver`` — identity, card, envelope verification, gate, queue, ack — rather than
calling the two pieces in isolation, because the bug lived in the gap between them.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from helpers import build_envelope

T0 = datetime(2026, 11, 18, 5, 0, tzinfo=timezone.utc)


def expects_of(agent, context_id="c-1"):
    row = agent.threads._conn.execute(
        "SELECT expects FROM threads WHERE context = ?", (context_id,)
    ).fetchone()
    return None if row is None else row[0]


def test_a_retry_after_a_lost_ack_decrements_exactly_once(pair):
    """Symptom A: B owes two replies, answers once, and the hub offers the same envelope again."""
    muse = pair.muse
    muse.threads.note_sent("c-1", expects_reply=True, closes=False, now=T0)
    muse.threads.note_sent("c-1", expects_reply=True, closes=False, now=T0)
    assert expects_of(muse) == 2

    first = build_envelope(pair.carl_id, pair.muse_id.agent_id, context_id="c-1")
    assert muse.bridge.deliver(first) is not None, "the first delivery must be accepted"
    assert expects_of(muse) == 1
    assert muse.queue.depth() == 1

    # The ack never reached carl, so the hub re-offers the identical envelope.
    assert muse.bridge.deliver(first) is not None, "a retransmission is acked, not refused (§6)"
    assert expects_of(muse) == 1, "one message must not be charged to the thread twice"
    assert muse.queue.depth() == 1, "and it must not be delivered twice"

    # The second reply the thread still owes is admitted: the lost ack did not eat an expectation.
    # It carries seq 1: a real sender assigns increasing seqs per context, and two distinct
    # replies cannot share seq 0 — one seq holds one message (issue #111).
    second = build_envelope(pair.carl_id, pair.muse_id.agent_id, context_id="c-1", seq=1)
    assert muse.bridge.deliver(second) is not None
    assert expects_of(muse) == 0
    assert muse.queue.depth() == 2

    # And a third reply, which nobody asked for, is refused.
    third = build_envelope(pair.carl_id, pair.muse_id.agent_id, context_id="c-1")
    assert muse.bridge.deliver(third) is None
    assert expects_of(muse) == 0


def test_a_failed_insert_leaves_the_counter_untouched(pair, monkeypatch):
    """Symptom B: the store fails, so no expectation may be spent on it."""
    muse = pair.muse
    muse.threads.note_sent("c-1", expects_reply=True, closes=False, now=T0)
    assert expects_of(muse) == 1

    envelope = build_envelope(pair.carl_id, pair.muse_id.agent_id, context_id="c-1")
    real_put = muse.queue.put

    def exploding_put(*_args, **_kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(muse.queue, "put", exploding_put)
    assert muse.bridge.deliver(envelope) is None, "an unwritable queue must not be acked"
    assert expects_of(muse) == 1, "the decrement must never have been made"

    # The retry, once the store is healthy again, is the one that spends the expectation.
    monkeypatch.setattr(muse.queue, "put", real_put)
    assert muse.bridge.deliver(envelope) is not None
    assert expects_of(muse) == 0
    assert muse.queue.depth() == 1


def test_the_queue_applies_the_receipt_in_the_insert_transaction(pair):
    """The unit behind both symptoms: one transaction, so a failed write takes both rows back."""
    muse = pair.muse
    muse.threads.note_sent("c-1", expects_reply=True, closes=False, now=T0)
    envelope = build_envelope(pair.carl_id, pair.muse_id.agent_id, context_id="c-1")
    message_id = envelope["message"]["messageId"]

    decision = muse.gate.decide(envelope)
    assert decision.allowed and decision.transition is not None

    class Refusing:
        """A transition that fails the way a store does: after the row it would have changed."""

        def apply(self, conn, now):
            conn.execute(
                "INSERT INTO seen (message_id, context_id, first_seen) VALUES (?, ?, ?)",
                ("poison", "c-1", 0.0),
            )
            raise sqlite3.OperationalError("disk I/O error")

    with pytest.raises(sqlite3.OperationalError):
        muse.queue.put(envelope, transition=Refusing())

    # Nothing survived the rollback: not the message, not its dedupe record, not the receipt.
    assert muse.queue.depth() == 0
    assert muse.queue.seen(message_id) is False
    assert expects_of(muse) == 1

    # The real receipt, applied by the queue, moves the counter and stores the message together.
    assert muse.queue.put(envelope, transition=decision.transition) == "accepted"
    assert muse.queue.seen(message_id) is True
    assert expects_of(muse) == 0
