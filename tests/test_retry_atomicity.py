"""Bridge-level proof of #69: the retry path and the failed write.

The component tests in ``test_gate_atomicity.py`` assert the ordering contract. These drive the
real ``Bridge._handle`` with a real signed envelope from a real hub, because the bug lived in the
*wiring* — a correct gate and a correct queue, called in the wrong order.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from test_phase2 import deployment, send


def now():
    return datetime.now(timezone.utc)


def expects_a_reply(carl, context) -> bool:
    """True when the thread still owes an answer (i.e. the counter has not been spent)."""
    return carl.threads.check_received(context, now()).allowed


def fetch_one(bridge, predicate):
    page = bridge.client.fetch(limit=50)
    for item in page.get("messages", []):
        if predicate(item):
            return item
    raise AssertionError("the expected envelope was not offered by the hub")


def refusals(bridge):
    path = bridge.state.directory / "refused.jsonl"
    return path.read_text().splitlines() if path.exists() else []


def test_a_retry_after_a_lost_ack_does_not_spend_the_reply_twice(deployment):
    """Delivered, ack lost, re-offered. The counter must move once."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    context = "c-retry-69"

    # Carl asked muse a question, so the thread owes exactly one answer.
    carl.threads.note_sent(context, expects_reply=True, closes=False, now=now())
    assert expects_a_reply(carl, context) is True

    send(muse, carl.identity.agent_id, "the answer", context=context)
    item = fetch_one(carl, lambda i: (i.get("message") or {}).get("contextId") == context)

    first, _ = carl._handle(item)
    assert first == "queued"
    assert expects_a_reply(carl, context) is False, "the delivery should have spent the reply"

    # The ack never reached the hub, so the same envelope is offered again.
    second, _ = carl._handle(item)
    assert second == "queued"
    assert expects_a_reply(carl, context) is False, "the retry spent the reply a second time"
    assert refusals(carl) == [], "a retry must not be refused as a reply the thread never asked for"


def test_a_failed_durable_write_leaves_the_reply_and_the_budget_untouched(
    deployment, monkeypatch
):
    """A Queue.put that raises must not consume thread state or the sender's quota."""
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    context = "c-write-fails-69"

    carl.threads.note_sent(context, expects_reply=True, closes=False, now=now())
    send(muse, carl.identity.agent_id, "the answer", context=context)
    item = fetch_one(carl, lambda i: (i.get("message") or {}).get("contextId") == context)

    def boom(*args, **kwargs):
        raise OSError("no space left on device")

    monkeypatch.setattr(carl.queue, "put", boom)
    outcome, message_id = carl._handle(item)
    # Unhandled means "not acked": the envelope stays at the hub and the next poll retries it.
    assert outcome == "unhandled" and message_id is None
    assert expects_a_reply(carl, context) is True, "a failed write spent the reply"

    # With the disk back, the retry is an ordinary first delivery.
    monkeypatch.undo()
    outcome, _ = carl._handle(item)
    assert outcome == "queued"
    assert expects_a_reply(carl, context) is False
