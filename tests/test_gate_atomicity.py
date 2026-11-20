"""A message that is not durably ours must not move conversation state (#69).

The gate used to answer *by mutating*: ``decide`` decremented the reply counter and charged the
rate budget before the queue had stored anything. Two consequences, both real:

* an ack lost on the wire made the sender retry, and the retry decremented the reply counter a
  second time — delivery correct, conversation state corrupted;
* a ``Queue.put`` that raised left the counter changed for a message that was never stored.

The order is now: verify → dedupe → decide (read-only) → put (durable) → confirm. These tests
assert the order rather than the implementation, because the order is the fix.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from knok.contacts import Contacts
from knok.gate import Gate, Threads
from knok.policy import parse
from knok.queue import Queue

T0 = datetime(2026, 11, 18, 5, 0, tzinfo=timezone.utc)
OWNER = "muse@bridge.example"
POLICY = {
    "agent_id": OWNER,
    "contact_policy": "closed",
    "allow": ["carl@bridge.example"],
    "block": [],
    "limits": {},
}


def build(tmp_path):
    contacts = Contacts(tmp_path / "contacts.db")
    threads = Threads(tmp_path / "threads.db")
    queue = Queue(tmp_path / "queue.sqlite", OWNER)
    gate = Gate(parse(POLICY), contacts, threads)
    return gate, threads, queue


def expects_of(threads, context):
    return threads.check_received(context, T0).allowed


def test_a_retried_delivery_does_not_decrement_the_counter_twice(tmp_path, envelope_factory):
    """The sequence from the review: delivered, ack lost, retried."""
    gate, threads, queue = build(tmp_path)
    env = envelope_factory()
    context = env["message"]["contextId"]
    message_id = env["message"]["messageId"]
    threads.note_sent(context, expects_reply=True, closes=False, now=T0)

    # First delivery, in the order the bridge uses.
    assert queue.seen(message_id) is False
    assert gate.decide(env, T0).allowed is True
    assert queue.put(env, T0) == "accepted"
    gate.confirm(env, T0)
    # The question has been answered: the thread now expects nothing.
    assert expects_of(threads, context) is False

    # The acknowledgement is lost and the hub offers the very same envelope again. Dedupe runs
    # before the gate, so the bridge answers "already have it" and stops.
    assert queue.seen(message_id) is True
    assert expects_of(threads, context) is False

    # And this is why the order matters: had the gate run first, the retry would have been refused
    # as a reply the thread never asked for, and the sender would have received a refusal notice
    # for mail we had already delivered.
    assert gate.decide(env, T0).allowed is False


def test_a_failed_insert_leaves_thread_state_untouched(tmp_path, envelope_factory):
    """A durable-write failure must not consume the reply — nor the sender's rate budget."""
    gate, threads, queue = build(tmp_path)
    env = envelope_factory()
    context = env["message"]["contextId"]
    threads.note_sent(context, expects_reply=True, closes=False, now=T0)

    assert gate.decide(env, T0).allowed is True
    with pytest.raises(OSError):
        raise OSError("no space left on device")  # what Queue.put raises; confirm is never reached

    # decide() is read-only: nothing moved, so the retry will be accepted as a first delivery.
    assert expects_of(threads, context) is True


def test_confirm_is_what_moves_the_counter(tmp_path, envelope_factory):
    """The complement: a successful delivery does move it, once and only once."""
    gate, threads, queue = build(tmp_path)
    env = envelope_factory()
    context = env["message"]["contextId"]
    threads.note_sent(context, expects_reply=True, closes=False, now=T0)

    assert gate.decide(env, T0).allowed is True
    assert expects_of(threads, context) is True  # unchanged by decide
    assert queue.put(env, T0) == "accepted"
    assert expects_of(threads, context) is True  # still unchanged by the put
    gate.confirm(env, T0)
    assert expects_of(threads, context) is False  # moved exactly once, by confirm
