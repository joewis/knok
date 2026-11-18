from datetime import datetime, timezone

import pytest

from knok.contacts import REFUSED, Contacts
from knok.gate import Gate, Threads
from knok.policy import parse

T0 = datetime(2026, 11, 18, 5, 0, tzinfo=timezone.utc)
SENDER = "muse@bridge.example"
POLICY = {
    "agent_id": "carl@bridge.example",
    "contact_policy": "request",
    "allow": [SENDER],
    "block": [],
    "limits": {},
}


@pytest.fixture
def gate(tmp_path):
    contacts = Contacts(tmp_path / "contacts.db")
    threads = Threads(tmp_path / "threads.db")
    yield Gate(parse(POLICY), contacts, threads)
    contacts.close()
    threads.close()


def envelope(sender=SENDER, context="c-1"):
    return {
        "from": sender,
        "message": {"kind": "message", "messageId": "m-1", "contextId": context,
                    "role": "agent", "parts": [{"kind": "text", "text": "hi"}]},
        "to": ["carl@bridge.example"],
    }


def test_stranger_is_refused_with_the_shared_reason(gate):
    decision = gate.decide(envelope(), T0)
    assert decision.allowed is False
    assert decision.reason == REFUSED


def test_blocked_agent_is_refused_with_the_same_reason(gate):
    gate.contacts.request(SENDER, T0)
    gate.contacts.accept(SENDER, T0)
    gate.policy = parse({**POLICY, "block": [SENDER]})
    decision = gate.decide(envelope(), T0)
    assert decision.allowed is False and decision.reason == REFUSED


def test_accepted_contact_is_allowed(gate):
    gate.contacts.request(SENDER, T0)
    gate.contacts.accept(SENDER, T0)
    assert gate.decide(envelope(), T0).allowed is True


def test_reply_to_a_message_that_asked_for_none_is_dropped(gate):
    gate.contacts.request(SENDER, T0)
    gate.contacts.accept(SENDER, T0)
    gate.threads.note_sent("c-1", expects_reply=False, closes=False, now=T0)
    decision = gate.decide(envelope(context="c-1"), T0)
    assert decision.allowed is False and decision.reason == REFUSED


def test_reply_to_a_question_is_allowed_and_consumes_the_expectation(gate):
    gate.contacts.request(SENDER, T0)
    gate.contacts.accept(SENDER, T0)
    gate.threads.note_sent("c-1", expects_reply=True, closes=False, now=T0)
    assert gate.decide(envelope(context="c-1"), T0).allowed is True
    # A second reply in the same context is no longer owed one.
    assert gate.decide(envelope(context="c-1"), T0).allowed is False


def test_closed_thread_refuses_further_traffic(gate):
    gate.contacts.request(SENDER, T0)
    gate.contacts.accept(SENDER, T0)
    gate.threads.note_sent("c-1", expects_reply=True, closes=True, now=T0)
    decision = gate.decide(envelope(context="c-1"), T0)
    assert decision.allowed is False and decision.closes_thread is True
