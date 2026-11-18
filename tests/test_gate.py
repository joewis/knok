import pytest

from knok.contacts import REFUSED, Contacts
from knok.gate import Gate, Rates, Threads
from knok.policy import parse

T0 = __import__("datetime").datetime(2026, 11, 18, 5, 0, tzinfo=__import__("datetime").timezone.utc)
SENDER = "muse@bridge.example"
STRANGER = "mallory@bridge.example"

CLOSED = {
    "agent_id": "carl@bridge.example",
    "contact_policy": "closed",
    "allow": ["muse@bridge.example"],
    "block": [],
    "limits": {},
}
DIRECT = {
    "agent_id": "carl@bridge.example",
    "contact_policy": "direct",
    "deployment": "private",
    "allow": [],
    "block": [],
    "limits": {},
}


def build(tmp_path, policy_doc, rates=False):
    contacts = Contacts(tmp_path / "contacts.db")
    threads = Threads(tmp_path / "threads.db")
    store = Rates(tmp_path / "rates.db") if rates else None
    return Gate(parse(policy_doc), contacts, threads, store), contacts


def envelope(sender=SENDER, context="c-1"):
    return {
        "from": sender,
        "message": {"kind": "message", "messageId": "m-1", "contextId": context,
                    "role": "agent", "parts": [{"kind": "text", "text": "hi"}]},
        "to": ["carl@bridge.example"],
    }


def test_stranger_is_refused_with_the_shared_reason(tmp_path):
    gate, _ = build(tmp_path, CLOSED)
    decision = gate.decide(envelope(sender=STRANGER), T0)
    assert decision.allowed is False and decision.reason == REFUSED


def test_allow_list_is_a_pre_approval_and_needs_no_handshake(tmp_path):
    gate, _ = build(tmp_path, CLOSED)
    assert gate.decide(envelope(), T0).allowed is True


def test_an_accepted_contact_is_admitted_without_being_pre_listed(tmp_path):
    # The handshake must be able to admit someone the policy file never listed. Under v1 this was
    # refused forever, which made §9's handshake decorative.
    gate, contacts = build(tmp_path, {**CLOSED, "allow": []})
    contacts.request(SENDER, "", T0)
    contacts.accept(SENDER, T0)
    assert gate.decide(envelope(), T0).allowed is True


def test_blocked_agent_is_refused_even_when_accepted(tmp_path):
    doc = {**CLOSED, "allow": [], "block": [SENDER]}
    gate, contacts = build(tmp_path, doc)
    contacts.request(SENDER, "", T0)
    contacts.accept(SENDER, T0)
    decision = gate.decide(envelope(), T0)
    assert decision.allowed is False and decision.reason == REFUSED


def test_direct_delivery_policy_admits_a_stranger(tmp_path):
    gate, _ = build(tmp_path, DIRECT)
    assert gate.decide(envelope(), T0).allowed is True


def test_reply_to_a_message_that_asked_for_none_is_dropped(tmp_path):
    gate, _ = build(tmp_path, CLOSED)
    gate.threads.note_sent("c-1", expects_reply=False, closes=False, now=T0)
    decision = gate.decide(envelope(context="c-1"), T0)
    assert decision.allowed is False and decision.reason == REFUSED


def test_two_questions_in_one_context_owe_two_answers(tmp_path):
    gate, _ = build(tmp_path, CLOSED)
    gate.threads.note_sent("c-1", expects_reply=True, closes=False, now=T0)
    gate.threads.note_sent("c-1", expects_reply=True, closes=False, now=T0)
    assert gate.decide(envelope(context="c-1"), T0).allowed is True
    assert gate.decide(envelope(context="c-1"), T0).allowed is True
    assert gate.decide(envelope(context="c-1"), T0).allowed is False


def test_closed_thread_refuses_further_traffic(tmp_path):
    gate, _ = build(tmp_path, CLOSED)
    gate.threads.note_sent("c-1", expects_reply=True, closes=True, now=T0)
    assert gate.decide(envelope(context="c-1"), T0).allowed is False


def test_sealed_envelope_is_refused_rather_than_crashing(tmp_path):
    gate, _ = build(tmp_path, CLOSED)
    sealed = {"from": SENDER, "messageId": "m-1",
              "sealed": {"hpke": {"enc": "x", "ciphertext": "y"}, "recipientKeyId": "z"}}
    decision = gate.decide(sealed, T0)
    assert decision.allowed is False and decision.reason == REFUSED


def test_malformed_envelope_is_refused(tmp_path):
    gate, _ = build(tmp_path, CLOSED)
    for bad in (None, "nope", {}, {"from": SENDER, "message": "text"}):
        assert gate.decide(bad, T0).allowed is False


def test_rate_limit_is_enforced(tmp_path):
    doc = {**CLOSED, "limits": {"per_sender_per_hour": 2}}
    gate, _ = build(tmp_path, doc, rates=True)
    assert gate.decide(envelope(context="c-1"), T0).allowed is True
    assert gate.decide(envelope(context="c-2"), T0).allowed is True
    assert gate.decide(envelope(context="c-3"), T0).allowed is False
    # The next hour starts clean.
    assert gate.decide(envelope(context="c-4"), T0.replace(hour=6)).allowed is True
