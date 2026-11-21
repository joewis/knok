import copy
from datetime import datetime, timedelta, timezone

import pytest

from knok.envelope import form_of, sign, validate, verify_envelope
from knok.identity import generate


def sealed_factory(envelope_factory, **overrides):
    """A form 2 envelope: cleartext headers + messageId, sealed body in place of message."""
    envelope = envelope_factory()
    message_id = envelope["message"]["messageId"]
    del envelope["message"]
    envelope["messageId"] = message_id
    envelope["sealed"] = {
        "hpke": {"enc": "AAECAwQFBgc=", "ciphertext": "AAECAwQFBgcICQoLDA0ODw=="},
        "recipientKeyId": "x25519:deadbeef",
    }
    envelope.update(overrides)
    return envelope


def test_expires_at_is_capped_at_thirty_days(envelope_factory):
    """#107: SPEC §6 allows up to 30 days, and the queue's retention is sized
    around that bound; a longer lifetime is a different contract."""
    envelope = envelope_factory()
    sent = datetime.strptime(envelope["sentAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    envelope["expiresAt"] = (sent + timedelta(days=31)).strftime("%Y-%m-%dT%H:%M:%SZ")
    reason = validate(envelope, now=sent)
    assert reason is not None and "30 days" in reason

    envelope["expiresAt"] = (sent + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert validate(envelope, now=sent) is None


def test_turn_rejects_an_unknown_field(envelope_factory):
    """#108: an unknown turn field is a sender expecting behaviour that does
    not exist, and nothing downstream would notice."""
    envelope = envelope_factory()
    envelope["turn"]["forceClose"] = True
    assert validate(envelope) == "turn carries an unknown field: forceClose"


def test_turn_cannot_expect_a_reply_and_close_the_thread(envelope_factory):
    """#108: the gate refuses a reply to a closed thread, so the two flags
    together ask for a reply the message has already forbidden."""
    envelope = envelope_factory()
    envelope["turn"] = {"expectsReply": True, "closesThread": True}
    reason = validate(envelope)
    assert reason is not None and "close the thread" in reason


def test_valid_form_2_validates(identity, envelope_factory):
    assert validate(sealed_factory(envelope_factory)) is None
    assert form_of(sealed_factory(envelope_factory)) == "sealed"
    assert form_of(envelope_factory()) == "plain"


def test_form_2_sign_verify_round_trip(identity, envelope_factory):
    signed = sign(sealed_factory(envelope_factory), identity)
    ok, reason = verify_envelope(signed, identity.public_key)
    assert ok, reason
    assert form_of(signed) == "sealed"


def test_form_2_tampered_sealed_fails(identity, envelope_factory):
    signed = sign(sealed_factory(envelope_factory), identity)
    signed["sealed"]["hpke"]["ciphertext"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    ok, reason = verify_envelope(signed, identity.public_key)
    assert not ok and "signature" in reason


def test_form_2_message_id_swap_breaks_signature(identity, envelope_factory):
    """Changing messageId after signing must fail: the signature covers the whole
    envelope, not the sealed field alone (SPEC §6)."""
    signed = sign(sealed_factory(envelope_factory), identity)
    signed["messageId"] = "m-swapped"
    ok, reason = verify_envelope(signed, identity.public_key)
    assert not ok and "signature" in reason


def test_both_forms_present_is_invalid(identity, envelope_factory):
    envelope = sealed_factory(envelope_factory)
    envelope["message"] = envelope_factory()["message"]
    reason = validate(envelope)
    assert reason is not None and "message" in reason and "sealed" in reason


def test_neither_form_present_is_invalid(identity, envelope_factory):
    envelope = envelope_factory()
    del envelope["message"]
    reason = validate(envelope)
    assert reason is not None and "message" in reason and "sealed" in reason
    assert form_of(envelope) is None
    assert form_of({"message": {}, "sealed": {}}) is None
    assert form_of("not an envelope") is None


def test_form_2_without_message_id_is_invalid(identity, envelope_factory):
    envelope = sealed_factory(envelope_factory)
    del envelope["messageId"]
    reason = validate(envelope)
    assert reason is not None and "messageId" in reason


def test_form_2_without_recipient_key_id_is_invalid(identity, envelope_factory):
    envelope = sealed_factory(envelope_factory)
    del envelope["sealed"]["recipientKeyId"]
    reason = validate(envelope)
    assert reason is not None and "recipientKeyId" in reason


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s["hpke"].pop("enc"),
        lambda s: s["hpke"].pop("ciphertext"),
        lambda s: s["hpke"].update(enc=42),
        lambda s: s["hpke"].update(ciphertext=["not", "a", "string"]),
        lambda s: s.update(hpke="not-an-object"),
        lambda s: s.update(extra="smuggled"),
    ],
)
def test_malformed_hpke_is_invalid(identity, envelope_factory, mutate):
    envelope = sealed_factory(envelope_factory)
    mutate(envelope["sealed"])
    reason = validate(envelope)
    assert reason is not None, "malformed sealed.hpke must be rejected"


def test_form_1_with_top_level_message_id_is_invalid(identity, envelope_factory):
    envelope = envelope_factory(messageId="m-1")
    reason = validate(envelope)
    assert reason is not None and "messageId" in reason


def test_sign_verify_round_trip(identity, envelope_factory):
    signed = sign(envelope_factory(), identity)
    ok, reason = verify_envelope(signed, identity.public_key)
    assert ok, reason


def test_tampered_text_fails(identity, envelope_factory):
    signed = sign(envelope_factory(), identity)
    signed["message"]["parts"][0]["text"] = "is §4 ready? (edited)"
    ok, reason = verify_envelope(signed, identity.public_key)
    assert not ok and "signature" in reason


def test_changed_seq_fails(identity, envelope_factory):
    signed = sign(envelope_factory(), identity)
    signed["seq"] = 99
    assert verify_envelope(signed, identity.public_key)[0] is False


def test_missing_signature_fails(identity, envelope_factory):
    signed = sign(envelope_factory(), identity)
    del signed["signature"]
    ok, reason = verify_envelope(signed, identity.public_key)
    assert not ok and "signature" in reason


def test_wrong_signer_fails(identity, envelope_factory):
    thief = generate("mallory", "bridge.example")
    signed = sign(envelope_factory(), identity)
    ok, reason = verify_envelope(signed, thief.public_key)
    assert not ok and "signature" in reason


def test_from_must_match_signing_identity(identity, envelope_factory):
    with pytest.raises(ValueError):
        sign(envelope_factory(**{"from": "muse@bridge.example"}), identity)


def test_key_order_does_not_break_verification(identity, envelope_factory):
    signed = sign(envelope_factory(), identity)
    reordered = {k: signed[k] for k in reversed(list(signed))}
    assert verify_envelope(reordered, identity.public_key)[0]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: "not an envelope",
        lambda e: {**e, "message": {"kind": "message"}},
        lambda e: {**e, "seq": "one"},
        lambda e: {**e, "to": []},
        lambda e: {**e, "turn": {"expectsReply": "yes", "closesThread": False}},
        lambda e: {**e, "from": "not-an-id"},
        lambda e: {**e, "signature": "ed25519:not-base64!"},
    ],
)
def test_malformed_input_never_raises(identity, envelope_factory, mutate):
    signed = sign(envelope_factory(), identity)
    ok, reason = verify_envelope(mutate(copy.deepcopy(signed)), identity.public_key)
    assert ok is False and isinstance(reason, str) and reason


def test_float_seq_is_rejected_not_raised(identity, envelope_factory):
    signed = sign(envelope_factory(), identity)
    signed["seq"] = 1.5
    ok, reason = verify_envelope(signed, identity.public_key)
    assert ok is False
