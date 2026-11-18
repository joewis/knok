import copy

import pytest

from knok.envelope import sign, validate, verify_envelope
from knok.identity import generate


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
