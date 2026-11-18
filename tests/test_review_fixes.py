"""Regression tests for the findings in Muse's review of PR #10.

Each test names the defect it pins down, so a future change that reintroduces it fails here
rather than in review.
"""

import copy
from datetime import datetime, timezone

import pytest
import rfc8785

from knok.agentcard import sign_card, verify_card
from knok.canonical import CanonicalisationError, canonical_bytes
from knok.envelope import sign, validate, verify_envelope
from knok.identity import generate, load


# --- H1: an unauthenticated sender must not be able to crash or stall verify ----------------


def test_deeply_nested_metadata_does_not_raise(identity, envelope_factory):
    deep = {"x": 1}
    for _ in range(1500):
        deep = {"x": deep}
    signed = sign(envelope_factory(), identity)
    signed["message"]["metadata"] = deep
    ok, reason = verify_envelope(signed, identity.public_key)
    assert ok is False and "nested" in reason


def test_oversized_message_is_refused(identity, envelope_factory):
    signed = sign(envelope_factory(), identity)
    signed["message"]["parts"] = [{"kind": "text", "text": "x" * 400} for _ in range(1000)]
    ok, reason = verify_envelope(signed, identity.public_key)
    assert ok is False and ("exceeds" in reason or "canonical" in reason)


def test_lone_surrogate_is_refused_not_raised(identity, envelope_factory):
    signed = sign(envelope_factory(), identity)
    signed["message"]["parts"] = [{"kind": "text", "text": "\ud800"}]
    ok, reason = verify_envelope(signed, identity.public_key)
    assert ok is False and isinstance(reason, str) and reason


# --- H2: canonicalisation must be JCS --------------------------------------------------------


def test_integers_outside_the_jcs_range_are_rejected():
    with pytest.raises(CanonicalisationError):
        canonical_bytes({"n": 2**70})
    with pytest.raises(CanonicalisationError):
        canonical_bytes({"n": -(2**70)})


def test_keys_sort_by_utf16_code_units():
    value = {"\U00010000": 1, "\ue000": 2}
    assert canonical_bytes(value) == rfc8785.dumps(value)


def test_astral_and_bmp_keys_agree_with_reference():
    value = {"b": {"\U0001F600": [1, 2], "\uffff": None}, "a": True}
    assert canonical_bytes(value) == rfc8785.dumps(value)


# --- M3: a card must not verify under a header it did not sign -------------------------------


def _card(identity):
    return {
        "name": "alice",
        "description": "alice",
        "url": "https://alice.example/a2a",
        "version": "0.0.1",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [],
        "securitySchemes": {},
        "bridge": {
            "publicKey": identity.public_b64(),
            "encryptionKey": "x25519:AAAA",
            "sealedRequired": True,
            "contactPolicy": "request",
            "hub": "bridge.example",
        },
    }


def test_card_with_swapped_kid_is_refused():
    alice = generate("alice", "bridge.example")
    mallory = generate("mallory", "bridge.example")
    jws = sign_card(_card(alice), alice)
    forged = copy.deepcopy(jws)
    from knok.canonical import canonical_bytes as cb
    from knok.identity import b64url

    forged["protected"] = b64url(cb({"alg": "EdDSA", "kid": mallory.fingerprint}))
    ok, reason = verify_card(forged, {mallory.fingerprint: alice.public_b64()})
    assert ok is False


def test_card_for_the_wrong_agent_id_is_refused():
    alice = generate("alice", "bridge.example")
    jws = sign_card(_card(alice), alice)
    registry = {alice.fingerprint: alice.public_b64()}
    ok, reason = verify_card(jws, registry, expected_agent_id="mallory@bridge.example")
    assert ok is False and "expected" in reason
    ok, _ = verify_card(jws, registry, expected_agent_id="alice@bridge.example")
    assert ok is True


def test_expired_card_is_refused():
    alice = generate("alice", "bridge.example")
    card = _card(alice)
    card["validUntil"] = "2020-01-01T00:00:00Z"
    jws = sign_card(card, alice)
    ok, reason = verify_card(jws, {alice.fingerprint: alice.public_b64()})
    assert ok is False and "expired" in reason


# --- M4: load() must bind an id to the registered key -------------------------------------


def test_load_rejects_a_mismatched_fingerprint(tmp_path, identity, peer):
    path = identity.save(tmp_path / "k.key")
    with pytest.raises(Exception):
        load(identity.agent_id, path, peer.fingerprint)


# --- M5: envelope validation must enforce types and expiry ---------------------------------


def test_expired_envelope_is_refused(identity, envelope_factory):
    # Sign a valid envelope, then age it: this is what arrives on the wire from an attacker,
    # and expiry must be refused on structure rather than on the (still valid) signature.
    signed = sign(envelope_factory(), identity)
    signed["expiresAt"] = "2020-01-01T00:00:00Z"
    signed["sentAt"] = "2019-12-31T00:00:00Z"
    ok, reason = verify_envelope(signed, identity.public_key)
    assert ok is False and "expired" in reason


def test_expiry_enforced_at_sign_time(identity, envelope_factory):
    with pytest.raises(ValueError, match="expired"):
        sign(envelope_factory(expiresAt="2020-01-01T00:00:00Z", sentAt="2019-12-31T00:00:00Z"), identity)


def test_boolean_version_is_rejected(identity, envelope_factory):
    with pytest.raises(ValueError):
        sign(envelope_factory(envelopeVersion=True), identity)


def test_timestamp_must_be_a_string(identity, envelope_factory):
    with pytest.raises(ValueError):
        sign(envelope_factory(sentAt=12345), identity)


def test_unknown_top_level_field_is_rejected(identity, envelope_factory):
    with pytest.raises(ValueError, match="unknown"):
        sign(envelope_factory(intent="question"), identity)


def test_expires_before_sent_is_rejected(identity, envelope_factory):
    with pytest.raises(ValueError, match="after"):
        sign(envelope_factory(expiresAt="2026-11-17T00:00:00Z"), identity)


def test_seq_outside_safe_range_is_rejected(identity, envelope_factory):
    with pytest.raises(ValueError):
        sign(envelope_factory(seq=2**60), identity)


def test_message_with_knok_signature_inside_is_rejected(identity, envelope_factory):
    with pytest.raises(ValueError, match="message"):
        sign(envelope_factory(message={
            "kind": "message", "messageId": "m", "contextId": "c", "role": "agent",
            "parts": [{"kind": "text", "text": "hi"}], "signature": "ed25519:xx",
        }), identity)
