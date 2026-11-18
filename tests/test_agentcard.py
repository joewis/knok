import copy

from knok.agentcard import sign_card, verify_card
from knok.identity import generate


def card(identity):
    return {
        "name": "carl",
        "description": "Carl on elitedesk",
        "url": "https://elitedesk.example/a2a",
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


def test_card_verifies_against_registry(identity):
    jws = sign_card(card(identity), identity)
    registry = {identity.fingerprint: identity.public_b64()}
    ok, reason = verify_card(jws, registry)
    assert ok, reason


def test_card_from_unregistered_key_is_refused(identity):
    jws = sign_card(card(identity), identity)
    ok, reason = verify_card(jws, {})
    assert not ok and "registry" in reason


def test_card_with_swapped_key_is_refused(identity):
    other = generate("mallory", "bridge.example")
    jws = sign_card(card(identity), identity)
    ok, reason = verify_card(jws, {identity.fingerprint: other.public_b64()})
    assert not ok


def test_tampered_payload_is_refused(identity):
    jws = sign_card(card(identity), identity)
    tampered = copy.deepcopy(jws)
    tampered["payload"] = tampered["payload"][:-4] + "AAAA"
    ok, reason = verify_card(tampered, {identity.fingerprint: identity.public_b64()})
    assert not ok


def test_malformed_card_never_raises(identity):
    registry = {identity.fingerprint: identity.public_b64()}
    for bad in (None, {}, {"protected": 1, "payload": 2, "signature": 3}, "string"):
        ok, reason = verify_card(bad, registry)
        assert ok is False and reason
