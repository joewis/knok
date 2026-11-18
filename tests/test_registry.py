"""Key records and the registry that holds them (decision 0002, issues #15 and #23)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from knok.agentcard import verify_card
from knok.identity import generate
from knok.registry import KeyRecord, Registry
from knok.transport import make_agent_card

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def _record(**overrides):
    identity = overrides.pop("identity", None) or generate("carl", "bridge.example")
    body = {
        "agent_id": identity.agent_id,
        "key_type": "ed25519",
        "public_key": identity.public_b64(),
        "fingerprint": identity.fingerprint,
        "not_before": NOW - timedelta(days=1),
        "not_after": NOW + timedelta(days=30),
    }
    body.update(overrides)
    return identity, KeyRecord(**body)


def test_a_key_is_valid_inside_its_window_only():
    _, record = _record()
    assert record.status(NOW - timedelta(days=2)) == "not-yet-valid"
    assert record.status(NOW) == "valid"
    assert record.status(NOW + timedelta(days=31)) == "expired"


def test_a_revocation_takes_effect_from_its_own_instant():
    """The whole point of a log: yesterday's message still verifies, today's does not."""
    _, record = _record(revoked_at=NOW)
    assert record.status(NOW - timedelta(hours=1)) == "valid"
    assert record.status(NOW) == "revoked"
    assert record.status(NOW + timedelta(days=1)) == "revoked"


def test_a_superseded_key_stops_validating_at_the_rotation():
    _, successor = _record()
    _, record = _record(superseded_by=successor.fingerprint, superseded_at=NOW)
    assert record.status(NOW - timedelta(minutes=1)) == "valid"
    assert record.status(NOW) == "superseded"


def test_an_unknown_fingerprint_is_unknown_not_valid():
    registry = Registry()
    _, record = _record()
    assert registry.status(record.fingerprint, NOW) == "unknown"
    assert registry.public_key(record.fingerprint) is None


def test_a_second_different_record_for_one_fingerprint_is_refused():
    _, record = _record()
    registry = Registry([record])
    with pytest.raises(ValueError):
        registry.add(KeyRecord(**{**record.__dict__, "revoked_at": NOW}))
    registry.add(record)  # the same record again is fine: adding is idempotent


def test_records_round_trip_through_json():
    _, record = _record(revoked_at=NOW, reason="laptop stolen")
    parsed = KeyRecord.from_dict(record.to_dict())
    assert parsed.status(NOW) == "revoked"
    assert parsed.reason == "laptop stolen"
    assert parsed.fingerprint == record.fingerprint


def test_a_bad_record_is_refused_with_a_reason():
    _, record = _record()
    body = record.to_dict()
    body["notAfter"] = body["notBefore"]
    with pytest.raises(ValueError):
        KeyRecord.from_dict(body)
    body = record.to_dict()
    body["keyType"] = "rsa"
    with pytest.raises(ValueError):
        KeyRecord.from_dict(body)


def test_the_legacy_dict_means_valid_forever():
    """#23's gap, made explicit: a dict cannot express a withdrawn key."""
    identity, _ = _record()
    registry = Registry.from_dict({identity.fingerprint: identity.public_b64()})
    assert registry.status(identity.fingerprint, NOW) == "valid"
    assert registry.status(identity.fingerprint, NOW + timedelta(days=3650)) == "valid"


def test_a_card_verifies_against_a_registry_of_records():
    identity, record = _record()
    card = make_agent_card(identity, "bridge.example", "http://127.0.0.1:8080")
    ok, reason = verify_card(card, Registry([record]), expected_agent_id=identity.agent_id, now=NOW)
    assert ok, reason


def test_a_revoked_card_is_refused_and_says_why():
    identity, record = _record(revoked_at=NOW)
    card = make_agent_card(identity, "bridge.example", "http://127.0.0.1:8080")
    ok, reason = verify_card(card, Registry([record]), expected_agent_id=identity.agent_id, now=NOW)
    assert not ok
    assert reason == "card key is revoked"


def test_a_card_signed_before_the_revocation_still_verifies():
    """Historical verification is the reason records carry instants rather than flags."""
    identity, record = _record(revoked_at=NOW)
    card = make_agent_card(identity, "bridge.example", "http://127.0.0.1:8080")
    ok, reason = verify_card(
        card, Registry([record]), expected_agent_id=identity.agent_id,
        now=NOW - timedelta(hours=1),
    )
    assert ok, reason


def test_an_expired_card_is_refused():
    identity, record = _record(not_after=NOW)
    card = make_agent_card(identity, "bridge.example", "http://127.0.0.1:8080")
    ok, reason = verify_card(card, Registry([record]), expected_agent_id=identity.agent_id, now=NOW)
    assert not ok
    assert reason == "card key is expired"


def test_the_encryption_key_is_a_record_of_its_own():
    """Issue #15: rotating the X25519 key must not require reissuing the card."""
    identity, signing = _record()
    old_seal, new_seal = generate("carl", "bridge.example"), generate("carl", "bridge.example")
    registry = Registry([
        signing,
        KeyRecord(agent_id=identity.agent_id, key_type="x25519",
                  public_key=old_seal.public_b64(), fingerprint=old_seal.fingerprint,
                  not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=30),
                  superseded_by=new_seal.fingerprint, superseded_at=NOW),
        KeyRecord(agent_id=identity.agent_id, key_type="x25519",
                  public_key=new_seal.public_b64(), fingerprint=new_seal.fingerprint,
                  not_before=NOW, not_after=NOW + timedelta(days=30)),
    ])
    assert registry.status(old_seal.fingerprint, NOW) == "superseded"
    assert registry.status(new_seal.fingerprint, NOW) == "valid"
    # The signing key never moved, so the card never had to be reissued.
    assert registry.status(identity.fingerprint, NOW) == "valid"
    assert len(registry.for_agent(identity.agent_id, "x25519")) == 2
