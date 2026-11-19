"""A pinned card's ``validUntil`` keeps meaning something after load (#62).

``load_cards`` verifies each card once, when the process starts, and ``verify_card`` checks
``validUntil`` at that instant. Nothing checked it again, so a card that was valid at 09:00 was the
key every envelope from that agent was verified against at 17:00 — a restart was the only thing
that could retire it. ``Bridge.public_key_of`` is the trust path that answered with a key checked
some time ago; ``transport`` and ``Hub`` already re-verify per message.

The body is what is pinned, and ``validUntil`` lives inside the signed payload, so re-reading it
per message cannot be moved without the key that signed the card: this enforces expiry without
keeping the JWS around. Re-verifying the whole document (and consulting a ``Registry`` for
revocation) is the rest of #62, not this slice.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from knok.bridge import Bridge, BridgeState


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pinned(peer, **extra):
    """The registry entry ``load_cards`` would have pinned for ``peer``."""
    return {
        "name": "muse",
        "bridge": {"publicKey": peer.public_b64(), "hub": "bridge.example"},
        **extra,
    }


def bridge_with(registry):
    bridge = object.__new__(Bridge)
    bridge.state = BridgeState(
        agent_id="carl@bridge.example",
        directory=Path("."),
        hub_url="",
        registry=registry,
    )
    return bridge


def test_a_card_without_valid_until_is_trusted_at_any_instant(peer):
    """Every card in the live registry states no expiry; their answer must not change."""
    bridge = bridge_with({peer.agent_id: pinned(peer)})
    far_future = datetime.now(timezone.utc) + timedelta(days=3650)
    assert bridge.public_key_of(peer.agent_id, at=far_future) is not None


def test_the_card_stops_being_trusted_at_valid_until(peer):
    """The boundary is ``>=``, the same comparison ``verify_card`` makes."""
    expires = datetime(2026, 11, 20, 9, 0, tzinfo=timezone.utc)
    bridge = bridge_with({peer.agent_id: pinned(peer, validUntil=iso(expires))})

    assert bridge.public_key_of(peer.agent_id, at=expires - timedelta(seconds=1)) is not None
    assert bridge.public_key_of(peer.agent_id, at=expires) is None
    assert bridge.public_key_of(peer.agent_id, at=expires + timedelta(hours=8)) is None


def test_without_an_instant_the_question_is_asked_about_now(peer):
    now = datetime.now(timezone.utc)
    lapsed = bridge_with({peer.agent_id: pinned(peer, validUntil=iso(now - timedelta(minutes=1)))})
    live = bridge_with({peer.agent_id: pinned(peer, validUntil=iso(now + timedelta(hours=1)))})

    assert lapsed.public_key_of(peer.agent_id) is None
    assert live.public_key_of(peer.agent_id) is not None


def test_an_unreadable_valid_until_means_no_stated_limit(peer):
    """``verify_card`` already answers this way: a field it cannot read is no field."""
    bridge = bridge_with({peer.agent_id: pinned(peer, validUntil="the end of days")})
    assert bridge.public_key_of(peer.agent_id) is not None
