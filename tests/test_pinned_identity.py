"""A card is pinned under the name it signed for (#62).

``load_cards`` verified that a card's JWS matched the key the card carried, but keyed the pinned
dict by the file name (or by a ``bridge.agent`` field the spec does not define). Nothing checked that
the card was *about* the agent it was filed under, so a card dropped in as ``mallory@hub.json``
granted its key authority over ``mallory@hub`` while the signed body said ``carl@hub`` — a name
binding decided by a file name, which no signature covers.

The id now comes from the body: ``name@hub``, the same rule ``verify_card`` uses when it is handed an
expected id. A card that names no agent is dropped rather than guessed at, because a key with no id in
its own signature is a key nobody signed for.

A second, smaller fail-open lives in the same field: a ``validUntil`` that was present but unreadable
used to mean "no deadline stated", so a card could state a limit and be trusted forever. It now
refuses. Both changes are about one invariant: ``public_key_of`` answers only for a card whose signed
body accounts for *that name* at *that instant*.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from knok.agentcard import sign_card, verify_card
from knok.bridge import load_cards


def card(identity, *, name="carl", hub="bridge.example", **extra):
    body = {
        "name": name,
        "description": f"{name} on elitedesk",
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
            "hub": hub,
        },
        **extra,
    }
    return body


def test_a_card_is_pinned_under_the_id_its_body_claims(identity, tmp_path):
    """The file name is not evidence; the signed body is.

    Writing carl's valid card to ``mallory@bridge.example.json`` must not give carl's key authority
    over mallory's name — and it must not hide carl either, since that body is genuinely his.
    """
    document = sign_card(card(identity), identity)
    (tmp_path / "mallory@bridge.example.json").write_text(json.dumps(document))

    cards = load_cards(tmp_path)

    assert set(cards) == {"carl@bridge.example"}
    assert cards["carl@bridge.example"]["bridge"]["publicKey"] == identity.public_b64()


def test_a_card_that_names_no_agent_is_not_pinned(identity, tmp_path):
    """No ``name@hub`` in the body means no id to pin it under — not "use the file name"."""
    body = card(identity)
    body["bridge"].pop("hub")
    (tmp_path / "carl@bridge.example.json").write_text(json.dumps(sign_card(body, identity)))

    assert load_cards(tmp_path) == {}


def test_bridge_agent_is_not_an_id_the_code_honours(identity, tmp_path):
    """``bridge.agent`` is not in SPEC §5's card shape, and it must not grant a name.

    A body that carries one is still pinned by ``name@hub``; otherwise a stray field would be a
    second, unsigned-ish source of identity that nothing else in the protocol reads.
    """
    body = card(identity)
    body["bridge"]["agent"] = "mallory@bridge.example"
    (tmp_path / "carl@bridge.example.json").write_text(json.dumps(sign_card(body, identity)))

    cards = load_cards(tmp_path)

    assert set(cards) == {"carl@bridge.example"}
    assert "mallory@bridge.example" not in cards


def test_verify_card_answers_for_the_id_the_body_claims(identity, peer):
    """The same rule in the other reader: a card is only ever *about* one agent."""
    document = sign_card(card(peer, name="muse"), peer)
    registry = {peer.fingerprint: peer.public_b64()}

    ok, reason = verify_card(document, registry, expected_agent_id="muse@bridge.example")
    assert ok, reason
    refused, why = verify_card(document, registry, expected_agent_id="carl@bridge.example")
    assert not refused
    assert "muse@bridge.example" in why


def test_a_card_with_an_unreadable_valid_until_is_not_pinned(identity, tmp_path):
    """A stated deadline that cannot be read refuses the card instead of being ignored (#62)."""
    body = card(identity, validUntil="the end of days")
    (tmp_path / "carl@bridge.example.json").write_text(json.dumps(sign_card(body, identity)))

    assert load_cards(tmp_path) == {}
    ok, reason = verify_card(sign_card(body, identity),
                             {identity.fingerprint: identity.public_b64()}, now=datetime.now(timezone.utc))
    assert not ok
    assert "validUntil" in reason
