"""``card_body`` is the trust anchor's decoder, so it answers — it does not merely not-crash (#59).

``load_cards`` builds ``BridgeState.registry`` out of ``card_body`` for every ``*.json`` in the
registry directory, and ``Bridge.public_key_of`` decides from that dict whether a sender's envelope
signature is even checked. Its docstring has always said *None when it does not verify*; until now
the code called ``verify_card`` and threw the verdict away, so every document whose payload merely
decoded was returned as if it had been checked.

Two failure modes, one contract: a card that does not verify, and a card that is not a card at all.
The second one used to escape as an exception out of ``load_cards`` — i.e. one unreadable file
stopped the bridge from starting, which is the same silent-drop class from the other end.
"""

from __future__ import annotations

import json

from knok.agentcard import sign_card
from knok.bridge import card_body, load_cards
from knok.identity import b64url


def card(identity, name="carl"):
    return {
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
            "hub": "bridge.example",
        },
    }


def reencode(jws, body):
    """Same signature, different body: the cheapest forgery there is, and the one that worked."""
    return {**jws, "payload": b64url(json.dumps(body, sort_keys=True).encode("utf-8"))}


def mangle(signature):
    """Change one character in the middle — never a no-op, which ``"A" + sig[1:]`` can be."""
    middle = len(signature) // 2
    changed = signature[:middle] + ("A" if signature[middle] != "A" else "B") + signature[middle + 1:]
    assert changed != signature
    return changed


def test_a_valid_card_still_decodes(identity):
    """The positive control: this fix must not break the one case that ever worked."""
    body = card_body(sign_card(card(identity), identity))
    assert body is not None
    assert body["name"] == "carl"
    assert body["bridge"]["publicKey"] == identity.public_b64()


def test_a_tampered_signature_is_not_a_body(identity):
    jws = sign_card(card(identity), identity)
    assert card_body({**jws, "signature": mangle(jws["signature"])}) is None


def test_a_swapped_body_under_an_old_signature_is_not_a_body(identity):
    """The issue's demonstration: rename the agent, keep the signature, and it used to be pinned."""
    jws = sign_card(card(identity), identity)
    body = json.loads(json.dumps(card(identity)))
    body["name"] = "bobby"
    assert card_body(reencode(jws, body)) is None


def test_a_public_key_that_is_not_a_key_is_not_a_body(identity):
    jws = sign_card(card(identity), identity)
    body = card(identity)
    body["bridge"]["publicKey"] = "not base64 at all!!"
    # Not just "is None": it must not raise, because load_cards calls this per file.
    assert card_body(reencode(jws, body)) is None


def test_a_bridge_that_is_not_an_object_is_not_a_body(identity):
    jws = sign_card(card(identity), identity)
    body = card(identity)
    body["bridge"] = "bridge.example"
    assert card_body(reencode(jws, body)) is None


def test_load_cards_pins_the_good_card_and_drops_the_tampered_one(identity, peer, tmp_path):
    """The trust anchor's whole job, stated as a test: what it pins is what verified."""
    good = sign_card(card(identity), identity)
    (tmp_path / "carl@bridge.example.json").write_text(json.dumps(good))

    tampered = sign_card(card(peer, name="muse"), peer)
    (tmp_path / "muse@bridge.example.json").write_text(
        json.dumps({**tampered, "signature": mangle(tampered["signature"])})
    )

    cards = load_cards(tmp_path)
    # Keyed by file name: a real card carries no ``bridge.agent``, so the stem is the id.
    assert set(cards) == {"carl@bridge.example"}
    assert cards["carl@bridge.example"]["bridge"]["publicKey"] == identity.public_b64()


def test_load_cards_survives_a_card_whose_key_is_garbage(identity, peer, tmp_path):
    """One unreadable file must not take the directory, and therefore the bridge, down."""
    good = sign_card(card(identity), identity)
    (tmp_path / "carl@bridge.example.json").write_text(json.dumps(good))

    broken = card(peer, name="muse")
    broken["bridge"]["publicKey"] = "!!!"
    (tmp_path / "muse@bridge.example.json").write_text(
        json.dumps(reencode(sign_card(card(peer, name="muse"), peer), broken))
    )

    assert set(load_cards(tmp_path)) == {"carl@bridge.example"}


def test_an_empty_payload_is_not_a_body():
    assert card_body({"protected": "e30", "payload": "", "signature": "AAAA"}) is None
