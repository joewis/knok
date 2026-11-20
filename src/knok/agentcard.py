"""Agent Card signing and registry verification (SPEC §5).

Contract: a card is trusted only when its signature verifies against the key the *registry*
published **for the id named in the JWS header**, and the card's own key matches that entry.
The header is inside the signed input (RFC 7515 signs ``protected.payload``), because a header
the signature does not cover would let anyone re-attach a card to a different ``kid``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalisationError, canonical_bytes
from .identity import Identity, b64url, b64url_decode, fingerprint, public_key_from_b64, verify_signature
from .registry import Registry


class CardError(ValueError):
    """Raised when a card cannot be signed."""


class CardTimeError(ValueError):
    """Raised when ``validUntil`` is present and is not a timestamp.

    Separate from "no ``validUntil``" on purpose: a card that states a deadline this code cannot
    read must be refused, because the alternative is to trust it past a limit it just stated (#62).
    """


def _header(identity: Identity) -> str:
    return b64url(canonical_bytes({"alg": "EdDSA", "kid": identity.fingerprint}))


def sign_card(card: dict[str, Any], identity: Identity) -> dict[str, Any]:
    """Return a flattened JWS (RFC 7515, EdDSA) over the card's JCS bytes."""
    if card.get("bridge", {}).get("publicKey") != identity.public_b64():
        raise CardError("card publicKey does not match the signing identity")
    protected = _header(identity)
    payload = b64url(canonical_bytes(card))
    signature = identity.sign(f"{protected}.{payload}".encode("ascii")).removeprefix("ed25519:")
    return {"protected": protected, "payload": payload, "signature": signature}


def card_agent_id(card: dict) -> str | None:
    """The id the card claims for itself — ``name@hub`` — or ``None`` when it names no agent.

    The identity rule lives here because two callers need the same answer: ``verify_card`` checks a
    document against the id it is *about*, and ``load_cards`` pins a verified body under an id. When
    those disagreed, the pin came from the file name instead, so a card could be filed under a name
    it never signed for (#62).
    """
    if not isinstance(card, dict):
        return None
    bridge = card.get("bridge")
    name = card.get("name")
    hub = bridge.get("hub") if isinstance(bridge, dict) else None
    if not isinstance(name, str) or not name or not isinstance(hub, str) or not hub:
        return None
    return f"{name}@{hub}"


def card_valid_until(card: dict) -> datetime | None:
    """The instant the card stops being trusted, or ``None`` when it states no ``validUntil``.

    The one reading of the field, shared by the two places that ask the question at different
    times: ``verify_card`` asks it while the document is in hand, and a holder of an already
    pinned body (``Bridge.public_key_of``) asks it per message, because a card that verified at
    load does not stay valid on its own (#62).

    Raises :class:`CardTimeError` when the field is present and not a timestamp. ``None`` is
    reserved for "the card states no limit": a deadline that cannot be read is not the absence of
    a deadline, and treating it as one is how a stated expiry becomes decoration.
    """
    value = card.get("validUntil")
    if value is None:
        return None
    if not isinstance(value, str):
        raise CardTimeError(f"validUntil is {type(value).__name__}, not a string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise CardTimeError(f"validUntil {value!r} is not an ISO-8601 instant: {exc}") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def verify_card(
    jws: Any,
    registry: "dict[str, str] | Registry",
    expected_agent_id: str | None = None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Verify a card JWS against ``registry``. Never raises.

    ``registry`` is either a :class:`knok.registry.Registry` — which answers for an instant, so a
    revoked, expired or superseded key is refused — or the legacy ``{fingerprint: public_key}``
    dict, which means every key is valid forever (decision 0002).
    """
    if not isinstance(jws, dict):
        return False, "card must be an object"
    for field in ("protected", "payload", "signature"):
        if not isinstance(jws.get(field), str):
            return False, f"card is missing {field}"
    try:
        header = json.loads(b64url_decode(jws["protected"]))
        payload = b64url_decode(jws["payload"])
    except Exception as exc:  # malformed base64 or JSON
        return False, f"card is malformed: {exc}"
    if not isinstance(header, dict) or header.get("alg") != "EdDSA":
        return False, "card alg must be EdDSA"

    kid = header.get("kid")
    if isinstance(registry, Registry):
        record = registry.get(kid or "")
        if record is None:
            return False, "card key is not in the registry"
        state = record.status(now or datetime.now(timezone.utc))
        if state != "valid":
            # The key exists and is refused for a stated reason — revoked, expired, superseded,
            # or not yet valid. "Not in the registry" would be a different, wrong answer.
            return False, f"card key is {state}"
        registered = record.public_key
    else:
        registered = registry.get(kid or "")
        if not registered:
            return False, "card key is not in the registry"
    try:
        public_key: Ed25519PublicKey = public_key_from_b64(registered)
    except Exception:
        return False, "registry key is malformed"
    if fingerprint(public_key) != kid:
        return False, "registry entry does not match the key id it is filed under"

    signing_input = f"{jws['protected']}.{jws['payload']}".encode("ascii")
    if not verify_signature(public_key, signing_input, "ed25519:" + jws["signature"]):
        return False, "card signature does not verify"

    try:
        card = json.loads(payload)
        card_key = card["bridge"]["publicKey"]
    except (CanonicalisationError, KeyError, ValueError) as exc:
        return False, f"card body is malformed: {exc}"
    if card_key != registered:
        return False, "card publicKey differs from the registry entry"

    if expected_agent_id is not None:
        agent_id = card_agent_id(card)
        if agent_id != expected_agent_id:
            return False, f"card is for {agent_id!r}, expected {expected_agent_id!r}"

    try:
        valid_until = card_valid_until(card)
    except CardTimeError as exc:
        # A stated deadline that cannot be read is a refusal, never an absent deadline.
        return False, f"card validUntil is unusable: {exc}"
    if valid_until is not None and (now or datetime.now(timezone.utc)) >= valid_until:
        return False, "card has expired"
    return True, ""
