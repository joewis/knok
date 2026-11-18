"""Agent Card signing and registry verification (SPEC §5).

Contract: a card is only trusted when its signature verifies against the key the *registry*
published for that agent id. A card carrying a different key is refused, which is why the
registry — not the card — is the source of truth.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalisationError, canonical_bytes
from .identity import Identity, b64url, b64url_decode, public_key_from_b64, verify_signature


class CardError(ValueError):
    """Raised when a card cannot be signed."""


def sign_card(card: dict[str, Any], identity: Identity) -> dict[str, Any]:
    """Return a flattened JWS (RFC 7515, EdDSA) over the card's JCS bytes."""
    if card.get("bridge", {}).get("publicKey") != identity.public_b64():
        raise CardError("card publicKey does not match the signing identity")
    payload = canonical_bytes(card)
    protected = b64url(canonical_bytes({"alg": "EdDSA", "kid": identity.fingerprint}))
    signature = identity.sign(payload).removeprefix("ed25519:")
    return {"protected": protected, "payload": b64url(payload), "signature": signature}


def verify_card(jws: Any, registry: dict[str, str]) -> tuple[bool, str]:
    """Verify a card JWS against ``registry`` (agent fingerprint -> public key b64).

    Never raises: hostile input yields ``(False, reason)``.
    """
    if not isinstance(jws, dict):
        return False, "card must be an object"
    for field in ("protected", "payload", "signature"):
        if not isinstance(jws.get(field), str):
            return False, f"card is missing {field}"
    try:
        header = __import__("json").loads(b64url_decode(jws["protected"]))
        payload = b64url_decode(jws["payload"])
    except Exception as exc:  # malformed base64 or JSON
        return False, f"card is malformed: {exc}"
    if not isinstance(header, dict) or header.get("alg") != "EdDSA":
        return False, "card alg must be EdDSA"
    kid = header.get("kid")
    registered = registry.get(kid or "")
    if not registered:
        return False, "card key is not in the registry"

    try:
        public_key: Ed25519PublicKey = public_key_from_b64(registered)
    except Exception:
        return False, "registry key is malformed"

    signature = jws["signature"]
    if not verify_signature(public_key, payload, "ed25519:" + signature):
        return False, "card signature does not verify"

    try:
        card = __import__("json").loads(payload)
        card_key = card["bridge"]["publicKey"]
    except (CanonicalisationError, KeyError, ValueError) as exc:
        return False, f"card body is malformed: {exc}"
    if card_key != registered:
        return False, "card publicKey differs from the registry entry"
    return True, ""
