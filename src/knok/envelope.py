"""The signed envelope that carries an unmodified A2A ``Message`` (SPEC §6, form 1).

Contract: ``verify_envelope`` never raises. It returns ``(True, "")`` or ``(False, reason)``
so a caller handling hostile input cannot be made to crash by a malformed message.
"""

from __future__ import annotations

from typing import Any

from .canonical import CanonicalisationError, canonical_bytes
from .identity import Identity, IdentityError, validate_agent_id, verify_signature

REQUIRED = {
    "envelopeVersion",
    "seq",
    "message",
    "from",
    "to",
    "sentAt",
    "expiresAt",
    "turn",
}


def _check_message(message: Any) -> str | None:
    if not isinstance(message, dict):
        return "message must be an object"
    if message.get("kind") != "message":
        return "message.kind must be 'message'"
    if not isinstance(message.get("messageId"), str) or not message["messageId"]:
        return "message.messageId must be a non-empty string"
    if not isinstance(message.get("contextId"), str) or not message["contextId"]:
        return "message.contextId must be a non-empty string"
    if message.get("role") not in ("agent", "user"):
        return "message.role must be 'agent' or 'user'"
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts:
        return "message.parts must be a non-empty list"
    for part in parts:
        if not isinstance(part, dict) or "kind" not in part:
            return "each message.parts entry must be an object with a kind"
    return None


def validate(envelope: dict[str, Any]) -> str | None:
    """Return a human-readable reason the envelope is invalid, or None."""
    if not isinstance(envelope, dict):
        return "envelope must be an object"
    missing = REQUIRED - set(envelope)
    if missing:
        return "missing fields: " + ", ".join(sorted(missing))
    if envelope["envelopeVersion"] != 1:
        return "unsupported envelopeVersion"
    if not isinstance(envelope["seq"], int) or isinstance(envelope["seq"], bool):
        return "seq must be an integer"
    if envelope["seq"] < 0:
        return "seq must be >= 0"
    reason = _check_message(envelope["message"])
    if reason:
        return reason
    for field in ("from",):
        try:
            validate_agent_id(envelope[field])
        except IdentityError as exc:
            return str(exc)
    recipients = envelope["to"]
    if not isinstance(recipients, list) or not recipients:
        return "to must be a non-empty list"
    for recipient in recipients:
        try:
            validate_agent_id(recipient)
        except IdentityError as exc:
            return str(exc)
    turn = envelope["turn"]
    if not isinstance(turn, dict) or not isinstance(turn.get("expectsReply"), bool) \
            or not isinstance(turn.get("closesThread"), bool):
        return "turn must carry boolean expectsReply and closesThread"
    return None


def sign(envelope: dict[str, Any], identity: Identity) -> dict[str, Any]:
    """Return a new envelope with a signature over its JCS bytes."""
    reason = validate(envelope)
    if reason:
        raise ValueError(reason)
    if envelope["from"] != identity.agent_id:
        raise ValueError("envelope 'from' does not match the signing identity")
    body = {k: v for k, v in envelope.items() if k != "signature"}
    signed = dict(body)
    signed["signature"] = identity.sign(canonical_bytes(body))
    return signed


def verify_envelope(envelope: Any, public_key) -> tuple[bool, str]:
    """Verify structure and signature. Never raises."""
    reason = validate(envelope) if isinstance(envelope, dict) else "envelope must be an object"
    if reason:
        return False, reason
    signature = envelope.get("signature")
    if not isinstance(signature, str):
        return False, "missing signature"
    body = {k: v for k, v in envelope.items() if k != "signature"}
    try:
        payload = canonical_bytes(body)
    except CanonicalisationError as exc:
        return False, str(exc)
    if not verify_signature(public_key, payload, signature):
        return False, "signature does not verify"
    return True, ""
