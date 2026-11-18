"""The signed envelope that carries an unmodified A2A ``Message`` (SPEC §6, form 1).

Contract: ``verify_envelope`` never raises. It returns ``(True, "")`` or ``(False, reason)``, so a
caller handling hostile input cannot be made to crash, hang, or do unbounded work by it.

The structural checks run *before* any signature work on purpose: canonicalising an attacker's
envelope is the expensive part, so depth, size and shape are capped first (SPEC §2 goal 7).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .canonical import CanonicalisationError, canonical_bytes
from .identity import Identity, IdentityError, validate_agent_id, verify_signature
from .message import MessageValidationError, validate_message

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
OPTIONAL = {"signature"}
MAX_RECIPIENTS = 32


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def validate(envelope: Any, now: datetime | None = None) -> str | None:
    """Return why the envelope is invalid, or None when it is well formed and unexpired."""
    if not isinstance(envelope, dict):
        return "envelope must be an object"
    unknown = set(envelope) - REQUIRED - OPTIONAL
    if unknown:
        return "unknown envelope fields: " + ", ".join(sorted(unknown))
    missing = REQUIRED - set(envelope)
    if missing:
        return "missing fields: " + ", ".join(sorted(missing))

    version = envelope["envelopeVersion"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        return "unsupported envelopeVersion"

    seq = envelope["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        return "seq must be a non-negative integer"

    try:
        validate_message(envelope["message"])
    except MessageValidationError as exc:
        return f"message: {exc}"
    except RecursionError:
        # validate_message deep-copies its input; a hostile, deeply nested Message must not
        # escape this function as an exception (SPEC §2 goal 7).
        return "message: too deeply nested"

    try:
        validate_agent_id(envelope["from"])
    except (IdentityError, TypeError) as exc:
        return str(exc)

    recipients = envelope["to"]
    if not isinstance(recipients, list) or not recipients:
        return "to must be a non-empty list"
    if len(recipients) > MAX_RECIPIENTS:
        return f"to carries more than {MAX_RECIPIENTS} recipients"
    for recipient in recipients:
        try:
            validate_agent_id(recipient)
        except (IdentityError, TypeError) as exc:
            return str(exc)

    sent = _parse_time(envelope["sentAt"])
    if sent is None:
        return "sentAt must be an ISO-8601 timestamp"
    expires = _parse_time(envelope["expiresAt"])
    if expires is None:
        return "expiresAt must be an ISO-8601 timestamp"
    if expires <= sent:
        return "expiresAt must be after sentAt"
    moment = now or datetime.now(timezone.utc)
    if moment >= expires:
        return "envelope has expired"

    turn = envelope["turn"]
    if not isinstance(turn, dict) or not isinstance(turn.get("expectsReply"), bool) \
            or not isinstance(turn.get("closesThread"), bool):
        return "turn must carry boolean expectsReply and closesThread"
    return None


def sign(envelope: dict[str, Any], identity: Identity, now: datetime | None = None) -> dict[str, Any]:
    """Return a new envelope with a signature over its JCS bytes."""
    reason = validate(envelope, now)
    if reason:
        raise ValueError(reason)
    if envelope["from"] != identity.agent_id:
        raise ValueError("envelope 'from' does not match the signing identity")
    body = {key: value for key, value in envelope.items() if key != "signature"}
    signed = dict(body)
    signed["signature"] = identity.sign(canonical_bytes(body))
    return signed


def verify_envelope(envelope: Any, public_key, now: datetime | None = None) -> tuple[bool, str]:
    """Verify structure and signature. Never raises."""
    reason = validate(envelope, now)
    if reason:
        return False, reason
    signature = envelope.get("signature")
    if not isinstance(signature, str):
        return False, "missing signature"
    body = {key: value for key, value in envelope.items() if key != "signature"}
    try:
        payload = canonical_bytes(body)
    except CanonicalisationError as exc:
        return False, str(exc)
    except Exception as exc:  # defensive: a hostile value must not escape as an exception
        return False, f"envelope could not be canonicalised: {type(exc).__name__}"
    if not verify_signature(public_key, payload, signature):
        return False, "signature does not verify"
    return True, ""
