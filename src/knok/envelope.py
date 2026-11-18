"""The signed envelope that carries an unmodified A2A ``Message`` (SPEC §6, form 1),
or a sealed body (SPEC §6, form 2).

Contract: ``verify_envelope`` never raises. It returns ``(True, "")`` or ``(False, reason)``, so a
caller handling hostile input cannot be made to crash, hang, or do unbounded work by it.

The structural checks run *before* any signature work on purpose: canonicalising an attacker's
envelope is the expensive part, so depth, size and shape are capped first (SPEC §2 goal 7).

Which form was verified: ``verify_envelope`` keeps its ``(bool, reason)`` shape, and the parsed
form is reported by :func:`form_of` instead — ``"plain"`` for form 1, ``"sealed"`` for form 2,
``None`` when the envelope carries neither or both. The issue asked for the form to come back from
verification; returning it from ``verify_envelope`` would have changed every call site (bridge,
transport, hub) for one extra value, so the smaller diff is a separate ``form_of`` call on an
envelope that already verified. No decryption happens anywhere here: form 2 validation is
structural only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .canonical import MAX_BYTES, MAX_INT, CanonicalisationError, canonical_bytes
from .identity import Identity, IdentityError, validate_agent_id, verify_signature
from .message import MessageValidationError, validate_message

#: Fields present in both forms.
REQUIRED = {
    "envelopeVersion",
    "seq",
    "from",
    "to",
    "sentAt",
    "expiresAt",
    "turn",
}
#: Form 1 carries ``message``; form 2 carries ``sealed`` plus a cleartext ``messageId``.
FORM_FIELDS = {"message", "sealed", "messageId"}
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


def form_of(envelope: Any) -> str | None:
    """Return ``"plain"`` (form 1) or ``"sealed"`` (form 2), or ``None`` when the envelope
    carries neither or both payload fields. Presence only — it does not validate."""
    if not isinstance(envelope, dict):
        return None
    has_message = "message" in envelope
    has_sealed = "sealed" in envelope
    if has_message and not has_sealed:
        return "plain"
    if has_sealed and not has_message:
        return "sealed"
    return None


def _validate_sealed(sealed: Any) -> str | None:
    """Structural check of a form 2 ``sealed`` object. No decryption (SPEC §6)."""
    if not isinstance(sealed, dict):
        return "sealed must be an object"
    unknown = set(sealed) - {"hpke", "recipientKeyId"}
    if unknown:
        return "unknown sealed fields: " + ", ".join(sorted(unknown))
    missing = {"hpke", "recipientKeyId"} - set(sealed)
    if missing:
        return "sealed is missing fields: " + ", ".join(sorted(missing))
    recipient_key_id = sealed["recipientKeyId"]
    if not isinstance(recipient_key_id, str) or not recipient_key_id:
        return "sealed recipientKeyId must be a non-empty string"
    hpke = sealed["hpke"]
    if not isinstance(hpke, dict):
        return "sealed.hpke must be an object"
    unknown = set(hpke) - {"enc", "ciphertext"}
    if unknown:
        return "unknown sealed.hpke fields: " + ", ".join(sorted(unknown))
    missing = {"enc", "ciphertext"} - set(hpke)
    if missing:
        return "sealed.hpke is missing fields: " + ", ".join(sorted(missing))
    for field in ("enc", "ciphertext"):
        value = hpke[field]
        if not isinstance(value, str) or not value:
            return f"sealed.hpke.{field} must be a non-empty string"
        if len(value) > MAX_BYTES:
            # Size cap here, before any canonicalisation, so a hostile sealed
            # envelope is rejected on shape/size rather than by canonicalising it.
            return f"sealed.hpke.{field} exceeds {MAX_BYTES} bytes"
    return None


def validate(envelope: Any, now: datetime | None = None) -> str | None:
    """Return why the envelope is invalid, or None when it is well formed and unexpired."""
    if not isinstance(envelope, dict):
        return "envelope must be an object"
    unknown = set(envelope) - REQUIRED - FORM_FIELDS - OPTIONAL
    if unknown:
        return "unknown envelope fields: " + ", ".join(sorted(unknown))
    missing = REQUIRED - set(envelope)
    if missing:
        return "missing fields: " + ", ".join(sorted(missing))

    has_message = "message" in envelope
    has_sealed = "sealed" in envelope
    if has_message and has_sealed:
        return "envelope must carry exactly one of 'message' and 'sealed', not both"
    if not has_message and not has_sealed:
        return "envelope must carry exactly one of 'message' and 'sealed'"

    if has_sealed:
        message_id = envelope.get("messageId")
        if not isinstance(message_id, str) or not message_id:
            return "form 2 (sealed) envelope must carry a non-empty messageId in clear"
        reason = _validate_sealed(envelope["sealed"])
        if reason:
            return reason
    else:
        if "messageId" in envelope:
            return "form 1 (plain) envelope must not carry a top-level messageId"

    version = envelope["envelopeVersion"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        return "unsupported envelopeVersion"

    seq = envelope["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        return "seq must be a non-negative integer"
    if seq > MAX_INT:
        # Explicit rather than left to canonicalisation, so the reason names the field.
        return f"seq must not exceed {MAX_INT}"

    if has_message:
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
    """Return a new envelope with a signature over its JCS bytes.

    Works for both forms: the signature covers the whole envelope minus the signature field,
    so for form 2 it covers ``messageId`` and ``sealed`` as well as the cleartext headers.
    """
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
