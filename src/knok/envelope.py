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
envelope that already verified.

Form 2 is *validated* structurally by everything in this module and *opened* by exactly one
function, :func:`unseal`. Where that happens is decision 0003: the receiving bridge, at admission,
after the sender's card and signature have been checked and before the gate runs. ``unseal`` does
not verify a signature itself — it cannot, it does not have the sender's card — so its contract is
that the caller has already done :func:`verify_envelope` on the sealed envelope. The form 1
envelope it returns keeps that signature, which covers the *sealed* bytes: it is evidence, not a
signature over the returned envelope, and re-verifying it as form 1 will fail by design.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime, timezone
from typing import Any

from . import hpke
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


def sent_at(envelope: Any) -> datetime | None:
    """The envelope's own ``sentAt``, or ``None`` when it has no parseable one.

    Verification asks what a key meant *then*, not at the moment the bytes arrived: a key revoked
    this morning must still validate a message signed yesterday (decision 0002, issue #23).
    """
    if not isinstance(envelope, dict):
        return None
    return _parse_time(envelope.get("sentAt"))


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


def seal(envelope: dict[str, Any], identity: Identity, recipient_public: bytes,
         recipient_key_id: str, *, aad: bytes = b"", info: bytes = b"",
         encap_private: bytes | None = None) -> dict[str, Any]:
    """Return the form 2 (sealed) envelope carrying this form 1 envelope's body.

    The body sealed is the ``message`` object, JCS-encoded: ``contextId`` lives inside it, which is
    the point — an envelope whose context is only inside the ciphertext cannot be threaded by
    anything that routes it. ``messageId`` is copied to the clear header so the receiver can dedupe
    and ack without decrypting, and :func:`unseal` refuses a body whose own id disagrees with it.

    The result is signed by ``identity`` over the sealed form, so the signature the sender's peer
    verifies covers the ciphertext and the clear header together. The form 1 input must already be
    valid and belong to ``identity``; this rebuilds the body rather than patching the old one, so a
    stale signature can never survive into the result.
    """
    reason = validate(envelope)
    if reason:
        raise ValueError(reason)
    if form_of(envelope) != "plain":
        raise ValueError("seal takes a form 1 envelope; this one is already sealed")
    if envelope["from"] != identity.agent_id:
        raise ValueError("envelope 'from' does not match the sealing identity")
    message = envelope["message"]
    message_id = message.get("messageId") if isinstance(message, dict) else None
    if not isinstance(message_id, str) or not message_id:
        raise ValueError("message has no messageId to carry in the clear header")

    plaintext = canonical_bytes(message)
    enc, ciphertext = hpke.seal(recipient_public, plaintext, aad=aad, info=info,
                                encap_private=encap_private)
    body = {key: value for key, value in envelope.items() if key not in {"message", "signature", "messageId"}}
    body["messageId"] = message_id
    body["sealed"] = {
        "hpke": {
            "enc": base64.b64encode(enc).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        },
        "recipientKeyId": recipient_key_id,
    }
    return sign(body, identity)


def unseal(envelope: Any, private_key: bytes, *, key_id: str | None = None, aad: bytes = b"",
           info: bytes = b"") -> tuple[dict[str, Any] | None, str]:
    """Open a sealed envelope into its form 1 form. Returns ``(envelope, "")`` or ``(None, reason)``.

    Never raises, for the same reason :func:`verify_envelope` never does: the input is hostile
    ciphertext and a crash is a caller's problem to avoid, not a reason for one.

    Three refusals are deliberate and worth telling apart in the reason, because they are different
    facts: the envelope is malformed or expired; it is sealed for a different recipient key
    (``key_id``, when the caller knows its own); the body does not authenticate (wrong key, or a
    changed byte — indistinguishable from each other on purpose, RFC 9180 §9.5). A body whose
    ``messageId`` disagrees with the clear header is malformed, not "the id from inside": the clear
    id is what the hub routed on and what ``seen`` holds.

    ``hpke``'s ``aad`` and ``info`` are empty by default. SPEC §6 does not pin them yet — the
    signature is the binding between the clear header and the body, and it covers both — so the
    first implementation to put sealed mail on the wire has to write that sentence before it can
    interoperate with anything but itself.
    """
    reason = validate(envelope)
    if reason:
        return None, reason
    if form_of(envelope) != "sealed":
        return None, "envelope is not sealed"
    sealed = envelope["sealed"]
    if key_id is not None and sealed["recipientKeyId"] != key_id:
        return None, "sealed for a different recipient key"

    try:
        enc = base64.b64decode(sealed["hpke"]["enc"], validate=True)
        ciphertext = base64.b64decode(sealed["hpke"]["ciphertext"], validate=True)
    except (binascii.Error, ValueError, TypeError):
        return None, "sealed.hpke carries something that is not base64"
    if len(enc) != hpke.NENC:
        return None, "sealed.hpke.enc is not a 32-byte key"
    if len(ciphertext) <= 16:  # AEAD tag only, or less: no plaintext can be inside
        return None, "sealed.hpke.ciphertext is too short to carry a message"

    try:
        plaintext = hpke.open_sealed(private_key, enc, ciphertext, aad=aad, info=info)
    except hpke.HpkeError as exc:
        return None, str(exc)
    try:
        message = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "sealed body is not a JSON message"
    except RecursionError:
        return None, "sealed body is too deeply nested to be a message"

    clear_id = envelope["messageId"]
    body_id = message.get("messageId") if isinstance(message, dict) else None
    if body_id != clear_id:
        return None, "sealed body's messageId does not match the clear header"

    opened = {key: value for key, value in envelope.items() if key not in {"sealed", "messageId"}}
    opened["message"] = message
    reason = validate(opened)
    if reason:
        return None, f"sealed body is not a valid envelope: {reason}"
    return opened, ""
