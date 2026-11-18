"""Unmodified A2A v1.0 client used by the slice-0 conformance harness.

This module is deliberately self-contained and stdlib-only: it must be usable
against any A2A server, so it imports nothing from the bridge library and
contains no bridge-specific code at all. The transport framing it adds around
the ``Message`` (the Form 1 envelope of spec section 6) is plain dict
construction, not a library call.

The parser is strict on purpose. It accepts every field A2A v1.0 defines on
a ``Message`` — ``kind``, ``messageId``, ``contextId``, ``role``, ``parts``
of ``{kind: "text", text: ...}``, plus ``taskId``, ``metadata``,
``extensions`` and ``referenceTaskIds``, and on a ``Part`` ``metadata``,
``filename`` and ``mediaType`` — and rejects any other field, including a
top-level ``signature`` inside the ``Message``. If a bridge-specific
extension were ever required to parse a message, this parser would fail
loudly instead of silently accepting it.

The same validation rules live in the bridge library so the server can check
inbound messages; the harness tests assert the two copies agree. Keeping a
copy here, rather than importing the library's, is the point: the client
path must work with the library entirely absent.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = ["MessageValidationError", "build_envelope", "send_message", "validate_message"]

_MESSAGE_KEYS = frozenset(
    {"kind", "messageId", "contextId", "role", "parts", "taskId",
     "metadata", "extensions", "referenceTaskIds"}
)
_PART_KEYS = frozenset({"kind", "text", "metadata", "filename", "mediaType"})
_ROLES = frozenset({"user", "agent"})


class MessageValidationError(ValueError):
    """Raised when a ``Message`` does not match the strict A2A shape."""


def validate_message(obj: Any) -> dict:
    """Validate ``obj`` as an A2A v1.0 ``Message`` and return a copy.

    The rule is "no field that A2A does not define": every A2A-defined field
    is accepted (with its A2A type), anything else raises
    ``MessageValidationError`` on the first violation.
    """
    if not isinstance(obj, dict):
        raise MessageValidationError(f"Message must be a JSON object, got {type(obj).__name__}")

    unknown = set(obj) - _MESSAGE_KEYS
    if unknown:
        raise MessageValidationError(f"Message has non-A2A fields: {sorted(unknown)}")

    if obj.get("kind") != "message":
        raise MessageValidationError(f"Message kind must be 'message', got {obj.get('kind')!r}")

    for field in ("messageId", "contextId"):
        value = obj.get(field)
        if not isinstance(value, str) or not value:
            raise MessageValidationError(f"Message {field} must be a non-empty string")

    if obj.get("role") not in _ROLES:
        raise MessageValidationError(f"Message role must be 'user' or 'agent', got {obj.get('role')!r}")

    if "metadata" in obj and not isinstance(obj["metadata"], dict):
        raise MessageValidationError("Message metadata must be an object")
    if "extensions" in obj and (
        not isinstance(obj["extensions"], list)
        or not all(isinstance(e, str) for e in obj["extensions"])
    ):
        raise MessageValidationError("Message extensions must be an array of strings")
    if "referenceTaskIds" in obj and (
        not isinstance(obj["referenceTaskIds"], list)
        or not all(isinstance(t, str) for t in obj["referenceTaskIds"])
    ):
        raise MessageValidationError("Message referenceTaskIds must be an array of strings")

    parts = obj.get("parts")
    if not isinstance(parts, list) or not parts:
        raise MessageValidationError("Message parts must be a non-empty list")

    for i, part in enumerate(parts):
        if not isinstance(part, dict):
            raise MessageValidationError(f"parts[{i}] must be a JSON object")
        unknown_part = set(part) - _PART_KEYS
        if unknown_part:
            raise MessageValidationError(f"parts[{i}] has non-A2A fields: {sorted(unknown_part)}")
        if part.get("kind") != "text":
            raise MessageValidationError(
                f"parts[{i}].kind must be 'text' (slice 0 exchanges text only), "
                f"got {part.get('kind')!r}"
            )
        if not isinstance(part.get("text"), str):
            raise MessageValidationError(f"parts[{i}].text must be a string")
        if "metadata" in part and not isinstance(part["metadata"], dict):
            raise MessageValidationError(f"parts[{i}].metadata must be an object")
        for field in ("filename", "mediaType"):
            if field in part and not isinstance(part[field], str):
                raise MessageValidationError(f"parts[{i}].{field} must be a string")

    return copy.deepcopy(obj)


def build_envelope(
    message: dict,
    *,
    sender: str,
    recipients: list[str],
    seq: int = 0,
    expects_reply: bool = True,
) -> dict:
    """Wrap a validated ``Message`` in a Form 1 transit envelope.

    The ``Message`` is placed in the envelope untouched — no field is added,
    removed or renamed inside it.
    """
    validated = validate_message(message)
    now = datetime.now(timezone.utc)
    return {
        "envelopeVersion": 1,
        "seq": seq,
        "message": validated,
        "from": sender,
        "to": list(recipients),
        "sentAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (now + timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "turn": {"expectsReply": expects_reply, "closesThread": False},
    }


def send_message(base_url: str, message: dict, *, sender: str, recipients: list[str]) -> dict:
    """POST ``message`` to ``base_url`` inside a Form 1 envelope.

    Returns the echoed ``Message`` after strict validation. Raises
    ``MessageValidationError`` if the reply's ``Message`` is not a plain A2A
    shape, and ``urllib.error.URLError`` / ``HTTPError`` on transport failure.
    """
    envelope = build_envelope(message, sender=sender, recipients=recipients)
    request = urllib.request.Request(
        base_url.rstrip("/") + "/",
        data=json.dumps(envelope).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            reply = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"bridge refused the message: HTTP {exc.code} {exc.read().decode()}") from exc
    if not isinstance(reply, dict) or "message" not in reply:
        raise MessageValidationError(f"reply has no message field: {reply!r}")
    return validate_message(reply["message"])


def main(argv: list[str] | None = None) -> int:
    """Standalone driver, so the harness can prove the client runs without
    the bridge library installed: ``python a2a_client.py --url ... --text ...``."""
    parser = argparse.ArgumentParser(description="Send one A2A text message and print the echo")
    parser.add_argument("--url", required=True, help="bridge base URL, e.g. http://127.0.0.1:1234")
    parser.add_argument("--text", required=True)
    parser.add_argument("--message-id", default="m-standalone-1")
    parser.add_argument("--context-id", default="c-standalone-1")
    parser.add_argument("--sender", default="muse@bridge.example")
    parser.add_argument("--recipient", default="carl@bridge.example")
    args = parser.parse_args(argv)
    message = {
        "kind": "message",
        "messageId": args.message_id,
        "contextId": args.context_id,
        "role": "agent",
        "parts": [{"kind": "text", "text": args.text}],
    }
    echoed = send_message(args.url, message, sender=args.sender, recipients=[args.recipient])
    print(json.dumps(echoed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
