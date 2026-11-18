"""Strict validation of an A2A v1.0 ``Message`` (spec §6, Form 1).

The ``Message`` itself is never modified by the bridge: no top-level
``signature`` field, no invented fields. This validator enforces the A2A v1.0
``Message`` shape — ``kind``, ``messageId``, ``contextId``, ``role``,
``parts`` of ``{kind: "text", text: ...}`` — plus every other field A2A
defines on ``Message`` and ``Part`` (``metadata``, ``extensions``,
``referenceTaskIds`` on the ``Message``; ``metadata``, ``filename``,
``mediaType`` on a ``Part``). The rule is "no field that A2A does not
define": a real, unmodified A2A agent that sends ``metadata`` must pass,
while a Knok-specific extension smuggled into the ``Message`` (e.g. a
``signature``) fails loudly instead of being silently tolerated.

This module is stdlib-only on purpose: the conformance client in
``tests/conformance/a2a_client.py`` carries its own copy of the same rules so
it never has to import ``knok``. The two copies are checked against each
other by ``tests/conformance/test_slice0.py``; if they drift, the tests fail.
"""

from __future__ import annotations

import copy
from typing import Any

__all__ = ["MessageValidationError", "validate_message"]

#: Every key A2A v1.0 defines on ``Message``. ``taskId`` is present only
#: when a ``Task`` exists; ``metadata`` is an object, ``extensions`` an array
#: of URIs, ``referenceTaskIds`` an array of strings.
_MESSAGE_KEYS = frozenset(
    {"kind", "messageId", "contextId", "role", "parts", "taskId",
     "metadata", "extensions", "referenceTaskIds"}
)
#: Every key A2A v1.0 defines on a ``Part`` (TextPart and friends).
#: ``metadata`` is an object, ``filename`` and ``mediaType`` are strings.
_PART_KEYS = frozenset({"kind", "text", "metadata", "filename", "mediaType"})
_ROLES = frozenset({"user", "agent"})


class MessageValidationError(ValueError):
    """Raised when a ``Message`` does not match the strict A2A shape."""


def validate_message(obj: Any) -> dict:
    """Validate ``obj`` as an A2A v1.0 ``Message`` and return a copy.

    The rule is "no field that A2A does not define": every A2A-defined field
    is accepted (with its A2A type), anything else raises
    ``MessageValidationError`` on the first violation. The returned dict is
    a deep copy of the input, so callers can never mutate the received
    object through it.
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
