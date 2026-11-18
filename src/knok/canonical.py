"""JCS (RFC 8785) canonicalisation.

Contract: ``canonical_bytes(obj)`` returns the exact UTF-8 bytes a signature is computed
over. Two objects that are equal as JSON values must produce identical bytes regardless of
key order or whitespace, and no other serialisation is conformant (SPEC §6).

Numbers must be integers. RFC 8785 also defines float formatting, but that is the part
implementations disagree about, and the spec forbids non-integer numbers in an envelope
anyway — rejecting them is cheaper than getting the formatting subtly wrong.
"""

from __future__ import annotations

import json
from typing import Any


class CanonicalisationError(ValueError):
    """Raised when a value cannot be canonicalised under this profile."""


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalisationError(f"{path}: numbers must be integers, got float {value!r}")
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalisationError(f"{path}: object keys must be strings, got {key!r}")
            _check(item, f"{path}.{key}")
        return
    raise CanonicalisationError(f"{path}: unsupported type {type(value).__name__}")


def canonical_bytes(obj: Any) -> bytes:
    """Return JCS bytes for ``obj``, or raise CanonicalisationError."""
    _check(obj, "$")
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
