"""JCS (RFC 8785) canonicalisation.

Contract: ``canonical_bytes(obj)`` returns the exact UTF-8 bytes a signature is computed over.
Equal JSON values must produce identical bytes regardless of key order or whitespace, and no
other serialisation is conformant (SPEC §6).

Three details are load-bearing, and the first implementation got two of them wrong:

* Numbers must be integers **within the IEEE-754 safe range** (abs(n) <= 2^53-1). RFC 8785 raises
  outside it; emitting such an integer verbatim would let us sign bytes no conformant peer can
  reproduce.
* Object keys sort by **UTF-16 code units**, not by Unicode code points. The two disagree for
  supplementary-plane characters, e.g. U+10000 versus U+E000.
* The encoder must not be made to recurse or allocate without bound, so depth and size are capped
  before serialisation (SPEC §2 goal 7: a stranger must not be able to make an agent do unbounded
  work).
"""

from __future__ import annotations

import json
from typing import Any

MAX_DEPTH = 32
MAX_BYTES = 256 * 1024
MAX_INT = 2**53 - 1


class CanonicalisationError(ValueError):
    """Raised when a value cannot be canonicalised under this profile."""


def _check(value: Any, path: str, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalisationError(f"{path}: nesting deeper than {MAX_DEPTH}")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise CanonicalisationError(f"{path}: integer outside the JCS safe range: {value}")
        return
    if isinstance(value, float):
        raise CanonicalisationError(f"{path}: numbers must be integers, got float {value!r}")
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalisationError(f"{path}: object keys must be strings, got {key!r}")
            _check(item, f"{path}.{key}", depth + 1)
        return
    raise CanonicalisationError(f"{path}: unsupported type {type(value).__name__}")


def _utf16_key(key: str) -> bytes:
    """Sort key matching RFC 8785's UTF-16 code-unit ordering."""
    return key.encode("utf-16-be", "surrogatepass")


def _ordered(value: Any) -> Any:
    """Rebuild the value with object keys in JCS order, preserving array order."""
    if isinstance(value, dict):
        return {key: _ordered(value[key]) for key in sorted(value, key=_utf16_key)}
    if isinstance(value, list):
        return [_ordered(item) for item in value]
    return value


def canonical_bytes(obj: Any) -> bytes:
    """Return JCS bytes for ``obj``, or raise CanonicalisationError."""
    _check(obj, "$", 0)
    try:
        encoded = json.dumps(
            _ordered(obj),
            sort_keys=False,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except RecursionError as exc:  # defensive: _check already caps depth
        raise CanonicalisationError("value is too deeply nested") from exc
    except UnicodeEncodeError as exc:
        raise CanonicalisationError(f"value contains an unencodable string: {exc}") from exc
    if len(encoded) > MAX_BYTES:
        raise CanonicalisationError(f"canonical form exceeds {MAX_BYTES} bytes")
    return encoded
