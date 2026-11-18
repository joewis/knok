import pytest
import rfc8785

from knok.canonical import CanonicalisationError, canonical_bytes


def test_key_order_does_not_change_bytes():
    a = {"b": 1, "a": {"z": [1, 2], "y": "x"}}
    b = {"a": {"y": "x", "z": [1, 2]}, "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_matches_reference_jcs():
    value = {"z": [3, {"b": True, "a": None}], "a": "héllo", "n": -7}
    assert canonical_bytes(value) == rfc8785.dumps(value)


def test_floats_are_rejected():
    with pytest.raises(CanonicalisationError):
        canonical_bytes({"seq": 1.0})


def test_non_string_keys_rejected():
    with pytest.raises(CanonicalisationError):
        canonical_bytes({1: "x"})


def test_unsupported_type_rejected():
    with pytest.raises(CanonicalisationError):
        canonical_bytes({"x": b"bytes"})


def test_unicode_is_not_escaped():
    assert canonical_bytes({"a": "é"}) == '{"a":"é"}'.encode("utf-8")
