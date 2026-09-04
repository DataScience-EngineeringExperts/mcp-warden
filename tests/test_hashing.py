"""JCS + SHA-256 reproducibility and canonical-form pin tests.

Pins the canonical byte form and exact digests so any deviation from RFC 8785 /
the §3 contract is caught (WARDEN_LOCK_SCHEMA.md §10.1, §10.6).
"""

from __future__ import annotations

import hashlib

import pytest

from mcp_warden.hashing import (
    canon,
    hash_arguments,
    hash_description,
    hash_input_schema,
    hash_value,
)

# Canonical-form pins (these are the contract; two impls MUST agree on these).
EMPTY_STRING_DIGEST = "sha256:12ae32cb1ec02d01eda3581b127c1fee3b0dc53572ed6baf239721a03d82e126"
EMPTY_OBJECT_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


def test_canon_sorts_object_keys_by_codepoint():
    assert canon({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canon_preserves_array_order():
    assert canon([3, 1, 2]) == b"[3,1,2]"


def test_canon_no_insignificant_whitespace():
    assert canon({"x": {"y": [1, 2]}}) == b'{"x":{"y":[1,2]}}'


def test_canon_non_ascii_emitted_literally_utf8():
    # JCS emits non-ASCII literally as UTF-8, not \uXXXX.
    assert canon({"k": "café"}) == '{"k":"café"}'.encode("utf-8")


def test_hash_value_is_sha256_of_canon():
    value = {"name": "read_file", "n": 3}
    expected = "sha256:" + hashlib.sha256(canon(value)).hexdigest()
    assert hash_value(value) == expected


def test_hash_value_prefix_and_length():
    digest = hash_value({"a": 1})
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
    assert digest[7:] == digest[7:].lower()


def test_null_description_hashes_empty_string():
    assert hash_description(None) == EMPTY_STRING_DIGEST
    assert hash_description("") == EMPTY_STRING_DIGEST


def test_null_inputschema_hashes_empty_object():
    assert hash_input_schema(None) == EMPTY_OBJECT_DIGEST


def test_null_arguments_hashes_empty_array():
    expected = "sha256:" + hashlib.sha256(canon([])).hexdigest()
    assert hash_arguments(None) == expected


def test_reproducibility_same_input_same_digest():
    schema = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
    assert hash_input_schema(schema) == hash_input_schema(dict(schema))


def test_key_order_does_not_affect_digest():
    a = {"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}}
    b = {"properties": {"path": {"type": "string"}}, "type": "object", "required": ["path"]}
    assert hash_value(a) == hash_value(b)


def test_schema_change_changes_digest():
    base = {"type": "object", "properties": {"path": {"type": "string"}}}
    changed = {"type": "object", "properties": {"path": {"type": "string"}, "enc": {"type": "string"}}}
    assert hash_input_schema(base) != hash_input_schema(changed)


# --- DSE-1527: normative nesting bound (SPEC.md §4) ---------------------------


def _nested_arrays(n: int) -> list:
    """``n`` enclosing arrays around an empty array: the innermost ``[]`` sits at depth ``n``."""
    v: list = []
    for _ in range(n):
        v = [v]
    return v


def test_canon_accepts_depth_512_and_refuses_513():
    from mcp_warden.hashing import MAX_JSON_DEPTH, DepthError

    assert MAX_JSON_DEPTH == 512
    ok = _nested_arrays(MAX_JSON_DEPTH)
    assert canon(ok) == b"[" * (MAX_JSON_DEPTH + 1) + b"]" * (MAX_JSON_DEPTH + 1)
    with pytest.raises(DepthError):
        canon(_nested_arrays(MAX_JSON_DEPTH + 1))
    # A leaf counts, and objects count like arrays: "leaf" ends up at depth 513.
    deep_obj: dict = {"k": "leaf"}
    for _ in range(MAX_JSON_DEPTH):
        deep_obj = {"k": deep_obj}
    with pytest.raises(DepthError):
        canon(deep_obj)


def test_depth_error_is_a_value_error_raised_before_serialization():
    from mcp_warden.hashing import DepthError, check_depth

    assert issubclass(DepthError, ValueError)
    with pytest.raises(DepthError, match="nesting deeper than 512"):
        check_depth(_nested_arrays(600), where="probe")
    # Iterative: far past any recursion limit, still a clean DepthError.
    check = _nested_arrays(5000)
    with pytest.raises(DepthError):
        check_depth(check)
