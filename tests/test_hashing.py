"""JCS + SHA-256 reproducibility and canonical-form pin tests.

Pins the canonical byte form and exact digests so any deviation from RFC 8785 /
the §3 contract is caught (WARDEN_LOCK_SCHEMA.md §10.1, §10.6).
"""

from __future__ import annotations

import hashlib

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
