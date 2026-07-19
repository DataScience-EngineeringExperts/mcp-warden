"""Bounded properties for the V1 deterministic content-envelope boundary."""

from __future__ import annotations

from itertools import permutations

import pytest
import rfc8785
from hypothesis import given, settings
from hypothesis import strategies as st

import mcp_warden.content_envelope as codec
from mcp_warden.content_envelope import (
    create_ingress,
    derive_envelope,
    parse_envelope,
    serialize_envelope,
    to_public_bytes,
)
from mcp_warden.content_models import (
    ContentEnvelopeError,
    IngressKindV1,
    MediaTypeV1,
    ParentRefV1,
    TaintV1,
    TransformKindV1,
)


def _meta(value: object) -> bytes:
    return rfc8785.dumps(value)


def _root(content: bytes, taints: tuple[TaintV1, ...] = ()):
    return create_ingress(
        content=content,
        media_type=MediaTypeV1.APPLICATION_OCTET_STREAM,
        source_kind=IngressKindV1.AGENT_MESSAGE,
        source_identity=_meta({"adapter": "property"}),
        source_claims=_meta({"truth": "unverified"}),
        capture_kind=TransformKindV1.INGRESS_CAPTURE,
        capture_implementation=_meta({"implementation": "property"}),
        capture_parameters=_meta({"mode": "strict"}),
        added_taints=taints,
    )


def _derived(parents):
    return derive_envelope(
        content=b"derived",
        media_type=MediaTypeV1.APPLICATION_OCTET_STREAM,
        parents=parents,
        transform_kind=TransformKindV1.DETERMINISTIC,
        transform_implementation=_meta({"implementation": "property"}),
        transform_parameters=_meta({"mode": "strict"}),
    )


@settings(max_examples=75)
@given(st.binary(max_size=512))
def test_repeated_bytes_are_identical_and_round_trip(content: bytes) -> None:
    first = _root(content)
    second = _root(content)
    assert first == second
    encoded = serialize_envelope(first)
    assert serialize_envelope(parse_envelope(encoded)) == encoded


@settings(max_examples=35)
@given(st.lists(st.binary(min_size=1, max_size=16), min_size=1, max_size=5, unique=True))
def test_parent_permutations_have_one_identity(contents: list[bytes]) -> None:
    parents = tuple(_root(content) for content in contents)
    sampled = list(permutations(parents))[:24]
    assert len({_derived(order).envelope_digest for order in sampled}) == 1


@settings(max_examples=50)
@given(st.sets(st.sampled_from(tuple(TaintV1)), max_size=len(TaintV1)))
def test_taint_propagation_is_monotonic(taints: set[TaintV1]) -> None:
    parent = _root(b"parent", tuple(taints))
    child = _derived((parent,))
    assert set(parent.taints).issubset(child.taints)
    assert child.taints == tuple(sorted(set(child.taints)))


@settings(max_examples=75)
@given(st.binary(min_size=1, max_size=256), st.integers(min_value=0, max_value=100_000))
def test_single_byte_wire_mutation_never_returns_a_different_envelope(
    content: bytes, selector: int
) -> None:
    original = _root(content)
    wire = bytearray(serialize_envelope(original))
    position = selector % len(wire)
    wire[position] ^= 1
    try:
        parsed = parse_envelope(bytes(wire))
    except ContentEnvelopeError:
        return
    assert parsed == original


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=2_048))
def test_arbitrary_malformed_bytes_terminate_with_stable_failure(data: bytes) -> None:
    try:
        envelope = parse_envelope(data)
    except ContentEnvelopeError as error:
        assert error.code.startswith("ENV-")
        assert error.__cause__ is None
        assert error.__context__ is None
    else:
        assert serialize_envelope(envelope) == data


def test_flat_crafted_cycle_ref_does_not_recurse() -> None:
    root = _root(b"root")
    template = _derived((root,))
    refs = (
        ParentRefV1(
            envelope_digest="sha256:" + "f" * 64,
            content_digest=root.content.digest,
        ),
    )
    crafted = template.model_copy(
        update={
            "source": codec._derived_source(refs, template.transform),
            "parents": refs,
        }
    )
    crafted = codec._replace_self_digest(crafted)
    child = _derived((crafted,))
    assert child.parents[0].envelope_digest == crafted.envelope_digest


def test_parser_registry_drift_rejects_instead_of_dropping(monkeypatch) -> None:
    encoded = serialize_envelope(_root(b"root"))
    monkeypatch.setattr(codec, "_TAINT_REGISTRY", frozenset())
    with pytest.raises(ContentEnvelopeError, match="ENV-TAINT-UNKNOWN"):
        parse_envelope(encoded)


@settings(max_examples=50)
@given(st.binary(min_size=1, max_size=128))
def test_raw_content_never_appears_in_public_bytes(suffix: bytes) -> None:
    marker = b"PLANTED-CONTENT-SECRET-715"
    envelope = _root(marker + suffix)
    assert marker not in to_public_bytes(envelope)
