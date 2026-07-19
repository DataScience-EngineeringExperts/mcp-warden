"""Security contract tests for deterministic untrusted content envelopes."""

from __future__ import annotations

import ast
import hashlib
import json
import traceback
from collections.abc import Iterator, Sequence
from itertools import permutations
from pathlib import Path

import pytest
import rfc8785

import mcp_warden.content_envelope as codec
from mcp_warden.content_envelope import (
    create_ingress,
    derive_envelope,
    parse_envelope,
    serialize_envelope,
    to_public_bytes,
    to_public_dict,
    verify_envelope,
    verify_lineage,
)
from mcp_warden.content_models import (
    MAX_BUNDLE_COMPONENT_BYTES,
    MAX_CONTENT_BYTES,
    MAX_DEPENDENCIES,
    MAX_ENVELOPE_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MAX_JSON_OBJECT_KEYS,
    MAX_JSON_STRING_BYTES,
    MAX_PARENTS,
    MAX_SOURCE_CLAIMS_BYTES,
    MAX_SOURCE_IDENTITY_BYTES,
    MAX_TAINTS,
    MAX_TRANSFORM_IDENTITY_BYTES,
    MAX_TRANSFORM_PARAMETERS_BYTES,
    TRANSFORM_KIND_BY_IDENTITY_V1,
    TRANSFORM_REGISTRY_V1,
    BundleEvidenceInput,
    BundleEvidenceV1,
    ContentEnvelopeError,
    ContentEnvelopeV1,
    ContentEvidenceV1,
    DigestDomain,
    IngressKindV1,
    MediaTypeV1,
    ParentRefV1,
    SourceEvidenceV1,
    TaintV1,
    TransformEvidenceV1,
    TransformKindV1,
)
from mcp_warden.hashing import hash_bytes

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _envelope(*, bundle: BundleEvidenceV1 | None = None) -> ContentEnvelopeV1:
    return ContentEnvelopeV1(
        schema_version=1,
        trust_state="untrusted",
        content=ContentEvidenceV1(digest=DIGEST_A, length=1, media_type="text/plain"),
        source=SourceEvidenceV1(
            kind="tool_result", identity_digest=DIGEST_A, claims_digest=DIGEST_B
        ),
        parents=(),
        transform=TransformEvidenceV1(
            id="mcp-warden.capture",
            version="1",
            implementation_digest=DIGEST_A,
            parameters_digest=DIGEST_B,
        ),
        taints=("core:untrusted",),
        bundle=bundle,
        envelope_digest=DIGEST_B,
    )


def test_models_are_strict_and_bundle_is_explicit() -> None:
    envelope = _envelope()
    assert envelope.schema_version == 1
    assert envelope.bundle is None

    body = {
        "schema_version": 1,
        "trust_state": "untrusted",
        "content": envelope.content,
        "source": envelope.source,
        "parents": (),
        "transform": envelope.transform,
        "taints": ("core:untrusted",),
        "envelope_digest": DIGEST_B,
    }
    with pytest.raises(ContentEnvelopeError):
        ContentEnvelopeV1(**body)
    with pytest.raises(ContentEnvelopeError):
        ContentEnvelopeV1(**(body | {"bundle": None, "surprise": True}))
    with pytest.raises(ContentEnvelopeError):
        ContentEnvelopeV1(**(body | {"bundle": None, "schema_version": "1"}))
    with pytest.raises(ContentEnvelopeError):
        ContentEnvelopeV1(**(body | {"bundle": None, "trust_state": "trusted"}))


def test_nested_models_and_collections_are_frozen() -> None:
    bundle = BundleEvidenceV1(
        artifact_digest=DIGEST_A,
        signature_evidence_digest=None,
        version_claims_digest=DIGEST_A,
        publisher_claims_digest=DIGEST_B,
        dependency_digests=(DIGEST_A, DIGEST_B),
        policy_binding_claims_digest=DIGEST_B,
    )
    envelope = _envelope(bundle=bundle)

    for obj, field, value in (
        (envelope, "trust_state", "trusted"),
        (envelope.content, "length", 2),
        (envelope.source, "kind", "web"),
        (envelope.transform, "version", "2"),
        (envelope.bundle, "artifact_digest", DIGEST_B),
    ):
        with pytest.raises(ContentEnvelopeError):
            setattr(obj, field, value)
    with pytest.raises(AttributeError):
        envelope.parents.append(ParentRefV1(envelope_digest=DIGEST_A, content_digest=DIGEST_B))
    with pytest.raises(AttributeError):
        envelope.taints.append("core:secret")
    with pytest.raises(AttributeError):
        envelope.bundle.dependency_digests.append(DIGEST_A)


def test_digest_domain_enum_is_complete_and_immutable() -> None:
    expected = {
        "content",
        "source-identity",
        "source-claims",
        "derived-source-identity",
        "derived-source-claims",
        "transform-implementation",
        "transform-parameters",
        "bundle-artifact",
        "bundle-signature",
        "bundle-version",
        "bundle-publisher",
        "bundle-dependency",
        "bundle-policy-binding",
        "envelope",
    }
    assert {domain.value.rsplit("/", 1)[-1] for domain in DigestDomain} == expected
    with pytest.raises((AttributeError, TypeError)):
        DigestDomain.CONTENT.value = "changed"


def test_transform_registry_reverse_mapping_is_exact() -> None:
    assert len(TRANSFORM_KIND_BY_IDENTITY_V1) == len(TRANSFORM_REGISTRY_V1)
    assert {
        identity: kind for kind, identity in TRANSFORM_REGISTRY_V1.items()
    } == TRANSFORM_KIND_BY_IDENTITY_V1
    for kind, identity in TRANSFORM_REGISTRY_V1.items():
        assert TRANSFORM_KIND_BY_IDENTITY_V1[identity] is kind


def test_hash_bytes_exact_golden_and_pairwise_domain_separation() -> None:
    payload = b"\x00raw\xffbytes"
    for domain in DigestDomain:
        expected = "sha256:" + hashlib.sha256(
            domain.value.encode("ascii") + b"\x00" + payload
        ).hexdigest()
        assert hash_bytes(payload, domain=domain) == expected
        assert hash_bytes(payload, domain=domain) == expected
        assert len(expected) == 71

    values = {hash_bytes(payload, domain=domain) for domain in DigestDomain}
    assert len(values) == len(DigestDomain)
    with pytest.raises(TypeError):
        hash_bytes(payload, domain=DigestDomain.CONTENT.value)
    with pytest.raises(TypeError):
        hash_bytes("not-bytes", domain=DigestDomain.CONTENT)


def test_digest_fields_require_lowercase_sha256_syntax() -> None:
    with pytest.raises(ContentEnvelopeError):
        ContentEvidenceV1(digest="sha256:" + "A" * 64, length=1, media_type="text/plain")
    with pytest.raises(ContentEnvelopeError):
        ParentRefV1(envelope_digest="bad", content_digest=DIGEST_A)


def test_new_subsystem_does_not_import_or_call_legacy_hash_helpers() -> None:
    root = Path(__file__).parents[1] / "src" / "mcp_warden"
    for name in ("content_models.py", "content_envelope.py"):
        path = root / name
        tree = ast.parse(path.read_text(encoding="utf-8"))
        forbidden: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                forbidden.extend(alias.name for alias in node.names if alias.name in {"canon", "hash_value"})
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"canon", "hash_value"}:
                    forbidden.append(node.func.id)
        assert forbidden == []


def _metadata(value: object) -> bytes:
    return rfc8785.dumps(value)


def _ingress(**changes: object) -> ContentEnvelopeV1:
    values: dict[str, object] = {
        "content": b"payload",
        "media_type": MediaTypeV1.TEXT_PLAIN,
        "source_kind": IngressKindV1.TOOL_RESULT,
        "source_identity": _metadata({"adapter": "test"}),
        "source_claims": _metadata({"claim": "untrusted"}),
        "capture_kind": TransformKindV1.INGRESS_CAPTURE,
        "capture_implementation": _metadata({"implementation": "test"}),
        "capture_parameters": _metadata({"mode": "strict"}),
    }
    values.update(changes)
    return create_ingress(**values)


@pytest.mark.parametrize("kind", tuple(IngressKindV1))
def test_create_ingress_covers_all_source_kinds(kind: IngressKindV1) -> None:
    bundle = _bundle_input() if kind is IngressKindV1.BUNDLE_METADATA else None
    envelope = _ingress(source_kind=kind, bundle=bundle)
    assert envelope.source.kind == kind.value
    assert envelope.parents == ()
    assert envelope.trust_state == "untrusted"
    assert "core:untrusted" in envelope.taints


def _bundle_input(*, signature: bytes | None = b"\xffopaque-signature") -> BundleEvidenceInput:
    return BundleEvidenceInput(
        artifact=_metadata({"artifact": "sha256:claim"}),
        signature_evidence=signature,
        version_claims=_metadata({"version": "1"}),
        publisher_claims=_metadata({"publisher": "unverified"}),
        dependencies=(_metadata({"dependency": "b"}), _metadata({"dependency": "a"})),
        policy_binding_claims=_metadata({"policy": "claim-only"}),
    )


def test_ingress_hashes_exact_opaque_content_and_signature() -> None:
    raw = b"\xff\x00not-utf8"
    signature = b"\xfe\x00opaque"
    envelope = _ingress(content=raw, bundle=_bundle_input(signature=signature))
    assert envelope.content.digest == hash_bytes(raw, domain=DigestDomain.CONTENT)
    assert envelope.bundle.signature_evidence_digest == hash_bytes(
        signature, domain=DigestDomain.BUNDLE_SIGNATURE
    )
    assert raw not in repr(envelope).encode()
    assert signature not in repr(envelope).encode()


def test_ingress_requires_exact_canonical_metadata_and_never_normalizes() -> None:
    composed = _metadata({"name": "é"})
    decomposed = _metadata({"name": "e\u0301"})
    assert _ingress(source_identity=composed).source.identity_digest != _ingress(
        source_identity=decomposed
    ).source.identity_digest

    for invalid in (b'{"b":1, "a":2}', b'{"a":1,"a":2}', b"{\xff}", b'{"x":NaN}'):
        with pytest.raises(ContentEnvelopeError) as caught:
            _ingress(source_identity=invalid)
        assert caught.value.code in {"ENV-MALFORMED", "ENV-NONCANONICAL"}
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None


def test_bundle_metadata_source_requires_bundle_and_taints_fail_closed(monkeypatch) -> None:
    with pytest.raises(ContentEnvelopeError, match="ENV-BUNDLE-INVALID"):
        _ingress(source_kind=IngressKindV1.BUNDLE_METADATA)
    with pytest.raises(ContentEnvelopeError, match="ENV-TAINT-UNKNOWN"):
        _ingress(added_taints=("future:unknown",))

    monkeypatch.setattr(codec, "_TAINT_REGISTRY", frozenset({"core:secret"}))
    with pytest.raises(ContentEnvelopeError, match="ENV-TAINT-UNKNOWN"):
        _ingress(added_taints=(TaintV1.SECRET,))


def test_ingress_cap_boundaries_are_exact() -> None:
    at_identity_cap = b'"' + b"x" * (MAX_SOURCE_IDENTITY_BYTES - 2) + b'"'
    assert len(at_identity_cap) == MAX_SOURCE_IDENTITY_BYTES
    _ingress(source_identity=at_identity_cap)
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _ingress(source_identity=at_identity_cap + b" ")

    at_content_cap = b"x" * MAX_CONTENT_BYTES
    assert _ingress(content=at_content_cap).content.length == MAX_CONTENT_BYTES
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _ingress(content=at_content_cap + b"x")


def test_depth_prescan_rejects_before_json_loads(monkeypatch) -> None:
    called = False

    def forbidden_loads(*args: object, **kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("json.loads must not be reached")

    monkeypatch.setattr(json, "loads", forbidden_loads)
    deep = b"[" * 10_000 + b"]" * 10_000
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        codec._canonical_metadata(
            deep, cap=len(deep), domain=DigestDomain.SOURCE_CLAIMS
        )
    assert called is False


@pytest.mark.parametrize(
    "value",
    (
        {"quoted": 'a\\"[still-string]'},
        {"slash": "\\\\"},
        {"unicode": "[é]"},
        {"escaped": "\\u005b"},
    ),
)
def test_depth_scanner_handles_string_escapes(value: object) -> None:
    _ingress(source_claims=_metadata(value))


def _derive(parents: tuple[ContentEnvelopeV1, ...], **changes: object) -> ContentEnvelopeV1:
    values: dict[str, object] = {
        "content": b"derived-content",
        "media_type": MediaTypeV1.TEXT_PLAIN,
        "parents": parents,
        "transform_kind": TransformKindV1.DETERMINISTIC,
        "transform_implementation": _metadata({"implementation": "transform"}),
        "transform_parameters": _metadata({"mode": "deterministic"}),
    }
    values.update(changes)
    return derive_envelope(**values)


def test_derivation_is_parent_permutation_invariant_and_refs_sort_ascii() -> None:
    parents = (
        _ingress(content=b"a", added_taints=(TaintV1.SECRET,)),
        _ingress(content=b"b", added_taints=(TaintV1.EXECUTABLE,)),
        _ingress(content=b"c"),
    )
    outputs = [_derive(tuple(order)) for order in permutations(parents)]
    assert {item.envelope_digest for item in outputs} == {outputs[0].envelope_digest}
    assert outputs[0].parents == tuple(
        sorted(outputs[0].parents, key=lambda ref: (ref.envelope_digest, ref.content_digest))
    )
    assert outputs[0].source.kind == "derived"
    assert set(outputs[0].taints) >= {
        "core:untrusted",
        "core:secret",
        "core:executable",
    }
    for order in permutations(parents):
        verify_lineage(outputs[0], parents=order)


def test_derivation_recomputes_parent_digest_before_acceptance() -> None:
    parent = _ingress()
    tampered_content = parent.content.model_copy(update={"digest": DIGEST_B})
    tampered = parent.model_copy(update={"content": tampered_content})
    with pytest.raises(ContentEnvelopeError, match="ENV-DIGEST-MISMATCH"):
        _derive((tampered,))


def test_lineage_rejects_missing_duplicate_extra_and_taint_loss() -> None:
    first = _ingress(content=b"a", added_taints=(TaintV1.SECRET,))
    second = _ingress(content=b"b")
    child = _derive((first, second))
    for supplied in ((first,), (first, first), (first, second, _ingress(content=b"c"))):
        with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
            verify_lineage(child, parents=supplied)

    lost = child.model_copy(update={"taints": ("core:untrusted",)})
    # Keep the self digest coherent so the failure specifically proves monotonic taint.
    lost = codec._replace_self_digest(lost)
    with pytest.raises(ContentEnvelopeError, match="ENV-TAINT-MISSING"):
        verify_lineage(lost, parents=(first, second))


def test_derive_rejects_duplicate_empty_and_complete_union_over_cap() -> None:
    parent = _ingress()
    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
        _derive(())
    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
        _derive((parent, parent))

    taints = tuple(item for item in TaintV1 if item is not TaintV1.UNTRUSTED)
    heavily_tainted = _ingress(added_taints=taints)
    assert set(_derive((heavily_tainted,)).taints) == set(item.value for item in TaintV1)


def test_no_schema_or_api_surface_removes_taint_or_grants_authority() -> None:
    fields = set(ContentEnvelopeV1.model_fields)
    forbidden = {"authority", "trusted", "remove_taints", "sanitized", "capabilities"}
    assert fields.isdisjoint(forbidden)
    assert not hasattr(codec, "remove_taint")
    assert not hasattr(codec, "grant_authority")


def test_codec_golden_round_trip_and_explicit_bundle_null() -> None:
    envelope = _ingress()
    encoded = serialize_envelope(envelope)
    assert encoded == rfc8785.dumps(to_public_dict(envelope))
    assert b'"bundle":null' in encoded
    assert parse_envelope(encoded) == envelope
    assert serialize_envelope(parse_envelope(encoded)) == encoded
    assert to_public_bytes(envelope) == encoded
    verify_envelope(envelope, content=b"payload")


def test_parser_rejects_missing_bundle_unknown_fields_and_versions() -> None:
    public = to_public_dict(_ingress())
    missing_bundle = dict(public)
    missing_bundle.pop("bundle")
    with pytest.raises(ContentEnvelopeError, match="ENV-BUNDLE-INVALID"):
        parse_envelope(rfc8785.dumps(missing_bundle))

    for path, code in (
        ({**public, "authority": "admin"}, "ENV-UNKNOWN-FIELD"),
        ({**public, "schema_version": 2}, "ENV-SCHEMA-UNKNOWN"),
        ({**public, "trust_state": "trusted"}, "ENV-TRUST-INVALID"),
    ):
        with pytest.raises(ContentEnvelopeError, match=code):
            parse_envelope(rfc8785.dumps(path))

    nested = dict(public)
    nested["content"] = {**public["content"], "secret_raw": "no"}
    with pytest.raises(ContentEnvelopeError, match="ENV-UNKNOWN-FIELD"):
        parse_envelope(rfc8785.dumps(nested))


@pytest.mark.parametrize(
    "malformed,code",
    (
        (b'{"a":1,"a":2}', "ENV-NONCANONICAL"),
        (b'{"a":1, "b":2}', "ENV-NONCANONICAL"),
        (b'{"a":NaN}', "ENV-MALFORMED"),
        (b"]", "ENV-MALFORMED"),
        (b'{"x":"unterminated}', "ENV-MALFORMED"),
    ),
)
def test_parser_rejects_malformed_and_noncanonical_bytes(malformed: bytes, code: str) -> None:
    with pytest.raises(ContentEnvelopeError, match=code):
        parse_envelope(malformed)


def test_parser_atomically_recomputes_self_digest_and_ordering() -> None:
    child = _derive((_ingress(content=b"a"), _ingress(content=b"b")))
    public = to_public_dict(child)
    public["envelope_digest"] = DIGEST_A
    with pytest.raises(ContentEnvelopeError, match="ENV-DIGEST-MISMATCH"):
        parse_envelope(rfc8785.dumps(public))

    public = to_public_dict(child)
    public["parents"] = list(reversed(public["parents"]))
    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
        parse_envelope(rfc8785.dumps(public))


def test_verify_rejects_wrong_content_and_tampered_self() -> None:
    envelope = _ingress(content=b"correct")
    for content in (b"wrong", b"correct\x00"):
        with pytest.raises(ContentEnvelopeError, match="ENV-DIGEST-MISMATCH"):
            verify_envelope(envelope, content=content)
    tampered = envelope.model_copy(update={"envelope_digest": DIGEST_A})
    with pytest.raises(ContentEnvelopeError, match="ENV-DIGEST-MISMATCH"):
        verify_envelope(tampered, content=b"correct")


def test_planted_secrets_never_escape_output_error_traceback_or_logs(caplog) -> None:
    secrets = {
        "content": b"content-SECRET-715",
        "identity": b'{"secret":"identity-SECRET-715"}',
        "claims": b'{"secret":"claims-SECRET-715"}',
        "implementation": b'{"secret":"implementation-SECRET-715"}',
        "parameters": b'{"secret":"parameters-SECRET-715"}',
        "signature": b"signature-SECRET-715",
        "policy": b'{"secret":"policy-SECRET-715"}',
    }
    bundle = _bundle_input(signature=secrets["signature"])
    bundle = BundleEvidenceInput(
        artifact=bundle.artifact,
        signature_evidence=bundle.signature_evidence,
        version_claims=bundle.version_claims,
        publisher_claims=bundle.publisher_claims,
        dependencies=bundle.dependencies,
        policy_binding_claims=secrets["policy"],
    )
    envelope = _ingress(
        content=secrets["content"],
        source_identity=secrets["identity"],
        source_claims=secrets["claims"],
        capture_implementation=secrets["implementation"],
        capture_parameters=secrets["parameters"],
        bundle=bundle,
    )
    outputs = [serialize_envelope(envelope), to_public_bytes(envelope), repr(to_public_dict(envelope)).encode()]
    for secret in secrets.values():
        assert all(secret not in output for output in outputs)

    invalid = b'{"secret":"trace-SECRET-715",}'
    try:
        parse_envelope(invalid)
    except ContentEnvelopeError as error:
        error_views = (
            str(error).encode(),
            repr(error).encode(),
            "".join(traceback.format_exception(error)).encode(),
        )
        assert error.__cause__ is None
        assert error.__context__ is None
        assert all(b"trace-SECRET-715" not in view for view in error_views)
    else:  # pragma: no cover
        pytest.fail("invalid bytes accepted")
    assert "SECRET-715" not in caplog.text


def test_public_projection_is_explicit_not_whole_model_dump() -> None:
    source = (Path(__file__).parents[1] / "src/mcp_warden/content_envelope.py").read_text()
    public_source = source[source.index("def to_public_dict") :]
    assert "model_dump" not in public_source
    assert "__dict__" not in public_source


class _OverlongTaints(Iterator[TaintV1]):
    def __init__(self) -> None:
        self.calls = 0

    def __next__(self) -> TaintV1:
        self.calls += 1
        if self.calls > MAX_TAINTS + 1:
            raise AssertionError("taint iterator was consumed past the security cap")
        return TaintV1.UNTRUSTED


def test_taint_iterables_are_bounded_and_iterator_failures_are_stable() -> None:
    overlong = _OverlongTaints()
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _ingress(added_taints=overlong)
    assert overlong.calls == MAX_TAINTS + 1

    def broken() -> Iterator[TaintV1]:
        yield TaintV1.SECRET
        raise RuntimeError("PLANTED-TAINT-ITERATOR-SECRET")

    with pytest.raises(ContentEnvelopeError, match="ENV-TAINT-UNKNOWN") as caught:
        _ingress(added_taints=broken())
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "PLANTED" not in traceback.format_exception_only(caught.value)[0]


class _HostileParents(Sequence[ContentEnvelopeV1]):
    def __init__(self, parent: ContentEnvelopeV1) -> None:
        self.parent = parent
        self.calls = 0

    def __len__(self) -> int:
        return 1

    def __getitem__(self, index: int) -> ContentEnvelopeV1:
        self.calls += 1
        if self.calls > MAX_PARENTS + 1:
            raise AssertionError("parent sequence was consumed past the security cap")
        return self.parent


def test_hostile_parent_sequences_are_consumed_to_a_hard_bound() -> None:
    hostile = _HostileParents(_ingress())
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _derive(hostile)  # type: ignore[arg-type]
    assert hostile.calls == MAX_PARENTS + 1


def test_parent_iteration_errors_are_stable() -> None:
    class BrokenParents(_HostileParents):
        def __getitem__(self, index: int) -> ContentEnvelopeV1:
            raise RuntimeError("PLANTED-PARENT-ITERATOR-SECRET")

    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID") as caught:
        _derive(BrokenParents(_ingress()))  # type: ignore[arg-type]
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_bundle_input_enforces_exact_tuple_bytes_and_stable_api_errors() -> None:
    with pytest.raises(ContentEnvelopeError, match="ENV-BUNDLE-INVALID"):
        BundleEvidenceInput(
            artifact="PLANTED-BUNDLE-SECRET",  # type: ignore[arg-type]
            signature_evidence=None,
            version_claims=b"{}",
            publisher_claims=b"{}",
            dependencies=(),
            policy_binding_claims=b"{}",
        )
    with pytest.raises(ContentEnvelopeError, match="ENV-BUNDLE-INVALID"):
        BundleEvidenceInput(
            artifact=b"{}",
            signature_evidence=None,
            version_claims=b"{}",
            publisher_claims=b"{}",
            dependencies=[b"{}"],  # type: ignore[arg-type]
            policy_binding_claims=b"{}",
        )


def test_bundle_dependency_iteration_is_bounded_even_if_model_is_bypassed() -> None:
    valid = _bundle_input()
    object.__setattr__(valid, "dependencies", _OverlongDependencies())
    with pytest.raises(ContentEnvelopeError, match="ENV-BUNDLE-INVALID"):
        _ingress(bundle=valid)


class _OverlongDependencies:
    def __iter__(self):
        for _ in range(258):
            yield b"{}"
        raise AssertionError("dependency iterable consumed past cap")


def test_parse_malformed_parent_types_are_lineage_errors() -> None:
    child = _derive((_ingress(),))
    public = to_public_dict(child)
    public["parents"][0]["envelope_digest"] = []
    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
        parse_envelope(rfc8785.dumps(public))


def test_derived_source_digests_are_recomputed_not_self_asserted() -> None:
    parents = (_ingress(content=b"parent"),)
    child = _derive(parents)
    forged_source = child.source.model_copy(update={"identity_digest": DIGEST_A})
    forged = codec._replace_self_digest(child.model_copy(update={"source": forged_source}))
    forged_public = codec._body_dict(
        content=forged.content,
        source=forged.source,
        parents=forged.parents,
        transform=forged.transform,
        taints=forged.taints,
        bundle=forged.bundle,
    )
    forged_public["envelope_digest"] = forged.envelope_digest
    forged_wire = rfc8785.dumps(forged_public)
    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
        parse_envelope(forged_wire)
    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
        verify_lineage(forged, parents=parents)
    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
        _derive((forged,))


def test_direct_validation_errors_hide_planted_input() -> None:
    marker = "PLANTED-PYDANTIC-INPUT-SECRET-715"
    with pytest.raises(ContentEnvelopeError) as caught:
        ContentEvidenceV1(digest=marker, length=1, media_type="text/plain")
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value)


def test_models_enforce_root_derived_and_bundle_cross_field_invariants() -> None:
    root = _ingress()
    ref = ParentRefV1(envelope_digest=root.envelope_digest, content_digest=root.content.digest)
    common = dict(
        schema_version=1,
        trust_state="untrusted",
        content=root.content,
        transform=root.transform,
        taints=root.taints,
        envelope_digest=root.envelope_digest,
    )
    with pytest.raises(ContentEnvelopeError):
        ContentEnvelopeV1(**common, source=root.source, parents=(ref,), bundle=None)
    with pytest.raises(ContentEnvelopeError):
        ContentEnvelopeV1(
            **common,
            source=root.source.model_copy(update={"kind": "derived"}),
            parents=(),
            bundle=None,
        )
    with pytest.raises(ContentEnvelopeError):
        ContentEnvelopeV1(
            **common,
            source=root.source.model_copy(update={"kind": "bundle_metadata"}),
            parents=(),
            bundle=None,
        )

    bypassed = codec._replace_self_digest(root.model_copy(update={"parents": (ref,)}))
    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
        serialize_envelope(bypassed)


def _legacy_helper_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    violations: list[str] = []
    aliases: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if node.module == "mcp_warden.hashing" and alias.name != "hash_bytes":
                    violations.append(f"import-from:{alias.name}")
                if node.module == "mcp_warden" and alias.name == "hashing":
                    violations.append("import-from:mcp_warden.hashing")
                if alias.name in {"canon", "hash_value"}:
                    aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.endswith("hashing"):
                    modules.add(alias.asname or alias.name.rsplit(".", 1)[-1])
                if alias.name == "mcp_warden.hashing":
                    rendered = alias.name if alias.asname is None else f"{alias.name} as {alias.asname}"
                    violations.append(f"import:{rendered}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in aliases | {"canon", "hash_value"}:
                violations.append(node.func.id)
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in modules
                and node.func.attr in {"canon", "hash_value"}
            ):
                violations.append(f"{node.func.value.id}.{node.func.attr}")
    return violations


def test_ast_guard_detects_direct_alias_and_qualified_legacy_calls() -> None:
    synthetic = """
from mcp_warden.hashing import canon as c, hash_value
import mcp_warden.hashing as hashing_alias
c({})
hash_value({})
hashing_alias.canon({})
"""
    assert set(_legacy_helper_violations(synthetic)) == {
        "c",
        "hash_value",
        "hashing_alias.canon",
        "import-from:canon",
        "import-from:hash_value",
        "import:mcp_warden.hashing as hashing_alias",
    }
    root = Path(__file__).parents[1] / "src" / "mcp_warden"
    for name in ("content_models.py", "content_envelope.py"):
        assert _legacy_helper_violations((root / name).read_text(encoding="utf-8")) == []


def test_ast_guard_forbids_hashing_module_handles_and_non_hash_bytes_imports() -> None:
    synthetic = """
import mcp_warden.hashing
import mcp_warden.hashing as hashing_alias
from mcp_warden.hashing import hash_bytes, SHA256_PREFIX
"""
    assert set(_legacy_helper_violations(synthetic)) == {
        "import:mcp_warden.hashing",
        "import:mcp_warden.hashing as hashing_alias",
        "import-from:SHA256_PREFIX",
    }


def test_parser_maps_nested_validation_failures_to_documented_codes() -> None:
    child_public = to_public_dict(_derive((_ingress(),)))
    child_public["parents"][0]["envelope_digest"] = "bad"
    with pytest.raises(ContentEnvelopeError, match="ENV-LINEAGE-INVALID"):
        parse_envelope(rfc8785.dumps(child_public))

    bundle_public = to_public_dict(_ingress(bundle=_bundle_input()))
    bundle_public["bundle"]["artifact_digest"] = "bad"
    with pytest.raises(ContentEnvelopeError, match="ENV-BUNDLE-INVALID"):
        parse_envelope(rfc8785.dumps(bundle_public))

    root_public = to_public_dict(_ingress())
    for missing, code in (
        ("schema_version", "ENV-SCHEMA-UNKNOWN"),
        ("trust_state", "ENV-TRUST-INVALID"),
        ("taints", "ENV-TAINT-MISSING"),
    ):
        malformed = dict(root_public)
        malformed.pop(missing)
        with pytest.raises(ContentEnvelopeError, match=code):
            parse_envelope(rfc8785.dumps(malformed))


def test_public_api_malformed_inputs_return_only_stable_codes(caplog) -> None:
    calls = (
        lambda: serialize_envelope("PLANTED-API-SECRET"),  # type: ignore[arg-type]
        lambda: verify_envelope(_ingress(), content="PLANTED-API-SECRET"),  # type: ignore[arg-type]
        lambda: verify_lineage(_ingress(), parents="PLANTED-API-SECRET"),  # type: ignore[arg-type]
    )
    for call in calls:
        with pytest.raises(ContentEnvelopeError) as caught:
            call()
        assert caught.value.code.startswith("ENV-")
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert "PLANTED" not in str(caught.value)
        assert "PLANTED" not in repr(caught.value)
    assert "PLANTED" not in caplog.text


@pytest.mark.parametrize(
    "values",
    (
        (1,),
        ([],),
        (TaintV1.SECRET, []),
        ("PLANTED-TAINT-VALUE-SECRET-715", 1),
    ),
)
def test_non_string_taints_fail_with_code_only_error(values: tuple[object, ...]) -> None:
    with pytest.raises(ContentEnvelopeError, match="ENV-TAINT-UNKNOWN") as caught:
        _ingress(added_taints=values)
    views = (
        str(caught.value),
        repr(caught.value),
        "".join(traceback.format_exception(caught.value)),
    )
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert all("PLANTED" not in view for view in views)


class _BytesSubclass(bytes):
    pass


def test_exact_byte_contract_rejects_bytes_subclasses() -> None:
    disguised = _BytesSubclass(b"PLANTED-BYTES-SUBCLASS-SECRET")
    with pytest.raises(TypeError):
        hash_bytes(disguised, domain=DigestDomain.CONTENT)
    for changes in (
        {"content": disguised},
        {"source_identity": disguised},
        {"source_claims": disguised},
        {"capture_implementation": disguised},
        {"capture_parameters": disguised},
    ):
        with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED") as caught:
            _ingress(**changes)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None


def _self_coherent(candidate: ContentEnvelopeV1) -> ContentEnvelopeV1:
    return codec._replace_self_digest(candidate)


def _assert_rejected_at_all_accepting_boundaries(
    forged: ContentEnvelopeV1, *, content: bytes, code: str
) -> None:
    calls = (
        lambda: serialize_envelope(forged),
        lambda: verify_envelope(forged, content=content),
        lambda: _derive((forged,)),
    )
    for call in calls:
        with pytest.raises(ContentEnvelopeError, match=code) as caught:
            call()
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None


def test_model_copy_bypasses_are_completely_revalidated() -> None:
    root = _ingress()
    bundled = _ingress(bundle=_bundle_input())
    cases = (
        (
            root.model_copy(update={"taints": ("core:untrusted", "core:untrusted")}),
            "ENV-LINEAGE-INVALID",
        ),
        (
            root.model_copy(update={"taints": ("core:untrusted", "core:secret")}),
            "ENV-LINEAGE-INVALID",
        ),
        (
            root.model_copy(update={"source": root.source.model_copy(update={"kind": "bad"})}),
            "ENV-MALFORMED",
        ),
        (
            root.model_copy(
                update={"content": root.content.model_copy(update={"media_type": "bad/type"})}
            ),
            "ENV-MALFORMED",
        ),
        (
            root.model_copy(
                update={"content": root.content.model_copy(update={"digest": "bad"})}
            ),
            "ENV-MALFORMED",
        ),
        (
            root.model_copy(
                update={"content": root.content.model_copy(update={"length": -1})}
            ),
            "ENV-MALFORMED",
        ),
        (
            root.model_copy(
                update={"transform": root.transform.model_copy(update={"id": "BAD ID"})}
            ),
            "ENV-MALFORMED",
        ),
        (
            bundled.model_copy(
                update={"bundle": bundled.bundle.model_copy(update={"artifact_digest": "bad"})}
            ),
            "ENV-BUNDLE-INVALID",
        ),
    )
    for candidate, code in cases:
        forged = _self_coherent(candidate)
        _assert_rejected_at_all_accepting_boundaries(forged, content=b"payload", code=code)


def test_model_copy_bypassed_parent_refs_and_order_are_revalidated() -> None:
    child = _derive((_ingress(content=b"a"), _ingress(content=b"b")))
    bad_ref = child.parents[0].model_copy(update={"envelope_digest": "bad"})
    cases = (
        child.model_copy(update={"parents": (bad_ref, child.parents[1])}),
        child.model_copy(update={"parents": tuple(reversed(child.parents))}),
        child.model_copy(update={"parents": (child.parents[0], child.parents[0])}),
    )
    for candidate in cases:
        forged = _self_coherent(candidate)
        _assert_rejected_at_all_accepting_boundaries(
            forged,
            content=b"derived-content",
            code="ENV-LINEAGE-INVALID",
        )


def test_pydantic_revalidates_bypassed_nested_instances() -> None:
    root = _ingress()
    invalid_content = root.content.model_copy(update={"media_type": "bad/type"})
    with pytest.raises(ContentEnvelopeError):
        ContentEvidenceV1.model_validate(invalid_content)
    with pytest.raises(ContentEnvelopeError):
        ContentEnvelopeV1.model_validate(root.model_copy(update={"content": invalid_content}))


@pytest.mark.parametrize(
    "forged",
    (
        ContentEnvelopeV1.model_construct(schema_version=1, trust_state="untrusted"),
        ContentEnvelopeV1.model_construct(
            schema_version=1,
            trust_state="untrusted",
            content={"secret": "PLANTED-CONSTRUCT-SECRET-715"},
        ),
    ),
)
def test_model_construct_missing_or_malformed_fields_fail_code_only(
    forged: ContentEnvelopeV1,
) -> None:
    calls = (
        lambda: serialize_envelope(forged),
        lambda: verify_envelope(forged, content=b"payload"),
        lambda: _derive((forged,)),
    )
    for call in calls:
        with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED") as caught:
            call()
        views = (
            str(caught.value),
            repr(caught.value),
            "".join(traceback.format_exception(caught.value)),
        )
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert all("PLANTED" not in view for view in views)


def test_direct_model_validation_entrypoints_are_code_only() -> None:
    marker = "PLANTED-STRUCTURED-PYDANTIC-SECRET-715"
    payload = {"digest": marker, "length": 1, "media_type": "text/plain"}
    calls = (
        lambda: ContentEvidenceV1(**payload),
        lambda: ContentEvidenceV1.model_validate(payload),
        lambda: ContentEvidenceV1.model_validate_json(json.dumps(payload)),
        lambda: ContentEvidenceV1.model_validate_strings(
            {"digest": marker, "length": "1", "media_type": "text/plain"}
        ),
    )
    for call in calls:
        with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED") as caught:
            call()
        views = (
            str(caught.value),
            repr(caught.value),
            "".join(traceback.format_exception(caught.value)),
        )
        assert not hasattr(caught.value, "errors")
        assert not hasattr(caught.value, "json")
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert all(marker not in view for view in views)


def test_frozen_model_mutation_entrypoints_are_code_only() -> None:
    marker = "PLANTED-MUTATION-SECRET-715"
    source = _ingress().source
    calls = (
        lambda: setattr(source, "kind", marker),
        lambda: delattr(source, "kind"),
    )
    for call in calls:
        with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED") as caught:
            call()
        views = (
            str(caught.value),
            repr(caught.value),
            "".join(traceback.format_exception(caught.value)),
        )
        assert not hasattr(caught.value, "errors")
        assert not hasattr(caught.value, "json")
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert all(marker not in view for view in views)


def test_direct_transform_model_rejects_registered_shape_but_unknown_cleartext() -> None:
    with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED"):
        TransformEvidenceV1(
            id="secret.exfil.channel",
            version="1",
            implementation_digest=DIGEST_A,
            parameters_digest=DIGEST_B,
        )
    ingress = _ingress()
    derived = _derive((ingress,))
    assert (ingress.transform.id, ingress.transform.version) == ("mcp-warden.capture", "1")
    assert (derived.transform.id, derived.transform.version) == (
        "mcp-warden.transform.deterministic",
        "1",
    )
    with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED"):
        _ingress(capture_kind="PLANTED-TRANSFORM-SECRET")
    with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED"):
        _derive((ingress,), transform_kind="PLANTED-TRANSFORM-SECRET")
    with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED"):
        _ingress(capture_kind=TransformKindV1.DETERMINISTIC)
    with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED"):
        _derive((ingress,), transform_kind=TransformKindV1.INGRESS_CAPTURE)
    forged_wire = to_public_dict(ingress)
    forged_wire["transform"]["id"] = "secret.exfil.channel"
    with pytest.raises(ContentEnvelopeError, match="ENV-MALFORMED"):
        parse_envelope(rfc8785.dumps(forged_wire))


class _HostileEnvelope(ContentEnvelopeV1):
    def __getattribute__(self, name: str):
        if name.startswith("__"):
            return super().__getattribute__(name)
        raise RuntimeError("PLANTED-HOSTILE-ENVELOPE-SECRET-715")


class _HostileBundle(BundleEvidenceInput):
    def __getattribute__(self, name: str):
        if name.startswith("__"):
            return super().__getattribute__(name)
        raise RuntimeError("PLANTED-HOSTILE-BUNDLE-SECRET-715")


def test_public_boundaries_reject_hostile_subclasses_before_attribute_access() -> None:
    valid = _ingress()
    hostile_envelope = _HostileEnvelope.model_construct(
        **object.__getattribute__(valid, "__dict__")
    )
    envelope_calls = (
        lambda: serialize_envelope(hostile_envelope),
        lambda: verify_envelope(hostile_envelope, content=b"payload"),
        lambda: verify_lineage(hostile_envelope, parents=()),
        lambda: _derive((hostile_envelope,)),
    )
    for call in envelope_calls:
        with pytest.raises(ContentEnvelopeError) as caught:
            call()
        assert caught.value.code in {"ENV-MALFORMED", "ENV-LINEAGE-INVALID"}
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert "PLANTED" not in "".join(traceback.format_exception(caught.value))

    hostile_bundle = object.__new__(_HostileBundle)
    with pytest.raises(ContentEnvelopeError, match="ENV-BUNDLE-INVALID") as caught:
        _ingress(bundle=hostile_bundle)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def _canonical_json_size(size: int) -> bytes:
    for count in range(1, MAX_JSON_NODES):
        payload_bytes = size - (1 + 3 * count)
        if 0 <= payload_bytes <= MAX_JSON_STRING_BYTES * count:
            base, extra = divmod(payload_bytes, count)
            values = ["x" * (base + (1 if index < extra else 0)) for index in range(count)]
            encoded = rfc8785.dumps(values)
            assert len(encoded) == size
            return encoded
    raise AssertionError("requested canonical size is not representable within V1 caps")


@pytest.mark.parametrize(
    "field,cap",
    (
        ("source_claims", MAX_SOURCE_CLAIMS_BYTES),
        ("capture_implementation", MAX_TRANSFORM_IDENTITY_BYTES),
        ("capture_parameters", MAX_TRANSFORM_PARAMETERS_BYTES),
    ),
)
def test_structured_component_caps_accept_exact_and_reject_plus_one(field: str, cap: int) -> None:
    _ingress(**{field: _canonical_json_size(cap)})
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _ingress(**{field: _canonical_json_size(cap + 1)})


@pytest.mark.parametrize(
    "field",
    ("artifact", "version_claims", "publisher_claims", "policy_binding_claims"),
)
def test_bundle_structured_component_caps(field: str) -> None:
    values = {
        "artifact": b"{}",
        "signature_evidence": b"signature",
        "version_claims": b"{}",
        "publisher_claims": b"{}",
        "dependencies": (b"{}",),
        "policy_binding_claims": b"{}",
    }
    values[field] = _canonical_json_size(MAX_BUNDLE_COMPONENT_BYTES)
    _ingress(bundle=BundleEvidenceInput(**values))
    values[field] = _canonical_json_size(MAX_BUNDLE_COMPONENT_BYTES + 1)
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        BundleEvidenceInput(**values)


def test_bundle_signature_and_dependency_component_caps() -> None:
    _ingress(bundle=_bundle_input(signature=b"x" * MAX_BUNDLE_COMPONENT_BYTES))
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _bundle_input(signature=b"x" * (MAX_BUNDLE_COMPONENT_BYTES + 1))

    at_cap = _canonical_json_size(MAX_BUNDLE_COMPONENT_BYTES)
    _ingress(
        bundle=BundleEvidenceInput(
            artifact=b"{}",
            signature_evidence=None,
            version_claims=b"{}",
            publisher_claims=b"{}",
            dependencies=(at_cap,),
            policy_binding_claims=b"{}",
        )
    )
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        BundleEvidenceInput(
            artifact=b"{}",
            signature_evidence=None,
            version_claims=b"{}",
            publisher_claims=b"{}",
            dependencies=(_canonical_json_size(MAX_BUNDLE_COMPONENT_BYTES + 1),),
            policy_binding_claims=b"{}",
        )


def test_json_structural_caps_exact_and_plus_one() -> None:
    exact_depth = b"[" * MAX_JSON_DEPTH + b"0" + b"]" * MAX_JSON_DEPTH
    _ingress(source_claims=exact_depth)
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _ingress(
            source_claims=b"[" * (MAX_JSON_DEPTH + 1)
            + b"0"
            + b"]" * (MAX_JSON_DEPTH + 1)
        )

    _ingress(source_claims=rfc8785.dumps([0] * (MAX_JSON_NODES - 1)))
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _ingress(source_claims=rfc8785.dumps([0] * MAX_JSON_NODES))

    _ingress(source_claims=rfc8785.dumps({f"k{index:03d}": 0 for index in range(MAX_JSON_OBJECT_KEYS)}))
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _ingress(
            source_claims=rfc8785.dumps(
                {f"k{index:03d}": 0 for index in range(MAX_JSON_OBJECT_KEYS + 1)}
            )
        )

    _ingress(source_claims=rfc8785.dumps("x" * MAX_JSON_STRING_BYTES))
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _ingress(source_claims=rfc8785.dumps("x" * (MAX_JSON_STRING_BYTES + 1)))


def test_envelope_parent_taint_and_dependency_count_caps() -> None:
    assert codec._parse_wire_json(_canonical_json_size(MAX_ENVELOPE_BYTES)) is not None
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        codec._parse_wire_json(_canonical_json_size(MAX_ENVELOPE_BYTES + 1))

    parents = tuple(_ingress(content=index.to_bytes(2, "big")) for index in range(MAX_PARENTS))
    _derive(parents)
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _derive(parents + (_ingress(content=b"overflow-parent"),))

    _ingress(added_taints=(TaintV1.UNTRUSTED,) * MAX_TAINTS)
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        _ingress(added_taints=(TaintV1.UNTRUSTED,) * (MAX_TAINTS + 1))

    dependency = b"{}"
    exact_dependencies = BundleEvidenceInput(
        artifact=b"{}",
        signature_evidence=None,
        version_claims=b"{}",
        publisher_claims=b"{}",
        dependencies=(dependency,) * MAX_DEPENDENCIES,
        policy_binding_claims=b"{}",
    )
    _ingress(bundle=exact_dependencies)
    with pytest.raises(ContentEnvelopeError, match="ENV-OVER-CAP"):
        BundleEvidenceInput(
            artifact=b"{}",
            signature_evidence=None,
            version_claims=b"{}",
            publisher_claims=b"{}",
            dependencies=(dependency,) * (MAX_DEPENDENCIES + 1),
            policy_binding_claims=b"{}",
        )


def _swapped_transform_candidate(context: str) -> ContentEnvelopeV1:
    root = _ingress(source_kind=IngressKindV1.WEB)
    if context == "root":
        deterministic = _derive((root,)).transform
        candidate = root.model_copy(update={"transform": deterministic})
    else:
        derived = _derive((root,))
        capture = root.transform
        forged_source = codec._derived_source(derived.parents, capture)
        candidate = derived.model_copy(update={"source": forged_source, "transform": capture})
    return codec._replace_self_digest(candidate)


def _candidate_wire(candidate: ContentEnvelopeV1) -> bytes:
    body = codec._body_dict(
        content=candidate.content,
        source=candidate.source,
        parents=candidate.parents,
        transform=candidate.transform,
        taints=candidate.taints,
        bundle=candidate.bundle,
    )
    body["envelope_digest"] = candidate.envelope_digest
    return rfc8785.dumps(body)


@pytest.mark.parametrize(
    "context,code",
    (("root", "ENV-MALFORMED"), ("derived", "ENV-LINEAGE-INVALID")),
)
def test_direct_model_rejects_source_context_transform_swap(context: str, code: str) -> None:
    candidate = _swapped_transform_candidate(context)
    with pytest.raises(ContentEnvelopeError, match=code):
        ContentEnvelopeV1(
            schema_version=candidate.schema_version,
            trust_state=candidate.trust_state,
            content=candidate.content,
            source=candidate.source,
            parents=candidate.parents,
            transform=candidate.transform,
            taints=candidate.taints,
            bundle=candidate.bundle,
            envelope_digest=candidate.envelope_digest,
        )


@pytest.mark.parametrize(
    "context,code",
    (("root", "ENV-MALFORMED"), ("derived", "ENV-LINEAGE-INVALID")),
)
def test_public_validation_rejects_source_context_transform_swap(context: str, code: str) -> None:
    candidate = _swapped_transform_candidate(context)
    with pytest.raises(ContentEnvelopeError, match=code):
        serialize_envelope(candidate)


@pytest.mark.parametrize(
    "context,code",
    (("root", "ENV-MALFORMED"), ("derived", "ENV-LINEAGE-INVALID")),
)
def test_parser_rejects_self_coherent_source_context_transform_swap(context: str, code: str) -> None:
    candidate = _swapped_transform_candidate(context)
    with pytest.raises(ContentEnvelopeError, match=code):
        parse_envelope(_candidate_wire(candidate))
