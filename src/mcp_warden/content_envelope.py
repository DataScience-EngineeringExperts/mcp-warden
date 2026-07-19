"""Deterministic constructors and codec for untrusted content envelopes."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any, NoReturn

import rfc8785
from pydantic import ValidationError

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
    TAINT_REGISTRY_V1,
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

_TAINT_REGISTRY = frozenset(TAINT_REGISTRY_V1)


def _fail(code: str) -> NoReturn:
    raise ContentEnvelopeError(code) from None


def _scan_json_structure(data: bytes) -> None:
    depth = 0
    in_string = False
    escape = False
    for byte in data:
        if in_string:
            if escape:
                escape = False
            elif byte == 0x5C:  # backslash
                escape = True
            elif byte == 0x22:  # quote
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):  # { [
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail("ENV-OVER-CAP")
        elif byte in (0x7D, 0x5D):  # } ]
            depth -= 1
            if depth < 0:
                _fail("ENV-MALFORMED")
    if depth != 0 or in_string or escape:
        _fail("ENV-MALFORMED")


class _DuplicateKeyError(Exception):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_constant(_: str) -> NoReturn:
    raise ValueError


def _check_structural_caps(value: object) -> None:
    nodes = 0
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            _fail("ENV-OVER-CAP")
        if isinstance(item, dict):
            if len(item) > MAX_JSON_OBJECT_KEYS:
                _fail("ENV-OVER-CAP")
            for key, child in item.items():
                if len(key.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                    _fail("ENV-OVER-CAP")
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str) and len(item.encode("utf-8")) > MAX_JSON_STRING_BYTES:
            _fail("ENV-OVER-CAP")


def _canonical_metadata(data: bytes, *, cap: int, domain: DigestDomain) -> str:
    if type(data) is not bytes:
        _fail("ENV-MALFORMED")
    if len(data) > cap:
        _fail("ENV-OVER-CAP")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        text = ""
        invalid_utf8 = True
    else:
        invalid_utf8 = False
    if invalid_utf8:
        _fail("ENV-MALFORMED")
    _scan_json_structure(data)

    parsed: object | None = None
    duplicate = False
    malformed = False
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except _DuplicateKeyError:
        duplicate = True
    except (ValueError, TypeError, RecursionError):
        malformed = True
    if duplicate:
        _fail("ENV-NONCANONICAL")
    if malformed:
        _fail("ENV-MALFORMED")
    _check_structural_caps(parsed)

    canonical: bytes | None = None
    canonical_failed = False
    try:
        canonical = rfc8785.dumps(parsed)
    except Exception:
        canonical_failed = True
    if canonical_failed or canonical is None:
        _fail("ENV-MALFORMED")
    if canonical != data:
        _fail("ENV-NONCANONICAL")
    return hash_bytes(data, domain=domain)


def _hash_bundle(bundle: BundleEvidenceInput | None) -> BundleEvidenceV1 | None:
    if bundle is None:
        return None
    if type(bundle) is not BundleEvidenceInput:
        _fail("ENV-BUNDLE-INVALID")
    components = (
        bundle.artifact,
        bundle.version_claims,
        bundle.publisher_claims,
        bundle.policy_binding_claims,
    )
    if any(type(value) is not bytes for value in components):
        _fail("ENV-BUNDLE-INVALID")
    if bundle.signature_evidence is not None and type(bundle.signature_evidence) is not bytes:
        _fail("ENV-BUNDLE-INVALID")
    if type(bundle.dependencies) is not tuple:
        _fail("ENV-BUNDLE-INVALID")
    if len(bundle.dependencies) > MAX_DEPENDENCIES:
        _fail("ENV-OVER-CAP")
    if any(type(value) is not bytes for value in bundle.dependencies):
        _fail("ENV-BUNDLE-INVALID")
    bounded = components + bundle.dependencies
    if bundle.signature_evidence is not None:
        bounded += (bundle.signature_evidence,)
    if any(len(value) > MAX_BUNDLE_COMPONENT_BYTES for value in bounded):
        _fail("ENV-OVER-CAP")
    artifact = _canonical_metadata(
        bundle.artifact, cap=MAX_BUNDLE_COMPONENT_BYTES, domain=DigestDomain.BUNDLE_ARTIFACT
    )
    signature: str | None = None
    if bundle.signature_evidence is not None:
        if not isinstance(bundle.signature_evidence, bytes):
            _fail("ENV-BUNDLE-INVALID")
        if len(bundle.signature_evidence) > MAX_BUNDLE_COMPONENT_BYTES:
            _fail("ENV-OVER-CAP")
        signature = hash_bytes(
            bundle.signature_evidence,
            domain=DigestDomain.BUNDLE_SIGNATURE,
        )
    dependency_digests = tuple(
        sorted(
            {
                _canonical_metadata(
                    dependency,
                    cap=MAX_BUNDLE_COMPONENT_BYTES,
                    domain=DigestDomain.BUNDLE_DEPENDENCY,
                )
                for dependency in bundle.dependencies
            }
        )
    )
    try:
        return BundleEvidenceV1(
            artifact_digest=artifact,
            signature_evidence_digest=signature,
            version_claims_digest=_canonical_metadata(
                bundle.version_claims,
                cap=MAX_BUNDLE_COMPONENT_BYTES,
                domain=DigestDomain.BUNDLE_VERSION,
            ),
            publisher_claims_digest=_canonical_metadata(
                bundle.publisher_claims,
                cap=MAX_BUNDLE_COMPONENT_BYTES,
                domain=DigestDomain.BUNDLE_PUBLISHER,
            ),
            dependency_digests=dependency_digests,
            policy_binding_claims_digest=_canonical_metadata(
                bundle.policy_binding_claims,
                cap=MAX_BUNDLE_COMPONENT_BYTES,
                domain=DigestDomain.BUNDLE_POLICY_BINDING,
            ),
        )
    except (ValidationError, TypeError, ValueError):
        invalid = True
    else:
        invalid = False
    if invalid:
        _fail("ENV-BUNDLE-INVALID")


def _taints(added_taints: Iterable[TaintV1 | str]) -> tuple[str, ...]:
    values_list: list[str] = []
    iteration_failed = False
    invalid_item = False
    try:
        iterator = iter(added_taints)
        for _ in range(MAX_TAINTS + 1):
            try:
                item = next(iterator)
            except StopIteration:
                break
            if type(item) is TaintV1:
                values_list.append(item.value)
            elif type(item) is str:
                values_list.append(item)
            else:
                invalid_item = True
                break
    except Exception:
        iteration_failed = True
    if iteration_failed or invalid_item:
        _fail("ENV-TAINT-UNKNOWN")
    if len(values_list) > MAX_TAINTS:
        _fail("ENV-OVER-CAP")
    values = tuple(values_list)
    if len(values) > MAX_TAINTS:
        _fail("ENV-OVER-CAP")
    result = tuple(sorted(set(values) | {TaintV1.UNTRUSTED.value}))
    if any(not isinstance(item, str) or item not in _TAINT_REGISTRY for item in result):
        _fail("ENV-TAINT-UNKNOWN")
    if len(result) > MAX_TAINTS:
        _fail("ENV-OVER-CAP")
    return result


def _bundle_dict(bundle: BundleEvidenceV1 | None) -> dict[str, object] | None:
    if bundle is None:
        return None
    return {
        "artifact_digest": bundle.artifact_digest,
        "signature_evidence_digest": bundle.signature_evidence_digest,
        "version_claims_digest": bundle.version_claims_digest,
        "publisher_claims_digest": bundle.publisher_claims_digest,
        "dependency_digests": list(bundle.dependency_digests),
        "policy_binding_claims_digest": bundle.policy_binding_claims_digest,
    }


def _body_dict(
    *,
    content: ContentEvidenceV1,
    source: SourceEvidenceV1,
    parents: tuple[ParentRefV1, ...],
    transform: TransformEvidenceV1,
    taints: tuple[str, ...],
    bundle: BundleEvidenceV1 | None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "trust_state": "untrusted",
        "content": {
            "digest": content.digest,
            "length": content.length,
            "media_type": content.media_type,
        },
        "source": {
            "kind": source.kind,
            "identity_digest": source.identity_digest,
            "claims_digest": source.claims_digest,
        },
        "parents": [
            {"envelope_digest": item.envelope_digest, "content_digest": item.content_digest}
            for item in parents
        ],
        "transform": {
            "id": transform.id,
            "version": transform.version,
            "implementation_digest": transform.implementation_digest,
            "parameters_digest": transform.parameters_digest,
        },
        "taints": list(taints),
        "bundle": _bundle_dict(bundle),
    }


def _make_envelope(
    *,
    content: ContentEvidenceV1,
    source: SourceEvidenceV1,
    parents: tuple[ParentRefV1, ...],
    transform: TransformEvidenceV1,
    taints: tuple[str, ...],
    bundle: BundleEvidenceV1 | None,
) -> ContentEnvelopeV1:
    body = _body_dict(
        content=content,
        source=source,
        parents=parents,
        transform=transform,
        taints=taints,
        bundle=bundle,
    )
    body_bytes = rfc8785.dumps(body)
    envelope_digest = hash_bytes(body_bytes, domain=DigestDomain.ENVELOPE)
    try:
        return ContentEnvelopeV1(
            schema_version=1,
            trust_state="untrusted",
            content=content,
            source=source,
            parents=parents,
            transform=transform,
            taints=taints,
            bundle=bundle,
            envelope_digest=envelope_digest,
        )
    except (ValidationError, TypeError, ValueError):
        invalid = True
    else:
        invalid = False
    if invalid:
        _fail("ENV-MALFORMED")


def create_ingress(
    *,
    content: bytes,
    media_type: MediaTypeV1,
    source_kind: IngressKindV1,
    source_identity: bytes,
    source_claims: bytes,
    capture_kind: TransformKindV1,
    capture_implementation: bytes,
    capture_parameters: bytes,
    added_taints: Iterable[TaintV1 | str] = (),
    bundle: BundleEvidenceInput | None = None,
) -> ContentEnvelopeV1:
    """Create a root envelope from exact, explicitly untrusted ingress bytes."""
    if type(content) is not bytes or type(media_type) is not MediaTypeV1:
        _fail("ENV-MALFORMED")
    if type(source_kind) is not IngressKindV1:
        _fail("ENV-MALFORMED")
    if capture_kind is not TransformKindV1.INGRESS_CAPTURE:
        _fail("ENV-MALFORMED")
    if len(content) > MAX_CONTENT_BYTES:
        _fail("ENV-OVER-CAP")
    if source_kind is IngressKindV1.BUNDLE_METADATA and bundle is None:
        _fail("ENV-BUNDLE-INVALID")

    try:
        content_evidence = ContentEvidenceV1(
            digest=hash_bytes(content, domain=DigestDomain.CONTENT),
            length=len(content),
            media_type=media_type.value,
        )
        source = SourceEvidenceV1(
            kind=source_kind.value,
            identity_digest=_canonical_metadata(
                source_identity,
                cap=MAX_SOURCE_IDENTITY_BYTES,
                domain=DigestDomain.SOURCE_IDENTITY,
            ),
            claims_digest=_canonical_metadata(
                source_claims,
                cap=MAX_SOURCE_CLAIMS_BYTES,
                domain=DigestDomain.SOURCE_CLAIMS,
            ),
        )
        transform_id, transform_version = TRANSFORM_REGISTRY_V1[capture_kind]
        transform = TransformEvidenceV1(
            id=transform_id,
            version=transform_version,
            implementation_digest=_canonical_metadata(
                capture_implementation,
                cap=MAX_TRANSFORM_IDENTITY_BYTES,
                domain=DigestDomain.TRANSFORM_IMPLEMENTATION,
            ),
            parameters_digest=_canonical_metadata(
                capture_parameters,
                cap=MAX_TRANSFORM_PARAMETERS_BYTES,
                domain=DigestDomain.TRANSFORM_PARAMETERS,
            ),
        )
    except ContentEnvelopeError:
        raise
    except (ValidationError, TypeError, ValueError):
        invalid = True
    else:
        invalid = False
    if invalid:
        _fail("ENV-MALFORMED")
    return _make_envelope(
        content=content_evidence,
        source=source,
        parents=(),
        transform=transform,
        taints=_taints(added_taints),
        bundle=_hash_bundle(bundle),
    )


def _computed_envelope_digest(envelope: ContentEnvelopeV1) -> str:
    try:
        body = _body_dict(
            content=envelope.content,
            source=envelope.source,
            parents=envelope.parents,
            transform=envelope.transform,
            taints=envelope.taints,
            bundle=envelope.bundle,
        )
        body_bytes = rfc8785.dumps(body)
        return hash_bytes(body_bytes, domain=DigestDomain.ENVELOPE)
    except Exception:
        invalid = True
    else:  # pragma: no cover - return above; retained for explicit exception boundary
        invalid = False
    if invalid:
        _fail("ENV-DIGEST-MISMATCH")


def _replace_self_digest(envelope: ContentEnvelopeV1) -> ContentEnvelopeV1:
    """Test/support helper that replaces only the deterministically computed self digest."""
    return envelope.model_copy(update={"envelope_digest": _computed_envelope_digest(envelope)})


def _preflight_envelope(envelope: ContentEnvelopeV1) -> None:
    """Reject structurally incomplete constructed models before field dereference."""
    storage_failed = False
    try:
        storage = object.__getattribute__(envelope, "__dict__")
    except (AttributeError, TypeError):
        storage_failed = True
        storage = {}
    required = frozenset(ContentEnvelopeV1.model_fields)
    if storage_failed or type(storage) is not dict or not required.issubset(storage):
        _fail("ENV-MALFORMED")
    if type(storage["content"]) is not ContentEvidenceV1:
        _fail("ENV-MALFORMED")
    if type(storage["source"]) is not SourceEvidenceV1:
        _fail("ENV-MALFORMED")
    if type(storage["transform"]) is not TransformEvidenceV1:
        _fail("ENV-MALFORMED")
    if type(storage["parents"]) is not tuple or len(storage["parents"]) > MAX_PARENTS:
        _fail("ENV-LINEAGE-INVALID")
    if any(type(parent) is not ParentRefV1 for parent in storage["parents"]):
        _fail("ENV-LINEAGE-INVALID")
    if type(storage["taints"]) is not tuple or len(storage["taints"]) > MAX_TAINTS:
        _fail("ENV-LINEAGE-INVALID")
    if storage["bundle"] is not None and type(storage["bundle"]) is not BundleEvidenceV1:
        _fail("ENV-BUNDLE-INVALID")


def _verified_parents(
    parents: Sequence[ContentEnvelopeV1], *, allow_empty: bool = False
) -> tuple[ContentEnvelopeV1, ...]:
    if isinstance(parents, (bytes, bytearray, str)) or not isinstance(parents, Sequence):
        _fail("ENV-LINEAGE-INVALID")
    values_list: list[ContentEnvelopeV1] = []
    iteration_failed = False
    try:
        iterator = iter(parents)
        for _ in range(MAX_PARENTS + 1):
            try:
                parent = next(iterator)
            except StopIteration:
                break
            values_list.append(parent)
    except Exception:
        iteration_failed = True
    if iteration_failed:
        _fail("ENV-LINEAGE-INVALID")
    if len(values_list) > MAX_PARENTS:
        _fail("ENV-OVER-CAP")
    values = tuple(values_list)
    if not values and not allow_empty:
        _fail("ENV-LINEAGE-INVALID")
    # Recompute every complete parent self-digest before accepting refs or taints.
    for parent in values:
        if type(parent) is not ContentEnvelopeV1:
            _fail("ENV-LINEAGE-INVALID")
        _preflight_envelope(parent)
        if _computed_envelope_digest(parent) != parent.envelope_digest:
            _fail("ENV-DIGEST-MISMATCH")
    for parent in values:
        _validate_envelope_shape(parent)
    if len({parent.envelope_digest for parent in values}) != len(values):
        _fail("ENV-LINEAGE-INVALID")
    return values


def _derived_source(
    refs: tuple[ParentRefV1, ...], transform: TransformEvidenceV1
) -> SourceEvidenceV1:
    ref_payload = rfc8785.dumps(
        [
            {"envelope_digest": ref.envelope_digest, "content_digest": ref.content_digest}
            for ref in refs
        ]
    )
    identity_digest = hash_bytes(ref_payload, domain=DigestDomain.DERIVED_SOURCE_IDENTITY)
    claims_payload = rfc8785.dumps(
        {
            "parent_refs_digest": identity_digest,
            "transform_id": transform.id,
            "transform_version": transform.version,
            "implementation_digest": transform.implementation_digest,
            "parameters_digest": transform.parameters_digest,
        }
    )
    return SourceEvidenceV1(
        kind="derived",
        identity_digest=identity_digest,
        claims_digest=hash_bytes(claims_payload, domain=DigestDomain.DERIVED_SOURCE_CLAIMS),
    )


def _validate_derived_source(envelope: ContentEnvelopeV1) -> None:
    if envelope.source.kind == "derived" and envelope.source != _derived_source(
        envelope.parents, envelope.transform
    ):
        _fail("ENV-LINEAGE-INVALID")


def _revalidate_model(value: object, model_type: type, code: str) -> None:
    invalid = False
    try:
        model_type.model_validate(value)
    except (ValidationError, TypeError, ValueError, AttributeError):
        invalid = True
    if invalid:
        _fail(code)


def _validate_envelope_shape(envelope: ContentEnvelopeV1) -> None:
    _preflight_envelope(envelope)
    if type(envelope.schema_version) is not int or envelope.schema_version != 1:
        _fail("ENV-SCHEMA-UNKNOWN")
    if type(envelope.trust_state) is not str or envelope.trust_state != "untrusted":
        _fail("ENV-TRUST-INVALID")
    if type(envelope.content) is not ContentEvidenceV1:
        _fail("ENV-MALFORMED")
    if type(envelope.source) is not SourceEvidenceV1:
        _fail("ENV-MALFORMED")
    if type(envelope.transform) is not TransformEvidenceV1:
        _fail("ENV-MALFORMED")
    _revalidate_model(envelope.content, ContentEvidenceV1, "ENV-MALFORMED")
    _revalidate_model(envelope.source, SourceEvidenceV1, "ENV-MALFORMED")
    _revalidate_model(envelope.transform, TransformEvidenceV1, "ENV-MALFORMED")
    if type(envelope.parents) is not tuple or len(envelope.parents) > MAX_PARENTS:
        _fail("ENV-LINEAGE-INVALID")
    for parent in envelope.parents:
        if type(parent) is not ParentRefV1:
            _fail("ENV-LINEAGE-INVALID")
        _revalidate_model(parent, ParentRefV1, "ENV-LINEAGE-INVALID")
    if envelope.parents != tuple(
        sorted(
            envelope.parents,
            key=lambda item: (item.envelope_digest, item.content_digest),
        )
    ) or len({item.envelope_digest for item in envelope.parents}) != len(envelope.parents):
        _fail("ENV-LINEAGE-INVALID")
    if type(envelope.taints) is not tuple or len(envelope.taints) > MAX_TAINTS:
        _fail("ENV-LINEAGE-INVALID")
    if any(type(label) is not str for label in envelope.taints):
        _fail("ENV-TAINT-UNKNOWN")
    if "core:untrusted" not in envelope.taints:
        _fail("ENV-TAINT-MISSING")
    if any(label not in _TAINT_REGISTRY for label in envelope.taints):
        _fail("ENV-TAINT-UNKNOWN")
    if envelope.taints != tuple(sorted(set(envelope.taints))):
        _fail("ENV-LINEAGE-INVALID")
    if envelope.bundle is not None:
        if type(envelope.bundle) is not BundleEvidenceV1:
            _fail("ENV-BUNDLE-INVALID")
        _revalidate_model(envelope.bundle, BundleEvidenceV1, "ENV-BUNDLE-INVALID")
    if envelope.source.kind == "derived":
        if not envelope.parents:
            _fail("ENV-LINEAGE-INVALID")
        _validate_derived_source(envelope)
    elif envelope.parents:
        _fail("ENV-LINEAGE-INVALID")
    if envelope.source.kind == IngressKindV1.BUNDLE_METADATA.value and envelope.bundle is None:
        _fail("ENV-BUNDLE-INVALID")
    _revalidate_model(envelope, ContentEnvelopeV1, "ENV-MALFORMED")


def derive_envelope(
    *,
    content: bytes,
    media_type: MediaTypeV1,
    parents: Sequence[ContentEnvelopeV1],
    transform_kind: TransformKindV1,
    transform_implementation: bytes,
    transform_parameters: bytes,
    added_taints: Iterable[TaintV1 | str] = (),
    bundle: BundleEvidenceInput | None = None,
) -> ContentEnvelopeV1:
    """Derive one envelope from a bounded, atomically verified parent set."""
    verified = _verified_parents(parents)
    if type(content) is not bytes or type(media_type) is not MediaTypeV1:
        _fail("ENV-MALFORMED")
    if transform_kind is not TransformKindV1.DETERMINISTIC:
        _fail("ENV-MALFORMED")
    if len(content) > MAX_CONTENT_BYTES:
        _fail("ENV-OVER-CAP")

    refs = tuple(
        sorted(
            (
                ParentRefV1(
                    envelope_digest=parent.envelope_digest,
                    content_digest=parent.content.digest,
                )
                for parent in verified
            ),
            key=lambda item: (item.envelope_digest, item.content_digest),
        )
    )
    local_taints: set[str] = set()
    for parent in verified:
        if len(parent.taints) > MAX_TAINTS:
            _fail("ENV-OVER-CAP")
        if any(label not in _TAINT_REGISTRY for label in parent.taints):
            _fail("ENV-TAINT-UNKNOWN")
        local_taints.update(parent.taints)
    caller_taints = _taints(added_taints)
    local_taints.update(caller_taints)
    if len(local_taints) > MAX_TAINTS:
        _fail("ENV-OVER-CAP")
    taints = tuple(sorted(local_taints))

    try:
        transform_id, transform_version = TRANSFORM_REGISTRY_V1[transform_kind]
        transform = TransformEvidenceV1(
            id=transform_id,
            version=transform_version,
            implementation_digest=_canonical_metadata(
                transform_implementation,
                cap=MAX_TRANSFORM_IDENTITY_BYTES,
                domain=DigestDomain.TRANSFORM_IMPLEMENTATION,
            ),
            parameters_digest=_canonical_metadata(
                transform_parameters,
                cap=MAX_TRANSFORM_PARAMETERS_BYTES,
                domain=DigestDomain.TRANSFORM_PARAMETERS,
            ),
        )
        content_evidence = ContentEvidenceV1(
            digest=hash_bytes(content, domain=DigestDomain.CONTENT),
            length=len(content),
            media_type=media_type.value,
        )
    except ContentEnvelopeError:
        raise
    except (ValidationError, TypeError, ValueError):
        invalid = True
    else:
        invalid = False
    if invalid:
        _fail("ENV-MALFORMED")

    source = _derived_source(refs, transform)
    return _make_envelope(
        content=content_evidence,
        source=source,
        parents=refs,
        transform=transform,
        taints=taints,
        bundle=_hash_bundle(bundle),
    )


def verify_lineage(
    envelope: ContentEnvelopeV1, *, parents: Sequence[ContentEnvelopeV1]
) -> None:
    """Verify the exact one-hop parent set and monotonic local taint union."""
    if type(envelope) is not ContentEnvelopeV1:
        _fail("ENV-LINEAGE-INVALID")
    _validate_envelope_shape(envelope)
    if _computed_envelope_digest(envelope) != envelope.envelope_digest:
        _fail("ENV-DIGEST-MISMATCH")
    is_derived = envelope.source.kind == "derived"
    verified = _verified_parents(parents, allow_empty=not is_derived)
    if is_derived != bool(envelope.parents):
        _fail("ENV-LINEAGE-INVALID")
    if not is_derived:
        if verified:
            _fail("ENV-LINEAGE-INVALID")
        return

    expected = tuple(
        sorted(
            (
                ParentRefV1(
                    envelope_digest=parent.envelope_digest,
                    content_digest=parent.content.digest,
                )
                for parent in verified
            ),
            key=lambda item: (item.envelope_digest, item.content_digest),
        )
    )
    if expected != envelope.parents:
        _fail("ENV-LINEAGE-INVALID")
    if any(ref.envelope_digest == envelope.envelope_digest for ref in envelope.parents):
        _fail("ENV-LINEAGE-INVALID")
    required_taints = {TaintV1.UNTRUSTED.value}
    for parent in verified:
        required_taints.update(parent.taints)
    if not required_taints.issubset(envelope.taints):
        _fail("ENV-TAINT-MISSING")


def verify_envelope(envelope: ContentEnvelopeV1, *, content: bytes) -> None:
    """Verify envelope self-integrity and exact supplied content bytes."""
    if type(envelope) is not ContentEnvelopeV1 or type(content) is not bytes:
        _fail("ENV-MALFORMED")
    _validate_envelope_shape(envelope)
    if len(content) > MAX_CONTENT_BYTES:
        _fail("ENV-OVER-CAP")
    if _computed_envelope_digest(envelope) != envelope.envelope_digest:
        _fail("ENV-DIGEST-MISMATCH")
    if envelope.content.length != len(content):
        _fail("ENV-DIGEST-MISMATCH")
    if envelope.content.digest != hash_bytes(content, domain=DigestDomain.CONTENT):
        _fail("ENV-DIGEST-MISMATCH")
    if envelope.source.kind == "derived":
        if not envelope.parents:
            _fail("ENV-LINEAGE-INVALID")
    elif envelope.parents:
        _fail("ENV-LINEAGE-INVALID")
    if envelope.source.kind == IngressKindV1.BUNDLE_METADATA.value and envelope.bundle is None:
        _fail("ENV-BUNDLE-INVALID")


def to_public_dict(envelope: ContentEnvelopeV1) -> dict[str, object]:
    """Return the explicit digest-only V1 wire projection."""
    if type(envelope) is not ContentEnvelopeV1:
        _fail("ENV-MALFORMED")
    _validate_envelope_shape(envelope)
    if _computed_envelope_digest(envelope) != envelope.envelope_digest:
        _fail("ENV-DIGEST-MISMATCH")
    body = _body_dict(
        content=envelope.content,
        source=envelope.source,
        parents=envelope.parents,
        transform=envelope.transform,
        taints=envelope.taints,
        bundle=envelope.bundle,
    )
    body["envelope_digest"] = envelope.envelope_digest
    return body


def to_public_bytes(envelope: ContentEnvelopeV1) -> bytes:
    encoded = rfc8785.dumps(to_public_dict(envelope))
    if len(encoded) > MAX_ENVELOPE_BYTES:
        _fail("ENV-OVER-CAP")
    return encoded


def serialize_envelope(envelope: ContentEnvelopeV1) -> bytes:
    """Serialize an envelope to exact RFC 8785 wire bytes."""
    return to_public_bytes(envelope)


def _parse_wire_json(data: bytes) -> object:
    if type(data) is not bytes:
        _fail("ENV-MALFORMED")
    if len(data) > MAX_ENVELOPE_BYTES:
        _fail("ENV-OVER-CAP")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        invalid_utf8 = True
        text = ""
    else:
        invalid_utf8 = False
    if invalid_utf8:
        _fail("ENV-MALFORMED")
    _scan_json_structure(data)

    parsed: object | None = None
    duplicate = False
    malformed = False
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except _DuplicateKeyError:
        duplicate = True
    except (ValueError, TypeError, RecursionError):
        malformed = True
    if duplicate:
        _fail("ENV-NONCANONICAL")
    if malformed:
        _fail("ENV-MALFORMED")
    _check_structural_caps(parsed)

    canonical: bytes | None = None
    canonical_failed = False
    try:
        canonical = rfc8785.dumps(parsed)
    except Exception:
        canonical_failed = True
    if canonical_failed or canonical is None:
        _fail("ENV-MALFORMED")
    if canonical != data:
        _fail("ENV-NONCANONICAL")
    return parsed


def _object_with_fields(
    value: object, expected: frozenset[str], *, missing_code: str = "ENV-MALFORMED"
) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail("ENV-MALFORMED")
    keys = frozenset(value)
    if keys - expected:
        _fail("ENV-UNKNOWN-FIELD")
    if expected - keys:
        _fail(missing_code)
    return value


def parse_envelope(data: bytes) -> ContentEnvelopeV1:
    """Parse strict V1 bytes and atomically verify their self digest."""
    parsed = _parse_wire_json(data)
    top_expected = frozenset(
        {
            "schema_version",
            "trust_state",
            "content",
            "source",
            "parents",
            "transform",
            "taints",
            "bundle",
            "envelope_digest",
        }
    )
    if not isinstance(parsed, dict):
        _fail("ENV-MALFORMED")
    if "schema_version" not in parsed:
        _fail("ENV-SCHEMA-UNKNOWN")
    if "trust_state" not in parsed:
        _fail("ENV-TRUST-INVALID")
    if "taints" not in parsed:
        _fail("ENV-TAINT-MISSING")
    if "bundle" not in parsed:
        _fail("ENV-BUNDLE-INVALID")
    top = _object_with_fields(parsed, top_expected)
    if top["schema_version"] != 1 or isinstance(top["schema_version"], bool):
        _fail("ENV-SCHEMA-UNKNOWN")
    if top["trust_state"] != "untrusted":
        _fail("ENV-TRUST-INVALID")

    content_data = _object_with_fields(
        top["content"], frozenset({"digest", "length", "media_type"})
    )
    source_data = _object_with_fields(
        top["source"], frozenset({"kind", "identity_digest", "claims_digest"})
    )
    transform_data = _object_with_fields(
        top["transform"],
        frozenset({"id", "version", "implementation_digest", "parameters_digest"}),
    )
    if not isinstance(top["parents"], list) or not isinstance(top["taints"], list):
        _fail("ENV-MALFORMED")
    if len(top["parents"]) > MAX_PARENTS or len(top["taints"]) > MAX_TAINTS:
        _fail("ENV-OVER-CAP")

    parent_dicts_list: list[dict[str, object]] = []
    for item in top["parents"]:
        if not isinstance(item, dict):
            _fail("ENV-LINEAGE-INVALID")
        parent_dicts_list.append(
            _object_with_fields(
                item,
                frozenset({"envelope_digest", "content_digest"}),
                missing_code="ENV-LINEAGE-INVALID",
            )
        )
    parent_dicts = tuple(parent_dicts_list)
    try:
        parents = tuple(ParentRefV1(**item) for item in parent_dicts)
    except (ValidationError, TypeError, ValueError):
        invalid_parents = True
        parents = ()
    else:
        invalid_parents = False
    if invalid_parents:
        _fail("ENV-LINEAGE-INVALID")
    if parents != tuple(
        sorted(parents, key=lambda item: (item.envelope_digest, item.content_digest))
    ) or len({item.envelope_digest for item in parents}) != len(parents):
        _fail("ENV-LINEAGE-INVALID")

    bundle_data: dict[str, object] | None = None
    if top["bundle"] is not None:
        bundle_data = _object_with_fields(
            top["bundle"],
            frozenset(
                {
                    "artifact_digest",
                    "signature_evidence_digest",
                    "version_claims_digest",
                    "publisher_claims_digest",
                    "dependency_digests",
                    "policy_binding_claims_digest",
                }
            ),
            missing_code="ENV-BUNDLE-INVALID",
        )
        dependencies = bundle_data["dependency_digests"]
        if not isinstance(dependencies, list):
            _fail("ENV-BUNDLE-INVALID")
        if len(dependencies) > MAX_DEPENDENCIES:
            _fail("ENV-OVER-CAP")

    bundle: BundleEvidenceV1 | None = None
    invalid_bundle = False
    if bundle_data is not None:
        try:
            bundle = BundleEvidenceV1(
                artifact_digest=bundle_data["artifact_digest"],
                signature_evidence_digest=bundle_data["signature_evidence_digest"],
                version_claims_digest=bundle_data["version_claims_digest"],
                publisher_claims_digest=bundle_data["publisher_claims_digest"],
                dependency_digests=tuple(bundle_data["dependency_digests"]),
                policy_binding_claims_digest=bundle_data["policy_binding_claims_digest"],
            )
        except (ValidationError, TypeError, ValueError):
            invalid_bundle = True
    if invalid_bundle:
        _fail("ENV-BUNDLE-INVALID")

    taint_values = top["taints"]
    if any(not isinstance(item, str) or item not in _TAINT_REGISTRY for item in taint_values):
        _fail("ENV-TAINT-UNKNOWN")
    if "core:untrusted" not in taint_values:
        _fail("ENV-TAINT-MISSING")
    if taint_values != sorted(set(taint_values)):
        _fail("ENV-LINEAGE-INVALID")

    try:
        content = ContentEvidenceV1(**content_data)
        source = SourceEvidenceV1(**source_data)
        transform = TransformEvidenceV1(**transform_data)
    except (ValidationError, TypeError, ValueError):
        invalid = True
        content = None
        source = None
        transform = None
    else:
        invalid = False
    if invalid or content is None or source is None or transform is None:
        _fail("ENV-MALFORMED")

    if source.kind == "derived":
        if not parents:
            _fail("ENV-LINEAGE-INVALID")
    elif parents:
        _fail("ENV-LINEAGE-INVALID")
    if source.kind == IngressKindV1.BUNDLE_METADATA.value and bundle is None:
        _fail("ENV-BUNDLE-INVALID")
    try:
        envelope = ContentEnvelopeV1(
            schema_version=top["schema_version"],
            trust_state=top["trust_state"],
            content=content,
            source=source,
            parents=parents,
            transform=transform,
            taints=tuple(taint_values),
            bundle=bundle,
            envelope_digest=top["envelope_digest"],
        )
    except (ValidationError, TypeError, ValueError):
        invalid_envelope = True
        envelope = None
    else:
        invalid_envelope = False
    if invalid_envelope or envelope is None:
        _fail("ENV-MALFORMED")
    if any(ref.envelope_digest == envelope.envelope_digest for ref in parents):
        _fail("ENV-LINEAGE-INVALID")
    if _computed_envelope_digest(envelope) != envelope.envelope_digest:
        _fail("ENV-DIGEST-MISMATCH")
    _validate_envelope_shape(envelope)
    return envelope
