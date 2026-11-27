"""Supplied-payload adapters for every declared ingress; never fetches a source."""

from __future__ import annotations

from .content_envelope import create_ingress, derive_envelope
from .content_models import (
    BundleEvidenceInput,
    ContentEnvelopeError,
    ContentEnvelopeV1,
    IngressKindV1,
    MediaTypeV1,
    TransformKindV1,
)
from .normalization import _digest, normalize_ingress
from .normalization_ipc import NormalizationError, canonical
from .normalization_models import NormalizationProfileV1, NormalizationResultV1
from .taint_lineage import ContentLineageV1


def normalize_supplied(content: bytes, media_type: MediaTypeV1, source_kind: IngressKindV1,
                       profile: NormalizationProfileV1, *, source_identity: bytes = b"{}",
                       source_claims: bytes = b"{}",
                       lineage: ContentLineageV1 | None = None) -> NormalizationResultV1:
    """Capture exact supplied bytes then derive evidence through the shared engine.

    Source metadata remains an unverified claim. Bundle-metadata roots describe
    the supplied metadata payload's digest, not an approved executable bundle.
    Adapters explicitly supply data parents. The payload and its claims never
    select parents, change taint labels, or authorize an action.
    """
    if (type(content) is not bytes or type(media_type) is not MediaTypeV1
            or type(source_kind) is not IngressKindV1):
        raise NormalizationError()
    bundle = None
    if source_kind is IngressKindV1.BUNDLE_METADATA:
        bundle = BundleEvidenceInput(
            artifact=canonical({"metadata_content_digest": _digest(content)}),
            signature_evidence=None, version_claims=b"{}", publisher_claims=b"{}",
            dependencies=(), policy_binding_claims=b"{}",
        )
    try:
        root = create_ingress(
            content=content, media_type=media_type, source_kind=source_kind,
            source_identity=source_identity, source_claims=source_claims,
            capture_kind=TransformKindV1.INGRESS_CAPTURE,
            capture_implementation=canonical({"adapter": "supplied-bytes", "version": "1"}),
            capture_parameters=canonical({"media_type": media_type.value, "kind": source_kind.value}),
            bundle=bundle,
        )
        ancestors: tuple[ContentEnvelopeV1, ...] = ()
        if lineage is not None:
            if type(lineage) is not ContentLineageV1:
                raise NormalizationError("NRM-LINEAGE")
            try:
                ContentLineageV1.__post_init__(lineage)
                parents = lineage.parents
                ancestors = parents + lineage.ancestors
                if all(parent.envelope_digest != root.envelope_digest for parent in parents):
                    parents = (root, *parents)
                if all(ancestor.envelope_digest != root.envelope_digest for ancestor in ancestors):
                    ancestors = (root, *ancestors)
                root = derive_envelope(
                    content=content,
                    media_type=media_type,
                    parents=parents,
                    transform_kind=TransformKindV1.DETERMINISTIC,
                    transform_implementation=b'{"adapter":"mcp-warden.link-supplied-ancestry","version":"1"}',
                    transform_parameters=canonical({"captured_envelope": root.envelope_digest}),
                )
            except ContentEnvelopeError:
                raise NormalizationError("NRM-LINEAGE") from None
        return normalize_ingress(content, root, profile, ancestors=ancestors)
    except NormalizationError:
        raise
    except Exception:
        raise NormalizationError() from None
