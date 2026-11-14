"""Revalidate public evidence without mistaking a constructor for a trust boundary."""

import re
from dataclasses import asdict

from .content_envelope import verify_envelope
from .content_models import ContentEnvelopeV1, DigestDomain
from .hashing import hash_bytes
from .normalization import TEXT_MEDIA, _check_text_root, _digest, _profile, _segment, make_manifest
from .normalization_ipc import NormalizationError, canonical
from .normalization_models import (
    PROFILE_ID,
    SUPPORTED_MEDIA,
    NormalizationBudgetV1,
    NormalizationProfileV1,
    NormalizationResultV1,
    NormalizedSegmentV1,
)
from .normalization_trace import decode_object


def validate_result(result) -> None:
    """Structural evidence validation only; does not prove worker execution or authority."""
    try:
        _validate(result)
    except NormalizationError:
        raise
    except Exception:
        raise NormalizationError("NRM-MANIFEST") from None


def _validate(result) -> None:
    if (type(result) is not NormalizationResultV1 or type(result.segments) is not tuple
            or not 0 < len(result.segments) <= 4096 or type(result.manifest) is not bytes
            or len(result.manifest) > 8*1024*1024
            or type(result.manifest_digest) is not str or type(result.profile_id) is not str
            or result.profile_id != PROFILE_ID or type(result.status) is not str
            or result.status != "structurally-complete" or result.semantic_completeness_proven is not False
            or type(result.envelope) is not ContentEnvelopeV1
            or result.manifest_digest != _digest(result.manifest)):
        raise NormalizationError("NRM-MANIFEST")
    for segment in result.segments:
        if (type(segment) is not NormalizedSegmentV1
                or any(type(getattr(segment, k)) is not str or len(getattr(segment, k)) > 16*1024*1024
                       for k in ("text", "raw_text", "locator", "precision"))):
            raise NormalizationError("NRM-MANIFEST")
    manifest = decode_object(result.manifest)
    profile_dict = manifest["profile"]
    budget = NormalizationBudgetV1(**profile_dict["budget"])
    profile = NormalizationProfileV1(**(profile_dict | {"budget": budget}))
    _profile(profile)
    raw_size = size = 0
    for segment in result.segments:
        raw_size += len(segment.raw_text.encode("utf-8"))
        size += len(segment.text.encode("utf-8"))
        if raw_size + size > budget.map_bytes or size > budget.output_bytes:
            raise NormalizationError("NRM-OVER-CAP")
    length, media = manifest["input_length"], manifest["input_media_type"]
    if (type(length) is not int or not 0 < length <= budget.input_bytes or media not in SUPPORTED_MEDIA
            or type(manifest["input_digest"]) is not str
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", manifest["input_digest"])):
        raise NormalizationError("NRM-MANIFEST")
    raw = result.segments[0].raw_text.encode("utf-8") if media in TEXT_MEDIA else None
    for segment in result.segments:
        _segment(asdict(segment), raw, media, profile, root_length=length)
    if raw is not None:
        _check_text_root(result.segments, raw, media)
        if (len(raw) != length or _digest(raw) != manifest["input_digest"]
                or hash_bytes(raw, domain=DigestDomain.CONTENT) != manifest["parent_content_digest"]):
            raise NormalizationError("NRM-MANIFEST")
    usage, caps = manifest["usage"], asdict(budget)
    values = [asdict(s) for s in result.segments]
    if (type(usage) is not dict or usage.keys() != caps.keys()
            or any(type(v) is not int or not 0 <= v <= caps[k] for k, v in usage.items())
            or usage["input_bytes"] != length or usage["map_bytes"] != len(canonical(values))
            or usage["spans"] != len(values)
            or usage["output_bytes"] != sum(len(s.text.encode("utf-8")) for s in result.segments)):
        raise NormalizationError("NRM-MANIFEST")
    if not any(s.text.strip() for s in result.segments):
        raise NormalizationError("NRM-PARTIAL")
    output, rebuilt = make_manifest(result.segments, usage, manifest["input_digest"], length,
                                     media, manifest["parent_content_digest"], profile)
    if rebuilt != result.manifest:
        raise NormalizationError("NRM-MANIFEST")
    verify_envelope(result.envelope, content=output)
    envelope = result.envelope
    if (len(envelope.parents) != 1 or envelope.source.kind != "derived"
            or envelope.parents[0].content_digest != manifest["parent_content_digest"]
            or envelope.transform.implementation_digest != hash_bytes(
                canonical({"image": profile.image_digest, "profile": PROFILE_ID}),
                domain=DigestDomain.TRANSFORM_IMPLEMENTATION)
            or envelope.transform.parameters_digest != hash_bytes(
                canonical({"manifest_digest": result.manifest_digest, "budget": asdict(budget)}),
                domain=DigestDomain.TRANSFORM_PARAMETERS)):
        raise NormalizationError("NRM-MANIFEST")
