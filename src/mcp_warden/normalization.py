"""Trusted validation of untrusted worker evidence; never authorizes delivery."""

from __future__ import annotations

import base64
import hashlib
import unicodedata
from dataclasses import asdict

from .content_envelope import derive_envelope, verify_envelope
from .content_models import ContentEnvelopeV1, MediaTypeV1, TransformKindV1
from .normalization_ipc import NormalizationError, canonical
from .normalization_models import (
    PROFILE_ID,
    SUPPORTED_MEDIA,
    NormalizationBudgetV1,
    NormalizationProfileV1,
    NormalizationResultV1,
    NormalizedSegmentV1,
)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _run_worker(request: dict, profile: NormalizationProfileV1) -> dict:
    from .normalization_sandbox import run_worker
    return run_worker(request, profile)


def _profile(profile: NormalizationProfileV1) -> None:
    if type(profile) is not NormalizationProfileV1 or type(profile.budget) is not NormalizationBudgetV1:
        raise NormalizationError("NRM-PROFILE")
    # Revalidate even exact instances constructed unsafely outside the public API.
    budget = NormalizationBudgetV1(**asdict(profile.budget))
    NormalizationProfileV1(**(asdict(profile) | {"budget": budget}))


def _segment(value: object, raw: bytes, media: str, profile: NormalizationProfileV1) -> NormalizedSegmentV1:
    keys = {"text", "raw_text", "locator", "precision", "source_start", "source_end"}
    if type(value) is not dict or value.keys() != keys:
        raise NormalizationError("NRM-MANIFEST")
    if any(type(value[k]) is not str for k in ("text", "raw_text", "locator", "precision")):
        raise NormalizationError("NRM-MANIFEST")
    if (not value["locator"] or len(value["locator"].encode("utf-8")) > 1024
            or any(unicodedata.category(c).startswith("C") for c in value["locator"])):
        raise NormalizationError("NRM-MANIFEST")
    if (any(type(value[k]) is not int for k in ("source_start", "source_end"))
            or not 0 <= value["source_start"] <= value["source_end"] <= len(raw)):
        raise NormalizationError("NRM-MANIFEST")
    if value["precision"] == "exact":
        if (media != "text/plain" or value["source_start"] != 0
                or value["source_end"] != len(raw)
                or value["raw_text"].encode("utf-8") != raw
                or value["text"] != value["raw_text"]):
            raise NormalizationError("NRM-MANIFEST")
    elif value["precision"] != "container" or (value["source_start"], value["source_end"]) != (0, len(raw)):
        raise NormalizationError("NRM-MANIFEST")
    if unicodedata.unidata_version == profile.unicode_version:
        expected = "".join(c for c in unicodedata.normalize("NFKC", value["raw_text"])
                           if unicodedata.category(c) != "Cf" and (ord(c) >= 32 or c in "\n\r\t"))
        if value["text"] != expected:
            raise NormalizationError("NRM-MANIFEST")
    return NormalizedSegmentV1(**value)


def _validate_response(response: object, raw: bytes, media: str, profile: NormalizationProfileV1) -> tuple:
    if (type(response) is not dict or type(response.get("schema_version")) is not int
            or response.get("schema_version") != 1):
        raise NormalizationError("NRM-MANIFEST")
    if response.get("status") == "refused":
        code = response.get("code")
        # Never expose a worker-supplied error message or arbitrary code text.
        known = {"NRM-MALFORMED", "NRM-OVER-CAP", "NRM-UNSUPPORTED", "NRM-AMBIGUOUS",
                 "NRM-PARTIAL", "NRM-ENCRYPTED", "NRM-ENCODING", "NRM-RUNTIME"}
        raise NormalizationError(code if type(code) is str and code in known else "NRM-WORKER")
    fields = {"schema_version", "status", "profile_id", "input_digest", "runtime", "segments", "usage"}
    if (response.keys() != fields or response["status"] != "structurally-complete"
            or response["profile_id"] != PROFILE_ID or response["input_digest"] != _digest(raw)
            or response["runtime"] != {"python": profile.python_version,
                                      "unicode": profile.unicode_version,
                                      "parser": "pypdf==" + profile.parser_version}):
        raise NormalizationError("NRM-MANIFEST")
    values, usage, caps = response["segments"], response["usage"], asdict(profile.budget)
    if (type(values) is not list or not values or len(values) > min(caps["spans"], caps["nodes"])
            or type(usage) is not dict or usage.keys() != caps.keys()
            or any(type(v) is not int or not 0 <= v <= caps[k] for k, v in usage.items())):
        raise NormalizationError("NRM-OVER-CAP")
    map_size = len(canonical(values))
    if (usage["input_bytes"] != len(raw) or map_size > caps["map_bytes"]
            or usage["map_bytes"] != map_size):
        raise NormalizationError("NRM-MANIFEST")
    segments = tuple(_segment(v, raw, media, profile) for v in values)
    size = sum(len(s.text.encode("utf-8")) for s in segments)
    raw_size = sum(len(s.raw_text.encode("utf-8")) for s in segments)
    if (size > caps["output_bytes"] or raw_size > caps["expanded_bytes"]
            or usage["output_bytes"] != size or usage["spans"] != len(segments)):
        raise NormalizationError("NRM-OVER-CAP")
    if not any(s.text.strip() for s in segments):
        raise NormalizationError("NRM-PARTIAL")
    return segments, usage


def normalize_ingress(content: bytes, envelope: ContentEnvelopeV1,
                      profile: NormalizationProfileV1) -> NormalizationResultV1:
    """Normalize supplied bytes under an immutable profile, preserving untrusted lineage.

    Structural checks do not prove semantic parser completeness. Unsupported,
    partial or unavailable execution raises a stable non-clean refusal.
    """
    try:
        return _normalize(content, envelope, profile)
    except NormalizationError:
        raise
    except Exception:
        raise NormalizationError("NRM-MALFORMED") from None


def _normalize(content: bytes, envelope: ContentEnvelopeV1,
               profile: NormalizationProfileV1) -> NormalizationResultV1:
    if type(content) is not bytes or type(envelope) is not ContentEnvelopeV1:
        raise NormalizationError()
    _profile(profile)
    if not content or len(content) > profile.budget.input_bytes:
        raise NormalizationError("NRM-OVER-CAP")
    verify_envelope(envelope, content=content)
    media = envelope.content.media_type
    if media not in SUPPORTED_MEDIA:
        raise NormalizationError("NRM-UNSUPPORTED")
    request = {"schema_version": 1, "profile_id": PROFILE_ID, "media_type": media,
               "content_b64": base64.b64encode(content).decode("ascii"), "budget": asdict(profile.budget)}
    segments, usage = _validate_response(_run_worker(request, profile), content, media, profile)
    output = "\n".join(s.text for s in segments).encode("utf-8")
    if len(output) > profile.budget.output_bytes:
        raise NormalizationError("NRM-OVER-CAP")
    offset, mapping = 0, []
    for index, segment in enumerate(segments):
        if index:
            mapping.append({"output_start": offset, "output_end": offset + 1,
                            "precision": "synthetic", "source_ranges": []})
            offset += 1
        end = offset + len(segment.text.encode("utf-8"))
        mapping.append({"output_start": offset, "output_end": end, "precision": segment.precision,
                        "locator": segment.locator,
                        "source_ranges": [[segment.source_start, segment.source_end]]})
        offset = end
    manifest = canonical({"schema_version": 1, "profile": asdict(profile), "usage": usage,
                          "input_digest": _digest(content), "output_digest": _digest(output),
                          "map": mapping, "semantic_completeness_proven": False})
    if len(manifest) > profile.budget.map_bytes:
        raise NormalizationError("NRM-OVER-CAP")
    digest = _digest(manifest)
    derived = derive_envelope(
        content=output, media_type=MediaTypeV1.TEXT_PLAIN, parents=(envelope,),
        transform_kind=TransformKindV1.DETERMINISTIC,
        transform_implementation=canonical({"image": profile.image_digest, "profile": PROFILE_ID}),
        transform_parameters=canonical({"manifest_digest": digest, "budget": asdict(profile.budget)}),
    )
    return NormalizationResultV1(segments=segments, envelope=derived,
                                 manifest_digest=digest, manifest=manifest)
