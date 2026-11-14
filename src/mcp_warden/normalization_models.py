"""Finite Linux normalization profile; evidence is never delivery authority."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .content_models import ContentEnvelopeV1
from .normalization_ipc import NormalizationError

PROFILE_ID = "mcp-warden.normalizer.v1"
SUPPORTED_MEDIA = frozenset({
    "text/plain", "application/json", "application/xml", "text/xml", "text/html",
    "text/markdown", "text/csv", "message/rfc822", "application/zip", "application/pdf",
})


@dataclass(frozen=True)
class NormalizationBudgetV1:
    input_bytes: int = 16 * 1024 * 1024
    expanded_bytes: int = 64 * 1024 * 1024
    output_bytes: int = 16 * 1024 * 1024
    depth: int = 8
    nodes: int = 4096
    members: int = 256
    spans: int = 100_000
    map_bytes: int = 8 * 1024 * 1024
    combining_run: int = 64
    work: int = 100_000_000

    def __post_init__(self) -> None:
        ceilings = (16*1024*1024, 64*1024*1024, 16*1024*1024, 8, 4096, 256,
                    100_000, 8*1024*1024, 64, 100_000_000)
        if any(type(v) is not int or not 0 < v <= maximum
               for v, maximum in zip(asdict(self).values(), ceilings, strict=True)):
            raise NormalizationError("NRM-PROFILE")


@dataclass(frozen=True)
class NormalizationProfileV1:
    image_digest: str
    budget: NormalizationBudgetV1 = NormalizationBudgetV1()
    profile_id: str = PROFILE_ID
    python_version: str = "3.12"
    unicode_version: str = "15.0.0"

    def __post_init__(self) -> None:
        if (type(self.image_digest) is not str
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_digest)
                or type(self.budget) is not NormalizationBudgetV1
                or self.profile_id != PROFILE_ID or self.python_version != "3.12"
                or self.unicode_version != "15.0.0"):
            raise NormalizationError("NRM-PROFILE")


@dataclass(frozen=True)
class NormalizedSegmentV1:
    text: str
    raw_text: str
    locator: str
    precision: str
    source_start: int
    source_end: int


@dataclass(frozen=True)
class NormalizationResultV1:
    segments: tuple[NormalizedSegmentV1, ...]
    envelope: ContentEnvelopeV1
    manifest_digest: str
    manifest: bytes
    profile_id: str = PROFILE_ID
    status: str = "structurally-complete"
    semantic_completeness_proven: bool = False
