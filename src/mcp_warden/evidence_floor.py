"""Closed artifact floors shared by protected-state contracts."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictInt, model_validator

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FloorKind = Literal[
    "policy",
    "rule",
    "trust-root",
    "signer-authorization",
    "adapter",
    "executable-bundle",
    "revocation",
    "receipt-log",
    "fallback-log",
    "override",
]
FLOOR_KINDS = (
    "adapter",
    "executable-bundle",
    "fallback-log",
    "override",
    "policy",
    "receipt-log",
    "revocation",
    "rule",
    "signer-authorization",
    "trust-root",
)
MAX_COUNTER = 2**53 - 1


class ArtifactFloorV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)
    kind: FloorKind
    generation: StrictInt
    digest: str

    @model_validator(mode="before")
    @classmethod
    def _exact(cls, value):
        if type(value) is dict and any(
            type(value.get(k)) is not t
            for k, t in (("kind", str), ("generation", int), ("digest", str))
        ):
            raise ValueError("inexact floor")
        return value

    @model_validator(mode="after")
    def _valid(self) -> ArtifactFloorV1:
        if not 0 <= self.generation <= MAX_COUNTER or DIGEST_RE.fullmatch(self.digest) is None:
            raise ValueError("invalid floor")
        return self
