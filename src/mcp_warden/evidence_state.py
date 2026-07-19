"""Protected monotonic state contracts for DSE-717.

This module intentionally contains no persistence provider.  Providers implement
the protocols and must expose only code-only failures to policy code.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, StrictInt, field_validator, model_validator

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class StateError(Exception):
    """Stable, code-only protected-state failure."""

    def __init__(self, code: str, *, provider_detail: str | None = None) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code

    def __repr__(self) -> str:
        return self.code


class ProtectedStateModeV1(StrEnum):
    HEALTHY = "healthy"
    EVIDENCE_DEGRADED = "evidence-degraded"
    RECOVERY_LATCHED = "recovery-latched"
    RECOVERY_EXIT_AUTHORIZED = "recovery-exit-authorized"


class ProtectedStateSnapshotV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    state_generation: StrictInt
    state_digest: str
    primary_sequence: StrictInt
    primary_tail_digest: str
    fallback_sequence: StrictInt
    fallback_tail_digest: str
    receipt_generation_floor: StrictInt
    rule_generation_floor: StrictInt
    override_generation_floor: StrictInt
    mode: ProtectedStateModeV1

    @field_validator(
        "state_digest",
        "primary_tail_digest",
        "fallback_tail_digest",
        mode="before",
    )
    @classmethod
    def _digest(cls, value: object) -> str:
        if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
            raise ValueError("invalid digest")
        return value

    @model_validator(mode="after")
    def _nonnegative(self) -> ProtectedStateSnapshotV1:
        if any(
            value < 0
            for value in (
                self.state_generation,
                self.primary_sequence,
                self.fallback_sequence,
                self.receipt_generation_floor,
                self.rule_generation_floor,
                self.override_generation_floor,
            )
        ):
            raise ValueError("negative protected state")
        return self


def _invalid(code: str) -> None:
    raise StateError(code)


def validate_snapshot(
    candidate: ProtectedStateSnapshotV1,
    previous: ProtectedStateSnapshotV1,
) -> None:
    """Validate a candidate against the last protected snapshot."""
    if (
        type(candidate) is not ProtectedStateSnapshotV1
        or type(previous) is not ProtectedStateSnapshotV1
    ):
        _invalid("RCT-STATE-MALFORMED")
    if (
        candidate.primary_sequence < previous.primary_sequence
        or candidate.fallback_sequence < previous.fallback_sequence
    ):
        _invalid("RCT-SEQUENCE-BACKWARD")
    if candidate.state_generation < previous.state_generation:
        _invalid("RCT-GENERATION-BELOW-FLOOR")
    if (
        candidate.state_generation == previous.state_generation
        and candidate.state_digest != previous.state_digest
    ):
        _invalid("RCT-GENERATION-DIGEST")
    if candidate.primary_tail_digest != candidate.fallback_tail_digest:
        _invalid("RCT-TAIL-MISMATCH")


@runtime_checkable
class ProtectedStateV1(Protocol):
    def read(self) -> ProtectedStateSnapshotV1: ...

    def compare_and_advance(
        self, expected: ProtectedStateSnapshotV1, candidate: ProtectedStateSnapshotV1
    ) -> ProtectedStateSnapshotV1: ...


@runtime_checkable
class RecoveryLatchV1(Protocol):
    def read(self) -> ProtectedStateSnapshotV1: ...

    def clear(self, expected: ProtectedStateSnapshotV1) -> None: ...
