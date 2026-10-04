"""Protected monotonic state contracts for DSE-717.

This module intentionally contains no persistence provider.  Providers implement
the protocols and must expose only code-only failures to policy code.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, field_validator, model_validator

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

    @model_validator(mode="after")
    def _valid(self) -> ArtifactFloorV1:
        if not 0 <= self.generation <= MAX_COUNTER or DIGEST_RE.fullmatch(self.digest) is None:
            raise ValueError("invalid floor")
        return self


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
    floors: tuple[ArtifactFloorV1, ...] = ()
    recovery_generation: StrictInt = 0
    prior_latch_event_digest: str | None = None
    recovery_exit_receipt_digest: str | None = None

    @field_validator("floors")
    @classmethod
    def _floors(cls, value: tuple[ArtifactFloorV1, ...]) -> tuple[ArtifactFloorV1, ...]:
        if any(type(f) is not ArtifactFloorV1 for f in value) or tuple(
            f.kind for f in value
        ) != tuple(sorted({f.kind for f in value})):
            raise ValueError("invalid floors")
        return value

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
            not 0 <= value <= MAX_COUNTER
            for value in (
                self.state_generation,
                self.primary_sequence,
                self.fallback_sequence,
                self.receipt_generation_floor,
                self.rule_generation_floor,
                self.override_generation_floor,
                self.recovery_generation,
            )
        ):
            raise ValueError("negative protected state")
        for digest in (self.prior_latch_event_digest, self.recovery_exit_receipt_digest):
            if digest is not None and DIGEST_RE.fullmatch(digest) is None:
                raise ValueError("invalid recovery digest")
        if self.mode is ProtectedStateModeV1.RECOVERY_EXIT_AUTHORIZED and (
            self.prior_latch_event_digest is None or self.recovery_exit_receipt_digest is None
        ):
            # Legacy snapshots are representable, but never operationally eligible.
            pass
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
    for stream in ("primary", "fallback"):
        if getattr(candidate, stream + "_sequence") == getattr(
            previous, stream + "_sequence"
        ) and getattr(candidate, stream + "_tail_digest") != getattr(
            previous, stream + "_tail_digest"
        ):
            _invalid("RCT-TAIL-MISMATCH")
    for field in (
        "receipt_generation_floor",
        "rule_generation_floor",
        "override_generation_floor",
        "recovery_generation",
    ):
        if getattr(candidate, field) < getattr(previous, field):
            _invalid("RCT-GENERATION-BELOW-FLOOR")
    current = {f.kind: f for f in candidate.floors}
    for old in previous.floors:
        if old.kind not in current:
            _invalid("STATE-FLOOR-MISSING")
        new = current[old.kind]
        validate_floor(previous, kind=new.kind, generation=new.generation, digest=new.digest)
    if (
        previous.mode is not ProtectedStateModeV1.HEALTHY
        and candidate.mode is ProtectedStateModeV1.HEALTHY
    ):
        if previous.mode is not ProtectedStateModeV1.RECOVERY_EXIT_AUTHORIZED:
            _invalid("STATE-RECOVERY-REQUIRED")


def validate_floor(
    snapshot: ProtectedStateSnapshotV1, *, kind: str, generation: int, digest: str
) -> None:
    if (
        type(snapshot) is not ProtectedStateSnapshotV1
        or kind not in FLOOR_KINDS
        or type(generation) is not int
        or not 0 <= generation <= MAX_COUNTER
        or type(digest) is not str
        or DIGEST_RE.fullmatch(digest) is None
    ):
        _invalid("RCT-STATE-MALFORMED")
    floor = next((f for f in snapshot.floors if f.kind == kind), None)
    if floor is None:
        _invalid("STATE-FLOOR-MISSING")
    if generation < floor.generation:
        _invalid("STATE-FLOOR-ROLLBACK")
    if generation == floor.generation and digest != floor.digest:
        _invalid("STATE-FLOOR-INTEGRITY")


class RecoveryLatchSnapshotV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)
    generation: StrictInt
    latched: StrictBool
    event_digest: str | None = None
    cleared_generation: StrictInt | None = None
    cleared_event_digest: str | None = None
    exit_receipt_digest: str | None = None

    @model_validator(mode="after")
    def _valid(self) -> RecoveryLatchSnapshotV1:
        if not 0 <= self.generation <= MAX_COUNTER:
            raise ValueError("invalid latch generation")
        for digest in (self.event_digest, self.cleared_event_digest, self.exit_receipt_digest):
            if digest is not None and DIGEST_RE.fullmatch(digest) is None:
                raise ValueError("invalid latch digest")
        if self.latched and self.event_digest is None:
            raise ValueError("missing event")
        if self.cleared_generation is not None and (
            type(self.cleared_generation) is not int
            or self.cleared_generation != self.generation
            or self.cleared_event_digest is None
            or self.exit_receipt_digest is None
            or self.latched
        ):
            raise ValueError("invalid clear tuple")
        return self


def operationally_healthy(state: ProtectedStateSnapshotV1, latch: RecoveryLatchSnapshotV1) -> bool:
    if (
        type(state) is not ProtectedStateSnapshotV1
        or type(latch) is not RecoveryLatchSnapshotV1
        or latch.latched
        or state.recovery_generation != latch.generation
    ):
        return False
    if state.mode is ProtectedStateModeV1.HEALTHY:
        return True
    return (
        state.mode is ProtectedStateModeV1.RECOVERY_EXIT_AUTHORIZED
        and latch.cleared_generation == state.recovery_generation
        and latch.cleared_event_digest == state.prior_latch_event_digest
        and latch.exit_receipt_digest == state.recovery_exit_receipt_digest
        and state.recovery_exit_receipt_digest is not None
    )


@runtime_checkable
class ProtectedStateV1(Protocol):
    def read(self) -> ProtectedStateSnapshotV1: ...

    def compare_and_advance(
        self, expected: ProtectedStateSnapshotV1, candidate: ProtectedStateSnapshotV1
    ) -> ProtectedStateSnapshotV1: ...


@runtime_checkable
class RecoveryLatchV1(Protocol):
    def read(self) -> RecoveryLatchSnapshotV1: ...

    def set(self, *, generation: int, event_digest: str) -> RecoveryLatchSnapshotV1: ...

    def authenticated_clear(
        self,
        *,
        generation: int,
        prior_event_digest: str,
        exit_receipt_digest: str,
        authorization: object,
    ) -> RecoveryLatchSnapshotV1: ...
