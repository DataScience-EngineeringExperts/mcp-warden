"""Independent latch snapshots with exact primitive and restart-state contracts."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, field_validator, model_validator

from mcp_warden.evidence_floor import DIGEST_RE, MAX_COUNTER


class RecoveryLatchSnapshotV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )
    generation: StrictInt
    latched: StrictBool
    event_digest: str | None = None
    cleared_generation: StrictInt | None = None
    cleared_event_digest: str | None = None
    exit_receipt_digest: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _exact_primitives(cls, value):
        if type(value) is dict:
            if type(value.get("generation")) is not int or type(value.get("latched")) is not bool:
                raise ValueError("invalid exact latch primitives")
            cleared = value.get("cleared_generation")
            if cleared is not None and type(cleared) is not int:
                raise ValueError("invalid exact cleared generation")
        return value

    @field_validator("event_digest", "cleared_event_digest", "exit_receipt_digest", mode="before")
    @classmethod
    def _exact_digest(cls, value):
        if value is not None and (type(value) is not str or DIGEST_RE.fullmatch(value) is None):
            raise ValueError("invalid latch digest")
        return value

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


def latch_is_valid(value: object) -> bool:
    """Revalidate original primitive types before any recovery-state comparison."""
    if type(value) is not RecoveryLatchSnapshotV1:
        return False
    valid = False
    try:
        storage = object.__getattribute__(value, "__dict__")
        if (
            type(storage) is dict
            and type(storage.get("generation")) is int
            and type(storage.get("latched")) is bool
        ):
            RecoveryLatchSnapshotV1.model_validate(value)
            valid = True
    except Exception:
        pass
    return valid
