"""RED contracts for the protected evidence-state kernel."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_warden.evidence_state import (
    ProtectedStateModeV1,
    ProtectedStateSnapshotV1,
    StateError,
    validate_snapshot,
)


def _snapshot(**overrides: object) -> ProtectedStateSnapshotV1:
    values: dict[str, object] = {
        "state_generation": 3,
        "state_digest": "sha256:" + "a" * 64,
        "primary_sequence": 8,
        "primary_tail_digest": "sha256:" + "b" * 64,
        "fallback_sequence": 8,
        "fallback_tail_digest": "sha256:" + "b" * 64,
        "receipt_generation_floor": 2,
        "rule_generation_floor": 4,
        "override_generation_floor": 1,
        "mode": ProtectedStateModeV1.HEALTHY,
    }
    values.update(overrides)
    return ProtectedStateSnapshotV1(**values)


def test_snapshot_is_frozen_and_exact() -> None:
    snapshot = _snapshot()
    assert snapshot.primary_sequence == snapshot.fallback_sequence == 8
    assert snapshot.primary_tail_digest == snapshot.fallback_tail_digest
    with pytest.raises(ValidationError):
        snapshot.mode = ProtectedStateModeV1.EVIDENCE_DEGRADED  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ProtectedStateSnapshotV1(**{**snapshot.model_dump(), "unexpected": True})


@pytest.mark.parametrize(
    "mode",
    [
        ProtectedStateModeV1.HEALTHY,
        ProtectedStateModeV1.EVIDENCE_DEGRADED,
        ProtectedStateModeV1.RECOVERY_LATCHED,
        ProtectedStateModeV1.RECOVERY_EXIT_AUTHORIZED,
    ],
)
def test_all_protected_modes_are_closed(mode: ProtectedStateModeV1) -> None:
    assert _snapshot(mode=mode).mode is mode


@pytest.mark.parametrize(
    "changes, code",
    [
        ({"primary_sequence": 7}, "RCT-SEQUENCE-BACKWARD"),
        ({"fallback_sequence": 7}, "RCT-SEQUENCE-BACKWARD"),
        ({"state_generation": 2}, "RCT-GENERATION-BELOW-FLOOR"),
        ({"state_generation": 3, "state_digest": "sha256:" + "c" * 64}, "RCT-GENERATION-DIGEST"),
        ({"primary_tail_digest": "sha256:" + "c" * 64}, "RCT-TAIL-MISMATCH"),
    ],
)
def test_snapshot_validation_rejects_rollback_and_provider_errors(
    changes: dict[str, object], code: str
) -> None:
    with pytest.raises(StateError) as error:
        validate_snapshot(_snapshot(**changes), _snapshot())
    assert error.value.code == code


def test_snapshot_validation_rejects_non_snapshot_provider_value() -> None:
    with pytest.raises(StateError) as error:
        validate_snapshot(object(), _snapshot())  # type: ignore[arg-type]
    assert error.value.code == "RCT-STATE-MALFORMED"


def test_code_only_state_error_does_not_expose_provider_text() -> None:
    error = StateError("RCT-PROVIDER-UNAVAILABLE", provider_detail="secret path")
    assert str(error) == "RCT-PROVIDER-UNAVAILABLE"
    assert repr(error) == "RCT-PROVIDER-UNAVAILABLE"
