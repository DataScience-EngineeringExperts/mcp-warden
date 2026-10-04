"""Recovered Task0 regressions: independent streams, floors, and latch ports."""

import pytest

from mcp_warden import evidence_state as state

D = "sha256:" + "a" * 64
E = "sha256:" + "b" * 64


def snapshot(**updates):
    values = dict(
        state_generation=1,
        state_digest=D,
        primary_sequence=2,
        primary_tail_digest=D,
        fallback_sequence=1,
        fallback_tail_digest=E,
        receipt_generation_floor=0,
        rule_generation_floor=0,
        override_generation_floor=0,
        mode=state.ProtectedStateModeV1.HEALTHY,
    )
    values.update(updates)
    return state.ProtectedStateSnapshotV1(**values)


def test_independent_stream_tails_are_valid():
    state.validate_snapshot(snapshot(), snapshot())


@pytest.mark.parametrize(
    "field", ["receipt_generation_floor", "rule_generation_floor", "override_generation_floor"]
)
def test_legacy_generation_floor_cannot_decrease(field):
    with pytest.raises(state.StateError, match="RCT-GENERATION-BELOW-FLOOR"):
        state.validate_snapshot(
            snapshot(fallback_tail_digest=D, **{field: 1}),
            snapshot(fallback_tail_digest=D, **{field: 2}),
        )


def test_all_artifact_floors_and_equal_generation_digest_integrity():
    floor = state.ArtifactFloorV1(kind="rule", generation=7, digest=D)
    s = snapshot(floors=(floor,))
    with pytest.raises(state.StateError, match="STATE-FLOOR-INTEGRITY"):
        state.validate_floor(s, kind="rule", generation=7, digest=E)
    with pytest.raises(state.StateError, match="STATE-FLOOR-ROLLBACK"):
        state.validate_floor(s, kind="rule", generation=6, digest=D)
    with pytest.raises(state.StateError, match="STATE-FLOOR-MISSING"):
        state.validate_floor(s, kind="policy", generation=7, digest=D)


def test_independent_latch_snapshot_and_closed_clear_contract():
    latch = state.RecoveryLatchSnapshotV1(generation=1, latched=True, event_digest=D)
    assert latch.latched
    assert hasattr(state.RecoveryLatchV1, "set")
    assert hasattr(state.RecoveryLatchV1, "authenticated_clear")
    assert not hasattr(state.RecoveryLatchV1, "clear")
