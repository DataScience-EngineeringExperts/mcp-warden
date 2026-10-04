"""Council regressions for mandatory V2 floors and legacy snapshot compatibility."""

import pytest

from mcp_warden.evidence_floor import FLOOR_KINDS
from mcp_warden.evidence_reference import InMemoryProtectedStateV1
from mcp_warden.policy_enforcement import ActivatedAdapterV1
from tests.receipt_fixtures import pep_fixture


@pytest.mark.parametrize("missing", [kind for kind in FLOOR_KINDS if kind != "override"])
def test_v2_missing_mandatory_floor_blocks_before_handler_or_primary_permit(monkeypatch, missing):
    pep, request, runtime, effect, p = pep_fixture()
    state = p["state"].read()
    p["state"] = InMemoryProtectedStateV1(
        state.model_copy(update={"floors": tuple(f for f in state.floors if f.kind != missing)})
    )
    pep._coordinator.protected_state = p["state"]
    selections = []
    monkeypatch.setattr(ActivatedAdapterV1, "_handler", lambda *args: selections.append(args))
    result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert not result.invoked and not selections
    assert "evidence" in trace.events and not p["primary"].payloads
    assert result.decision.effective_verdict == "deny"
    assert result.decision.public_reason == "PEP-RECOVERY-ONLY"
    assert result.evidence.mode in {"recovery-latched", "unavailable"}
    assert p["latch"].read().latched


def test_override_floor_is_optional_without_override_and_legacy_empty_floors_remain_valid():
    from mcp_warden.evidence_reference import advance_state
    from mcp_warden.evidence_state import validate_snapshot
    from tests.receipt_fixtures import authority

    _, _, _, legacy = authority()
    legacy = legacy.model_copy(update={"floors": ()})
    newer = advance_state(legacy)
    validate_snapshot(newer, legacy)
    assert newer.floors == ()
    pep, request, runtime, effect, p = pep_fixture()
    state = p["state"].read()
    without_override = state.model_copy(
        update={"floors": tuple(f for f in state.floors if f.kind != "override")}
    )
    p["state"] = InMemoryProtectedStateV1(without_override)
    pep._coordinator.protected_state = p["state"]
    assert pep.execute(request, runtime=runtime, effect=effect).invoked


def test_override_floor_required_when_context_carries_override():
    from mcp_warden.evidence_models import create_evidence_context
    from mcp_warden.governed_decision import create_governed_decision
    from mcp_warden.receipt_kernel import ZERO_DIGEST
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    state = p["state"].read()
    p["state"] = InMemoryProtectedStateV1(
        state.model_copy(update={"floors": tuple(f for f in state.floors if f.kind != "override")})
    )
    c.protected_state = p["state"]
    values = context.decision.model_dump(exclude={"decision_digest"})
    values.update(public_reason="RULE-OVERRIDE", override_digest=ZERO_DIGEST, override_generation=1)
    from mcp_warden.receipt_models import ReceiptEventContextV1

    event = ReceiptEventContextV1(
        kind="override",
        actor_digest=ZERO_DIGEST,
        scope_digest=ZERO_DIGEST,
        authority_digest=ZERO_DIGEST,
        expires_at=20,
    )
    override_context = create_evidence_context(
        decision=create_governed_decision(**values),
        effect_digest=context.effect_digest,
        trusted_time=10,
        trusted_time_valid_until=20,
        signer_authorization_digest=c.authorization.digest,
        event=event,
    )
    result = c.record_decision(override_context)
    assert result.mode == "unavailable" and not p["primary"].payloads
