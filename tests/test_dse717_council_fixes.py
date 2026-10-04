"""Council-confirmed defensive regressions using deterministic trusted test ports."""

import pytest

from mcp_warden.content_models import TaintV1
from mcp_warden.evidence_floor import FLOOR_KINDS
from mcp_warden.evidence_reference import InMemoryProtectedStateV1
from mcp_warden.policy_decision import (
    compute_request_binding_digest,
    create_capability_lease,
    create_decision_request,
)
from mcp_warden.policy_enforcement import ActivatedAdapterV1
from mcp_warden.receipt_verification import parse_signed_receipt
from tests.receipt_fixtures import pep_fixture
from tests.test_policy_decision import _envelope


@pytest.mark.parametrize("grant,critical", [(True, True), (False, False), (True, False)])
def test_invalid_override_preserves_critical_quarantine_and_rejects_input(
    monkeypatch, grant, critical
):
    pep, request, runtime, effect, p = pep_fixture(grant=grant)
    if critical:
        envelope = _envelope(taints=(TaintV1.CRITICAL,))
        binding = compute_request_binding_digest(
            identity=request.identity,
            operation=request.operation,
            envelope=envelope,
            data_scope_digest=request.data_scope_digest,
            purpose_digest=request.purpose_digest,
        )
        lease = create_capability_lease(
            **(
                request.lease.model_dump(exclude={"schema_version", "lease_digest"})
                | {"request_binding_digest": binding}
            )
        )
        request = create_decision_request(
            identity=request.identity,
            operation=request.operation,
            envelope=envelope,
            data_scope_digest=request.data_scope_digest,
            purpose_digest=request.purpose_digest,
            lease=lease,
        )
    base = pep._pdp.evaluate(request, runtime=runtime)
    assert base.verdict == ("quarantine" if critical else "allow" if grant else "deny")
    selections = []
    monkeypatch.setattr(ActivatedAdapterV1, "_handler", lambda *args: selections.append(args))
    result, trace = pep._execute_instrumented(
        request, runtime=runtime, effect=effect, override=object()
    )
    assert not result.invoked and not selections and "evidence" in trace.events
    assert result.decision.effective_verdict == ("quarantine" if critical else "deny")
    assert result.decision.public_reason == (base.reason if critical else "RULE-OVERRIDE-INVALID")
    assert result.decision.recovery_code == base.recovery
    assert result.evidence.mode == "primary-durable"
    signed = parse_signed_receipt(p["primary"].payloads[0])
    assert signed.receipt.effective_verdict == result.decision.effective_verdict
    assert signed.receipt.public_reason == result.decision.public_reason


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
