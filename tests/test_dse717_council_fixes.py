"""Council regressions for quarantine precedence and closed rejection codes."""

import pytest

from mcp_warden.content_models import TaintV1
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


def test_unknown_governor_exception_is_closed_and_authority_failure_is_not_recovery(monkeypatch):
    from mcp_warden.decision_governor import DecisionGovernorV1
    from mcp_warden.receipt_kernel import ReceiptError

    for error, expected in (
        (ValueError("secret provider path"), "RCT-INTERNAL-ERROR"),
        (ReceiptError("RCT-SIGNER-UNAUTHORIZED"), "RCT-SIGNER-UNAUTHORIZED"),
        (ReceiptError("RCT-RECOVERY-ONLY"), "PEP-RECOVERY-ONLY"),
    ):
        pep, request, runtime, effect, _ = pep_fixture()

        def fail(*args, failure=error, **kwargs):
            raise failure

        monkeypatch.setattr(DecisionGovernorV1, "govern", fail)
        result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
        assert not result.invoked
        assert result.decision.public_reason == expected
        assert b"secret" not in b"".join(trace.output_channels)
        assert "evidence" in trace.events


def test_invalid_override_preserves_signed_rule_strengthening_to_quarantine():
    from mcp_warden.decision_governor import DecisionGovernorV1
    from mcp_warden.decision_models import (
        SignedPolicyCandidateV1,
        SignedRuntimeCandidateV1,
        VerificationAlgorithmV1,
    )
    from mcp_warden.policy_decision import PolicyDecisionPointV1, activate_policy, activate_runtime
    from mcp_warden.policy_enforcement_v2 import PolicyEnforcementPointV2
    from mcp_warden.receipt_kernel import ZERO_DIGEST, canonical, receipt_digest
    from mcp_warden.rule_engine import activate_rule_bundle
    from mcp_warden.rule_models import RuleBundleV1, RuleConditionV1, RuleGroupV1, RuleV1
    from tests.test_policy_enforcement import Verifier, _activated_adapter, _noop_handler

    pep, request, runtime, effect, p = pep_fixture()
    c = pep._coordinator
    bundle = RuleBundleV1(
        generation=2,
        valid_from=0,
        valid_until=1000,
        rules=(
            RuleV1(
                rule_id="quarantine-rule",
                effect="quarantine",
                group=RuleGroupV1(
                    mode="all",
                    conditions=(
                        RuleConditionV1(field="base.verdict", operator="equals", value="allow"),
                    ),
                ),
            ),
        ),
    )
    rule_digest = receipt_digest(canonical(bundle), "rule")
    policy = activate_policy(
        SignedPolicyCandidateV1(
            policy=pep._governor.policy.policy.model_copy(update={"rule_set_digest": rule_digest}),
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=ZERO_DIGEST,
            signature=b"valid-signature",
        ),
        verifier=Verifier(),
    )
    runtime = activate_runtime(
        SignedRuntimeCandidateV1(
            runtime=runtime.runtime.model_copy(
                update={
                    "policy_digest_at_floor": policy.policy_digest,
                    "revocation_digest_at_floor": policy.revocation_digest,
                }
            ),
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=ZERO_DIGEST,
            signature=b"valid-signature",
        ),
        verifier=Verifier(),
    )
    state = p["state"].read()
    updates = {
        "policy": (policy.policy.policy_generation, policy.policy_digest),
        "rule": (bundle.generation, rule_digest),
    }
    from mcp_warden.evidence_floor import ArtifactFloorV1

    floors = tuple(
        ArtifactFloorV1(kind=f.kind, generation=updates[f.kind][0], digest=updates[f.kind][1])
        if f.kind in updates
        else f
        for f in state.floors
    )
    p["state"] = InMemoryProtectedStateV1(state.model_copy(update={"floors": floors}))
    c.protected_state = p["state"]
    rules = activate_rule_bundle(
        bundle,
        evidence=c.signer.sign(
            payload=canonical(bundle),
            artifact_kind="rule",
            role="rule-publisher",
            authorization_digest=c.authorization.digest,
        ),
        authorization=c.authorization,
        verifier=c.verifier,
        snapshot=p["state"].read(),
        now=200,
        policy_rule_digest=rule_digest,
    )
    governor = DecisionGovernorV1(policy=policy, rules=rules, authorization=c.authorization)
    adapter, _, _ = _activated_adapter(policy, _noop_handler)
    pep = PolicyEnforcementPointV2(
        PolicyDecisionPointV1(policy), adapter, governor=governor, coordinator=c
    )
    assert pep._pdp.evaluate(request, runtime=runtime).verdict == "allow"
    result = pep.execute(request, runtime=runtime, effect=effect, override=object())
    assert not result.invoked and result.decision.effective_verdict == "quarantine"
    assert result.decision.public_reason == "RULE-QUARANTINED"
    assert result.evidence.mode == "primary-durable"
    assert (
        parse_signed_receipt(p["primary"].payloads[0]).receipt.public_reason == "RULE-QUARANTINED"
    )
