import pytest

from mcp_warden.receipt_kernel import ReceiptError
from mcp_warden.rule_engine import evaluate_rules
from mcp_warden.rule_models import RuleConditionV1, RuleGroupV1, RuleV1


@pytest.mark.parametrize(
    "values",
    [
        dict(field="trusted_time", operator="equals", value=1),
        dict(field="trusted_time", operator="integer-range", minimum=True, maximum=2),
        dict(field="base.verdict", operator="in", value=()),
        dict(field="base.verdict", operator="in", value=("deny", "allow")),
        dict(field="unknown", operator="equals", value="allow"),
        dict(field="base.verdict", operator="equals", value="invented"),
    ],
)
def test_closed_condition_grammar(values):
    with pytest.raises(ReceiptError):
        RuleConditionV1(**values)


def test_empty_duplicate_groups_and_allow_effect_are_rejected():
    c = RuleConditionV1(field="base.verdict", operator="equals", value="allow")
    for conditions in [(), (c, c)]:
        with pytest.raises(ReceiptError):
            RuleGroupV1(mode="all", conditions=conditions)
    with pytest.raises(ReceiptError):
        RuleV1(rule_id="a", group=RuleGroupV1(mode="all", conditions=(c,)), effect="allow")


def test_all_matching_effects_strengthen_with_fixed_precedence():
    c = RuleConditionV1(field="base.verdict", operator="equals", value="allow")
    g = RuleGroupV1(mode="all", conditions=(c,))
    rules = (
        RuleV1(rule_id="a", group=g, effect="deny"),
        RuleV1(rule_id="b", group=g, effect="quarantine"),
    )
    assert evaluate_rules(rules, {"base.verdict": "allow"}, base_verdict="allow") == "quarantine"
    assert (
        evaluate_rules(rules[::-1], {"base.verdict": "allow"}, base_verdict="deny") == "quarantine"
    )
    assert evaluate_rules((), {}, base_verdict="deny") == "deny"


def test_signed_rules_activation_and_policy_binding():
    from mcp_warden.receipt_kernel import canonical, receipt_digest
    from mcp_warden.rule_engine import activate_rule_bundle
    from mcp_warden.rule_models import RuleBundleV1
    from tests.receipt_fixtures import authority

    auth, verifier, signer, state = authority()
    bundle = RuleBundleV1(generation=1, valid_from=0, valid_until=1000, rules=())
    digest = receipt_digest(canonical(bundle), "rule")
    evidence = signer.sign(
        payload=canonical(bundle),
        artifact_kind="rule",
        role="rule-publisher",
        authorization_digest=auth.digest,
    )
    assert (
        activate_rule_bundle(
            bundle,
            evidence=evidence,
            authorization=auth,
            verifier=verifier,
            snapshot=state,
            now=10,
            policy_rule_digest=digest,
        ).digest
        == digest
    )
    with pytest.raises(ReceiptError, match="RULE-POLICY-MISMATCH"):
        activate_rule_bundle(
            bundle,
            evidence=evidence,
            authorization=auth,
            verifier=verifier,
            snapshot=state,
            now=10,
            policy_rule_digest="sha256:" + "f" * 64,
        )


def test_governed_decision_is_self_integrity_checked():
    from mcp_warden.governed_decision import create_governed_decision, serialize_governed_decision
    from mcp_warden.receipt_kernel import ZERO_DIGEST

    decision = create_governed_decision(
        request_digest=ZERO_DIGEST,
        base_decision_digest=None,
        effective_verdict="deny",
        public_reason="PEP-EVIDENCE-UNAVAILABLE",
        recovery_code="recovery-only",
        policy_digest=ZERO_DIGEST,
        policy_generation=0,
        runtime_digest=ZERO_DIGEST,
        rule_digest=ZERO_DIGEST,
        rule_generation=0,
        revocation_digest=ZERO_DIGEST,
        revocation_generation=0,
        adapter_digest=ZERO_DIGEST,
        bundle_digest=None,
        envelope_digest=ZERO_DIGEST,
    )
    with pytest.raises(ReceiptError, match="RCT-INTEGRITY"):
        serialize_governed_decision(decision.model_copy(update={"effective_verdict": "allow"}))
