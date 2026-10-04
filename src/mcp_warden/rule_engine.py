"""Pure strengthening-only rule evaluation and isolated signed activation."""

from dataclasses import dataclass

from mcp_warden.evidence_state import validate_floor
from mcp_warden.receipt_kernel import ReceiptError, canonical, exact, receipt_digest
from mcp_warden.rule_models import RuleBundleV1, RuleConditionV1, RuleV1
from mcp_warden.signer_authorization import verify_authorized_artifact

PRECEDENCE = {"allow": 0, "deny": 1, "quarantine": 2}


def matches(condition: RuleConditionV1, fields: dict) -> bool:
    exact(condition, RuleConditionV1)
    value = fields.get(condition.field)
    if value is None:
        return False
    if condition.operator == "integer-range":
        return type(value) is int and condition.minimum <= value <= condition.maximum
    if condition.operator == "contains-taint":
        return type(value) is tuple and condition.value in value
    if type(value) is not str:
        return False
    if condition.operator == "equals":
        return value == condition.value
    if condition.operator == "not-equals":
        return value != condition.value
    return value in condition.value


def evaluate_rules(rules: tuple[RuleV1, ...], fields: dict, *, base_verdict: str) -> str:
    if type(rules) is not tuple or type(fields) is not dict or base_verdict not in PRECEDENCE:
        raise ReceiptError("RULE-BUNDLE-MALFORMED")
    verdict = base_verdict
    for rule in rules:
        exact(rule, RuleV1)
        results = tuple(matches(c, fields) for c in rule.group.conditions)
        matched = all(results) if rule.group.mode == "all" else any(results)
        if matched and PRECEDENCE[rule.effect] > PRECEDENCE[verdict]:
            verdict = rule.effect
    return verdict


_RULE_SEAL = object()


@dataclass(frozen=True, slots=True)
class ActivatedRuleBundleV1:
    bundle: RuleBundleV1
    digest: str
    authorization_digest: str
    _seal: object

    def __post_init__(self):
        if self._seal is not _RULE_SEAL:
            raise ReceiptError("RULE-BUNDLE-MALFORMED")


def activate_rule_bundle(
    bundle: RuleBundleV1,
    *,
    evidence,
    authorization,
    verifier,
    snapshot,
    now: int,
    policy_rule_digest: str,
) -> ActivatedRuleBundleV1:
    exact(bundle, RuleBundleV1)
    payload = canonical(bundle)
    digest = receipt_digest(payload, "rule")
    if digest != policy_rule_digest:
        raise ReceiptError("RULE-POLICY-MISMATCH")
    if type(now) is not int or not bundle.valid_from <= now < bundle.valid_until:
        raise ReceiptError("RCT-STALE")
    validate_floor(snapshot, kind="rule", generation=bundle.generation, digest=digest)
    verify_authorized_artifact(
        payload=payload,
        evidence=evidence,
        authorization=authorization,
        artifact_kind="rule",
        role="rule-publisher",
        verifier=verifier,
        snapshot=snapshot,
        now=now,
    )
    # Fixed negative corpus is mandatory and cannot be supplied/removed by a caller.
    for verdict in ("deny", "quarantine"):
        for reason in ("PDP-CRITICAL-TAINT", "PDP-LEASE-REVOKED", "PDP-POLICY-ROLLBACK"):
            effective = evaluate_rules(
                bundle.rules, {"base.verdict": verdict, "base.reason": reason}, base_verdict=verdict
            )
            if PRECEDENCE[effective] < PRECEDENCE[verdict]:
                raise ReceiptError("RULE-BUNDLE-MALFORMED")
    return ActivatedRuleBundleV1(bundle, digest, authorization.digest, _RULE_SEAL)


def check_rules(active, *, policy_rule_digest: str, snapshot, now: int):
    if type(active) is not ActivatedRuleBundleV1 or active._seal is not _RULE_SEAL:
        raise ReceiptError("RULE-BUNDLE-MALFORMED")
    exact(active.bundle, RuleBundleV1)
    if (
        receipt_digest(canonical(active.bundle), "rule") != active.digest
        or active.digest != policy_rule_digest
    ):
        raise ReceiptError("RULE-POLICY-MISMATCH")
    if not active.bundle.valid_from <= now < active.bundle.valid_until:
        raise ReceiptError("RCT-STALE")
    validate_floor(snapshot, kind="rule", generation=active.bundle.generation, digest=active.digest)
