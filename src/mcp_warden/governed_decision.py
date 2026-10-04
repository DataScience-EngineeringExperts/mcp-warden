"""Closed public reason registry for governed enforcement decisions."""

from typing import Literal

from pydantic import StrictInt, model_validator

from mcp_warden.decision_models import DecisionReasonV1, DecisionRecoveryV1
from mcp_warden.policy_enforcement import EnforcementCodeV1
from mcp_warden.receipt_kernel import (
    ZERO_DIGEST,
    ReceiptError,
    ReceiptModel,
    canonical,
    exact,
    receipt_digest,
)

PUBLIC_REASONS = (
    frozenset(r.value for r in DecisionReasonV1)
    | frozenset(r.value for r in EnforcementCodeV1)
    | {
        "RULE-BLOCKED",
        "RULE-QUARANTINED",
        "RULE-OVERRIDE",
        "PEP-REQUEST-MALFORMED",
        "PEP-RECOVERY-ONLY",
    }
)
RECOVERY_CODES = frozenset(r.value for r in DecisionRecoveryV1)


class EnforcementDecisionV2(ReceiptModel):
    schema_version: Literal[2] = 2
    request_digest: str
    base_decision_digest: str | None
    effective_verdict: Literal["allow", "deny", "quarantine"]
    public_reason: str
    recovery_code: str
    policy_digest: str
    policy_generation: StrictInt
    runtime_digest: str
    rule_digest: str
    rule_generation: StrictInt
    revocation_digest: str
    revocation_generation: StrictInt
    adapter_digest: str
    bundle_digest: str | None
    envelope_digest: str
    override_digest: str | None = None
    converted_from_decision_digest: str | None = None
    decision_digest: str

    @model_validator(mode="after")
    def _codes(self):
        if self.public_reason not in PUBLIC_REASONS or self.recovery_code not in RECOVERY_CODES:
            raise ValueError("closed code")
        if self.override_digest is not None and (
            self.effective_verdict != "allow" or self.public_reason != "RULE-OVERRIDE"
        ):
            raise ValueError("override binding")
        if self.converted_from_decision_digest is not None and (
            self.effective_verdict != "deny" or self.public_reason != "PEP-EVIDENCE-UNAVAILABLE"
        ):
            raise ValueError("conversion binding")
        return self


def create_governed_decision(**values) -> EnforcementDecisionV2:
    draft = EnforcementDecisionV2(**values, decision_digest=ZERO_DIGEST)
    body = draft.model_dump(mode="json", exclude={"decision_digest"})
    return draft.model_copy(
        update={"decision_digest": receipt_digest(canonical(body), "governed-decision")}
    )


def serialize_governed_decision(decision: EnforcementDecisionV2) -> bytes:
    exact(decision, EnforcementDecisionV2)
    body = decision.model_dump(mode="json", exclude={"decision_digest"})
    if receipt_digest(canonical(body), "governed-decision") != decision.decision_digest:
        raise ReceiptError("RCT-INTEGRITY")
    return canonical(decision)


def convert_failed_allow(decision: EnforcementDecisionV2) -> EnforcementDecisionV2:
    serialize_governed_decision(decision)
    if decision.effective_verdict != "allow":
        raise ReceiptError("RCT-MALFORMED")
    values = decision.model_dump(exclude={"decision_digest"})
    values.update(
        effective_verdict="deny",
        public_reason="PEP-EVIDENCE-UNAVAILABLE",
        recovery_code="recovery-only",
        override_digest=None,
        converted_from_decision_digest=decision.decision_digest,
    )
    return create_governed_decision(**values)
