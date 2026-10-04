"""Strict, signature-free PEP V2 output with closed outcome and binding checks."""

from typing import Literal

from pydantic import StrictBool, model_validator

from mcp_warden.content_envelope import to_public_bytes
from mcp_warden.content_models import ContentEnvelopeV1
from mcp_warden.evidence_models import DecisionEvidenceResultV1
from mcp_warden.governed_decision import (
    PUBLIC_REASONS,
    EnforcementDecisionV2,
    serialize_governed_decision,
)
from mcp_warden.receipt_kernel import (
    ZERO_DIGEST,
    ReceiptError,
    ReceiptModel,
    canonical,
    exact,
    receipt_digest,
)


class EnforcementResultV2(ReceiptModel):
    schema_version: Literal[2] = 2
    decision: EnforcementDecisionV2
    evidence: DecisionEvidenceResultV1
    invoked: StrictBool
    outcome: Literal["blocked", "completed", "indeterminate"]
    code: str
    output: ContentEnvelopeV1 | None = None
    result_digest: str

    @model_validator(mode="after")
    def _validate_result(self):
        serialize_governed_decision(self.decision)
        exact(self.evidence, DecisionEvidenceResultV1)
        e = self.evidence
        d = self.decision
        if (
            self.code not in PUBLIC_REASONS
            or (self.outcome == "blocked") == self.invoked
            or e.decision_digest != d.decision_digest
            or e.request_digest != d.request_digest
            or e.policy_digest != d.policy_digest
            or e.runtime_digest != d.runtime_digest
            or e.rule_digest != d.rule_digest
            or e.adapter_digest != d.adapter_digest
            or e.bundle_digest != d.bundle_digest
        ):
            raise ValueError("result binding")
        if (
            receipt_digest(
                canonical(e.model_dump(mode="json", exclude={"result_digest"})), "evidence-result"
            )
            != e.result_digest
        ):
            raise ValueError("evidence integrity")
        if self.invoked:
            if (
                d.effective_verdict != "allow"
                or e.mode != "primary-durable"
                or e.recovery_mode != "healthy"
                or e.failure_code is not None
            ):
                raise ValueError("invoked without permit evidence")
        elif d.effective_verdict == "allow":
            raise ValueError("blocked without deny conversion")
        if self.output is not None:
            exact(self.output, ContentEnvelopeV1)
            if self.outcome != "completed":
                raise ValueError("indeterminate output")
            to_public_bytes(self.output)
        return self


def _body(result):
    return {
        "schema_version": 2,
        "decision": result.decision.model_dump(mode="json"),
        "evidence": result.evidence.model_dump(mode="json"),
        "invoked": result.invoked,
        "outcome": result.outcome,
        "code": result.code,
        "output_envelope_digest": None if result.output is None else result.output.envelope_digest,
    }


def make_enforcement_result_v2(decision, evidence, invoked, outcome, code, output=None):
    draft = EnforcementResultV2(
        decision=decision,
        evidence=evidence,
        invoked=invoked,
        outcome=outcome,
        code=code,
        output=output,
        result_digest=ZERO_DIGEST,
    )
    return draft.model_copy(
        update={"result_digest": receipt_digest(canonical(_body(draft)), "evidence-result")}
    )


def serialize_enforcement_result_v2(result):
    exact(result, EnforcementResultV2)
    body = _body(result)
    if receipt_digest(canonical(body), "evidence-result") != result.result_digest:
        raise ReceiptError("RCT-INTEGRITY")
    return canonical(body | {"result_digest": result.result_digest})
