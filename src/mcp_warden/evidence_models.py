"""Exact context/result bindings for evidence-before-effect coordination."""

from typing import Literal

from pydantic import StrictInt, model_validator

from mcp_warden.governed_decision import EnforcementDecisionV2, serialize_governed_decision
from mcp_warden.receipt_kernel import (
    ZERO_DIGEST,
    ReceiptError,
    ReceiptModel,
    canonical,
    exact,
    receipt_digest,
)


class EvidenceContextV1(ReceiptModel):
    schema_version: Literal[1] = 1
    decision: EnforcementDecisionV2
    effect_digest: str
    trusted_time: StrictInt
    trusted_time_valid_until: StrictInt
    trusted_time_digest: str
    signer_authorization_digest: str
    context_digest: str

    @model_validator(mode="after")
    def _binding(self):
        serialize_governed_decision(self.decision)
        if not self.trusted_time < self.trusted_time_valid_until:
            raise ValueError("stale trusted time")
        expected = receipt_digest(
            canonical(
                {
                    "runtime_digest": self.decision.runtime_digest,
                    "trusted_time": self.trusted_time,
                    "valid_until": self.trusted_time_valid_until,
                }
            ),
            "time",
        )
        if self.trusted_time_digest != expected:
            raise ValueError("time binding")
        return self


def create_evidence_context(
    *,
    decision,
    effect_digest: str,
    trusted_time: int,
    trusted_time_valid_until: int,
    signer_authorization_digest: str,
):
    time_digest = receipt_digest(
        canonical(
            {
                "runtime_digest": decision.runtime_digest,
                "trusted_time": trusted_time,
                "valid_until": trusted_time_valid_until,
            }
        ),
        "time",
    )
    draft = EvidenceContextV1(
        decision=decision,
        effect_digest=effect_digest,
        trusted_time=trusted_time,
        trusted_time_valid_until=trusted_time_valid_until,
        trusted_time_digest=time_digest,
        signer_authorization_digest=signer_authorization_digest,
        context_digest=ZERO_DIGEST,
    )
    return draft.model_copy(
        update={
            "context_digest": receipt_digest(
                canonical(draft.model_dump(mode="json", exclude={"context_digest"})), "context"
            )
        }
    )


def validate_context(context):
    exact(context, EvidenceContextV1)
    if (
        receipt_digest(
            canonical(context.model_dump(mode="json", exclude={"context_digest"})), "context"
        )
        != context.context_digest
    ):
        raise ReceiptError("RCT-INTEGRITY")


class DecisionEvidenceResultV1(ReceiptModel):
    schema_version: Literal[1] = 1
    context_digest: str
    decision_digest: str
    request_digest: str
    policy_digest: str
    runtime_digest: str
    rule_digest: str
    adapter_digest: str
    bundle_digest: str | None
    signer_authorization_digest: str
    mode: Literal["primary-durable", "fallback-durable", "recovery-latched", "unavailable"]
    evidence_digest: str | None
    sequence: StrictInt
    store_identity_digest: str
    recovery_generation: StrictInt
    recovery_mode: Literal[
        "healthy", "evidence-degraded", "recovery-latched", "recovery-exit-authorized"
    ]
    failure_code: str | None
    protection_status: Literal["unsupported"] = "unsupported"
    result_digest: str

    @model_validator(mode="after")
    def _code(self):
        from mcp_warden.receipt_kernel import ERROR_CODES

        if self.failure_code is not None and self.failure_code not in ERROR_CODES:
            raise ValueError("closed code")
        if self.mode in {"primary-durable", "fallback-durable"} and (
            self.evidence_digest is None or self.sequence < 1
        ):
            raise ValueError("missing durable evidence")
        return self


def create_evidence_result(
    context,
    *,
    mode,
    evidence_digest=None,
    sequence=0,
    store_identity_digest=ZERO_DIGEST,
    recovery_generation=0,
    recovery_mode="healthy",
    failure_code=None,
):
    validate_context(context)
    d = context.decision
    draft = DecisionEvidenceResultV1(
        context_digest=context.context_digest,
        decision_digest=d.decision_digest,
        request_digest=d.request_digest,
        policy_digest=d.policy_digest,
        runtime_digest=d.runtime_digest,
        rule_digest=d.rule_digest,
        adapter_digest=d.adapter_digest,
        bundle_digest=d.bundle_digest,
        signer_authorization_digest=context.signer_authorization_digest,
        mode=mode,
        evidence_digest=evidence_digest,
        sequence=sequence,
        store_identity_digest=store_identity_digest,
        recovery_generation=recovery_generation,
        recovery_mode=recovery_mode,
        failure_code=failure_code,
        result_digest=ZERO_DIGEST,
    )
    return draft.model_copy(
        update={
            "result_digest": receipt_digest(
                canonical(draft.model_dump(mode="json", exclude={"result_digest"})),
                "evidence-result",
            )
        }
    )


def validate_evidence_result(result, context, *, primary_identity=None):
    validate_context(context)
    exact(result, DecisionEvidenceResultV1)
    expected = create_evidence_result(
        context,
        mode=result.mode,
        evidence_digest=result.evidence_digest,
        sequence=result.sequence,
        store_identity_digest=result.store_identity_digest,
        recovery_generation=result.recovery_generation,
        recovery_mode=result.recovery_mode,
        failure_code=result.failure_code,
    )
    if result != expected:
        raise ReceiptError("RCT-INTEGRITY")
    return (
        result.mode == "primary-durable"
        and result.recovery_mode == "healthy"
        and result.failure_code is None
        and result.evidence_digest is not None
        and (primary_identity is None or result.store_identity_digest == primary_identity)
    )


class FallbackEventV1(ReceiptModel):
    schema_version: Literal[1] = 1
    sequence: StrictInt
    failed_receipt_digest: str
    failure_code: Literal[
        "RCT-PROVIDER-UNAVAILABLE",
        "RCT-TAIL-MISMATCH",
        "RCT-STATE-COMMIT",
        "RCT-SIGNATURE-INVALID",
        "RCT-RECOVERY-ONLY",
        "RCT-INTEGRITY",
    ]
    trusted_time_digest: str
    previous_entry_digest: str
    recovery_generation: StrictInt
