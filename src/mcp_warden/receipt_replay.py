"""Pure historical reconstruction. Equality never authorizes a current effect."""

from dataclasses import dataclass
from typing import Literal

from pydantic import ConfigDict, model_validator

from mcp_warden.decision_governor import ActivatedOverrideV1, DecisionGovernorV1
from mcp_warden.decision_models import DecisionRequestV1
from mcp_warden.decision_receipts import serialize_unsigned_receipt
from mcp_warden.evidence_coordinator import receipt_from_context
from mcp_warden.evidence_models import create_evidence_context
from mcp_warden.evidence_state import (
    ProtectedStateSnapshotV1,
    _validate_exact_snapshot,
    validate_floor,
)
from mcp_warden.governed_decision import serialize_governed_decision
from mcp_warden.policy_decision import (
    ActivatedPolicyV1,
    ActivatedRuntimeV1,
    PolicyDecisionPointV1,
    _has_activation_marker,
)
from mcp_warden.policy_enforcement import EffectInputV1, create_effect_input
from mcp_warden.receipt_kernel import ReceiptError, ReceiptModel, canonical, exact, receipt_digest
from mcp_warden.receipt_models import ReceiptEventContextV1
from mcp_warden.rule_engine import ActivatedRuleBundleV1
from mcp_warden.signer_authorization import ActivatedSignerAuthorizationV1


class ReplayVectorV1(ReceiptModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        arbitrary_types_allowed=True,
    )
    schema_version: Literal[1] = 1
    request: DecisionRequestV1
    effect: EffectInputV1
    policy: ActivatedPolicyV1
    runtime: ActivatedRuntimeV1
    rules: ActivatedRuleBundleV1
    signer_authorization: ActivatedSignerAuthorizationV1
    snapshot: ProtectedStateSnapshotV1
    store_identity_digest: str
    signer_identity_digest: str
    event: ReceiptEventContextV1
    override: ActivatedOverrideV1 | None = None

    @model_validator(mode="after")
    def _complete(self):
        exact(self.request, DecisionRequestV1)
        exact(self.event, ReceiptEventContextV1)
        _validate_exact_snapshot(self.snapshot)
        if (
            type(self.effect) is not EffectInputV1
            or create_effect_input(self.effect.arguments) != self.effect
            or self.effect.arguments_digest != self.request.operation.arguments_digest
            or not _has_activation_marker(self.policy, ActivatedPolicyV1)
            or not _has_activation_marker(self.runtime, ActivatedRuntimeV1)
            or type(self.rules) is not ActivatedRuleBundleV1
            or type(self.signer_authorization) is not ActivatedSignerAuthorizationV1
            or self.override is not None
            and type(self.override) is not ActivatedOverrideV1
        ):
            raise ValueError("incomplete historical vector")
        return self


@dataclass(frozen=True, slots=True)
class ReplayReportV1:
    decision_bytes: bytes
    unsigned_receipt_bytes: bytes
    decision_matches: bool
    receipt_matches: bool
    authority_granted: Literal[False] = False


def replay_historical(vector, *, expected_decision_bytes: bytes, expected_receipt_bytes: bytes):
    exact(vector, ReplayVectorV1)
    if (
        type(expected_decision_bytes) is not bytes
        or type(expected_receipt_bytes) is not bytes
        or len(expected_decision_bytes) > 256 * 1024
        or len(expected_receipt_bytes) > 256 * 1024
    ):
        raise ReceiptError("RCT-MALFORMED")
    # Activated historical candidates carry raw models and exact activation
    # digests. No verifier/provider/activation function is called during replay.
    base = PolicyDecisionPointV1(vector.policy).evaluate(vector.request, runtime=vector.runtime)
    now = vector.runtime.runtime.trusted_time
    until = vector.runtime.runtime.trusted_time_valid_until
    time_digest = receipt_digest(
        canonical(
            {
                "runtime_digest": vector.runtime.runtime_digest,
                "trusted_time": now,
                "valid_until": until,
            }
        ),
        "time",
    )
    governor = DecisionGovernorV1(
        policy=vector.policy, rules=vector.rules, authorization=vector.signer_authorization
    )
    decision = governor.govern(
        base,
        request=vector.request,
        snapshot=vector.snapshot,
        now=now,
        trusted_time_digest=time_digest,
        override=vector.override,
    )
    context = create_evidence_context(
        decision=decision,
        effect_digest=vector.effect.arguments_digest,
        trusted_time=now,
        trusted_time_valid_until=until,
        signer_authorization_digest=vector.signer_authorization.digest,
        event=vector.event,
    )
    receipt = receipt_from_context(
        context,
        state=vector.snapshot,
        store_identity_digest=vector.store_identity_digest,
        authorization=vector.signer_authorization,
        signer_identity_digest=vector.signer_identity_digest,
        event=vector.event,
    )
    dbytes = serialize_governed_decision(decision)
    rbytes = serialize_unsigned_receipt(receipt)
    return ReplayReportV1(
        dbytes, rbytes, dbytes == expected_decision_bytes, rbytes == expected_receipt_bytes
    )


def current_eligibility(vector, *, snapshot: ProtectedStateSnapshotV1):
    exact(vector, ReplayVectorV1)
    _validate_exact_snapshot(snapshot)
    compatible = True
    try:
        for kind, generation, digest in (
            ("policy", vector.policy.policy.policy_generation, vector.policy.policy_digest),
            ("rule", vector.rules.bundle.generation, vector.rules.digest),
            (
                "signer-authorization",
                vector.signer_authorization.bundle.generation,
                vector.signer_authorization.digest,
            ),
            (
                "trust-root",
                vector.signer_authorization.trust_root_generation,
                vector.signer_authorization.bundle.trust_root_digest,
            ),
            (
                "revocation",
                vector.policy.policy.revocation_generation,
                vector.policy.revocation_digest,
            ),
        ):
            validate_floor(snapshot, kind=kind, generation=generation, digest=digest)
        compatible = (
            snapshot.mode.value == "healthy"
            and snapshot.recovery_generation == vector.snapshot.recovery_generation
        )
    except Exception:
        compatible = False
    return "eligible-foundation" if compatible else "recovery-only"
