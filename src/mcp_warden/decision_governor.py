"""Closed governor combining base authority, strengthening rules and finite overrides."""

from dataclasses import dataclass
from typing import Literal

from pydantic import StrictInt, model_validator

from mcp_warden.decision_models import DecisionRequestV1, DecisionV1
from mcp_warden.evidence_state import validate_floor
from mcp_warden.governed_decision import create_governed_decision
from mcp_warden.policy_decision import ActivatedPolicyV1, serialize_decision
from mcp_warden.receipt_kernel import ReceiptError, ReceiptModel, canonical, exact, receipt_digest
from mcp_warden.rule_engine import check_rules, evaluate_rules
from mcp_warden.signer_authorization import check_authorization, verify_authorized_artifact

# Deliberately narrow noncritical registry. Every unlisted deny remains critical.
NONCRITICAL_OVERRIDE_REASONS = frozenset({"PDP-DENY-DEFAULT"})


class OverrideAuthorizationV1(ReceiptModel):
    schema_version: Literal[1] = 1
    generation: StrictInt
    request_digest: str
    base_decision_digest: str
    policy_digest: str
    policy_generation: StrictInt
    rule_digest: str
    rule_generation: StrictInt
    actor_digest: str
    scope_digest: str
    reason: Literal["PDP-DENY-DEFAULT"]
    not_before: StrictInt
    expires_at: StrictInt
    trusted_time_digest: str

    @model_validator(mode="after")
    def _finite(self):
        if not 0 < self.expires_at - self.not_before <= 3600:
            raise ValueError("nonfinite override")
        return self


_OVERRIDE_SEAL = object()


@dataclass(frozen=True, slots=True)
class ActivatedOverrideV1:
    authorization: OverrideAuthorizationV1
    digest: str
    signer_authorization_digest: str
    _seal: object

    def __post_init__(self):
        if self._seal is not _OVERRIDE_SEAL:
            raise ReceiptError("RULE-OVERRIDE-INVALID")


def activate_override(
    candidate: OverrideAuthorizationV1, *, evidence, authorization, verifier, snapshot, now: int
) -> ActivatedOverrideV1:
    exact(candidate, OverrideAuthorizationV1)
    payload = canonical(candidate)
    digest = receipt_digest(payload, "override")
    if not candidate.not_before <= now < candidate.expires_at:
        raise ReceiptError("RCT-STALE")
    validate_floor(snapshot, kind="override", generation=candidate.generation, digest=digest)
    verify_authorized_artifact(
        payload=payload,
        evidence=evidence,
        authorization=authorization,
        artifact_kind="override",
        role="override-authorizer",
        verifier=verifier,
        snapshot=snapshot,
        now=now,
    )
    return ActivatedOverrideV1(candidate, digest, authorization.digest, _OVERRIDE_SEAL)


class DecisionGovernorV1:
    __slots__ = ("policy", "rules", "authorization")

    def __init__(self, *, policy: ActivatedPolicyV1, rules, authorization):
        if type(policy) is not ActivatedPolicyV1:
            raise ReceiptError("RCT-MALFORMED")
        object.__setattr__(self, "policy", policy)
        object.__setattr__(self, "rules", rules)
        object.__setattr__(self, "authorization", authorization)

    def __setattr__(self, name, value):
        raise ReceiptError("RCT-MALFORMED")

    def govern(
        self,
        base: DecisionV1,
        *,
        request: DecisionRequestV1,
        snapshot,
        now: int,
        trusted_time_digest: str,
        override=None,
    ):
        exact(request, DecisionRequestV1)
        serialize_decision(base)
        check_authorization(self.authorization, snapshot=snapshot, now=now)
        check_rules(
            self.rules,
            policy_rule_digest=self.policy.policy.rule_set_digest,
            snapshot=snapshot,
            now=now,
        )
        if self.rules.authorization_digest != self.authorization.digest:
            raise ReceiptError("RCT-SIGNER-UNAUTHORIZED")
        for kind, generation, digest in (
            ("policy", self.policy.policy.policy_generation, self.policy.policy_digest),
            ("revocation", self.policy.policy.revocation_generation, self.policy.revocation_digest),
        ):
            validate_floor(snapshot, kind=kind, generation=generation, digest=digest)
        if (
            base.request_digest != request.request_digest
            or base.policy_digest != self.policy.policy_digest
        ):
            raise ReceiptError("RCT-INTEGRITY")
        fields = {
            "base.verdict": base.verdict,
            "base.reason": base.reason,
            "base.recovery": base.recovery,
            "request_digest": request.request_digest,
            "purpose_digest": request.purpose_digest,
            "scope_digest": request.data_scope_digest,
            "trusted_time": now,
            "policy_generation": base.policy_generation,
            "revocation_generation": base.revocation_generation,
            "rule_generation": self.rules.bundle.generation,
            "envelope.taints": request.envelope.taints,
            "envelope.media": request.envelope.content.media_type,
            "envelope.source": request.envelope.source.source_kind,
        }
        fields.update(request.identity.model_dump())
        fields.update(request.operation.model_dump())
        verdict = evaluate_rules(self.rules.bundle.rules, fields, base_verdict=base.verdict)
        reason = (
            base.reason
            if verdict == base.verdict
            else ("RULE-QUARANTINED" if verdict == "quarantine" else "RULE-BLOCKED")
        )
        override_digest = None
        if override is not None:
            self._check_override(
                override,
                base=base,
                request=request,
                snapshot=snapshot,
                now=now,
                trusted_time_digest=trusted_time_digest,
            )
            # A deny imposed by strengthening rules is never bypassed by an override.
            if verdict != base.verdict:
                raise ReceiptError("RULE-OVERRIDE-INVALID")
            verdict, reason, override_digest = "allow", "RULE-OVERRIDE", override.digest
        return create_governed_decision(
            request_digest=request.request_digest,
            base_decision_digest=base.decision_digest,
            effective_verdict=verdict,
            public_reason=reason,
            recovery_code=base.recovery if verdict != "allow" else "none",
            policy_digest=base.policy_digest,
            policy_generation=base.policy_generation,
            runtime_digest=base.runtime_digest,
            rule_digest=self.rules.digest,
            rule_generation=self.rules.bundle.generation,
            revocation_digest=self.policy.revocation_digest,
            revocation_generation=base.revocation_generation,
            adapter_digest=request.operation.adapter_manifest_digest,
            bundle_digest=request.operation.bundle_manifest_digest,
            envelope_digest=request.envelope.envelope_digest,
            override_digest=override_digest,
        )

    def _check_override(self, active, *, base, request, snapshot, now, trusted_time_digest):
        if type(active) is not ActivatedOverrideV1 or active._seal is not _OVERRIDE_SEAL:
            raise ReceiptError("RULE-OVERRIDE-INVALID")
        c = active.authorization
        exact(c, OverrideAuthorizationV1)
        if (
            base.verdict != "deny"
            or base.reason not in NONCRITICAL_OVERRIDE_REASONS
            or c.reason != base.reason
            or c.request_digest != request.request_digest
            or c.base_decision_digest != base.decision_digest
            or c.policy_digest != base.policy_digest
            or c.policy_generation != base.policy_generation
            or c.rule_digest != self.rules.digest
            or c.rule_generation != self.rules.bundle.generation
            or c.actor_digest != request.identity.user_digest
            or c.scope_digest != request.data_scope_digest
            or c.trusted_time_digest != trusted_time_digest
            or not c.not_before <= now < c.expires_at
            or active.signer_authorization_digest != self.authorization.digest
            or receipt_digest(canonical(c), "override") != active.digest
        ):
            raise ReceiptError("RULE-OVERRIDE-INVALID")
        validate_floor(snapshot, kind="override", generation=c.generation, digest=active.digest)
