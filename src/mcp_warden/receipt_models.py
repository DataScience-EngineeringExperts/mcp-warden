"""Strict canonical receipt and independently authorized signing models."""

from __future__ import annotations

from typing import Literal

from pydantic import StrictInt, model_validator

from mcp_warden.receipt_kernel import ReceiptError, ReceiptModel, exact

SignerRole = Literal[
    "receipt-signer", "rule-publisher", "override-authorizer", "recovery-administrator"
]
ArtifactKind = Literal["receipt", "rule", "override", "recovery"]
ROLE_KIND = {
    "receipt-signer": "receipt",
    "rule-publisher": "rule",
    "override-authorizer": "override",
    "recovery-administrator": "recovery",
}


class ReceiptEventContextV1(ReceiptModel):
    kind: Literal[
        "allow", "deny", "quarantine", "override", "revoke", "expiry", "limit", "recovery-exit"
    ]
    actor_digest: str | None = None
    scope_digest: str | None = None
    authority_digest: str | None = None
    expires_at: StrictInt | None = None
    artifact_kind: ArtifactKind | None = None
    artifact_digest: str | None = None
    artifact_generation: StrictInt | None = None
    revocation_generation: StrictInt | None = None
    validity_boundary: StrictInt | None = None

    def __init__(self, **data):
        if type(data.get("kind")) is str and data["kind"] == "limit":
            raise ReceiptError("RCT-LIMIT-UNSUPPORTED")
        super().__init__(**data)

    @model_validator(mode="after")
    def _union(self):
        required = {
            "allow": set(),
            "deny": set(),
            "quarantine": set(),
            "override": {"actor_digest", "scope_digest", "authority_digest", "expires_at"},
            "revoke": {
                "artifact_kind",
                "artifact_digest",
                "artifact_generation",
                "revocation_generation",
            },
            "expiry": {"artifact_kind", "artifact_digest", "validity_boundary"},
            "recovery-exit": {"authority_digest"},
        }
        present = {
            name
            for name in type(self).model_fields
            if name != "kind" and getattr(self, name) is not None
        }
        if self.kind not in required or present != required[self.kind]:
            raise ValueError("event binding")
        return self


class SignerGrantV1(ReceiptModel):
    signer_identity_digest: str
    role: SignerRole
    artifact_kind: ArtifactKind

    @model_validator(mode="after")
    def _binding(self):
        if ROLE_KIND[self.role] != self.artifact_kind:
            raise ValueError("role binding")
        return self


class SignerAuthorizationBundleV1(ReceiptModel):
    schema_version: Literal[1] = 1
    generation: StrictInt
    valid_from: StrictInt
    valid_until: StrictInt
    trust_root_digest: str
    grants: tuple[SignerGrantV1, ...]

    @model_validator(mode="after")
    def _valid(self):
        keys = tuple((g.signer_identity_digest, g.role, g.artifact_kind) for g in self.grants)
        if (
            self.valid_until <= self.valid_from
            or not self.grants
            or len(self.grants) > 256
            or any(type(g) is not SignerGrantV1 for g in self.grants)
            or keys != tuple(sorted(set(keys)))
        ):
            raise ValueError("invalid authorization")
        return self


class SignatureEvidenceV1(ReceiptModel):
    algorithm: Literal["ed25519"] = "ed25519"
    role: SignerRole
    artifact_kind: ArtifactKind
    signer_identity_digest: str
    authorization_digest: str
    signature: bytes

    @model_validator(mode="after")
    def _valid(self):
        if (
            type(self.signature) is not bytes
            or len(self.signature) != 64
            or ROLE_KIND[self.role] != self.artifact_kind
        ):
            raise ValueError("invalid signature")
        return self


class UnsignedReceiptV1(ReceiptModel):
    schema_version: Literal[1] = 1
    event: ReceiptEventContextV1
    request_digest: str
    effect_digest: str
    decision_digest: str
    base_decision_digest: str | None
    base_verdict: Literal["allow", "deny", "quarantine"] | None = None
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
    sequence: StrictInt
    trusted_time: StrictInt
    trusted_time_digest: str
    previous_entry_digest: str
    store_identity_digest: str
    recovery_generation: StrictInt
    recovery_mode: Literal[
        "healthy", "evidence-degraded", "recovery-latched", "recovery-exit-authorized"
    ]
    signer_role: Literal["receipt-signer"] = "receipt-signer"
    signer_identity_digest: str
    signer_authorization_digest: str
    signer_authorization_generation: StrictInt
    trust_root_digest: str
    override_digest: str | None = None
    converted_from_decision_digest: str | None = None

    @model_validator(mode="after")
    def _event(self):
        exact(self.event, ReceiptEventContextV1)
        from mcp_warden.governed_decision import PUBLIC_REASONS, RECOVERY_CODES

        if self.public_reason not in PUBLIC_REASONS or self.recovery_code not in RECOVERY_CODES:
            raise ValueError("closed public code")
        if self.sequence < 1:
            raise ValueError("invalid sequence")
        if (
            self.event.kind in {"allow", "deny", "quarantine"}
            and self.event.kind != self.effective_verdict
        ):
            raise ValueError("verdict binding")
        if (self.event.kind == "override") != (self.override_digest is not None):
            raise ValueError("override binding")
        return self


class SignedReceiptV1(ReceiptModel):
    receipt: UnsignedReceiptV1
    evidence: SignatureEvidenceV1
    receipt_digest: str

    @model_validator(mode="after")
    def _exact(self):
        exact(self.receipt, UnsignedReceiptV1)
        exact(self.evidence, SignatureEvidenceV1)
        return self
