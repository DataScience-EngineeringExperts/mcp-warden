"""Exact allowlist projections of verified-shaped evidence; no raw authority data."""

from mcp_warden.decision_receipts import serialize_signed_receipt
from mcp_warden.evidence_models import DecisionEvidenceResultV1
from mcp_warden.receipt_kernel import ReceiptError, exact
from mcp_warden.receipt_models import SignedReceiptV1

HUMAN_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_reference",
        "receipt_digest",
        "event_kind",
        "primary_sequence",
        "fallback_sequence",
        "trusted_time",
        "trusted_time_status",
        "request_digest",
        "decision_digest",
        "base_verdict",
        "effective_verdict",
        "public_reason",
        "recovery_code",
        "policy_generation",
        "policy_digest",
        "rule_generation",
        "rule_digest",
        "signer_role",
        "signer_identity_digest",
        "store_identity_digest",
        "evidence_mode",
        "recovery_mode",
        "verification_status",
    }
)
AGENT_FIELDS = frozenset(
    {"schema_version", "receipt_reference", "effective_verdict", "reason", "next_action"}
)


def _receipt(record):
    exact(record, SignedReceiptV1)
    serialize_signed_receipt(record)
    return record.receipt


def human_projection(record, *, evidence, verification_status):
    r = _receipt(record)
    exact(evidence, DecisionEvidenceResultV1)
    if (
        type(verification_status) is not str
        or verification_status not in {"verified", "unverified", "invalid"}
        or evidence.decision_digest != r.decision_digest
        or evidence.evidence_digest != record.receipt_digest
        or evidence.mode != "primary-durable"
    ):
        raise ReceiptError("RCT-INTEGRITY")
    return {
        "schema_version": 1,
        "receipt_reference": record.receipt_digest,
        "receipt_digest": record.receipt_digest,
        "event_kind": r.event.kind,
        "primary_sequence": r.sequence,
        "fallback_sequence": None,
        "trusted_time": r.trusted_time,
        "trusted_time_status": "verified",
        "request_digest": r.request_digest,
        "decision_digest": r.decision_digest,
        "base_verdict": r.base_verdict,
        "effective_verdict": r.effective_verdict,
        "public_reason": r.public_reason,
        "recovery_code": r.recovery_code,
        "policy_generation": r.policy_generation,
        "policy_digest": r.policy_digest,
        "rule_generation": r.rule_generation,
        "rule_digest": r.rule_digest,
        "signer_role": r.signer_role,
        "signer_identity_digest": r.signer_identity_digest,
        "store_identity_digest": r.store_identity_digest,
        "evidence_mode": evidence.mode,
        "recovery_mode": evidence.recovery_mode,
        "verification_status": verification_status,
    }


def agent_projection(record):
    r = _receipt(record)
    if r.recovery_code == "recovery-only" or r.recovery_mode != "healthy":
        reason, action = "recovery-only", "request-recovery"
    elif r.recovery_code == "reauthenticate":
        reason, action = "reauthenticate", "reauthenticate"
    elif r.recovery_code in {"refresh-authority", "obtain-new-lease"}:
        reason, action = "refresh-authority", "refresh-authority"
    elif r.effective_verdict == "quarantine":
        reason, action = "quarantined", "quarantine-input"
    elif r.effective_verdict == "allow":
        reason, action = "authorized", "none"
    else:
        reason, action = "blocked", "review-request"
    return {
        "schema_version": 1,
        "receipt_reference": record.receipt_digest,
        "effective_verdict": r.effective_verdict,
        "reason": reason,
        "next_action": action,
    }
