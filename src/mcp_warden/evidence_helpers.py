"""Pure receipt, floor and durable-append binding helpers."""

from mcp_warden.evidence_models import validate_context
from mcp_warden.evidence_state import (
    ArtifactFloorV1,
    validate_floor,
)
from mcp_warden.receipt_kernel import ReceiptError, exact, receipt_digest
from mcp_warden.receipt_log import DurableAppendEvidenceV1, LogTailV1, entry_digest
from mcp_warden.receipt_models import UnsignedReceiptV1


def receipt_from_context(
    context, *, state, store_identity_digest, authorization, signer_identity_digest, event=None
):
    validate_context(context)
    d = context.decision
    if event is None:
        event = context.event
    values = d.model_dump(exclude={"schema_version"})
    return UnsignedReceiptV1(
        **values,
        event=event,
        sequence=state.primary_sequence + 1,
        trusted_time=context.trusted_time,
        trusted_time_digest=context.trusted_time_digest,
        previous_entry_digest=state.primary_tail_digest,
        store_identity_digest=store_identity_digest,
        recovery_generation=state.recovery_generation,
        recovery_mode=state.mode.value,
        signer_identity_digest=signer_identity_digest,
        signer_authorization_digest=authorization.digest,
        signer_authorization_generation=authorization.bundle.generation,
        trust_root_digest=authorization.bundle.trust_root_digest,
    )


def protected_floors(state, context, authorization, *, primary_tail=None, fallback_tail=None):
    d = context.decision
    updates = {
        "policy": (d.policy_generation, d.policy_digest),
        "rule": (d.rule_generation, d.rule_digest),
        "revocation": (d.revocation_generation, d.revocation_digest),
        "signer-authorization": (authorization.bundle.generation, authorization.digest),
        "trust-root": (authorization.trust_root_generation, authorization.bundle.trust_root_digest),
    }
    if d.override_digest is not None:
        updates["override"] = (d.override_generation, d.override_digest)
    if primary_tail is not None:
        updates["receipt-log"] = (primary_tail.sequence, primary_tail.entry_digest)
    if fallback_tail is not None:
        updates["fallback-log"] = (fallback_tail.sequence, fallback_tail.entry_digest)
    # Adapter/bundle have no generation in the frozen V1 API. Their exact digests
    # must match independently established floors; the coordinator cannot enroll them.
    for kind, (generation, digest) in tuple(updates.items()):
        validate_floor(state, kind=kind, generation=generation, digest=digest)
    return tuple(
        ArtifactFloorV1(kind=f.kind, generation=updates[f.kind][0], digest=updates[f.kind][1])
        if f.kind in updates
        else f
        for f in state.floors
    )


def validate_append(proof, *, payload, expected, store_identity):
    exact(proof, DurableAppendEvidenceV1)
    exact(proof.tail, LogTailV1)
    digest = entry_digest(
        payload, sequence=expected.sequence + 1, previous_entry_digest=expected.entry_digest
    )
    if (
        proof.store_identity_digest != store_identity
        or proof.payload_digest != receipt_digest(payload, "log-entry")
        or proof.tail.sequence != expected.sequence + 1
        or proof.tail.entry_digest != digest
    ):
        raise ReceiptError("RCT-INTEGRITY")
