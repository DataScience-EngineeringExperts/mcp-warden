"""One-attempt evidence ordering over independent trusted ports."""

from mcp_warden.decision_receipts import serialize_signed_receipt, sign_receipt
from mcp_warden.evidence_models import FallbackEventV1, create_evidence_result, validate_context
from mcp_warden.evidence_reference import advance_state, validate_protected_state
from mcp_warden.evidence_state import (
    ArtifactFloorV1,
    ProtectedStateModeV1,
    RecoveryLatchSnapshotV1,
    operationally_healthy,
    validate_floor,
)
from mcp_warden.receipt_kernel import ReceiptError, canonical, exact, receipt_digest
from mcp_warden.receipt_log import DurableAppendEvidenceV1, LogTailV1, entry_digest
from mcp_warden.receipt_models import UnsignedReceiptV1
from mcp_warden.signer_authorization import check_authorization


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


class DecisionEvidenceCoordinatorV1:
    """Trusted composition boundary; an allow failure is never rewritten here."""

    def __init__(
        self,
        *,
        primary,
        fallback,
        protected_state,
        recovery_latch,
        signer,
        authorization,
        verifier,
        signer_identity_digest=None,
    ):
        if primary.store_identity_digest == fallback.store_identity_digest or primary is fallback:
            raise ReceiptError("RCT-STORE-ALIAS")
        self.primary, self.fallback = primary, fallback
        self.protected_state, self.recovery_latch = protected_state, recovery_latch
        self.signer, self.authorization, self.verifier = signer, authorization, verifier
        identities = tuple(
            g.signer_identity_digest
            for g in authorization.bundle.grants
            if g.role == "receipt-signer"
        )
        self.signer_identity_digest = signer_identity_digest or (
            identities[0] if len(identities) == 1 else None
        )
        if self.signer_identity_digest not in identities:
            raise ReceiptError("RCT-SIGNER-UNAUTHORIZED")

    def _read(self):
        state = self.protected_state.read()
        validate_protected_state(state)
        latch = self.recovery_latch.read()
        exact(latch, RecoveryLatchSnapshotV1)
        return state, latch

    def record_decision(self, context):
        return self._record_decision(context, channels=None)

    def record_decision_instrumented(self, context):
        channels = []
        result = self._record_decision(context, channels=channels)
        return result, tuple(channels)

    def _record_decision(self, context, *, channels):
        validate_context(context)
        state = None
        failure = "RCT-PROVIDER-UNAVAILABLE"
        record = None
        try:
            state, latch = self._read()
            if not operationally_healthy(state, latch):
                raise ReceiptError("RCT-RECOVERY-ONLY")
            if context.trusted_time_status != "verified":
                raise ReceiptError("RCT-RECOVERY-ONLY")
            check_authorization(self.authorization, snapshot=state, now=context.trusted_time)
            if context.signer_authorization_digest != self.authorization.digest:
                raise ReceiptError("RCT-SIGNER-UNAUTHORIZED")
            protected_floors(state, context, self.authorization)
            expected = LogTailV1(
                sequence=state.primary_sequence, entry_digest=state.primary_tail_digest
            )
            if self.primary.read_tail() != expected:
                raise ReceiptError("RCT-TAIL-MISMATCH")
            receipt = receipt_from_context(
                context,
                state=state,
                store_identity_digest=self.primary.store_identity_digest,
                authorization=self.authorization,
                signer_identity_digest=self.signer_identity_digest,
            )
            record = sign_receipt(
                receipt,
                signer=self.signer,
                authorization=self.authorization,
                verifier=self.verifier,
                snapshot=state,
                now=context.trusted_time,
            )
            payload = serialize_signed_receipt(record)
            if channels is not None:
                channels.append(payload)
            proof = self.primary.append(record, expected_tail=expected)
            validate_append(
                proof,
                payload=payload,
                expected=expected,
                store_identity=self.primary.store_identity_digest,
            )
            candidate = advance_state(
                state,
                primary_sequence=proof.tail.sequence,
                primary_tail_digest=proof.tail.entry_digest,
                floors=protected_floors(
                    state, context, self.authorization, primary_tail=proof.tail
                ),
                mode=ProtectedStateModeV1.HEALTHY,
            )
            committed = self.protected_state.compare_and_advance(state, candidate)
            if committed != candidate:
                raise ReceiptError("RCT-STATE-COMMIT")
            latest, latch = self._read()
            if latest != candidate or not operationally_healthy(latest, latch):
                raise ReceiptError("RCT-STATE-COMMIT")
            return create_evidence_result(
                context,
                mode="primary-durable",
                evidence_digest=record.receipt_digest,
                sequence=proof.tail.sequence,
                store_identity_digest=self.primary.store_identity_digest,
                recovery_generation=latest.recovery_generation,
                recovery_mode="healthy",
            )
        except Exception as error:
            if type(error) is ReceiptError and error.code in {
                "RCT-TAIL-MISMATCH",
                "RCT-STATE-COMMIT",
                "RCT-SIGNATURE-INVALID",
                "RCT-RECOVERY-ONLY",
                "RCT-INTEGRITY",
            }:
                failure = error.code
        if context.decision.effective_verdict == "allow":
            return create_evidence_result(
                context,
                mode="unavailable",
                failure_code=failure,
                recovery_generation=0 if state is None else state.recovery_generation,
                recovery_mode="recovery-latched" if state is None else state.mode.value,
            )
        failed_digest = (
            context.decision.decision_digest if record is None else record.receipt_digest
        )
        return self._fallback(
            context, state=state, failure=failure, failed_digest=failed_digest, channels=channels
        )

    def _fallback(self, context, *, state, failure, failed_digest, channels):
        generation = 0 if state is None else state.recovery_generation
        try:
            if state is None:
                raise ReceiptError("RCT-RECOVERY-ONLY")
            current = self.protected_state.read()
            validate_protected_state(current)
            state = current
            generation = state.recovery_generation
            if state.mode is ProtectedStateModeV1.HEALTHY:
                degraded = advance_state(state, mode=ProtectedStateModeV1.EVIDENCE_DEGRADED)
                if self.protected_state.compare_and_advance(state, degraded) != degraded:
                    raise ReceiptError("RCT-STATE-COMMIT")
                state = degraded
            expected = LogTailV1(
                sequence=state.fallback_sequence, entry_digest=state.fallback_tail_digest
            )
            if self.fallback.read_tail() != expected:
                raise ReceiptError("RCT-TAIL-MISMATCH")
            event = FallbackEventV1(
                sequence=expected.sequence + 1,
                failed_receipt_digest=failed_digest,
                failure_code=failure,
                trusted_time_digest=context.trusted_time_digest,
                previous_entry_digest=expected.entry_digest,
                recovery_generation=generation,
            )
            if channels is not None:
                channels.append(canonical(event))
            proof = self.fallback.append(event, expected_tail=expected)
            validate_append(
                proof,
                payload=canonical(event),
                expected=expected,
                store_identity=self.fallback.store_identity_digest,
            )
            floors = tuple(
                ArtifactFloorV1(
                    kind=f.kind, generation=proof.tail.sequence, digest=proof.tail.entry_digest
                )
                if f.kind == "fallback-log"
                else f
                for f in state.floors
            )
            validate_floor(
                state,
                kind="fallback-log",
                generation=proof.tail.sequence,
                digest=proof.tail.entry_digest,
            )
            candidate = advance_state(
                state,
                fallback_sequence=proof.tail.sequence,
                fallback_tail_digest=proof.tail.entry_digest,
                floors=floors,
            )
            if self.protected_state.compare_and_advance(state, candidate) != candidate:
                raise ReceiptError("RCT-STATE-COMMIT")
            return create_evidence_result(
                context,
                mode="fallback-durable",
                evidence_digest=receipt_digest(canonical(event), "fallback"),
                sequence=proof.tail.sequence,
                store_identity_digest=self.fallback.store_identity_digest,
                recovery_generation=generation,
                recovery_mode=state.mode.value,
                failure_code=failure,
            )
        except Exception:
            pass
        event_digest = receipt_digest(
            canonical(
                {
                    "decision_digest": context.decision.decision_digest,
                    "failure_code": failure,
                    "recovery_generation": generation,
                }
            ),
            "latch",
        )
        latched = False
        try:
            existing = self.recovery_latch.read()
            exact(existing, RecoveryLatchSnapshotV1)
            if existing.latched:
                latched = True
            else:
                result = self.recovery_latch.set(
                    generation=max(generation, existing.generation), event_digest=event_digest
                )
                exact(result, RecoveryLatchSnapshotV1)
                latched = result.latched and result.event_digest == event_digest
        except Exception:
            pass
        return create_evidence_result(
            context,
            mode="recovery-latched" if latched else "unavailable",
            recovery_generation=generation,
            recovery_mode="recovery-latched",
            failure_code="RCT-LATCH-FAILED" if not latched else failure,
        )
