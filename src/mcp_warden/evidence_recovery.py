"""Signed recovery-exit protocol: protected authorization first, latch clear last."""

from dataclasses import dataclass
from typing import Literal

from pydantic import StrictInt, model_validator

from mcp_warden.decision_receipts import serialize_signed_receipt, sign_receipt
from mcp_warden.evidence_coordinator import protected_floors, receipt_from_context, validate_append
from mcp_warden.evidence_models import validate_context
from mcp_warden.evidence_reference import advance_state
from mcp_warden.evidence_state import ProtectedStateModeV1, operationally_healthy
from mcp_warden.policy_decision import ActivatedRuntimeV1, _has_activation_marker
from mcp_warden.receipt_kernel import ReceiptError, ReceiptModel, canonical, exact, receipt_digest
from mcp_warden.receipt_log import LogTailV1
from mcp_warden.receipt_models import ReceiptEventContextV1
from mcp_warden.rule_engine import check_rules
from mcp_warden.signer_authorization import check_authorization, verify_authorized_artifact


class RecoveryActionV1(ReceiptModel):
    schema_version: Literal[1] = 1
    generation: StrictInt
    latch_generation: StrictInt
    latch_event_digest: str
    context_digest: str
    primary_sequence: StrictInt
    primary_tail_digest: str
    fallback_sequence: StrictInt
    fallback_tail_digest: str
    not_before: StrictInt
    expires_at: StrictInt

    @model_validator(mode="after")
    def _finite(self):
        if (
            self.generation != self.latch_generation + 1
            or not 0 < self.expires_at - self.not_before <= 3600
        ):
            raise ValueError("invalid recovery bounds")
        return self


_ACTION_SEAL = object()
_CLEAR_SEAL = object()


@dataclass(frozen=True, slots=True)
class ActivatedRecoveryActionV1:
    action: RecoveryActionV1
    digest: str
    authorization_digest: str
    _seal: object

    def __post_init__(self):
        if self._seal is not _ACTION_SEAL:
            raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")


@dataclass(frozen=True, slots=True)
class AuthorizedLatchClearV1:
    generation: int
    prior_event_digest: str
    exit_receipt_digest: str
    _seal: object

    def __post_init__(self):
        if self._seal is not _CLEAR_SEAL:
            raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")


def validate_latch_clear(token, *, generation, prior_event_digest, exit_receipt_digest):
    if (
        type(token) is not AuthorizedLatchClearV1
        or token._seal is not _CLEAR_SEAL
        or token.generation != generation
        or token.prior_event_digest != prior_event_digest
        or token.exit_receipt_digest != exit_receipt_digest
    ):
        raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")


def activate_recovery_action(
    action: RecoveryActionV1, *, evidence, authorization, verifier, snapshot, now: int
):
    exact(action, RecoveryActionV1)
    if (
        not action.not_before <= now < action.expires_at
        or action.generation <= snapshot.recovery_generation
    ):
        raise ReceiptError("RCT-STALE")
    payload = canonical(action)
    verify_authorized_artifact(
        payload=payload,
        evidence=evidence,
        authorization=authorization,
        artifact_kind="recovery",
        role="recovery-administrator",
        verifier=verifier,
        snapshot=snapshot,
        now=now,
    )
    return ActivatedRecoveryActionV1(
        action, receipt_digest(payload, "recovery"), authorization.digest, _ACTION_SEAL
    )


class RecoveryCoordinatorV1:
    def __init__(self, coordinator, *, governor, runtime):
        from mcp_warden.decision_governor import DecisionGovernorV1
        from mcp_warden.evidence_coordinator import DecisionEvidenceCoordinatorV1

        if (
            type(coordinator) is not DecisionEvidenceCoordinatorV1
            or type(governor) is not DecisionGovernorV1
            or not _has_activation_marker(runtime, ActivatedRuntimeV1)
        ):
            raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")
        self.coordinator, self.governor, self.runtime = coordinator, governor, runtime

    def exit(self, active, context):
        failed = False
        result = False
        try:
            result = self._exit(active, context)
        except Exception:
            failed = True
        if failed:
            raise ReceiptError("RCT-RECOVERY-AUTHORIZATION") from None
        return result

    def _exit(self, active, context):
        validate_context(context)
        if type(active) is not ActivatedRecoveryActionV1 or active._seal is not _ACTION_SEAL:
            raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")
        action = active.action
        exact(action, RecoveryActionV1)
        if receipt_digest(canonical(action), "recovery") != active.digest:
            raise ReceiptError("RCT-INTEGRITY")
        c = self.coordinator
        state, latch = c._read()
        now = context.trusted_time
        check_authorization(c.authorization, snapshot=state, now=now)
        check_rules(
            self.governor.rules,
            policy_rule_digest=self.governor.policy.policy.rule_set_digest,
            snapshot=state,
            now=now,
        )
        d = context.decision
        if (
            active.authorization_digest != c.authorization.digest
            or context.context_digest != action.context_digest
            or context.trusted_time_status != "verified"
            or now != self.runtime.runtime.trusted_time
            or context.trusted_time_valid_until != self.runtime.runtime.trusted_time_valid_until
            or d.runtime_digest != self.runtime.runtime_digest
            or d.policy_digest != self.governor.policy.policy_digest
            or d.rule_digest != self.governor.rules.digest
            or not action.not_before <= now < action.expires_at
        ):
            raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")
        protected_floors(state, context, c.authorization)
        primary = LogTailV1(sequence=state.primary_sequence, entry_digest=state.primary_tail_digest)
        fallback = LogTailV1(
            sequence=state.fallback_sequence, entry_digest=state.fallback_tail_digest
        )
        if c.primary.read_tail() != primary or c.fallback.read_tail() != fallback:
            raise ReceiptError("RCT-TAIL-MISMATCH")
        if state.mode is ProtectedStateModeV1.RECOVERY_EXIT_AUTHORIZED:
            if (
                state.recovery_generation != action.generation
                or state.prior_latch_event_digest != action.latch_event_digest
                or state.recovery_authorization_digest != active.digest
                or state.recovery_exit_receipt_digest is None
            ):
                raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")
        else:
            if (
                not latch.latched
                or latch.generation != action.latch_generation
                or state.recovery_generation != action.latch_generation
                or latch.event_digest != action.latch_event_digest
                or primary.sequence != action.primary_sequence
                or primary.entry_digest != action.primary_tail_digest
                or fallback.sequence != action.fallback_sequence
                or fallback.entry_digest != action.fallback_tail_digest
            ):
                raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")
            receipt = receipt_from_context(
                context,
                state=state,
                store_identity_digest=c.primary.store_identity_digest,
                authorization=c.authorization,
                signer_identity_digest=c.signer_identity_digest,
                event=ReceiptEventContextV1(kind="recovery-exit", authority_digest=active.digest),
            )
            record = sign_receipt(
                receipt,
                signer=c.signer,
                authorization=c.authorization,
                verifier=c.verifier,
                snapshot=state,
                now=now,
            )
            proof = c.primary.append(record, expected_tail=primary)
            validate_append(
                proof,
                payload=serialize_signed_receipt(record),
                expected=primary,
                store_identity=c.primary.store_identity_digest,
            )
            candidate = advance_state(
                state,
                primary_sequence=proof.tail.sequence,
                primary_tail_digest=proof.tail.entry_digest,
                floors=protected_floors(state, context, c.authorization, primary_tail=proof.tail),
                mode=ProtectedStateModeV1.RECOVERY_EXIT_AUTHORIZED,
                recovery_generation=action.generation,
                prior_latch_event_digest=action.latch_event_digest,
                recovery_exit_receipt_digest=record.receipt_digest,
                recovery_authorization_digest=active.digest,
            )
            if c.protected_state.compare_and_advance(state, candidate) != candidate:
                raise ReceiptError("RCT-STATE-COMMIT")
            state, latch = c._read()
            if state != candidate:
                raise ReceiptError("RCT-STATE-COMMIT")
        token = AuthorizedLatchClearV1(
            state.recovery_generation,
            state.prior_latch_event_digest,
            state.recovery_exit_receipt_digest,
            _CLEAR_SEAL,
        )
        c.recovery_latch.authenticated_clear(
            generation=token.generation,
            prior_event_digest=token.prior_event_digest,
            exit_receipt_digest=token.exit_receipt_digest,
            authorization=token,
        )
        state, latch = c._read()
        return operationally_healthy(state, latch)
