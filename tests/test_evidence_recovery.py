import pytest

from mcp_warden.evidence_recovery import (
    RecoveryActionV1,
    RecoveryCoordinatorV1,
    activate_recovery_action,
)
from mcp_warden.evidence_state import operationally_healthy
from mcp_warden.receipt_kernel import ReceiptError, canonical, receipt_digest
from tests.receipt_fixtures import pep_fixture


def recovery_fixture():
    pep, request, runtime, effect, p = pep_fixture()
    result = pep.execute(request, runtime=runtime, effect=effect)
    from mcp_warden.evidence_models import create_evidence_context

    context = create_evidence_context(
        decision=result.decision,
        effect_digest=effect.arguments_digest,
        trusted_time=runtime.runtime.trusted_time,
        trusted_time_valid_until=runtime.runtime.trusted_time_valid_until,
        signer_authorization_digest=pep._coordinator.authorization.digest,
    )
    event = receipt_digest(b"incident", "latch")
    p["latch"].set(generation=0, event_digest=event)
    action = RecoveryActionV1(
        generation=1,
        latch_generation=0,
        latch_event_digest=event,
        context_digest=context.context_digest,
        primary_tail_digest=p["primary"].tail.entry_digest,
        primary_sequence=p["primary"].tail.sequence,
        fallback_tail_digest=p["fallback"].tail.entry_digest,
        fallback_sequence=p["fallback"].tail.sequence,
        not_before=190,
        expires_at=240,
    )
    c = pep._coordinator
    signature = c.signer.sign(
        payload=canonical(action),
        artifact_kind="recovery",
        role="recovery-administrator",
        authorization_digest=c.authorization.digest,
    )
    active = activate_recovery_action(
        action,
        evidence=signature,
        authorization=c.authorization,
        verifier=c.verifier,
        snapshot=p["state"].read(),
        now=200,
    )
    return RecoveryCoordinatorV1(c, governor=pep._governor, runtime=runtime), active, context, p


def test_recovery_commits_authorized_exit_before_latch_clear():
    recovery, active, context, p = recovery_fixture()
    assert recovery.exit(active, context)
    assert operationally_healthy(p["state"].read(), p["latch"].read())
    assert p["state"].read().recovery_generation == 1
    assert p["latch"].read().exit_receipt_digest == p["state"].read().recovery_exit_receipt_digest
    assert recovery.exit(active, context)  # exact retry is idempotent


def test_clear_failure_blocks_and_exact_restart_retry_succeeds():
    recovery, active, context, p = recovery_fixture()
    p["latch"].fail = True
    with pytest.raises(ReceiptError):
        recovery.exit(active, context)
    p["latch"].fail = False
    assert not operationally_healthy(p["state"].read(), p["latch"].read())
    assert recovery.exit(active, context)


def test_unactivated_clear_and_wrong_authority_are_rejected():
    recovery, active, context, p = recovery_fixture()
    with pytest.raises(ReceiptError):
        p["latch"].authenticated_clear(
            generation=1,
            prior_event_digest=active.action.latch_event_digest,
            exit_receipt_digest=receipt_digest(b"forged", "receipt"),
            authorization=object(),
        )
    with pytest.raises(ReceiptError):
        recovery.exit(object(), context)
    assert p["latch"].read().latched
