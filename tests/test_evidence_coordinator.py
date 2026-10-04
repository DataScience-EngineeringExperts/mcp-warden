import pytest

from mcp_warden.evidence_models import validate_evidence_result
from tests.receipt_fixtures import coordinator_fixture


@pytest.mark.parametrize("verdict", ["allow", "deny", "quarantine"])
def test_primary_signed_evidence_before_effect(verdict):
    coordinator, context, providers = coordinator_fixture(verdict=verdict)
    result = coordinator.record_decision(context)
    assert result.mode == "primary-durable"
    assert validate_evidence_result(result, context)
    assert providers["state"].read().primary_sequence == 1


def test_primary_and_fallback_failures_latch_without_leaking_exception():
    coordinator, context, providers = coordinator_fixture(verdict="deny")
    providers["primary"].fail = True
    providers["fallback"].fail = True
    result = coordinator.record_decision(context)
    assert result.mode == "recovery-latched"
    assert providers["latch"].read().latched
    assert "secret" not in str(result.model_dump())


def test_independent_fallback_is_durable_but_never_permit_evidence():
    coordinator, context, providers = coordinator_fixture(verdict="deny")
    providers["primary"].fail = True
    result = coordinator.record_decision(context)
    assert result.mode == "fallback-durable"
    assert not validate_evidence_result(result, context)
    assert providers["state"].read().fallback_sequence == 1


def test_allow_failure_is_bound_to_original_allow_only():
    coordinator, context, providers = coordinator_fixture()
    providers["primary"].fail = True
    result = coordinator.record_decision(context)
    assert result.mode == "unavailable"
    assert result.decision_digest == context.decision.decision_digest
    assert not validate_evidence_result(result, context)


def test_false_latch_set_acknowledgement_is_not_durable(monkeypatch):
    from mcp_warden.evidence_state import RecoveryLatchSnapshotV1

    c, x, p = coordinator_fixture(verdict="deny")
    p["primary"].fail = p["fallback"].fail = True

    def fake_set(*, generation, event_digest):
        return RecoveryLatchSnapshotV1(
            generation=generation, latched=True, event_digest=event_digest
        )

    monkeypatch.setattr(p["latch"], "set", fake_set)
    result = c.record_decision(x)
    assert result.mode == "unavailable"
    assert result.failure_code == "RCT-LATCH-FAILED"


def test_hostile_tail_equality_is_rejected_before_append(monkeypatch):
    c, x, p = coordinator_fixture()

    class HostileTail:
        def __eq__(self, other):
            return True

        def __ne__(self, other):
            return False

    monkeypatch.setattr(p["primary"], "read_tail", lambda: HostileTail())
    result = c.record_decision(x)
    assert result.mode == "unavailable"
    assert not p["primary"].payloads


def test_forged_error_code_cannot_escape_provider_frame(monkeypatch):
    from mcp_warden.receipt_kernel import ReceiptError

    c, x, p = coordinator_fixture(verdict="deny")

    def fail(*args, **kwargs):
        error = ReceiptError("RCT-APPEND-FAILED")
        error.code = {"secret": "provider path"}
        raise error

    monkeypatch.setattr(p["primary"], "append", fail)
    result = c.record_decision(x)
    assert result.mode == "fallback-durable"
    assert "secret" not in str(result.model_dump())
