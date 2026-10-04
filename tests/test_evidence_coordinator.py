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
