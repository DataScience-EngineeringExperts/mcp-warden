"""Nonoptional reference failure corpus, including real file restart and output probes."""

from dataclasses import replace

import pytest

from mcp_warden.receipt_conformance import (
    ReceiptConformanceScenarioV1,
    ReceiptConformanceVectorV1,
    run_receipt_conformance,
    serialize_receipt_conformance_report,
)
from mcp_warden.receipt_kernel import ZERO_DIGEST, ReceiptError, receipt_digest
from mcp_warden.receipt_log import FilePrimaryReceiptStoreV1, LogTailV1
from mcp_warden.receipt_verification import primary_payload_validator
from tests.receipt_fixtures import pep_fixture


def matrix(tmp_path):
    scenarios = {}
    for name in (
        "allow",
        "deny",
        "primary_failure",
        "dual_failure",
        "state_failure",
        "latched",
        "rollback",
        "restarted",
        "malformed_latch",
        "false_primary_commit",
        "false_fallback_commit",
    ):
        pep, request, runtime, effect, providers = pep_fixture(grant=name != "deny")
        if name in {"primary_failure", "dual_failure"}:
            providers["primary"].fail = True
        if name == "dual_failure":
            providers["fallback"].fail = True
        if name == "malformed_latch":
            from mcp_warden.evidence_state import RecoveryLatchSnapshotV1

            providers["latch"].read = lambda: RecoveryLatchSnapshotV1.model_construct(
                schema_version=1,
                generation=0,
                latched=0,
                event_digest=ZERO_DIGEST,
                cleared_generation=None,
                cleared_event_digest=None,
            )
        if name in {"false_primary_commit", "false_fallback_commit"}:
            providers["state"].compare_and_advance = lambda expected, candidate: candidate
            if name == "false_fallback_commit":
                providers["primary"].fail = True
        if name == "state_failure":

            def fail_commit(expected, candidate):
                raise ValueError("PLANTED-COMMIT-SECRET")

            providers["state"].compare_and_advance = fail_commit
        if name == "latched":
            providers["latch"].set(generation=1, event_digest=receipt_digest(b"latched", "latch"))
        if name == "rollback":
            assert pep.execute(request, runtime=runtime, effect=effect).invoked
            providers["primary"].tail = LogTailV1(sequence=0, entry_digest=ZERO_DIGEST)
            providers["primary"].payloads.clear()
        if name == "restarted":
            coordinator = pep._coordinator
            path = tmp_path / "receipts.log"
            options = {
                "store_identity_digest": providers["primary"].store_identity_digest,
                "validate_payload": primary_payload_validator(
                    authorization=coordinator.authorization,
                    verifier=coordinator.verifier,
                    snapshot=providers["state"].read,
                ),
            }
            coordinator.primary = FilePrimaryReceiptStoreV1(path, **options)
            assert pep.execute(request, runtime=runtime, effect=effect).invoked
            coordinator.primary = FilePrimaryReceiptStoreV1(path, **options)
        scenarios[name] = ReceiptConformanceScenarioV1(pep, request, runtime, effect)
    return ReceiptConformanceVectorV1(**scenarios)


def test_fixed_reference_matrix_runs_and_never_claims_platform_support(tmp_path):
    report = run_receipt_conformance(
        (matrix(tmp_path),), planted_secrets=(b"PLANTED-COMMIT-SECRET", b"secret provider text")
    )
    assert report.passed, report.failures
    assert report.total_cases == 16
    assert report.fixed_cases == 5
    assert report.platform_status == "unsupported"
    assert report.atk_conformant is False
    assert report.covered_operations == report.registration_operations
    assert serialize_receipt_conformance_report(report) == serialize_receipt_conformance_report(
        report
    )


def test_missing_failure_scenario_cannot_be_omitted(tmp_path):
    vector = matrix(tmp_path)
    with pytest.raises(ReceiptError):
        replace(vector, dual_failure=None)


def test_healthy_provider_cannot_pass_as_failed_primary(tmp_path):
    vector = matrix(tmp_path)
    report = run_receipt_conformance((replace(vector, primary_failure=vector.allow),))
    assert not report.passed
    assert "CONF-CASE-MISMATCH" in report.failures


def test_truncated_real_restart_fails_reference_profile(tmp_path):
    vector = matrix(tmp_path)
    path = vector.restarted.pep._coordinator.primary.path
    path.write_bytes(path.read_bytes()[:-1])
    report = run_receipt_conformance((vector,))
    assert not report.passed
    assert "CONF-CASE-MISMATCH" in report.failures


def test_actual_receipt_channels_are_scanned_for_planted_secret(tmp_path):
    vector = matrix(tmp_path)
    report = run_receipt_conformance((vector,), planted_secrets=(b"signature_hex",))
    assert not report.passed
    assert "CONF-SECRET-LEAK" in report.failures


@pytest.mark.parametrize("fault", ["early_output", "missing_receipt", "empty_channels"])
def test_instrumentation_cannot_make_evidence_or_order_checks_vacuous(tmp_path, monkeypatch, fault):
    from mcp_warden.policy_enforcement import EnforcementTraceV1
    from mcp_warden.policy_enforcement_v2 import PolicyEnforcementPointV2

    vector = matrix(tmp_path)
    original = PolicyEnforcementPointV2._execute_instrumented

    def forged_trace(self, *args, **kwargs):
        result, trace = original(self, *args, **kwargs)
        events, channels = trace.events, trace.output_channels
        if fault == "early_output" and result.invoked:
            events = ("output",) + tuple(e for e in events if e != "output")
        elif fault == "missing_receipt":
            channels = tuple(c for c in channels if b"signature_hex" not in c)
        elif fault == "empty_channels":
            channels = ()
        return result, EnforcementTraceV1(events=events, output_channels=channels)

    monkeypatch.setattr(PolicyEnforcementPointV2, "_execute_instrumented", forged_trace)
    report = run_receipt_conformance((vector,))
    assert not report.passed
    assert "CONF-INSTRUMENTATION" in report.failures


def test_forged_platform_claim_and_digest_are_rejected(tmp_path):
    report = run_receipt_conformance((matrix(tmp_path),))
    for updates in (
        {"atk_conformant": True},
        {"platform_status": "supported"},
        {"report_digest": ZERO_DIGEST},
    ):
        with pytest.raises(ReceiptError) as error:
            serialize_receipt_conformance_report(report.model_copy(update=updates))
        assert error.value.__context__ is None


def test_empty_matrix_is_closed_error():
    with pytest.raises(ReceiptError) as error:
        run_receipt_conformance(())
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    "attack", ["malformed_latch", "false_primary_commit", "false_fallback_commit"]
)
def test_required_hostile_provider_scenarios_cannot_claim_success_or_resume(tmp_path, attack):
    from mcp_warden.evidence_reference import InMemoryProtectedStateV1

    scenario = getattr(matrix(tmp_path), attack)
    pep = scenario.pep
    result, trace = pep._execute_instrumented(
        scenario.request, runtime=scenario.runtime, effect=scenario.effect
    )
    assert not result.invoked and "sink" not in trace.events
    assert result.evidence.mode in {"unavailable", "recovery-latched"}
    if attack == "false_fallback_commit":
        state = pep._coordinator.protected_state
        state.compare_and_advance = InMemoryProtectedStateV1.compare_and_advance.__get__(state)
        pep._coordinator.primary.fail = False
        second, trace = pep._execute_instrumented(
            scenario.request, runtime=scenario.runtime, effect=scenario.effect
        )
        assert not second.invoked and "sink" not in trace.events
