from __future__ import annotations

import ast
from pathlib import Path

import pytest

from mcp_warden.adapter_conformance import (
    AdapterConformanceCaseV1,
    ConformanceError,
    ConformanceFailureV1,
    ConformanceReportV1,
    run_adapter_conformance,
    serialize_conformance_report,
)
from mcp_warden.policy_decision import PolicyDecisionPointV1
from mcp_warden.policy_enforcement import (
    EnforcementCodeV1,
    PolicyEnforcementPointV1,
    create_effect_input,
)
from tests.test_policy_enforcement import (
    PermitGate,
    _activated_adapter,
    _active_components,
    _noop_handler,
)


def _pep_and_cases():
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    pep = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=PermitGate(trace)
    )
    allow = AdapterConformanceCaseV1(
        name="allow-document-read",
        request=request,
        runtime=runtime,
        effect=effect,
        expected_code=EnforcementCodeV1.EXECUTED,
        expected_invoked=True,
        planted_secrets=(b"planted-secret-allow",),
    )
    blocked = AdapterConformanceCaseV1(
        name="block-effect-substitution",
        request=request,
        runtime=runtime,
        effect=create_effect_input(b'{"document_id":"forged"}'),
        expected_code=EnforcementCodeV1.EFFECT_DIGEST_MISMATCH,
        expected_invoked=False,
        planted_secrets=(b"planted-secret-blocked",),
    )
    return pep, (allow, blocked), trace


def test_conformance_report_passes_with_full_operation_and_negative_coverage() -> None:
    pep, cases, trace = _pep_and_cases()
    report = run_adapter_conformance(pep, cases=cases)
    assert report.passed is True
    assert report.total_cases > len(cases)
    assert report.registration_operations == ("document.read",)
    assert report.instrumented_cases == report.total_cases
    assert report.covered_operations == ("document.read",)
    assert report.failures == ()
    assert trace == ["evidence"]
    assert b"planted-secret" not in serialize_conformance_report(report)


def test_missing_allow_vector_fails_operation_coverage() -> None:
    pep, cases, _ = _pep_and_cases()
    report = run_adapter_conformance(pep, cases=(cases[1],))
    assert report.passed is False
    assert ConformanceFailureV1.OPERATION_UNCOVERED.value in report.failures


def test_expected_code_or_invocation_mismatch_is_reported_without_input_echo() -> None:
    pep, cases, _ = _pep_and_cases()
    wrong = AdapterConformanceCaseV1(
        name="wrong-expectation",
        request=cases[0].request,
        runtime=cases[0].runtime,
        effect=cases[0].effect,
        expected_code=EnforcementCodeV1.DECISION_BLOCKED,
        expected_invoked=False,
        planted_secrets=(b"secret-expectation",),
    )
    report = run_adapter_conformance(pep, cases=(wrong, cases[1]))
    assert report.passed is False
    assert ConformanceFailureV1.CASE_MISMATCH.value in report.failures
    assert b"secret-expectation" not in serialize_conformance_report(report)


def test_planted_secret_scan_covers_serialized_enforcement_result() -> None:
    pep, cases, _ = _pep_and_cases()
    collision = AdapterConformanceCaseV1(
        name="secret-scan-proof",
        request=cases[0].request,
        runtime=cases[0].runtime,
        effect=cases[0].effect,
        expected_code=EnforcementCodeV1.EXECUTED,
        expected_invoked=True,
        planted_secrets=(b"PEP-EXECUTED",),
    )
    report = run_adapter_conformance(pep, cases=(collision, cases[1]))
    assert report.passed is False
    assert ConformanceFailureV1.SECRET_LEAK.value in report.failures


def test_planted_secret_scan_covers_pep_owned_instrumentation_channel() -> None:
    pep, cases, _ = _pep_and_cases()
    collision = AdapterConformanceCaseV1(
        name="instrumentation-secret-scan-proof",
        request=cases[0].request,
        runtime=cases[0].runtime,
        effect=cases[0].effect,
        expected_code=EnforcementCodeV1.EXECUTED,
        expected_invoked=True,
        planted_secrets=(b'"sink"',),
    )
    report = run_adapter_conformance(pep, cases=(collision, cases[1]))
    assert report.passed is False
    assert ConformanceFailureV1.SECRET_LEAK.value in report.failures


def test_reports_are_byte_identical_for_identical_case_outcomes() -> None:
    first_pep, first_cases, _ = _pep_and_cases()
    second_pep, second_cases, _ = _pep_and_cases()
    first = run_adapter_conformance(first_pep, cases=first_cases)
    second = run_adapter_conformance(second_pep, cases=second_cases)
    assert first == second
    assert serialize_conformance_report(first) == serialize_conformance_report(second)


@pytest.mark.parametrize("cases", [[], (), "cases", object()])
def test_harness_rejects_nonexact_or_empty_case_collections_code_only(cases) -> None:
    pep, _, _ = _pep_and_cases()
    with pytest.raises(ConformanceError, match="CONF-CASES-MALFORMED") as caught:
        run_adapter_conformance(pep, cases=cases)
    assert "secret" not in repr(caught.value)


def test_duplicate_case_names_are_rejected() -> None:
    pep, cases, _ = _pep_and_cases()
    with pytest.raises(ConformanceError, match="CONF-CASES-MALFORMED"):
        run_adapter_conformance(pep, cases=(cases[0], cases[0]))


def test_case_rejects_nonbytes_or_empty_planted_secret() -> None:
    _, cases, _ = _pep_and_cases()
    with pytest.raises(ConformanceError, match="CONF-CASE-MALFORMED"):
        AdapterConformanceCaseV1(
            name="bad-secret",
            request=cases[0].request,
            runtime=cases[0].runtime,
            effect=cases[0].effect,
            expected_code=EnforcementCodeV1.EXECUTED,
            expected_invoked=True,
            planted_secrets=(b"",),
        )


def test_harness_module_has_no_network_clock_or_environment_imports() -> None:
    path = Path(__file__).parents[1] / "src/mcp_warden/adapter_conformance.py"
    tree = ast.parse(path.read_text())
    forbidden = {"requests", "httpx", "socket", "urllib", "time", "datetime", "os"}
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert not imports & forbidden


def test_conformance_serializer_rejects_self_digest_forgery() -> None:
    pep, cases, _ = _pep_and_cases()
    report = run_adapter_conformance(pep, cases=cases)
    forged = report.model_copy(update={"passed": False})
    with pytest.raises(ConformanceError, match="CONF-REPORT-INTEGRITY"):
        serialize_conformance_report(forged)


def test_conformance_report_validation_is_code_only_and_frozen() -> None:
    with pytest.raises(ConformanceError, match="CONF-REPORT-MALFORMED") as caught:
        ConformanceReportV1(
            schema_version=1,
            corpus_version="dse716-foundation-v1",
            manifest_digest="secret-invalid-digest",
            total_cases=1,
            caller_cases=1,
            fixed_cases=0,
            instrumented_cases=1,
            registration_operations=(),
            passed=True,
            covered_operations=(),
            failures=(),
            report_digest="secret-invalid-digest",
        )
    assert "secret" not in str(caught.value)
    assert caught.value.__context__ is None

    pep, cases, _ = _pep_and_cases()
    report = run_adapter_conformance(pep, cases=cases)
    with pytest.raises(ConformanceError, match="CONF-REPORT-MALFORMED"):
        del report.report_digest  # type: ignore[misc]
