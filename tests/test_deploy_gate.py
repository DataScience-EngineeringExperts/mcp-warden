"""Fail-closed deploy-gate tests (WRD-GATE-*) — DSE-1257.

Covers the pure ``evaluate_gate`` engine (each control passing + each failing,
plus fail-closed on missing/malformed evidence) and the ``deploy-gate`` CLI
(exit codes, JSON, fail-closed on unreadable inputs).
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from mcp_warden.cli import app
from mcp_warden.deploy_gate import DeployGateError, evaluate_gate

runner = CliRunner()


def _rules(outcome):
    return {f.rule_id for f in outcome.findings}


FULL_POLICY = {
    "required_evals": [{"suite": "safety", "min_score": 0.9}],
    "required_guardrails": ["prompt-injection", "pii-redaction"],
    "require_budget": True,
    "require_approval": True,
}

FULL_EVIDENCE = {
    "evals": {"safety": {"score": 0.95}},
    "guardrails": ["prompt-injection", "pii-redaction"],
    "budget": {"limit": 100},
    "approval": {"approved": True, "approver": "ernest@thedataexperts.us"},
}


def test_fully_satisfied_gate_passes():
    outcome = evaluate_gate(FULL_POLICY, FULL_EVIDENCE)
    assert outcome.passed
    assert outcome.controls_checked == 5


def test_eval_below_threshold_fails():
    ev = {**FULL_EVIDENCE, "evals": {"safety": {"score": 0.5}}}
    outcome = evaluate_gate(FULL_POLICY, ev)
    assert not outcome.passed
    assert "WRD-GATE-EVAL-THRESHOLD" in _rules(outcome)


def test_missing_eval_suite_fails_closed():
    ev = {**FULL_EVIDENCE, "evals": {}}
    assert "WRD-GATE-EVAL-MISSING" in _rules(evaluate_gate(FULL_POLICY, ev))


def test_non_numeric_eval_score_fails_closed():
    ev = {**FULL_EVIDENCE, "evals": {"safety": {"score": "great"}}}
    assert "WRD-GATE-EVAL-MALFORMED" in _rules(evaluate_gate(FULL_POLICY, ev))


def test_missing_guardrail_fails():
    ev = {**FULL_EVIDENCE, "guardrails": ["prompt-injection"]}
    outcome = evaluate_gate(FULL_POLICY, ev)
    assert "WRD-GATE-GUARDRAIL-MISSING" in _rules(outcome)


def test_missing_budget_fails_when_required():
    ev = {k: v for k, v in FULL_EVIDENCE.items() if k != "budget"}
    assert "WRD-GATE-BUDGET-MISSING" in _rules(evaluate_gate(FULL_POLICY, ev))


def test_non_positive_budget_fails():
    ev = {**FULL_EVIDENCE, "budget": {"limit": 0}}
    assert "WRD-GATE-BUDGET-INVALID" in _rules(evaluate_gate(FULL_POLICY, ev))


def test_missing_approval_fails_when_required():
    ev = {k: v for k, v in FULL_EVIDENCE.items() if k != "approval"}
    assert "WRD-GATE-APPROVAL-MISSING" in _rules(evaluate_gate(FULL_POLICY, ev))


def test_unapproved_receipt_fails():
    ev = {**FULL_EVIDENCE, "approval": {"approved": False, "approver": "x"}}
    assert "WRD-GATE-APPROVAL-INVALID" in _rules(evaluate_gate(FULL_POLICY, ev))


def test_unattributed_approval_fails():
    ev = {**FULL_EVIDENCE, "approval": {"approved": True, "approver": ""}}
    assert "WRD-GATE-APPROVAL-INVALID" in _rules(evaluate_gate(FULL_POLICY, ev))


def test_empty_policy_passes_vacuously_but_reports_zero_controls():
    outcome = evaluate_gate({}, {})
    assert outcome.passed
    assert outcome.controls_checked == 0


def test_malformed_evals_evidence_block_fails_closed():
    outcome = evaluate_gate(FULL_POLICY, {**FULL_EVIDENCE, "evals": ["not", "a", "dict"]})
    assert "WRD-GATE-EVAL-EVIDENCE" in _rules(outcome)


def _write(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return p


def test_cli_pass_exit_zero(tmp_path):
    policy = _write(tmp_path, "policy.json", FULL_POLICY)
    evidence = _write(tmp_path, "evidence.json", FULL_EVIDENCE)
    result = runner.invoke(app, ["deploy-gate", "--policy", str(policy), "--evidence", str(evidence)])
    assert result.exit_code == 0, result.output


def test_cli_fail_exit_one(tmp_path):
    policy = _write(tmp_path, "policy.json", FULL_POLICY)
    bad = {**FULL_EVIDENCE, "approval": {"approved": False, "approver": "x"}}
    evidence = _write(tmp_path, "evidence.json", bad)
    result = runner.invoke(app, ["deploy-gate", "--policy", str(policy), "--evidence", str(evidence)])
    assert result.exit_code == 1, result.output


def test_cli_json_output(tmp_path):
    policy = _write(tmp_path, "policy.json", FULL_POLICY)
    bad = {**FULL_EVIDENCE, "guardrails": []}
    evidence = _write(tmp_path, "evidence.json", bad)
    result = runner.invoke(app, ["deploy-gate", "--policy", str(policy), "--evidence", str(evidence), "--json"])
    assert result.exit_code == 1
    assert any("WRD-GATE-" in line for line in result.stdout.splitlines() if line.strip())


def test_cli_unreadable_evidence_exit_two(tmp_path):
    policy = _write(tmp_path, "policy.json", FULL_POLICY)
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{ broken")
    result = runner.invoke(app, ["deploy-gate", "--policy", str(policy), "--evidence", str(evidence)])
    assert result.exit_code == 2


def test_non_object_policy_document_fails_closed(tmp_path):
    import pytest

    from mcp_warden.deploy_gate import run_deploy_gate

    policy = tmp_path / "policy.json"
    policy.write_text("[1, 2, 3]")
    evidence = _write(tmp_path, "evidence.json", FULL_EVIDENCE)
    with pytest.raises(DeployGateError):
        run_deploy_gate(policy, evidence)


def test_malformed_eval_spec_entries_are_skipped():
    policy = {"required_evals": ["not-a-dict", {"suite": "safety", "min_score": 0.9}]}
    outcome = evaluate_gate(policy, {"evals": {"safety": {"score": 0.99}}})
    assert outcome.passed


def test_cli_sarif_output(tmp_path):
    policy = _write(tmp_path, "policy.json", FULL_POLICY)
    bad = {**FULL_EVIDENCE, "budget": {"limit": 0}}
    evidence = _write(tmp_path, "evidence.json", bad)
    sarif = tmp_path / "gate.sarif"
    result = runner.invoke(
        app, ["deploy-gate", "--policy", str(policy), "--evidence", str(evidence), "--sarif", str(sarif)]
    )
    assert result.exit_code == 1
    doc = json.loads(sarif.read_text())
    assert doc["runs"][0]["results"]


def test_run_deploy_gate_raises_on_missing_file(tmp_path):
    import pytest

    from mcp_warden.deploy_gate import run_deploy_gate

    with pytest.raises(DeployGateError):
        run_deploy_gate(tmp_path / "nope.json", tmp_path / "also-nope.json")
