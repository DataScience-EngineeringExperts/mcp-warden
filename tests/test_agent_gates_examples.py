"""The shipped agent-gate examples must behave exactly as documented.

`examples/agent-gates/README.md` states per-server verdicts and exit codes. A
documented claim nobody verifies rots; these tests pin the examples to their
README so a rule change that alters the demo output fails CI instead of quietly
making the docs wrong.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_warden.auth_audit import audit_path
from mcp_warden.cli import app
from mcp_warden.deploy_gate import run_deploy_gate

runner = CliRunner()

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "agent-gates"
CONFIG = EXAMPLES / "mcp-config-audit-demo.json"
POLICY = EXAMPLES / "gate-policy.json"
EVIDENCE_PASS = EXAMPLES / "evidence-pass.json"
EVIDENCE_FAIL = EXAMPLES / "evidence-fail.json"

#: README table: which server yields which rules.
EXPECTED_AUTH = {
    "mcpServers/internal-http": {"WRD-AUTH-PLAINTEXT-HTTP", "WRD-AUTH-NOAUTH"},
    "mcpServers/vendor-api": {"WRD-AUTH-TOKEN-IN-CONFIG", "WRD-SEC-ENTROPY"},
    "mcpServers/legacy": {"WRD-AUTH-URL-CREDENTIAL", "WRD-AUTH-NOAUTH"},
}

#: README: these three are correct configuration and must never be flagged.
CLEAN_SERVERS = {"mcpServers/filesystem-local", "mcpServers/loopback-dev", "mcpServers/good-citizen"}


def test_example_files_exist():
    for p in (CONFIG, POLICY, EVIDENCE_PASS, EVIDENCE_FAIL):
        assert p.is_file(), f"shipped example missing: {p}"


def test_auth_demo_matches_documented_verdicts():
    findings = audit_path(CONFIG)
    by_target: dict[str, set[str]] = {}
    for f in findings:
        by_target.setdefault(f.target, set()).add(f.rule_id)
    assert by_target == EXPECTED_AUTH
    assert len(findings) == 6, "README says six findings"


def test_auth_demo_never_flags_the_correct_servers():
    targets = {f.target for f in audit_path(CONFIG)}
    assert not (targets & CLEAN_SERVERS), "a correct config was flagged — false positive"


def test_auth_demo_leaks_no_credential():
    # The two fake credentials planted in the demo config must never appear in
    # any finding field.
    planted = ("hunter2pass", "sk-live-9f2c8a7b6d5e4f3a2b1c0d9e")
    blob = json.dumps([f.model_dump() for f in audit_path(CONFIG)])
    for secret in planted:
        assert secret not in blob, f"credential leaked into findings: {secret[:6]}..."


def test_gate_pass_example_passes():
    outcome = run_deploy_gate(POLICY, EVIDENCE_PASS)
    assert outcome.passed
    assert outcome.controls_checked == 6


def test_gate_fail_example_trips_exactly_four_controls():
    outcome = run_deploy_gate(POLICY, EVIDENCE_FAIL)
    assert not outcome.passed
    assert {f.rule_id for f in outcome.findings} == {
        "WRD-GATE-EVAL-THRESHOLD",
        "WRD-GATE-GUARDRAIL-MISSING",
        "WRD-GATE-BUDGET-INVALID",
        "WRD-GATE-APPROVAL-INVALID",
    }


def test_documented_cli_exit_codes():
    assert runner.invoke(app, ["auth", "audit", str(CONFIG)]).exit_code == 1
    assert (
        runner.invoke(
            app, ["deploy-gate", "--policy", str(POLICY), "--evidence", str(EVIDENCE_PASS)]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["deploy-gate", "--policy", str(POLICY), "--evidence", str(EVIDENCE_FAIL)]
        ).exit_code
        == 1
    )
