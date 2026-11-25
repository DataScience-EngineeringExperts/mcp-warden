"""Parity test (non-negotiable #1): guard and inspect agree on the same frames.

Record a real guard session (--record) in shadow mode, then run `inspect` over the
trace and assert the (rule_id, tool, direction) findings are IDENTICAL. Also asserts
inspect's exit codes (non-zero on BLOCK-tier; --audit-only forces 0).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.test_guard_proxy import GuardClient  # reuse the real driver

REPO = Path(__file__).resolve().parent.parent
PY = sys.executable


def _run_recording_session(tmp_path: Path) -> tuple[Path, Path]:
    """Drive a shadow-mode guard session that records its frames + finding sink."""
    trace = tmp_path / "trace.jsonl"
    sink = tmp_path / "guard_findings.jsonl"
    client = GuardClient("--record", str(trace), "--json", str(sink))
    try:
        client.initialize()
        client.call_and_get(2, "ansi_tool")
        client.call_and_get(3, "secret_tool")
        client.call_and_get(4, "exfil_tool")
        client.call_and_get(5, "inject_tool")
        client.call_and_get(6, "clean_tool")
        client.call_and_get(7, "ip_literal_tool")
    finally:
        client.close()
    return trace, sink


def _run_inspect(trace: Path, tmp_path: Path, *extra: str) -> tuple[int, list[dict]]:
    """Run `mcp-warden inspect` over a trace; return (exit_code, findings)."""
    out = tmp_path / "inspect.jsonl"
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
    proc = subprocess.run(
        [PY, "-m", "mcp_warden.cli", "inspect", str(trace), "--json", str(out), *extra],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        timeout=60,
    )
    findings = [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()] if out.exists() else []
    return proc.returncode, findings


def _result_keys(findings: list[dict]) -> set[tuple]:
    """The comparable (rule_id, tool, direction) set, restricted to result rules.

    Skips the additive ``run-summary`` record (issue #12), which carries counts
    (no ``rule_id``) rather than a finding.
    """
    return {
        (f["rule_id"], f["tool"], f["direction"])
        for f in findings
        if f.get("kind") == "result-finding"
        and f["rule_id"].startswith("WRD-RES-")
        and f["rule_id"] != "WRD-RES-FRAME-ERROR"
    }


def test_guard_and_inspect_agree_on_findings(tmp_path):
    trace, sink = _run_recording_session(tmp_path)
    assert trace.exists() and trace.read_text().strip(), "guard must have recorded frames"

    guard_findings = [json.loads(ln) for ln in sink.read_text().splitlines() if ln.strip()]
    _code, inspect_findings = _run_inspect(trace, tmp_path)

    guard_set = _result_keys(guard_findings)
    inspect_set = _result_keys(inspect_findings)
    assert guard_set, "guard produced result findings"
    assert guard_set == inspect_set, f"parity mismatch: guard={guard_set} inspect={inspect_set}"

    # The new BLOCK rule must appear in BOTH sides (proves end-to-end parity for it).
    assert any(k[0] == "WRD-RES-EXFIL-IP-LITERAL" for k in guard_set), guard_set
    assert any(k[0] == "WRD-RES-EXFIL-IP-LITERAL" for k in inspect_set), inspect_set


def test_inspect_exit_nonzero_on_block_tier(tmp_path):
    trace, _sink = _run_recording_session(tmp_path)
    code, findings = _run_inspect(trace, tmp_path)
    # ANSI/SECRET-ECHO/EXFIL are BLOCK-tier and present -> non-zero exit (CI-usable).
    assert any(f.get("tier") == "block" for f in findings)
    assert code != 0


def test_inspect_audit_only_forces_exit_zero(tmp_path):
    trace, _sink = _run_recording_session(tmp_path)
    code, _findings = _run_inspect(trace, tmp_path, "--audit-only")
    assert code == 0


def test_inspect_trace_read_error_exits_two(tmp_path):
    missing = tmp_path / "nope.jsonl"
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
    proc = subprocess.run(
        [PY, "-m", "mcp_warden.cli", "inspect", str(missing)],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 2



def test_catalog_evidence_agrees_across_guard_and_offline_cli(tmp_path):
    trace = tmp_path / "trace.jsonl"
    guard_json = tmp_path / "guard.jsonl"
    guard_sarif = tmp_path / "guard.sarif"
    inspect_sarif = tmp_path / "inspect.sarif"
    client = GuardClient("--record", str(trace), "--json", str(guard_json), "--sarif", str(guard_sarif),
                         env_extra={"COLUMNS": "200"})
    try:
        client.initialize()
        response = client.call_and_get(2, "catalog_tool")
        assert "Fixture marker: terracotta." in response["result"]["content"][0]["text"]
    finally:
        guard_code = client.close()
    assert guard_code == 0
    guard_stderr = client.proc.stderr.read().decode()

    code, offline = _run_inspect(trace, tmp_path, "--sarif", str(inspect_sarif))
    assert code == 0
    guard = [json.loads(line) for line in guard_json.read_text().splitlines()]
    live_match, = [f for f in guard if f.get("rule_id") == "WRD-RES-INJECT-PHRASE"]
    offline_match, = [f for f in offline if f.get("rule_id") == "WRD-RES-INJECT-PHRASE"]
    assert live_match["action"] == "shadowed"
    assert offline_match["action"] == "reported"
    assert live_match["tier"] == offline_match["tier"] == "monitor"
    assert live_match["matched_phrases"] == offline_match["matched_phrases"] == []
    assert live_match["snippet"] == offline_match["snippet"] == ""
    assert live_match["injection_matches"] == offline_match["injection_matches"]
    match, = live_match["injection_matches"]
    assert match["rule_id"] == "WRD-RES-INJECT-TOOL-COERCION"
    assert match["catalog_version"] == 1
    assert match["evidence_ids"] == ["tool-coercion.must-call"]

    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "COLUMNS": "200"}
    table = subprocess.run(
        [PY, "-m", "mcp_warden.cli", "inspect", str(trace)],
        cwd=str(REPO), env=env, capture_output=True, text=True, timeout=30,
    )
    assert table.returncode == 0
    for output in (guard_stderr, table.stdout):
        assert match["rule_id"] in output
        assert match["evidence_ids"][0] in output
        assert "terracotta" not in output.lower()

    for report in (guard_sarif, inspect_sarif):
        findings = json.loads(report.read_text())["runs"][0]["results"]
        finding, = [f for f in findings if f["ruleId"] == "WRD-RES-INJECT-PHRASE"]
        evidence, = finding["properties"]["injectionMatches"]
        assert evidence == {
            "ruleId": match["rule_id"],
            "catalogVersion": match["catalog_version"],
            "category": match["category"],
            "severity": match["severity"],
            "rationale": match["rationale"],
            "evidenceIds": match["evidence_ids"],
        }
    for report in (guard_json, guard_sarif, tmp_path / "inspect.jsonl", inspect_sarif):
        assert "terracotta" not in report.read_text().lower()
