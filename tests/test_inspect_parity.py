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
    """The comparable (rule_id, tool, direction) set, restricted to result rules."""
    return {
        (f["rule_id"], f["tool"], f["direction"])
        for f in findings
        if f["rule_id"].startswith("WRD-RES-") and f["rule_id"] != "WRD-RES-FRAME-ERROR"
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
    assert any(f["tier"] == "block" for f in findings)
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
