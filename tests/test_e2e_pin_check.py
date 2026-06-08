"""End-to-end acceptance test: real stdio round-trip (the headline demo).

Spawns the CLEAN fixture -> ``pin`` -> re-runs ``check`` against the MUTATED
fixture -> asserts non-zero exit AND the expected drift + SARIF finding.

This is NOT a mock: ``capture_surface_sync`` spawns each fixture as a real child
MCP server over stdio via the official MCP SDK.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcp_warden.capture import CaptureError, capture_surface_sync
from mcp_warden.checks import run_checks
from mcp_warden.drift import compute_drift
from mcp_warden.emitters import build_sarif, sarif_to_json
from mcp_warden.lockfile import build_lock, read_lock, write_lock

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = str(FIXTURES / "clean_server.py")
MUTATED = str(FIXTURES / "mutated_server.py")
PY = sys.executable


def test_clean_capture_roundtrip():
    surface = capture_surface_sync(PY, [CLEAN])
    names = sorted(t.name for t in surface.tools)
    assert names == ["list_dir", "read_file"]
    assert any(r.uri == "file:///etc/motd" for r in surface.resources)
    assert any(p.name == "summarize" for p in surface.prompts)
    assert surface.protocol_version  # initialize echoed a protocol version


def test_pin_then_check_clean_is_no_drift(tmp_path):
    surface = capture_surface_sync(PY, [CLEAN])
    lock = build_lock(surface, run_checks(surface), approve=True, approver="ci-bot@example.invalid")
    write_lock(lock, tmp_path / "warden.lock")

    baseline = read_lock(tmp_path / "warden.lock")
    surface2 = capture_surface_sync(PY, [CLEAN])
    current = build_lock(surface2, run_checks(surface2))
    assert compute_drift(baseline, current) == []
    # Reproducibility across two independent captures of the same server.
    assert baseline.overall_digest == current.overall_digest


def test_pin_clean_then_check_mutated_detects_drift_and_sarif(tmp_path):
    # 1. Pin the clean server.
    clean_surface = capture_surface_sync(PY, [CLEAN])
    clean_lock = build_lock(
        clean_surface, run_checks(clean_surface), approve=True, approver="ci-bot@example.invalid"
    )
    lock_path = tmp_path / "warden.lock"
    write_lock(clean_lock, lock_path)

    # 2. Re-run check against the mutated server.
    baseline = read_lock(lock_path)
    mutated_surface = capture_surface_sync(PY, [MUTATED])
    mutated_findings = run_checks(mutated_surface)
    mutated_lock = build_lock(mutated_surface, mutated_findings)

    drift = compute_drift(baseline, mutated_lock)

    # --- Assert the expected drift set (non-empty => non-zero CI exit) ---
    assert drift, "expected drift between clean and mutated surfaces"
    classes = {d.drift_class for d in drift}
    # Added shell tool
    assert "tool-added" in classes
    assert any(d.target == "tools/run_command" and d.severity == "high" for d in drift)
    # read_file schema changed: adding an unconstrained "encoding" string param
    # is now classified granularly (#15) as schema-unconstrained-added (high).
    assert "schema-unconstrained-added" in classes
    assert any(
        d.target == "tools/read_file" and d.drift_class == "schema-unconstrained-added"
        for d in drift
    )
    # The legacy blob-level class must NOT fire now that skeletons are present.
    assert "schema-modified" not in classes
    # unapproved-change because the clean lock was approved
    assert "unapproved-change" in classes

    # --- Assert the SARIF finding for the dangerous new shell tool ---
    sarif = build_sarif(mutated_findings, drift)
    text = sarif_to_json(sarif)
    parsed = json.loads(text)
    results = parsed["runs"][0]["results"]
    rule_ids = {r["ruleId"] for r in results}
    assert "WRD-CAP-SHELL" in rule_ids  # static finding on run_command
    assert "WRD-DRIFT-TOOL-ADDED" in rule_ids  # drift result
    # The shell finding must be error-level.
    shell = [r for r in results if r["ruleId"] == "WRD-CAP-SHELL"][0]
    assert shell["level"] == "error"


def test_check_exit_code_via_simulated_cli(tmp_path):
    """Mirror the CLI exit semantics: drift -> non-zero."""
    clean_surface = capture_surface_sync(PY, [CLEAN])
    write_lock(build_lock(clean_surface, run_checks(clean_surface)), tmp_path / "warden.lock")

    baseline = read_lock(tmp_path / "warden.lock")
    mutated_surface = capture_surface_sync(PY, [MUTATED])
    current = build_lock(mutated_surface, run_checks(mutated_surface))
    drift = compute_drift(baseline, current)
    exit_code = 1 if drift else 0
    assert exit_code == 1


def test_capture_error_on_bad_command():
    with pytest.raises(CaptureError):
        capture_surface_sync("this-command-does-not-exist-xyz", [], timeout_s=5.0)


def test_capture_error_on_non_mcp_process():
    # `true` exits 0 immediately and speaks no MCP -> clean CaptureError, not traceback.
    with pytest.raises(CaptureError):
        capture_surface_sync(PY, ["-c", "pass"], timeout_s=8.0)
