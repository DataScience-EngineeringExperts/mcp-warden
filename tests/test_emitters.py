"""SARIF + JSONL emitter tests (CHECKS.md §2)."""

from __future__ import annotations

import json

from mcp_warden.drift import DriftItem
from mcp_warden.emitters import (
    build_sarif,
    findings_to_jsonl,
    severity_to_level,
)
from mcp_warden.models import Finding


def test_level_mapping():
    assert severity_to_level("critical") == "error"
    assert severity_to_level("high") == "error"
    assert severity_to_level("medium") == "warning"
    assert severity_to_level("low") == "note"


def test_sarif_shape_and_ruleid_verbatim():
    findings = [
        Finding(rule_id="WRD-CAP-SHELL", severity="critical", target="tools/run", message="m", snippet="command"),
    ]
    sarif = build_sarif(findings)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-warden"
    result = run["results"][0]
    # ruleId is the check ID verbatim
    assert result["ruleId"] == "WRD-CAP-SHELL"
    assert result["level"] == "error"
    # rule registered in driver.rules
    assert any(r["id"] == "WRD-CAP-SHELL" for r in run["tool"]["driver"]["rules"])
    # physicalLocation must be present so GitHub Code Scanning accepts the SARIF
    loc = result["locations"][0]
    assert "physicalLocation" in loc, "Each location must have physicalLocation for GitHub Code Scanning"
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "warden.lock"
    # logicalLocations must still be present alongside physicalLocation
    assert "logicalLocations" in loc


def test_sarif_includes_drift_results():
    drift = [DriftItem("tool-added", "high", "tools/evil", "Tool 'evil' added since pin")]
    sarif = build_sarif([], drift)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "WRD-DRIFT-TOOL-ADDED"
    assert result["level"] == "error"
    # physicalLocation must be present on drift results too
    loc = result["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "warden.lock"


def test_sarif_is_valid_json():
    sarif = build_sarif([Finding(rule_id="WRD-SEC-OPENAI", severity="critical", target="tools/t", message="m", snippet="sk-a…(len=22)")])
    text = json.dumps(sarif)
    json.loads(text)  # round-trips


def test_jsonl_one_record_per_line():
    findings = [
        Finding(rule_id="WRD-CAP-FS-READ", severity="medium", target="tools/read", message="m", snippet="path"),
    ]
    drift = [DriftItem("tool-added", "high", "tools/x", "added")]
    out = findings_to_jsonl(findings, drift)
    lines = [ln for ln in out.splitlines() if ln]
    assert len(lines) == 2
    rec0 = json.loads(lines[0])
    assert rec0["kind"] == "finding"
    rec1 = json.loads(lines[1])
    assert rec1["kind"] == "drift"
    assert rec1["rule_id"] == "WRD-DRIFT-TOOL-ADDED"


def test_sarif_schema_drift_carries_detail_and_schemapath():
    drift = [
        DriftItem(
            "schema-constraint-relaxed",
            "medium",
            "tools/read_file",
            "Tool 'read_file' schema schema-constraint-relaxed at 'a'",
            detail="maxLength 64→4096",
        )
    ]
    sarif = build_sarif([], drift)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "WRD-DRIFT-SCHEMA-CONSTRAINT-RELAXED"
    props = result["properties"]
    assert props["detail"] == "maxLength 64→4096"
    assert props["schemaPath"] == "tools/read_file"


def test_jsonl_schema_drift_includes_detail_field():
    drift = [
        DriftItem("schema-enum-widened", "high", "tools/t", "msg", detail="enum 1→3 values"),
        DriftItem("tool-added", "high", "tools/x", "added"),
    ]
    out = findings_to_jsonl([], drift)
    recs = [json.loads(ln) for ln in out.splitlines() if ln]
    assert recs[0]["detail"] == "enum 1→3 values"
    # Non-schema drift carries a null detail (field always present).
    assert recs[1]["detail"] is None


def test_jsonl_snippet_redacted_preserved():
    findings = [Finding(rule_id="WRD-SEC-OPENAI", severity="critical", target="tools/t", message="m", snippet="sk-a…(len=51)")]
    out = findings_to_jsonl(findings)
    rec = json.loads(out.strip())
    assert rec["snippet"] == "sk-a…(len=51)"


def test_every_result_location_has_physical_location_uri():
    """Invariant: every runs[].results[].locations[] must have physicalLocation.artifactLocation.uri.

    GitHub Code Scanning hard-rejects SARIF results lacking physicalLocation.
    This invariant guards against regressions in either _result_from_finding or
    _result_from_drift.
    """
    findings = [
        Finding(rule_id="WRD-CAP-SHELL", severity="critical", target="tools/run", message="m", snippet="x"),
        Finding(rule_id="WRD-SEC-OPENAI", severity="high", target="tools/t", message="m2", snippet="y"),
    ]
    drift = [
        DriftItem("tool-added", "high", "tools/evil", "added"),
        DriftItem("schema-constraint-relaxed", "medium", "tools/read_file", "relaxed", detail="maxLength 64→4096"),
    ]
    sarif = build_sarif(findings, drift)
    assert sarif["version"] == "2.1.0"
    for run_idx, run in enumerate(sarif["runs"]):
        for res_idx, result in enumerate(run["results"]):
            for loc_idx, loc in enumerate(result["locations"]):
                uri = (
                    loc.get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "")
                )
                assert uri, (
                    f"runs[{run_idx}].results[{res_idx}].locations[{loc_idx}] "
                    f"is missing physicalLocation.artifactLocation.uri — "
                    f"GitHub Code Scanning will reject this SARIF result "
                    f"(ruleId={result.get('ruleId')!r})"
                )
