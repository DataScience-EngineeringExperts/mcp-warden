"""SARIF + JSONL emitters (CHECKS.md §2).

``ruleId`` == the check ID verbatim. Level mapping (§2):
  critical/high -> ``error``, medium -> ``warning``, low -> ``note``.

Drift items are also emitted as SARIF results so ``check`` output points at the
exact entry that changed; their ``ruleId`` is ``WRD-DRIFT-<CLASS>``.
"""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .drift import DriftItem
from .models import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "mcp-warden"
INFO_URI = "https://github.com/dse/mcp-warden"

#: Severity -> SARIF level (CHECKS.md §2).
_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def severity_to_level(severity: str) -> str:
    """Map a severity to a SARIF level (defaults to ``warning`` if unknown)."""
    return _LEVEL_MAP.get(severity, "warning")


def _result_from_finding(f: Finding) -> dict[str, Any]:
    """Build a SARIF result object from a static-check finding."""
    return {
        "ruleId": f.rule_id,
        "level": severity_to_level(f.severity),
        "message": {"text": f"{f.message} [{f.snippet}]"},
        "locations": [
            {"logicalLocations": [{"fullyQualifiedName": f.target, "kind": "resource"}]}
        ],
        "properties": {"severity": f.severity, "target": f.target},
    }


def _result_from_drift(d: DriftItem) -> dict[str, Any]:
    """Build a SARIF result object from a drift item.

    Schema drift (#15) carries an optional compact ``detail`` (e.g.
    ``"maxLength 64→4096"``) surfaced under ``properties.detail`` and the changed
    entry under ``properties.schemaPath`` for downstream tooling.
    """
    rule_id = f"WRD-DRIFT-{d.drift_class.upper()}"
    properties: dict[str, Any] = {
        "severity": d.severity,
        "target": d.target,
        "driftClass": d.drift_class,
        "schemaPath": d.target,
    }
    if d.detail is not None:
        properties["detail"] = d.detail
    return {
        "ruleId": rule_id,
        "level": severity_to_level(d.severity),
        "message": {"text": d.message},
        "locations": [
            {"logicalLocations": [{"fullyQualifiedName": d.target, "kind": "resource"}]}
        ],
        "properties": properties,
    }


def build_sarif(findings: list[Finding], drift: list[DriftItem] | None = None) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log object from findings and (optional) drift.

    Args:
        findings: Static-check findings (snippets already redacted).
        drift: Drift items from ``check`` (omitted for ``pin``-only output).

    Returns:
        A SARIF 2.1.0 ``dict`` ready for ``json.dumps``.
    """
    drift = drift or []

    rule_ids = sorted({f.rule_id for f in findings} | {f"WRD-DRIFT-{d.drift_class.upper()}" for d in drift})
    rules = [{"id": rid, "name": rid} for rid in rule_ids]

    results: list[dict[str, Any]] = [_result_from_finding(f) for f in findings]
    results.extend(_result_from_drift(d) for d in drift)

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def sarif_to_json(sarif: dict[str, Any]) -> str:
    """Serialize a SARIF log to indented JSON text (trailing newline)."""
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def findings_to_jsonl(findings: list[Finding], drift: list[DriftItem] | None = None) -> str:
    """Serialize findings + drift as newline-delimited JSON (one record per line).

    Args:
        findings: Static-check findings.
        drift: Optional drift items.

    Returns:
        JSONL text. Each line is a self-contained JSON object with a ``kind``
        discriminator (``"finding"`` or ``"drift"``).
    """
    lines: list[str] = []
    for f in findings:
        lines.append(
            json.dumps(
                {
                    "kind": "finding",
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "level": severity_to_level(f.severity),
                    "target": f.target,
                    "message": f.message,
                    "snippet": f.snippet,
                },
                ensure_ascii=False,
            )
        )
    for d in drift or []:
        lines.append(
            json.dumps(
                {
                    "kind": "drift",
                    "rule_id": f"WRD-DRIFT-{d.drift_class.upper()}",
                    "drift_class": d.drift_class,
                    "severity": d.severity,
                    "level": severity_to_level(d.severity),
                    "target": d.target,
                    "message": d.message,
                    "detail": d.detail,
                },
                ensure_ascii=False,
            )
        )
    return "\n".join(lines) + ("\n" if lines else "")
