"""SARIF + JSONL emitters for result-inspection findings (GUARD_PROXY.md §10).

Same SARIF 2.1.0 + JSONL shape as v0.1 (``emitters.py`` / CHECKS.md §2). ``ruleId``
== the ``WRD-RES-*`` / ``POL-*`` id verbatim; ``level`` per the severity mapping.
Each result records ``direction``, the JSON-RPC ``id``, the tool, the content-block
index, the tier, and ``properties.action`` (``blocked|shadowed|modified|passed``).

All secret snippets arrive already redacted (``checks_secret``/``redact``); this
module never sees or emits a raw secret.
"""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .emitters import INFO_URI, SARIF_SCHEMA, SARIF_VERSION, TOOL_NAME, severity_to_level
from .result_inspection import ResultFinding


def _sarif_result(f: ResultFinding) -> dict[str, Any]:
    """Build a SARIF result object from a :class:`ResultFinding`."""
    msg = f.message + (f" [{f.snippet}]" if f.snippet else "")
    return {
        "ruleId": f.rule_id,
        "level": severity_to_level(f.severity),
        "message": {"text": msg},
        "locations": [
            {"logicalLocations": [{"fullyQualifiedName": f"tools/{f.tool}", "kind": "resource"}]}
        ],
        "properties": {
            "severity": f.severity,
            "tier": f.tier,
            "action": f.action,
            "direction": f.direction,
            "rpcId": f.rpc_id,
            "tool": f.tool,
            "contentBlockIndex": f.block_index,
            "subRule": f.sub_rule,
            # Curated denylist phrases only (never raw result content) — issue #12.
            "matchedPhrases": list(f.matched_phrases),
        },
    }


def build_result_sarif(
    findings: list[ResultFinding], *, frames_inspected: int | None = None
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from result-inspection findings.

    Args:
        findings: The stamped :class:`ResultFinding` list.
        frames_inspected: Optional count of ``tools/call`` result frames inspected
            this run. When supplied it is attached as a run-level
            ``properties.framesInspected`` so a per-phrase FP rate has a base-rate
            denominator (issue #12). It is a plain count — no result content.

    Returns:
        A SARIF ``dict`` ready for ``json.dumps``.
    """
    rule_ids = sorted({f.rule_id for f in findings})
    rules = [{"id": rid, "name": rid} for rid in rule_ids]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": __version__,
                "informationUri": INFO_URI,
                "rules": rules,
            }
        },
        "results": [_sarif_result(f) for f in findings],
    }
    if frames_inspected is not None:
        run["properties"] = {"framesInspected": frames_inspected}
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [run],
    }


def result_sarif_to_json(sarif: dict[str, Any]) -> str:
    """Serialize a result-inspection SARIF log to indented JSON (trailing newline)."""
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def result_finding_to_dict(f: ResultFinding) -> dict[str, Any]:
    """JSON-serializable record for one finding (one JSONL line).

    ``matched_phrases`` carries the discrete curated denylist phrases for a
    ``WRD-RES-INJECT-PHRASE`` finding (empty for every other rule). It is sourced
    from our own denylist — NEVER from raw result content — so per-phrase FP
    aggregation reads a structured field instead of parsing ``message`` (#12).
    """
    return {
        "kind": "result-finding",
        "rule_id": f.rule_id,
        "sub_rule": f.sub_rule,
        "severity": f.severity,
        "level": severity_to_level(f.severity),
        "tier": f.tier,
        "action": f.action,
        "direction": f.direction,
        "rpc_id": f.rpc_id,
        "tool": f.tool,
        "block_index": f.block_index,
        "message": f.message,
        "snippet": f.snippet,
        "matched_phrases": list(f.matched_phrases),
    }


def run_summary_to_dict(*, frames_inspected: int, inject_phrase_findings: int = 0) -> dict[str, Any]:
    """Build the one-line ``run-summary`` telemetry record (issue #12).

    The summary gives a per-phrase FP rate its **base rate**: ``frames_inspected``
    is the denominator (every ``tools/call`` result frame the catalog inspected
    this run) and ``inject_phrase_findings`` is a convenience numerator (how many
    ``WRD-RES-INJECT-PHRASE`` findings fired). It carries ONLY counts — never any
    result content, phrase text, tool arguments, or secrets.

    Args:
        frames_inspected: Count of inspected ``tools/call`` result frames.
        inject_phrase_findings: Count of ``WRD-RES-INJECT-PHRASE`` findings.

    Returns:
        A JSON-serializable ``run-summary`` record.
    """
    return {
        "kind": "run-summary",
        "frames_inspected": frames_inspected,
        "inject_phrase_findings": inject_phrase_findings,
    }


def result_findings_to_jsonl(
    findings: list[ResultFinding], *, summary: dict[str, Any] | None = None
) -> str:
    """Serialize result findings as newline-delimited JSON (one record per line).

    Args:
        findings: The stamped findings (one ``result-finding`` record per line).
        summary: Optional ``run-summary`` record (see :func:`run_summary_to_dict`)
            appended as a final, distinctly-``kind``ed line so a consumer reads the
            base-rate denominator from the same stream (issue #12).

    Returns:
        Newline-delimited JSON; empty string when there is nothing to emit.
    """
    lines = [json.dumps(result_finding_to_dict(f), ensure_ascii=False) for f in findings]
    if summary is not None:
        lines.append(json.dumps(summary, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")
