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
        },
    }


def build_result_sarif(findings: list[ResultFinding]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from result-inspection findings.

    Args:
        findings: The stamped :class:`ResultFinding` list.

    Returns:
        A SARIF ``dict`` ready for ``json.dumps``.
    """
    rule_ids = sorted({f.rule_id for f in findings})
    rules = [{"id": rid, "name": rid} for rid in rule_ids]
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
                "results": [_sarif_result(f) for f in findings],
            }
        ],
    }


def result_sarif_to_json(sarif: dict[str, Any]) -> str:
    """Serialize a result-inspection SARIF log to indented JSON (trailing newline)."""
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


def result_finding_to_dict(f: ResultFinding) -> dict[str, Any]:
    """JSON-serializable record for one finding (one JSONL line)."""
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
    }


def result_findings_to_jsonl(findings: list[ResultFinding]) -> str:
    """Serialize result findings as newline-delimited JSON (one record per line)."""
    lines = [json.dumps(result_finding_to_dict(f), ensure_ascii=False) for f in findings]
    return "\n".join(lines) + ("\n" if lines else "")
