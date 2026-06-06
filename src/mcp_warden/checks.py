"""Static-check engine orchestrator (CHECKS.md).

Runs the full ``WRD-*`` catalog over a captured surface:
  - capability checks ``WRD-CAP-*`` (via the shared tokenizer),
  - secret checks ``WRD-SEC-*`` (checks_secret),
  - supply-chain checks ``WRD-SUP-*`` (checks_supply),
  - robustness ``WRD-SCHEMA-MALFORMED``.

Findings are returned sorted by ``(target, rule_id)`` for deterministic output
(CHECKS.md §5.1). CUT items (fuzzy/NLP, result scanning, etc.) are NOT here.
"""

from __future__ import annotations

from typing import Any

from .checks_secret import scan_field
from .checks_supply import check_launch_command
from .models import CapturedSurface, Finding
from .tokenizer import capability_evidence, derive_capabilities

# Capability flag -> (rule_id, severity) per CHECKS.md §4.1.
_CAP_RULES: dict[str, tuple[str, str]] = {
    "shell-exec": ("WRD-CAP-SHELL", "critical"),
    "fs-write": ("WRD-CAP-FS-WRITE", "high"),
    "fs-read": ("WRD-CAP-FS-READ", "medium"),
    "http-request": ("WRD-CAP-HTTP", "high"),
    "sql-query": ("WRD-CAP-SQL", "high"),
}


def _string_values_from_schema(schema: dict[str, Any]) -> list[str]:
    """Collect string ``default``/``enum``/``examples`` values from a JSON Schema.

    Recurses nested schemas (``properties``, ``items``, ``$defs``, etc.). Property
    *keys* are intentionally NOT scanned (CHECKS.md §4.2 — a key named ``api_key``
    is not a leak).

    Args:
        schema: A JSON Schema fragment.

    Returns:
        Flat list of candidate string values to run secret scans over.
    """
    out: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("default"), str):
                out.append(node["default"])
            enum = node.get("enum")
            if isinstance(enum, list):
                out.extend(v for v in enum if isinstance(v, str))
            examples = node.get("examples")
            if isinstance(examples, list):
                out.extend(v for v in examples if isinstance(v, str))
            for key, val in node.items():
                if key in ("default", "enum", "examples"):
                    continue
                walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(schema)
    return out


def _schema_is_malformed(schema: Any) -> bool:
    """Return True if an inputSchema is present but not analyzable (not an object)."""
    return schema is not None and not isinstance(schema, dict)


def run_checks(surface: CapturedSurface) -> list[Finding]:
    """Run the full static-check catalog over a captured surface.

    Args:
        surface: The captured declared surface.

    Returns:
        Deterministically sorted (by ``target``, then ``rule_id``) list of
        findings. Secret snippets are redacted by the scanners.
    """
    findings: list[Finding] = []

    # --- Launch / supply-chain (target = launch/command) ---
    findings.extend(check_launch_command(surface.command, surface.args))
    for arg in (surface.command, *surface.args):
        findings.extend(scan_field(arg, "launch/command"))

    # --- Tools ---
    for tool in surface.tools:
        target = f"tools/{tool.name}"

        if _schema_is_malformed(tool.input_schema):
            findings.append(
                Finding(
                    rule_id="WRD-SCHEMA-MALFORMED",
                    severity="low",
                    target=target,
                    message="inputSchema is present but not a JSON object; capability analysis skipped",
                    snippet=f"inputSchema type={type(tool.input_schema).__name__}",
                )
            )
            schema_obj: dict[str, Any] | None = None
        else:
            schema_obj = tool.input_schema

        # Capability checks via the shared tokenizer.
        for flag in derive_capabilities(tool.name, schema_obj):
            rule_id, severity = _CAP_RULES[flag]
            evidence = capability_evidence(tool.name, schema_obj, flag)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    target=target,
                    message=f"Tool derives capability '{flag}' ({evidence})",
                    snippet=evidence,
                )
            )

        # Secret checks on name, description, and schema string values.
        findings.extend(scan_field(tool.name, target))
        if tool.description:
            findings.extend(scan_field(tool.description, target))
        if isinstance(schema_obj, dict):
            for sval in _string_values_from_schema(schema_obj):
                findings.extend(scan_field(sval, target))

    # --- Resources ---
    for res in surface.resources:
        target = f"resources/{res.uri}"
        for field in (res.uri, res.name, res.description):
            if field:
                findings.extend(scan_field(field, target))

    # --- Prompts ---
    for prompt in surface.prompts:
        target = f"prompts/{prompt.name}"
        findings.extend(scan_field(prompt.name, target))
        if prompt.description:
            findings.extend(scan_field(prompt.description, target))

    return _dedupe_and_sort(findings)


def _dedupe_and_sort(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate (rule_id, target, snippet) and sort by (target, rule_id).

    CHECKS.md §5.1/§5.2: one finding per (rule_id, target, match-location);
    emitted sorted by ``(target, rule_id)``.
    """
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.target, f.snippet)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (f.target, f.rule_id, f.snippet))
    return unique
