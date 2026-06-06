"""``inspect`` offline analyzer (GUARD_PROXY.md §3).

Runs the IDENTICAL ``RESULT_INSPECTION.md`` catalog over a recorded JSONL trace —
the SAME ``inspect_result`` code path ``guard`` uses, so findings agree byte-for-
byte (non-negotiable #1). No live processes, no blocking (offline) — report-only.

Input: a JSONL trace where each line is one recorded JSON-RPC frame, either a bare
frame or ``{"direction": ..., "ts": ..., "frame": ...}``. Result frames are
correlated to their ``tools/call`` requests by ``id`` exactly as ``guard`` does.

Exit code (§3): ``0`` if no BLOCK-tier finding; non-zero if any BLOCK-tier finding;
``2`` on trace read/parse error. ``--audit-only`` forces ``0``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from . import res_rules
from .result_inspection import (
    TIER_BLOCK,
    ResultFinding,
    inspect_result,
    policy_for_tool,
)

logger = logging.getLogger("mcp_warden.inspect")


class TraceError(Exception):
    """Raised when the trace file cannot be read/parsed (=> exit 2)."""


def _load_records(path: str | Path) -> list[dict[str, Any]]:
    """Load a JSONL trace into a list of normalized records.

    Each record is ``{"direction": str|None, "frame": dict}``. A bare frame line
    is wrapped with ``direction=None`` (inferred later).

    Raises:
        TraceError: On read failure or a non-JSON line.
    """
    p = Path(path)
    if not p.exists():
        raise TraceError(f"trace file not found: {p}")
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TraceError(f"could not read trace {p}: {exc}") from exc

    records: list[dict[str, Any]] = []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TraceError(f"trace line {n} is not valid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise TraceError(f"trace line {n} is not a JSON object")
        if "frame" in obj and isinstance(obj["frame"], dict):
            records.append({"direction": obj.get("direction"), "frame": obj["frame"]})
        else:
            records.append({"direction": None, "frame": obj})
    return records


def _direction_of(rec: dict[str, Any]) -> str:
    """Infer c2s/s2c for a record (explicit wins; else method/result heuristic)."""
    if rec["direction"] in ("c2s", "s2c"):
        return rec["direction"]
    frame = rec["frame"]
    if "method" in frame:
        return "c2s"
    if "result" in frame or "error" in frame:
        return "s2c"
    return "c2s"


def analyze_trace(
    path: str | Path,
    *,
    lock: Any = None,
    exfil_denylist: tuple[str, ...] | None = None,
    inject_phrases: tuple[str, ...] | None = None,
) -> list[ResultFinding]:
    """Analyze a recorded trace and return stamped result findings.

    Correlates ``result`` frames to their ``tools/call`` requests by ``id``
    (exactly as ``guard``), then runs the shared catalog on each result.

    Args:
        path: The JSONL trace path.
        lock: Optional loaded lock (per-tool precision).
        exfil_denylist/inject_phrases: Merged seed+org lists (defaults to seed).

    Returns:
        The list of stamped :class:`ResultFinding` over the whole trace.

    Raises:
        TraceError: On trace read/parse failure.
    """
    records = _load_records(path)
    exfil = exfil_denylist or res_rules.SEED_EXFIL_DENYLIST
    phrases = inject_phrases or res_rules.SEED_INJECT_PHRASES

    inflight: dict[Any, str] = {}  # id -> method, for tools/call correlation
    tool_by_id: dict[Any, str] = {}
    findings: list[ResultFinding] = []

    for rec in records:
        frame = rec["frame"]
        direction = _direction_of(rec)
        rpc_id = frame.get("id")
        if direction == "c2s" and frame.get("method") is not None and rpc_id is not None:
            inflight[rpc_id] = str(frame["method"])
            params = frame.get("params") or {}
            if isinstance(params, dict):
                tool_by_id[rpc_id] = str(params.get("name", ""))
            continue
        if direction != "s2c" or rpc_id is None or "result" not in frame:
            continue
        if inflight.get(rpc_id) != "tools/call":
            continue
        result = frame.get("result")
        if not isinstance(result, dict):
            continue
        tool = tool_by_id.get(rpc_id, "")
        pol = policy_for_tool(lock, tool)
        try:
            raw = inspect_result(result, tool, pol, exfil_denylist=exfil, inject_phrases=phrases)
        except Exception as exc:  # mirror guard's fail-open posture (§9)
            logger.error("inspect: catalog raised on id=%s: %s", rpc_id, exc)
            continue
        for f in raw:
            findings.append(
                ResultFinding(
                    rule_id=f.rule_id,
                    severity=f.severity,
                    tier=f.tier,
                    message=f.message,
                    snippet=f.snippet,
                    block_index=f.block_index,
                    sub_rule=f.sub_rule,
                    action="reported",
                    direction="s2c",
                    rpc_id=rpc_id,
                    tool=tool,
                )
            )
    return findings


def exit_code_for(findings: list[ResultFinding], *, audit_only: bool) -> int:
    """Compute the ``inspect`` exit code (§3).

    Args:
        findings: The analyzed findings.
        audit_only: When True, force exit ``0``.

    Returns:
        ``0`` if no BLOCK-tier finding (or audit-only); ``1`` if any BLOCK-tier.
    """
    if audit_only:
        return 0
    return 1 if any(f.tier == TIER_BLOCK for f in findings) else 0
