"""Guard server->client result-side handling + block decision (GUARD_PROXY.md §4.2, §7).

Inspects only ``tools/call`` responses (correlated by id); everything else passes
through. On a block, chooses redacted-content vs error-replacement per §7.2.
Split from ``guard_loop.py`` to keep each module under the LOC budget.
"""

from __future__ import annotations

import logging
from typing import Any

from . import wire_block
from .framing import Frame, serialize_frame
from .result_inspection import (
    TIER_BLOCK,
    TIER_MONITOR,
    InspectionPolicy,
    ResultFinding,
    inspect_result,
    policy_for_tool,
)

logger = logging.getLogger("mcp_warden.guard")


def _frame_error_note(direction: str, rpc_id: Any, detail: str) -> ResultFinding:
    """Build a WRD-RES-FRAME-ERROR pass-through note (§5.3)."""
    return ResultFinding(
        rule_id="WRD-RES-FRAME-ERROR",
        severity="low",
        tier="note",
        message=f"framing/inspection error (passed through): {detail}",
        action="passed",
        direction=direction,
        rpc_id=rpc_id,
    )


def handle_s2c(state, frame: Frame, mode: str) -> bytes:
    """Process one server->client frame; return the bytes to forward to the client.

    Args:
        state: The :class:`~mcp_warden.guard_loop.GuardState`.
        frame: The parsed/raw server->client frame.
        mode: The client-side framing mode (for re-serialization of a modified frame).

    Returns:
        The bytes to forward client-ward.
    """
    from .guard_loop import PASSTHROUGH_METHODS

    if state.record is not None and frame.json is not None:
        state.record("s2c", frame.json)
    obj = frame.json
    if obj is None:
        state.emit(_frame_error_note("s2c", None, frame.parse_error or "unparseable frame"))
        return frame.raw
    s2c_method = obj.get("method")
    if s2c_method in PASSTHROUGH_METHODS:
        # Cancellation/progress pass through untouched, even mid-tools/call (V3 §1).
        return frame.raw
    if s2c_method == "notifications/tools/list_changed":
        # Arm a re-check of the NEXT tools/list response (§4.3); forward the
        # notification itself unmodified.
        state.list_changed_pending = True
        return frame.raw
    rpc_id = obj.get("id")
    if rpc_id is None or "result" not in obj:
        return frame.raw  # notifications, errors, requests -> pass-through
    method = state.method_for(rpc_id)
    tool = state.tool_for(rpc_id)
    if method == "tools/list":
        return _handle_list_response(state, frame, mode, rpc_id, obj)
    if method != "tools/call":
        return frame.raw  # only inspect tools/call results (§4.4)

    if not tool:
        tool = _tool_name_from_result(obj)
    pol = policy_for_tool(state.lock, tool)
    result = obj.get("result")
    if not isinstance(result, dict):
        return frame.raw
    try:
        findings = inspect_result(
            result, tool, pol, exfil_denylist=state.exfil_denylist, inject_phrases=state.inject_phrases
        )
    except Exception as exc:  # inspection error -> fail-open pass-through (§9)
        state.emit(_frame_error_note("s2c", rpc_id, f"inspect error: {exc}"))
        return frame.raw
    return _apply_result_findings(state, frame, mode, rpc_id, tool, result, findings, pol)


def _handle_list_response(state, frame: Frame, mode: str, rpc_id: Any, obj: dict[str, Any]) -> bytes:
    """Gate a ``tools/list`` response against the lock when armed (§4.3, §7.3).

    Only runs the drift check when a prior ``notifications/tools/list_changed``
    armed it AND a lock is loaded. A divergence blocks by default (error-replace)
    unless ``--no-block-list-changed`` demotes it to shadow. Any error fails open.
    """
    if not state.list_changed_pending or state.lock is None:
        return frame.raw  # not armed (no list_changed seen) -> pass-through
    state.list_changed_pending = False  # consume the arming
    result = obj.get("result")
    if not isinstance(result, dict):
        return frame.raw
    try:
        from .guard_list_gate import diverges_from_lock

        diverged, reason = diverges_from_lock(result, state.lock)
    except Exception as exc:  # gate error -> fail-open pass-through (§9)
        state.emit(_frame_error_note("s2c", rpc_id, f"list-gate error: {exc}"))
        return frame.raw
    if not diverged:
        return frame.raw
    enabled = state.config.list_changed_enabled()
    _stamp_list_finding(state, rpc_id, reason, "blocked" if enabled else "shadowed")
    if not enabled:
        return frame.raw  # shadow: log the drift, forward the rug-pulled list
    err = wire_block.error_response(rpc_id, stage="list_changed", rule="MCP-DRIFT", tool="", reason=reason)
    return serialize_frame(err, mode)


def _stamp_list_finding(state, rpc_id: Any, reason: str, action: str) -> None:
    """Emit a BLOCK-tier finding for a tools/list_changed divergence."""
    state.emit(
        ResultFinding(
            rule_id="MCP-DRIFT",
            severity="high",
            tier=TIER_BLOCK,
            message=reason,
            action=action,
            direction="s2c",
            rpc_id=rpc_id,
            tool="",
        )
    )


def _tool_name_from_result(obj: dict[str, Any]) -> str:
    """Best-effort tool name from a result's _meta (else empty)."""
    res = obj.get("result")
    meta = res.get("_meta") if isinstance(res, dict) else None
    if isinstance(meta, dict) and isinstance(meta.get("tool"), str):
        return meta["tool"]
    return ""


def _apply_result_findings(
    state,
    frame: Frame,
    mode: str,
    rpc_id: Any,
    tool: str,
    result: dict[str, Any],
    findings: list[ResultFinding],
    pol: InspectionPolicy,
) -> bytes:
    """Decide pass-through / redact / error-replace from findings + flags (§7.2)."""
    if not findings:
        return frame.raw

    block_findings = [f for f in findings if f.tier == TIER_BLOCK and state.config.category_enabled(f.rule_id)]
    if state.config.block_inject_phrase and not state.config.audit_only:
        block_findings += [f for f in findings if f.tier == TIER_MONITOR]

    error_rules = {"WRD-RES-EXFIL-DOMAIN", "WRD-RES-INJECT-PHRASE"}
    if not state.config.redact_secret_echo:
        error_rules.add("WRD-RES-SECRET-ECHO")
    redact_rules = {"WRD-RES-ANSI"}
    if state.config.redact_secret_echo:
        redact_rules.add("WRD-RES-SECRET-ECHO")

    err_match = [f for f in block_findings if f.rule_id in error_rules]
    redact_match = [f for f in block_findings if f.rule_id in redact_rules]

    if err_match:  # error-replacement wins (never hand back poisoned content)
        chosen = err_match[0]
        for f in findings:
            _stamp(state, f, rpc_id, tool, "blocked" if f in block_findings else "shadowed")
        reason = f"{chosen.message} [{chosen.snippet}]" if chosen.snippet else chosen.message
        err = wire_block.error_response(rpc_id, stage="response", rule=chosen.rule_id, tool=tool, reason=reason)
        return serialize_frame(err, mode)

    if redact_match:  # redacted-content in place
        for f in findings:
            act = "modified" if f in redact_match else ("blocked" if f in block_findings else "shadowed")
            _stamp(state, f, rpc_id, tool, act)
        modified = wire_block.redacted_result(
            rpc_id, result, redact_match, pol, redact_secret_echo=state.config.redact_secret_echo
        )
        return serialize_frame(modified, mode)

    # Nothing blockable enabled -> shadow: emit findings, pass original bytes.
    for f in findings:
        _stamp(state, f, rpc_id, tool, "shadowed" if f.tier != "note" else "passed")
    return frame.raw


def _stamp(state, f: ResultFinding, rpc_id: Any, tool: str, action: str) -> None:
    """Stamp direction/id/tool/action onto a finding and emit it."""
    state.emit(
        ResultFinding(
            rule_id=f.rule_id,
            severity=f.severity,
            tier=f.tier,
            message=f.message,
            snippet=f.snippet,
            block_index=f.block_index,
            sub_rule=f.sub_rule,
            action=action,
            direction="s2c",
            rpc_id=rpc_id,
            tool=tool or f.tool,
        )
    )
