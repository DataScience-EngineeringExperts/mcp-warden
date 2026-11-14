"""Opt-in, atomic universal server-frame inspection before legacy delivery handling."""

from __future__ import annotations

from dataclasses import replace

from .framing import serialize_frame
from .normalization_inspection import inspect_mcp_frame
from .normalization_models import NormalizationProfileV1
from .result_inspection import TIER_BLOCK, TIER_MONITOR, policy_for_tool


def handle_universal(state, frame, mode: str, legacy) -> bytes:
    from . import res_rules, wire_block
    from .guard_loop import StrictInspectionAbort
    if state.record is not None:
        raise StrictInspectionAbort(site="normalization-record", tool="?",
                                    exc_type="RawRecordingUnsupported", rpc_id=None)
    if frame.json is None:
        raise StrictInspectionAbort(site="normalization-frame", tool="?",
                                    exc_type="MalformedFrame", rpc_id=None)
    obj = frame.json
    if type(obj) is not dict:
        raise StrictInspectionAbort(site="normalization-frame", tool="?",
                                    exc_type="MalformedFrame", rpc_id=None)
    rpc_id = obj.get("id")
    if rpc_id is not None and type(rpc_id) not in (str, int):
        raise StrictInspectionAbort(site="normalization-frame", tool="?",
                                    exc_type="MalformedID", rpc_id=None)
    # Read correlation without consuming it; the legacy handler owns that state.
    method = state.inflight.get(rpc_id, "")
    if method == "tools/call" and "result" in obj:
        state.frames_inspected += 1
    try:
        findings = inspect_mcp_frame(
            obj, method, NormalizationProfileV1(state.config.normalization_image),
            policy_for_tool(state.lock, state.inflight_tool.get(rpc_id, "")),
            exfil_denylist=state.exfil_denylist,
            inject_phrases=state.inject_phrases,
            raw_content=frame.body,
        )
    except Exception:
        raise StrictInspectionAbort(site="normalization-inspect", tool="?",
                                    exc_type="InspectionFailure", rpc_id=rpc_id) from None
    blocked = [f for f in findings if f.tier == TIER_BLOCK or (f.tier == TIER_MONITOR and (
        state.config.block_inject_phrase or any(res_rules.normalize_phrase_text(p)
            in state.config.block_inject_phrases_subset for p in f.matched_phrases)))]
    for finding in findings:
        state.emit(replace(finding, action="blocked" if finding in blocked else "reported",
                           direction="s2c", rpc_id=rpc_id))
    if blocked:
        if rpc_id is None:
            raise StrictInspectionAbort(site="normalization-control", tool="?",
                                        exc_type="ContentRefused", rpc_id=None)
        state.method_for(rpc_id)
        state.tool_for(rpc_id)
        return serialize_frame(wire_block.error_response(
            rpc_id, stage="response", rule=blocked[0].rule_id, tool="supplied",
            reason="universal content inspection refused delivery"), mode)
    return legacy(state, frame, mode)
