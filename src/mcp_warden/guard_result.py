"""Guard server->client result-side handling + block decision (GUARD_PROXY.md §4.2, §7).

Inspects only ``tools/call`` responses (correlated by id); everything else passes
through. On a block, chooses redacted-content vs error-replacement per §7.2.
Split from ``guard_loop.py`` to keep each module under the LOC budget.
"""

from __future__ import annotations

import logging
from typing import Any

from . import res_rules, wire_block
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
    from .guard_loop import PASSTHROUGH_METHODS, StrictInspectionAbort

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
    # Base-rate denominator (issue #12): count every tools/call result frame the
    # catalog actually inspects, so a per-phrase FP rate has a denominator. Counted
    # here (a real result about to be inspected), NOT for pass-through/list frames.
    state.frames_inspected += 1
    # Inspection-before-write invariant (binding #2): inspect_result runs BEFORE
    # this response frame is forwarded to the client, so a strict abort here
    # cannot leave a partially-forwarded (un-inspected) frame on the wire.
    try:
        findings = inspect_result(
            result, tool, pol, exfil_denylist=state.exfil_denylist, inject_phrases=state.inject_phrases
        )
    except StrictInspectionAbort:
        raise  # never swallow the abort (BaseException)
    except Exception as exc:  # inspection error -> fail-open pass-through (§9)
        if state.config.strict:
            # `from None` severs __cause__ (binding #4a); sanitized fields only.
            raise StrictInspectionAbort(
                site="result-inspect", tool=tool or "?", exc_type=type(exc).__name__, rpc_id=rpc_id
            ) from None
        state.emit(_frame_error_note("s2c", rpc_id, f"inspect error: {exc}"))
        return frame.raw

    # WRD-RES-EXFIL-DNS-SSRF: resolve URL hostnames to catch SSRF bypasses
    # (fail-open — any DNS error produces no hits, never aborts).
    if state.config.category_enabled("WRD-RES-EXFIL-DNS-SSRF"):
        try:
            dns_findings = _dns_ssrf_findings(result, tool)
            if dns_findings:
                findings = list(findings) + dns_findings
        except Exception as exc:  # pragma: no cover
            state.emit(_frame_error_note("s2c", rpc_id, f"dns-ssrf error: {exc}"))

    return _apply_result_findings(state, frame, mode, rpc_id, tool, result, findings, pol)


def _handle_list_response(state, frame: Frame, mode: str, rpc_id: Any, obj: dict[str, Any]) -> bytes:
    """Gate a ``tools/list`` response against the lock when armed (§4.3, §7.3).

    Only runs the drift check when a prior ``notifications/tools/list_changed``
    armed it AND a lock is loaded. A divergence blocks by default (error-replace)
    unless ``--no-block-list-changed`` demotes it to shadow. Any error fails open.
    """
    from .guard_loop import StrictInspectionAbort

    if not state.list_changed_pending or state.lock is None:
        return frame.raw  # not armed (no list_changed seen) -> pass-through
    state.list_changed_pending = False  # consume the arming
    result = obj.get("result")
    if not isinstance(result, dict):
        return frame.raw
    # Inspection-before-write invariant (binding #2): the drift gate runs BEFORE
    # the tools/list response is forwarded, so a strict abort here cannot leave a
    # partially-forwarded (un-gated) list on the wire.
    try:
        from .guard_list_gate import diverges_from_lock

        # strict threads down so the nested _hash_live_tools error RE-RAISES
        # (binding #5) instead of silently returning (False, "") = no divergence;
        # that re-raise lands here and becomes a list-gate StrictInspectionAbort.
        diverged, reason = diverges_from_lock(result, state.lock, strict=state.config.strict)
    except StrictInspectionAbort:
        raise  # never swallow the abort (BaseException)
    except Exception as exc:  # gate error -> fail-open pass-through (§9)
        if state.config.strict:
            # This is the boundary for the `_hash_live_tools` bare-`raise` (it
            # re-raises the malformed-entry exception under strict, which lands
            # here). `from None` severs `__cause__` AND sets `__suppress_context__`
            # on the new abort (binding #4a): Python's default traceback printer
            # honors `__suppress_context__`, so even though `__context__` is still
            # implicitly set to the original (secret-bearing) exception, it is
            # NEVER printed or logged -> no leak. The structured stderr is built
            # from sanitized fields only, so the original cannot escape that path
            # either. Sanitized fields only on the abort itself.
            raise StrictInspectionAbort(
                site="list-gate", tool="?", exc_type=type(exc).__name__, rpc_id=rpc_id
            ) from None
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


def _dns_ssrf_findings(result: dict, tool: str) -> list[ResultFinding]:
    """Resolve URL hostnames in ``result`` blocks; return WRD-RES-EXFIL-DNS-SSRF findings.

    Fail-open: DNS errors within :func:`~mcp_warden.res_dns.resolve_ssrf_hits`
    are already swallowed there (return ``[]``). This function raises only if
    the catalog/extract plumbing itself fails — caught by the caller.

    Args:
        result: The ``tools/call`` result dict.
        tool: The tool name (for finding messages).

    Returns:
        Per-block ``WRD-RES-EXFIL-DNS-SSRF`` findings (empty if no SSRF hits).
    """
    from . import res_catalog, res_dns

    blocks, _ = res_catalog.extract_blocks(result)
    if not blocks:
        return []

    # Collect unique candidates across all blocks (resolve once, match per block).
    all_candidates: set[str] = set()
    for _idx, text in blocks:
        all_candidates.update(res_dns.extract_dns_candidates(text))
    if not all_candidates:
        return []

    hits = res_dns.resolve_ssrf_hits(sorted(all_candidates))
    if not hits:
        return []

    hit_map: dict[str, tuple[str, str]] = {h: (ip, lbl) for h, ip, lbl in hits}
    findings: list[ResultFinding] = []
    for idx, text in blocks:
        block_candidates = res_dns.extract_dns_candidates(text)
        block_hits = [(h, hit_map[h][0], hit_map[h][1]) for h in block_candidates if h in hit_map]
        if block_hits:
            findings.extend(res_catalog.inspect_exfil_dns_ssrf(block_hits, tool, idx))
    return findings


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
    if not state.config.audit_only:
        if state.config.block_inject_phrase:
            # Whole fuzzy tier promoted to block (existing --block-inject-phrase).
            block_findings += [f for f in findings if f.tier == TIER_MONITOR]
        elif state.config.block_inject_phrases_subset:
            # Per-phrase opt-in (issue #12): promote ONLY the INJECT-PHRASE findings
            # whose matched curated phrase(s) are on the operator's named subset; all
            # other fuzzy matches stay monitor-only. Does NOT change the rule's tier
            # or default action — a runtime narrowing keyed on the safe, structured
            # matched_phrases field (never raw result content).
            subset = state.config.block_inject_phrases_subset
            block_findings += [
                f
                for f in findings
                if f.tier == TIER_MONITOR
                and f.rule_id == "WRD-RES-INJECT-PHRASE"
                and any(res_rules.normalize_phrase_text(p) in subset for p in f.matched_phrases)
            ]

    error_rules = {"WRD-RES-EXFIL-DOMAIN", "WRD-RES-INJECT-PHRASE", "WRD-RES-EXFIL-DNS-SSRF"}
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
            matched_phrases=f.matched_phrases,
        )
    )
