"""Fail-closed (policy) vs fail-open (inspector errors) posture + framing units."""

from __future__ import annotations

import json

from mcp_warden import guard_result
from mcp_warden.framing import (
    MODE_CONTENT_LENGTH,
    MODE_NEWLINE,
    serialize_frame,
)
from mcp_warden.guard_loop import GuardConfig, GuardState, handle_c2s
from mcp_warden.guard_result import handle_s2c
from mcp_warden.policy_model import Policy


def _frame(obj: dict):
    from mcp_warden.framing import Frame

    body = json.dumps(obj).encode()
    return Frame(raw=body + b"\n", body=body, json=obj)


def _state(config: GuardConfig, **kw) -> tuple[GuardState, list]:
    sink: list = []
    state = GuardState(config=config, on_finding=sink.append, **kw)
    return state, sink


# --- fail-OPEN: an inspector exception passes the frame through (§9) ----------


def test_inspector_exception_fails_open_passthrough(monkeypatch):
    # v0.3: ansi/exfil block by default (no flags); an inspector exception must
    # still fail OPEN (pass through), proving fail-open beats default-block.
    state, sink = _state(GuardConfig())
    state.remember_request(2, "tools/call", "ansi_tool")

    def _boom(*a, **k):
        raise RuntimeError("inspector bug")

    monkeypatch.setattr(guard_result, "inspect_result", _boom)

    resp = {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "\x1b[2J poison"}]}}
    out = handle_s2c(state, _frame(resp), MODE_NEWLINE)

    # Fail-open: the ORIGINAL bytes are forwarded unmodified despite blocking enabled.
    assert out == _frame(resp).raw
    assert any(f.rule_id == "WRD-RES-FRAME-ERROR" for f in sink)


def test_malformed_frame_fails_open_passthrough():
    state, sink = _state(GuardConfig())
    from mcp_warden.framing import Frame

    bad = Frame(raw=b"not json\n", body=b"not json", json=None, parse_error="bad")
    out = handle_s2c(state, bad, MODE_NEWLINE)
    assert out == b"not json\n"  # passed through
    assert any(f.rule_id == "WRD-RES-FRAME-ERROR" for f in sink)


# --- fail-CLOSED: a policy deny blocks by default when --policy is supplied ----


def test_policy_deny_fails_closed_blocks_request():
    # deny_private SSRF default denies link-local; http_request shape via url arg.
    # v0.3: a deny blocks by default once the policy is armed (armed_policy=True).
    policy = Policy(version=1, defaults={"http_request": {"deny_private": True}})
    state, sink = _state(GuardConfig(armed_policy=True), policy=policy)

    req = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "fetch", "arguments": {"url": "http://169.254.169.254/latest"}},
    }
    out = handle_c2s(state, _frame(req), MODE_NEWLINE)

    # Request is WITHHELD (b"") and a client-facing error is staged (fail-closed).
    assert out == b""
    assert state.pending_client_error is not None
    err = json.loads(state.pending_client_error.decode())
    assert err["error"]["code"] == -32001
    assert err["error"]["data"]["stage"] == "request"
    assert any(f.action == "blocked" for f in sink)


def test_policy_deny_shadow_passes_through_with_no_block_policy():
    # v0.3: --no-block-policy demotes a deny to shadow (armed but opted out).
    policy = Policy(version=1, defaults={"http_request": {"deny_private": True}})
    state, sink = _state(GuardConfig(armed_policy=True, no_block_policy=True), policy=policy)
    req = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "fetch", "arguments": {"url": "http://169.254.169.254/x"}},
    }
    out = handle_c2s(state, _frame(req), MODE_NEWLINE)
    assert out == _frame(req).raw  # shadow: forwarded
    assert state.pending_client_error is None
    assert any(f.action == "shadowed" for f in sink)


# --- audit-only precedence: disables blocking even over default-on ------------


def test_audit_only_disables_blocking():
    # v0.3: ansi/exfil block by default; audit-only (highest precedence) still
    # disables all blocking/mutation.
    cfg = GuardConfig(audit_only=True)
    assert cfg.category_enabled("WRD-RES-ANSI") is False
    assert cfg.category_enabled("WRD-RES-EXFIL-DOMAIN") is False

    state, sink = _state(cfg)
    state.remember_request(2, "tools/call", "ansi_tool")
    resp = {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "\x1b[2J poison"}]}}
    out = handle_s2c(state, _frame(resp), MODE_NEWLINE)
    # Audit-only: no mutation, original bytes forwarded, finding is a warning (shadowed).
    assert out == _frame(resp).raw
    ansi = [f for f in sink if f.rule_id == "WRD-RES-ANSI"]
    assert ansi and ansi[0].action == "shadowed"


# --- WRD-RES-EXFIL-IP-LITERAL category posture (#11 PR-1) ----------------------


def test_exfil_ip_literal_blocks_by_default():
    # Deterministic + default-on, exactly like the other BLOCK-tier result rules.
    assert GuardConfig().category_enabled("WRD-RES-EXFIL-IP-LITERAL") is True


def test_exfil_ip_literal_opt_out_demotes():
    assert GuardConfig(no_block_exfil_ip_literal=True).category_enabled("WRD-RES-EXFIL-IP-LITERAL") is False


def test_exfil_ip_literal_audit_only_demotes():
    assert GuardConfig(audit_only=True).category_enabled("WRD-RES-EXFIL-IP-LITERAL") is False


def test_exfil_ip_literal_no_block_deterministic_fold_demotes():
    # --no-block-deterministic folds into no_block_exfil_ip_literal in cli_guard;
    # the resulting config (simulated here) demotes the category, like every other.
    assert GuardConfig(no_block_exfil_ip_literal=True).category_enabled("WRD-RES-EXFIL-IP-LITERAL") is False


# --- framing: both modes round-trip ------------------------------------------


def test_serialize_newline_and_content_length():
    obj = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    nl = serialize_frame(obj, MODE_NEWLINE)
    assert nl.endswith(b"\n") and b"Content-Length" not in nl
    cl = serialize_frame(obj, MODE_CONTENT_LENGTH)
    assert cl.startswith(b"Content-Length: ") and b"\r\n\r\n" in cl
