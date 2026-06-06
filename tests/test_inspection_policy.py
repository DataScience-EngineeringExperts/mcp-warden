"""Per-tool inspection policy: fail-safe defaults + digest inclusion (lock §11)."""

from __future__ import annotations

import pytest

from mcp_warden import res_rules
from mcp_warden.drift import compute_drift
from mcp_warden.lockfile import (
    LockValidationError,
    _tool_entry,
    build_lock,
    read_lock,
    write_lock,
)
from mcp_warden.models import CapturedSurface, CapturedTool
from mcp_warden.result_inspection import InspectionPolicy, inspect_result, policy_for_tool

SEED_EXFIL = res_rules.SEED_EXFIL_DENYLIST
SEED_INJECT = res_rules.SEED_INJECT_PHRASES


class _Tool:
    """Minimal captured-tool stand-in for _tool_entry."""

    def __init__(self, name, schema=None, desc="d"):
        self.name = name
        self.description = desc
        self.input_schema = schema or {"type": "object", "properties": {"q": {"type": "string"}}}


# --- fail-safe defaults (absent => max protection) ---------------------------


def test_absent_policy_is_max_protection():
    pol = policy_for_tool(None, "anything")
    assert pol.expected_output_charset == "text"
    assert pol.may_return_urls is False
    assert pol.secret_echo_applies is True


def test_absent_policy_ansi_strict_secret_block_url_note():
    pol = InspectionPolicy()  # the fail-safe default
    findings = inspect_result(
        {"content": [{"type": "text", "text": "\x1b https://example.com ghp_" + "A" * 36}]},
        "t",
        pol,
        exfil_denylist=SEED_EXFIL,
        inject_phrases=SEED_INJECT,
    )
    ids = {f.rule_id for f in findings}
    assert "WRD-RES-ANSI" in ids
    assert "WRD-RES-URL" in ids
    secret = [f for f in findings if f.rule_id == "WRD-RES-SECRET-ECHO"]
    assert secret and secret[0].tier == "block"


# --- digest inclusion: absent inspection hashes identically to v0.1 ----------


def test_tool_entry_without_inspection_hashes_identically_to_v01():
    """A tool with no inspection block must hash byte-identically to v0.1."""
    t = _Tool("read_file")
    # Build the entry the way a v0.1 build would (no inspection arg at all).
    v01_like = _tool_entry(t)
    # Build it again with explicit inspection=None.
    v02_none = _tool_entry(t, inspection=None)
    assert v01_like.entry_digest == v02_none.entry_digest
    # Adding an inspection block CHANGES the digest.
    v02_with = _tool_entry(t, inspection={"expected_output_charset": "text"})
    assert v02_with.entry_digest != v01_like.entry_digest


def test_overall_digest_unchanged_when_no_inspection():
    surface = CapturedSurface(
        command="python",
        args=["s.py"],
        protocol_version="2025-06-18",
        tools=[CapturedTool(name="read_file", description="d", input_schema={"type": "object"})],
        resources=[],
        prompts=[],
    )
    a = build_lock(surface, [])
    b = build_lock(surface, [])
    assert a.overall_digest == b.overall_digest
    # Serialized lock must NOT carry an inspection key when none is set.
    from mcp_warden.lockfile import lock_to_pretty_json

    assert '"inspection"' not in lock_to_pretty_json(a)


# --- drift: changed inspection is medium "inspection-policy-modified" ---------


def test_inspection_change_is_drift(tmp_path):
    t = _Tool("fetch")
    base_entry = _tool_entry(t, inspection={"secret_echo_applies": True})
    cur_entry = _tool_entry(t, inspection={"secret_echo_applies": False})

    surface = CapturedSurface(command="python", args=["s.py"], protocol_version="v", tools=[], resources=[], prompts=[])
    base = build_lock(surface, [])
    cur = build_lock(surface, [])
    base.tools = [base_entry]
    cur.tools = [cur_entry]
    # Force differing overall digests so the per-entry drift path runs.
    base.overall_digest = "sha256:" + "a" * 64
    cur.overall_digest = "sha256:" + "b" * 64

    drift = compute_drift(base, cur)
    classes = {d.drift_class for d in drift}
    assert "inspection-policy-modified" in classes
    item = next(d for d in drift if d.drift_class == "inspection-policy-modified")
    assert item.severity == "medium"


# --- pin-time validation: invalid charset fails closed -----------------------


def test_invalid_charset_fails_at_pin():
    with pytest.raises(LockValidationError):
        _tool_entry(_Tool("x"), inspection={"expected_output_charset": "nonsense"})


def test_invalid_bool_fails_at_pin():
    with pytest.raises(LockValidationError):
        _tool_entry(_Tool("x"), inspection={"may_return_urls": "yes"})


# --- reader fallback on invalid value => fail-safe + LOCK-INVALID note --------


def test_reader_falls_back_on_invalid_charset(tmp_path):
    # Write a lock, then corrupt a tool's inspection charset on disk.
    surface = CapturedSurface(
        command="python",
        args=["s.py"],
        protocol_version="v",
        tools=[CapturedTool(name="fetch", description="d", input_schema={"type": "object"})],
        resources=[],
        prompts=[],
    )
    lock = build_lock(surface, [])
    p = tmp_path / "warden.lock"
    write_lock(lock, p)
    import json

    raw = json.loads(p.read_text())
    raw["tools"][0]["inspection"] = {"expected_output_charset": "bogus"}
    p.write_text(json.dumps(raw))

    reloaded = read_lock(p)
    pol = policy_for_tool(reloaded, "fetch")
    assert pol.expected_output_charset == "text"  # fail-safe fallback
    assert any(n.rule_id == "WRD-RES-LOCK-INVALID" for n in pol.lock_notes)
