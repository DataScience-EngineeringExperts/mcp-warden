"""Lock build / write / read + overall-digest exclusion tests (WARDEN_LOCK_SCHEMA.md)."""

from __future__ import annotations

import json

from mcp_warden.lockfile import build_lock, lock_to_pretty_json, read_lock, write_lock
from mcp_warden.models import CapturedSurface, CapturedTool, Finding


def _surface():
    return CapturedSurface(
        command="node",
        args=["./build/index.js"],
        protocol_version="2025-06-18",
        tools=[
            CapturedTool(name="read_file", description="Read a file", input_schema={"properties": {"path": {}}}),
            CapturedTool(name="apply", description="Apply", input_schema={"properties": {"path": {}, "data": {}}}),
        ],
    )


def test_tools_sorted_by_name():
    lock = build_lock(_surface(), [])
    names = [t.name for t in lock.tools]
    assert names == sorted(names)


def test_entry_digest_excludes_itself():
    lock = build_lock(_surface(), [])
    tool = lock.tools[0]
    # Rebuilding the body without entry_digest must reproduce the digest.
    from mcp_warden.hashing import hash_value

    body = {
        "name": tool.name,
        "description_hash": tool.description_hash,
        "input_schema_hash": tool.input_schema_hash,
        "capabilities": tool.capabilities,
        # SCHEMA_VERSION 2: the serialized skeleton is part of the hashed body.
        "schema_skeleton": tool.schema_skeleton.model_dump(mode="json"),
    }
    assert hash_value(body) == tool.entry_digest


def test_overall_digest_excludes_findings_pin_warden_version():
    s = _surface()
    lock_a = build_lock(s, [])
    lock_b = build_lock(s, [Finding(rule_id="WRD-CAP-FS-READ", severity="medium", target="tools/read_file", message="m", snippet="x")])
    # Adding findings must NOT change overall_digest.
    assert lock_a.overall_digest == lock_b.overall_digest


def test_approve_binds_digest():
    lock = build_lock(_surface(), [], approve=True, approver="ci-bot@example.invalid")
    assert lock.pin.approved is True
    assert lock.pin.approver == "ci-bot@example.invalid"
    assert lock.pin.approved_digest == lock.overall_digest


def test_roundtrip_write_read(tmp_path):
    lock = build_lock(_surface(), [], approve=True, approver="x@y.invalid")
    path = tmp_path / "warden.lock"
    write_lock(lock, path)
    loaded = read_lock(path)
    assert loaded.overall_digest == lock.overall_digest
    assert loaded.tools == lock.tools


def test_pretty_json_trailing_newline_and_indent():
    text = lock_to_pretty_json(build_lock(_surface(), []))
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    # 2-space indent present
    assert '\n  "schema_version"' in text
    json.loads(text)  # valid JSON


def test_lock_stores_hashes_not_raw_text():
    text = lock_to_pretty_json(build_lock(_surface(), []))
    # Raw description text must NOT appear in the lock.
    assert "Read a file" not in text
    assert "description_hash" in text
