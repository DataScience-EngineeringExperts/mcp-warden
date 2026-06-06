"""Drift-detection tests per class (WARDEN_LOCK_SCHEMA.md §6.2)."""

from __future__ import annotations

from mcp_warden.drift import compute_drift
from mcp_warden.lockfile import build_lock
from mcp_warden.models import CapturedPrompt, CapturedResource, CapturedSurface, CapturedTool


def _surface(tools=None, resources=None, prompts=None, command="python", args=None):
    return CapturedSurface(
        command=command,
        args=args if args is not None else ["server.py"],
        protocol_version="2025-06-18",
        tools=tools or [],
        resources=resources or [],
        prompts=prompts or [],
    )


def _lock(surface):
    return build_lock(surface, [])


def test_no_drift_identical_surface():
    s = _surface([CapturedTool(name="read_file", description="d", input_schema={"properties": {"path": {}}})])
    base = _lock(s)
    cur = _lock(s)
    assert compute_drift(base, cur) == []
    assert base.overall_digest == cur.overall_digest


def test_tool_added_high():
    base = _lock(_surface([CapturedTool(name="a", input_schema={})]))
    cur = _lock(_surface([CapturedTool(name="a", input_schema={}), CapturedTool(name="b", input_schema={})]))
    drift = compute_drift(base, cur)
    added = [d for d in drift if d.drift_class == "tool-added"]
    assert added and added[0].severity == "high" and added[0].target == "tools/b"


def test_tool_removed_medium():
    base = _lock(_surface([CapturedTool(name="a", input_schema={}), CapturedTool(name="b", input_schema={})]))
    cur = _lock(_surface([CapturedTool(name="a", input_schema={})]))
    drift = compute_drift(base, cur)
    removed = [d for d in drift if d.drift_class == "tool-removed"]
    assert removed and removed[0].severity == "medium"


def test_schema_modified_high():
    base = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {}}})]))
    cur = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {}, "b": {}}})]))
    drift = compute_drift(base, cur)
    assert any(d.drift_class == "schema-modified" and d.severity == "high" for d in drift)


def test_capability_added_high():
    base = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"x": {}}})]))
    cur = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"command": {}}})]))
    drift = compute_drift(base, cur)
    assert any(d.drift_class == "capability-added" and d.severity == "high" for d in drift)


def test_description_only_modified_low():
    base = _lock(_surface([CapturedTool(name="t", description="old", input_schema={"properties": {"x": {}}})]))
    cur = _lock(_surface([CapturedTool(name="t", description="new", input_schema={"properties": {"x": {}}})]))
    drift = compute_drift(base, cur)
    desc = [d for d in drift if d.drift_class == "description-modified"]
    assert desc and desc[0].severity == "low"
    # schema/caps unchanged -> only description drift on this entry
    assert not any(d.drift_class in ("schema-modified", "capability-added") for d in drift)


def test_server_identity_drift_critical():
    base = _lock(_surface([CapturedTool(name="t", input_schema={})], args=["server.py"]))
    cur = _lock(_surface([CapturedTool(name="t", input_schema={})], args=["other.py"]))
    drift = compute_drift(base, cur)
    sid = [d for d in drift if d.drift_class == "server-identity"]
    assert sid and sid[0].severity == "critical"


def test_resource_added_medium():
    base = _lock(_surface())
    cur = _lock(_surface(resources=[CapturedResource(uri="file:///x", name="x")]))
    drift = compute_drift(base, cur)
    assert any(d.drift_class == "resource-added" and d.severity == "medium" for d in drift)


def test_prompt_removed_low():
    base = _lock(_surface(prompts=[CapturedPrompt(name="p")]))
    cur = _lock(_surface())
    drift = compute_drift(base, cur)
    assert any(d.drift_class == "prompt-removed" and d.severity == "low" for d in drift)


def test_unapproved_change_finding():
    s = _surface([CapturedTool(name="t", input_schema={"properties": {"x": {}}})])
    base = build_lock(s, [], approve=True, approver="ci-bot@example.invalid")
    mutated = _surface([CapturedTool(name="t", input_schema={"properties": {"x": {}, "y": {}}})])
    cur = build_lock(mutated, [])
    drift = compute_drift(base, cur)
    assert any(d.drift_class == "unapproved-change" for d in drift)
