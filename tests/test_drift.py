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


def test_schema_added_unconstrained_high():
    # Adding an unconstrained property is now granular: schema-unconstrained-added (high).
    base = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {}}})]))
    cur = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {}, "b": {}}})]))
    drift = compute_drift(base, cur)
    assert any(d.drift_class == "schema-unconstrained-added" and d.severity == "high" for d in drift)
    # Legacy blob-level class must NOT fire when skeletons are present.
    assert not any(d.drift_class == "schema-modified" for d in drift)


def test_schema_modified_v1_fallback_high():
    # A v1 baseline (schema_skeleton=None) with a changed schema falls back to the
    # legacy single schema-modified (high) — never under-report.
    base = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {}}})]))
    cur = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {}, "b": {}}})]))
    # Simulate a v1 baseline tool entry by stripping its skeleton.
    base.tools[0] = base.tools[0].model_copy(update={"schema_skeleton": None})
    drift = compute_drift(base, cur)
    fb = [d for d in drift if d.drift_class == "schema-modified"]
    assert fb and fb[0].severity == "high"


def test_schema_cosmetic_modified_low():
    # Only a cosmetic key (description) changes inside the schema: hash differs
    # but the skeleton is identical -> schema-cosmetic-modified (low).
    base = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {"type": "string", "description": "old"}}})]))
    cur = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {"type": "string", "description": "new"}}})]))
    drift = compute_drift(base, cur)
    cosmetic = [d for d in drift if d.drift_class == "schema-cosmetic-modified"]
    assert cosmetic and cosmetic[0].severity == "low"
    assert not any(d.drift_class == "schema-modified" for d in drift)


def test_schema_constraint_relaxed_carries_detail():
    base = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {"type": "string", "maxLength": 64}}})]))
    cur = _lock(_surface([CapturedTool(name="t", input_schema={"properties": {"a": {"type": "string", "maxLength": 4096}}})]))
    drift = compute_drift(base, cur)
    relaxed = [d for d in drift if d.drift_class == "schema-constraint-relaxed"]
    assert relaxed and relaxed[0].severity == "medium"
    assert relaxed[0].detail == "maxLength 64→4096"


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


# --- #29 v2→v3 schema-version migration compat (B1) --------------------------


def _v2_approved_lock(surface, approver, monkeypatch):
    """Build an APPROVED baseline at schema_version=2 using the real builder.

    ``build_lock`` and ``compute_overall_digest`` both read the module-level
    ``lockfile.SCHEMA_VERSION``; patching it to 2 yields a genuine v2 lock whose
    ``overall_digest`` (and mirrored ``approved_digest``) are computed under the
    v2 payload — no hand-rolled JSON.
    """
    import mcp_warden.lockfile as lockfile_mod

    monkeypatch.setattr(lockfile_mod, "SCHEMA_VERSION", 2)
    return build_lock(surface, [], approve=True, approver=approver)


def test_schema_version_migrated_additive_low(monkeypatch):
    # A $ref-using surface: v2 records the ref opaquely, v3 follows it, so the
    # v3 overall_digest differs from the approved v2 digest of the SAME surface.
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/S"}},
        "$defs": {"S": {"type": "string", "maxLength": 64}},
    }
    s = _surface([CapturedTool(name="t", input_schema=schema)])

    base = _v2_approved_lock(s, "ci-bot@example.invalid", monkeypatch)
    monkeypatch.undo()  # restore SCHEMA_VERSION=3 for the current build
    cur = build_lock(s, [])

    assert base.schema_version == 2
    assert cur.schema_version == 3
    assert base.overall_digest != cur.overall_digest  # ref resolution moved the digest

    drift = compute_drift(base, cur)
    unapproved = [d for d in drift if d.drift_class == "unapproved-change"]
    migrated = [d for d in drift if d.drift_class == "schema-version-migrated"]
    assert unapproved and unapproved[0].severity == "high"
    assert migrated and migrated[0].severity == "low"
    assert "re-pin" in migrated[0].message
    # Non-zero exit: any non-empty drift set means check fails.
    assert drift


def test_genuine_surface_drift_across_version_boundary(monkeypatch):
    # A real surface change (added required unconstrained prop) ALSO crossing the
    # v2→v3 boundary still surfaces its real granular drift item, not just the
    # version-migration advisory.
    base_schema = {"type": "object", "properties": {"a": {"type": "string", "maxLength": 8}}}
    s = _surface([CapturedTool(name="t", input_schema=base_schema)])
    base = _v2_approved_lock(s, "ci-bot@example.invalid", monkeypatch)
    monkeypatch.undo()

    cur_schema = {
        "type": "object",
        "properties": {"a": {"type": "string", "maxLength": 8}, "b": {}},
        "required": ["b"],
    }
    cur = build_lock(_surface([CapturedTool(name="t", input_schema=cur_schema)]), [])

    drift = compute_drift(base, cur)
    assert any(d.drift_class == "unapproved-change" for d in drift)
    assert any(d.drift_class == "schema-version-migrated" for d in drift)
    # The genuine surface change is still reported granularly.
    assert any(d.drift_class == "schema-required-unconstrained-added" for d in drift)


def test_relaxed_ref_def_across_v2_v3_boundary_blocks_high(monkeypatch):
    # Compat regression: an APPROVED v2 baseline for a $ref-using surface, vs a v3
    # lock of a RELAXED version of that shared definition (drop a `required` entry).
    # With input_schema_hash differing, compute_drift MUST yield at least one HIGH
    # DriftItem (the gate blocks) AND must still report the genuine relaxation
    # granularly. Proves no silent under-report across the v2→v3 boundary.
    base_schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/S"}},
        "$defs": {
            "S": {
                "type": "object",
                "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
                "required": ["a", "b"],
            }
        },
    }
    s = _surface([CapturedTool(name="t", input_schema=base_schema)])
    base = _v2_approved_lock(s, "ci-bot@example.invalid", monkeypatch)
    monkeypatch.undo()  # restore SCHEMA_VERSION=3 for the current build

    # v3 lock of a RELAXED shared definition: drop the `required` entry "b".
    cur_schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/S"}},
        "$defs": {
            "S": {
                "type": "object",
                "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
                "required": ["a"],
            }
        },
    }
    cur = build_lock(_surface([CapturedTool(name="t", input_schema=cur_schema)]), [])

    # The shared-definition relaxation changes the tool's input_schema_hash.
    assert base.tools[0].input_schema_hash != cur.tools[0].input_schema_hash

    drift = compute_drift(base, cur)
    # The gate blocks: at least one HIGH DriftItem in the set (no silent pass).
    assert any(d.severity == "high" for d in drift), (
        "v2→v3 relaxed-ref-def must yield at least one HIGH drift item (gate blocks)"
    )
    # The genuine relaxation through the shared $ref is still reported granularly
    # at the tool path (never under-reported / laundered across the boundary).
    assert any(
        d.target == "tools/t" and d.drift_class == "schema-constraint-relaxed" for d in drift
    )
