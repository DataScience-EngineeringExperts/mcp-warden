"""Tool metadata must be covered without treating server hints as authority."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_warden.cli import app
from mcp_warden.drift import compute_drift
from mcp_warden.emitters import build_sarif
from mcp_warden.guard_list_gate import diverges_from_lock
from mcp_warden.hashing import hash_value
from mcp_warden.lockfile import build_lock, lock_is_self_consistent, lock_to_pretty_json, read_lock
from mcp_warden.models import CapturedSurface, CapturedTool


def make_lock(*, annotations=None, output_schema=None, description="Read a record."):
    return build_lock(
        CapturedSurface(
            command="fixture", protocol_version="2025-06-18",
            tools=[CapturedTool(
                name="read_record", description=description, input_schema={"type": "object"},
                annotations=annotations, output_schema=output_schema,
            )],
        ), [], approve=True, approver="reviewer@example.invalid",
    )


def classes(base, current):
    return {d.drift_class for d in compute_drift(base, current)}


@pytest.mark.parametrize("hint", ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"])
def test_every_hint_flip_changes_digest_and_blocks(hint):
    base, cur = make_lock(annotations={hint: False}), make_lock(annotations={hint: True})
    assert base.overall_digest != cur.overall_digest
    assert {"tool-annotations-modified", "unapproved-change"} <= classes(base, cur)
    assert base.tools[0].capabilities == cur.tools[0].capabilities


@pytest.mark.parametrize("base,cur", [(None, {}), ({}, None), ({"title": "a"}, {"title": "b"})])
def test_complete_annotation_object_is_hashed(base, cur):
    assert "tool-annotations-modified" in classes(make_lock(annotations=base), make_lock(annotations=cur))


def test_absent_and_null_metadata_have_same_digest():
    implicit = build_lock(CapturedSurface(
        command="fixture", protocol_version="2025-06-18",
        tools=[CapturedTool(name="read_record", description="Read a record.", input_schema={"type": "object"})],
    ), [])
    explicit = make_lock()
    assert implicit.overall_digest == explicit.overall_digest
    assert explicit.tools[0].annotations_hash == hash_value(None)
    assert explicit.tools[0].output_schema_hash == hash_value(None)
    assert explicit.tools[0].output_schema_skeleton is None


def test_metadata_key_order_is_canonical():
    a = make_lock(annotations={"readOnlyHint": True, "destructiveHint": False})
    b = make_lock(annotations={"destructiveHint": False, "readOnlyHint": True})
    assert a.overall_digest == b.overall_digest


def output_schema(**field):
    return {"type": "object", "properties": {"value": field}}


def test_output_type_broadening_has_distinct_structural_rule():
    base = make_lock(output_schema=output_schema(type="string"))
    cur = make_lock(output_schema=output_schema(type=["string", "number"]))
    assert "schema-out-type-broadened" in classes(base, cur)
    rules = {r["ruleId"] for r in build_sarif([], compute_drift(base, cur))["runs"][0]["results"]}
    assert "WRD-DRIFT-SCHEMA-OUT-TYPE-BROADENED" in rules


@pytest.mark.parametrize("before,after,expected", [
    (None, {}, "schema-out-added"),
    ({}, None, "schema-out-removed"),
    ({"type": "object", "title": "A"}, {"type": "object", "title": "B"}, "schema-out-cosmetic-modified"),
    (output_schema(type="string", maxLength=8), output_schema(type="string", maxLength=64), "schema-out-constraint-relaxed"),
])
def test_output_presence_and_structure(before, after, expected):
    assert expected in classes(make_lock(output_schema=before), make_lock(output_schema=after))


def test_output_schema_changes_inside_local_ref_are_detected():
    a = {"$defs": {"v": {"type": "string"}}, "properties": {"value": {"$ref": "#/$defs/v"}}}
    b = {"$defs": {"v": {"type": ["string", "number"]}}, "properties": {"value": {"$ref": "#/$defs/v"}}}
    assert "schema-out-type-broadened" in classes(make_lock(output_schema=a), make_lock(output_schema=b))


def test_annotation_values_are_never_rendered():
    sentinel = "private annotation sentinel value"
    drift = compute_drift(make_lock(annotations={"title": "before"}), make_lock(annotations={"title": sentinel}))
    assert sentinel not in json.dumps(build_sarif([], drift))
    assert sentinel not in lock_to_pretty_json(make_lock(annotations={"title": sentinel}))


def test_combined_metadata_changes_are_all_reported():
    a = make_lock(annotations={"destructiveHint": False}, output_schema=output_schema(type="string"))
    b = make_lock(annotations={"destructiveHint": True}, output_schema=output_schema(type="number"))
    assert {"tool-annotations-modified", "schema-out-type-changed", "unapproved-change"} <= classes(a, b)


@pytest.mark.parametrize("field", ["annotations", "output_schema"])
@pytest.mark.parametrize("value", [[], "not-an-object", True])
def test_non_object_metadata_is_rejected(field, value):
    with pytest.raises(ValueError):
        CapturedTool(name="x", **{field: value})


@pytest.mark.parametrize("field", ["annotations_hash", "output_schema_hash", "output_schema_skeleton"])
def test_v4_lock_requires_new_fields(field, tmp_path):
    doc = json.loads(lock_to_pretty_json(make_lock()))
    del doc["tools"][0][field]
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        read_lock(path)


def test_genuine_v3_lock_remains_readable_and_requires_reapproval(tmp_path):
    # Freeze historical bytes/formulas, not a v4 document relabeled as v3.
    doc = json.loads(Path("tests/fixtures/legacy-v3.warden.lock").read_text())
    path = tmp_path / "old.lock"
    path.write_text(json.dumps(doc))
    old = read_lock(path)
    assert old.schema_version == 3
    assert lock_is_self_consistent(old)
    current = build_lock(CapturedSurface(
        command=old.server.command, args=old.server.args, protocol_version="2025-06-18",
        tools=[CapturedTool(name="t", input_schema={"type": "object", "properties": {"x": {"type": "string"}}})],
    ), [])
    old.pin.approved = True
    old.pin.approved_digest = old.overall_digest
    assert {"schema-version-migrated", "unapproved-change"} <= classes(old, current)
    assert "tool-annotations-modified" not in classes(old, current)
    old.pin.approved = False
    assert "schema-version-migrated" in classes(old, current)


@pytest.mark.parametrize("mutation", [
    {"annotations": {"destructiveHint": True}},
    {"outputSchema": output_schema(type="number")},
])
def test_runtime_list_gate_covers_v4_metadata(mutation):
    base = make_lock(annotations={"destructiveHint": False}, output_schema=output_schema(type="string"))
    tool = {"name": "read_record", "description": "Read a record.", "inputSchema": {"type": "object"},
            "annotations": {"destructiveHint": False}, "outputSchema": output_schema(type="string")}
    assert diverges_from_lock({"tools": [tool]}, base) == (False, "")
    changed, reason = diverges_from_lock({"tools": [tool | mutation]}, base)
    assert changed and "modified" in reason


@pytest.mark.parametrize("mutation,rule", [
    ({"annotations": {"destructiveHint": True}}, "WRD-DRIFT-TOOL-ANNOTATIONS-MODIFIED"),
    ({"outputSchema": output_schema(type=["string", "number"])}, "WRD-DRIFT-SCHEMA-OUT-TYPE-BROADENED"),
])
def test_real_cli_roundtrip_rejects_metadata_only_change(tmp_path, mutation, rule):
    fixture = str(Path(__file__).parent / "fixtures" / "tool_integrity_server.py")
    declaration = tmp_path / "declaration.json"
    tool = {"name": "read_record", "inputSchema": {"type": "object"},
            "annotations": {"destructiveHint": False}, "outputSchema": output_schema(type="string")}
    declaration.write_text(json.dumps(tool))
    lock_path, sarif_path = tmp_path / "warden.lock", tmp_path / "drift.sarif"
    argv = [sys.executable, fixture, str(declaration)]
    runner = CliRunner()
    pinned = runner.invoke(app, ["pin", *argv, "--approve", "--approver", "reviewer@example.invalid", "--lock", str(lock_path)])
    assert pinned.exit_code == 0, pinned.output
    clean = runner.invoke(app, ["check", *argv, "--lock", str(lock_path)])
    assert clean.exit_code == 0, clean.output
    declaration.write_text(json.dumps(tool | mutation))
    changed = runner.invoke(app, ["check", *argv, "--lock", str(lock_path), "--sarif", str(sarif_path)])
    assert changed.exit_code == 1, changed.output
    rules = {r["ruleId"] for r in json.loads(sarif_path.read_text())["runs"][0]["results"]}
    assert rule in rules
    assert "WRD-DRIFT-UNAPPROVED-CHANGE" in rules
