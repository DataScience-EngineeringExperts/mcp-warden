"""Lock build / write / read + overall-digest exclusion tests (WARDEN_LOCK_SCHEMA.md)."""

from __future__ import annotations

import json

from mcp_warden.lockfile import build_lock, lock_to_pretty_json, read_lock, write_lock
from mcp_warden.models import (
    Attestation,
    CapturedSurface,
    CapturedTool,
    Finding,
    Pinner,
)


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


def test_provenance_fields_excluded_from_overall_digest():
    """Invariant 1 (#19): mutating EVERY new provenance field leaves overall_digest
    byte-identical, incl. a simulated future out-of-digest field (cross-version)."""
    lock = build_lock(_surface(), [])
    original_digest = lock.overall_digest

    # Mutate every #19 provenance field on the pin block.
    lock.pin.provenance_version = 99
    lock.pin.pinner = Pinner(tool="other", tool_version="9.9.9", actor="someone", environment="ci")
    lock.pin.attestations = [
        Attestation(
            actor="a@b.invalid",
            role="approver",
            method="manual",
            created_at="2026-01-01T00:00:00Z",
            bound_digest=original_digest,
            note="hand-mutated",
        )
    ]
    lock.pin.rotated_at = "2026-01-02T00:00:00Z"
    lock.pin.rotation_count = 7

    # overall_digest is NOT recomputed from the pin block; it must be unchanged.
    assert lock.overall_digest == original_digest

    # Cross-version: a #16/#23 reader/writer that drops an extra out-of-digest
    # provenance field into the serialized pin must not perturb overall_digest.
    data = lock.model_dump(mode="json")
    data["pin"]["future_signature"] = {"alg": "ed25519", "sig": "deadbeef"}
    reloaded = type(lock).model_validate(data)  # extra="ignore" tolerates it
    from mcp_warden.lockfile import compute_overall_digest

    recomputed = compute_overall_digest(
        reloaded.server, reloaded.tools, reloaded.resources, reloaded.prompts
    )
    assert recomputed == original_digest


def test_approve_mirrors_single_approver_attestation():
    """B2: --approve sets scalar approved AND appends exactly one role=approver
    attestation whose bound_digest == overall_digest."""
    lock = build_lock(_surface(), [], approve=True, approver="ci-bot@example.invalid")
    assert lock.pin.approved is True
    approver_atts = [a for a in lock.pin.attestations if a.role == "approver"]
    assert len(approver_atts) == 1
    assert lock.pin.attestations[-1].bound_digest == lock.overall_digest
    assert lock.pin.attestations[-1].actor == "ci-bot@example.invalid"


def test_unapproved_pin_has_pinner_no_attestations():
    """A plain pin populates the pinner block but appends no attestation."""
    lock = build_lock(_surface(), [])
    assert lock.pin.pinner is not None
    assert lock.pin.pinner.tool == "mcp-warden"
    assert lock.pin.attestations == []
    assert lock.pin.rotation_count == 0


def test_back_compat_v2_lock_without_provenance_validates(tmp_path):
    """A hand-written v2 lock with NO #19 provenance fields validates + round-trips;
    `check` (drift) runs against it with no crash."""
    s = _surface()
    lock = build_lock(s, [])
    data = lock.model_dump(mode="json")
    # Strip every #19 provenance field to mimic a pre-#19 on-disk lock.
    for key in ("provenance_version", "pinner", "attestations", "rotated_at", "rotation_count"):
        data["pin"].pop(key, None)
    path = tmp_path / "warden.lock"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    loaded = read_lock(path)  # must not raise; defaults apply
    assert loaded.pin.provenance_version == 1
    assert loaded.pin.pinner is None
    assert loaded.pin.attestations == []
    assert loaded.pin.rotation_count == 0
    assert loaded.overall_digest == lock.overall_digest

    # drift against the same surface is clean (no crash on missing provenance).
    from mcp_warden.drift import compute_drift

    current = build_lock(s, [])
    assert compute_drift(loaded, current) == []


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
