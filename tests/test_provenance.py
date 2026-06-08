"""Provenance + `warden lock rotate` tests (#19, WARDEN_LOCK_SCHEMA §8.x).

Covers the pure `rotate_provenance` helper (digest invariance, B2 consistency,
note cap) and the `lock rotate` CLI (integrity gate / fail-closed-on-tamper,
exit codes, approved re-bind, end-to-end clean `check` after rotate).
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from mcp_warden.cli import app
from mcp_warden.drift import compute_drift
from mcp_warden.lockfile import build_lock, read_lock, write_lock
from mcp_warden.models import ATTESTATION_NOTE_MAX_LEN, Attestation, CapturedSurface, CapturedTool
from mcp_warden.provenance import ProvenanceError, rotate_provenance

runner = CliRunner()


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


# --- pure rotate_provenance helper ------------------------------------------


def test_rotate_preserves_overall_digest_and_appends_attestation():
    lock = build_lock(_surface(), [])
    before = lock.overall_digest
    rotated = rotate_provenance(lock, approver=None, actor="ci@x.invalid", note=None, now="2026-06-08T00:00:00Z")
    assert rotated.overall_digest == before  # byte-identical
    assert rotated.pin.rotation_count == 1
    assert rotated.pin.rotated_at == "2026-06-08T00:00:00Z"
    assert len(rotated.pin.attestations) == 1
    att = rotated.pin.attestations[-1]
    assert att.role == "pinner"  # no approver given
    assert att.actor == "ci@x.invalid"
    assert att.bound_digest == before
    # The source lock is not mutated in place (deep copy).
    assert lock.pin.rotation_count == 0


def test_rotate_with_approver_rebinds_scalar_and_mirrors_attestation():
    """B2 after rotate: approved scalars set, exactly one role=approver attestation,
    bound_digest == overall_digest (unchanged)."""
    lock = build_lock(_surface(), [])  # unapproved baseline
    before = lock.overall_digest
    rotated = rotate_provenance(
        lock, approver="boss@x.invalid", actor=None, note="quarterly re-attest", now="2026-06-08T01:00:00Z"
    )
    assert rotated.overall_digest == before
    assert rotated.pin.approved is True
    assert rotated.pin.approver == "boss@x.invalid"
    assert rotated.pin.approved_digest == before
    approver_atts = [a for a in rotated.pin.attestations if a.role == "approver"]
    assert len(approver_atts) == 1
    assert rotated.pin.attestations[-1].bound_digest == before


def test_rotate_count_increments_across_repeated_rotations():
    lock = build_lock(_surface(), [])
    r1 = rotate_provenance(lock, approver=None, actor="a", note=None, now="2026-06-08T00:00:00Z")
    r2 = rotate_provenance(r1, approver=None, actor="b", note=None, now="2026-06-08T00:01:00Z")
    assert r2.pin.rotation_count == 2
    assert len(r2.pin.attestations) == 2
    assert r2.overall_digest == lock.overall_digest


def test_rotate_rejects_overlong_note():
    lock = build_lock(_surface(), [])
    with pytest.raises(ProvenanceError):
        rotate_provenance(
            lock, approver=None, actor="a", note="x" * (ATTESTATION_NOTE_MAX_LEN + 1), now="2026-06-08T00:00:00Z"
        )


def test_rotate_accepts_note_at_cap():
    lock = build_lock(_surface(), [])
    rotated = rotate_provenance(
        lock, approver=None, actor="a", note="x" * ATTESTATION_NOTE_MAX_LEN, now="2026-06-08T00:00:00Z"
    )
    assert rotated.pin.attestations[-1].note == "x" * ATTESTATION_NOTE_MAX_LEN


def test_attestation_model_validator_rejects_overlong_note():
    """D3: a DIRECT Attestation(...) constructor cannot bypass the note cap — the
    model-level field_validator fails closed with a pydantic ValidationError, so
    future #16/#23 paths that build attestations without the CLI helper are bounded."""
    with pytest.raises(ValidationError):
        Attestation(
            actor="a",
            created_at="2026-06-08T00:00:00Z",
            bound_digest="sha256:" + "0" * 64,
            note="x" * (ATTESTATION_NOTE_MAX_LEN + 1),
        )


def test_attestation_model_validator_accepts_note_at_cap():
    """D3 boundary: a note exactly at the cap constructs cleanly (off-by-one guard)."""
    att = Attestation(
        actor="a",
        created_at="2026-06-08T00:00:00Z",
        bound_digest="sha256:" + "0" * 64,
        note="x" * ATTESTATION_NOTE_MAX_LEN,
    )
    assert att.note == "x" * ATTESTATION_NOTE_MAX_LEN


# --- CLI `warden lock rotate` -----------------------------------------------


def test_cli_rotate_happy_path_preserves_digest_and_check_stays_clean(tmp_path):
    """pin -> rotate -> overall_digest unchanged + rotation_count+1; a later
    drift check against the same surface is still clean."""
    s = _surface()
    path = tmp_path / "warden.lock"
    write_lock(build_lock(s, []), path)
    before = read_lock(path).overall_digest

    result = runner.invoke(app, ["lock", "rotate", str(path), "--actor", "ci@x.invalid"])
    assert result.exit_code == 0, result.output

    after = read_lock(path)
    assert after.overall_digest == before
    assert after.pin.rotation_count == 1
    assert len(after.pin.attestations) == 1

    # A subsequent check against the same surface: no drift, no false unapproved.
    current = build_lock(s, [])
    assert compute_drift(after, current) == []


def test_cli_rotate_json_summary(tmp_path):
    path = tmp_path / "warden.lock"
    write_lock(build_lock(_surface(), []), path)
    # Capture the pre-rotate digest so the assertions below COMPUTE the unchanged
    # claim against ground truth — this test must be able to FAIL if rotate ever
    # mutates overall_digest (it can no longer pass on a hardcoded literal).
    before = read_lock(path).overall_digest
    result = runner.invoke(app, ["lock", "rotate", str(path), "--actor", "ci@x.invalid", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["rotation_count"] == {"old": 0, "new": 1}
    assert payload["overall_digest"] == before
    assert payload["overall_digest_unchanged"] is True


def test_cli_rotate_approved_lock_rebinds_and_stays_clean(tmp_path):
    """Rotate an approved lock with --approver: approved_digest still equals the
    unchanged overall_digest; unapproved-change does NOT fire on a clean check."""
    s = _surface()
    path = tmp_path / "warden.lock"
    write_lock(build_lock(s, [], approve=True, approver="orig@x.invalid"), path)
    before = read_lock(path).overall_digest

    result = runner.invoke(app, ["lock", "rotate", str(path), "--approver", "new@x.invalid"])
    assert result.exit_code == 0, result.output

    after = read_lock(path)
    assert after.overall_digest == before
    assert after.pin.approved is True
    assert after.pin.approver == "new@x.invalid"
    assert after.pin.approved_digest == before

    # Append-only contract (D2): the fresh build_lock(approve=True) wrote one
    # approver attestation; rotating with --approver appends a SECOND. The log is
    # NOT deduped, and the LATEST approver attestation binds the current digest.
    approver_atts = [a for a in after.pin.attestations if a.role == "approver"]
    assert len(approver_atts) == 2
    assert after.pin.attestations[-1].role == "approver"
    assert after.pin.attestations[-1].bound_digest == after.overall_digest

    current = build_lock(s, [])
    drift = compute_drift(after, current)
    assert [d for d in drift if d.drift_class == "unapproved-change"] == []


def test_cli_rotate_missing_lock_fails_closed(tmp_path):
    result = runner.invoke(app, ["lock", "rotate", str(tmp_path / "nope.lock")])
    assert result.exit_code == 2


def test_cli_rotate_fails_closed_on_tampered_entry_digest(tmp_path):
    """Hand-edit a stored entry_digest -> rotate refuses (exit 2) + writes nothing."""
    path = tmp_path / "warden.lock"
    write_lock(build_lock(_surface(), []), path)
    original_text = path.read_text(encoding="utf-8")

    data = json.loads(original_text)
    data["tools"][0]["entry_digest"] = "sha256:" + "0" * 64  # tamper
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tampered_text = path.read_text(encoding="utf-8")

    result = runner.invoke(app, ["lock", "rotate", str(path), "--actor", "a"])
    assert result.exit_code == 2
    # Nothing written: file is byte-for-byte the tampered input we wrote.
    assert path.read_text(encoding="utf-8") == tampered_text


def test_cli_rotate_fails_closed_on_tampered_overall_digest(tmp_path):
    path = tmp_path / "warden.lock"
    write_lock(build_lock(_surface(), []), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["overall_digest"] = "sha256:" + "1" * 64  # tamper
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tampered_text = path.read_text(encoding="utf-8")

    result = runner.invoke(app, ["lock", "rotate", str(path), "--actor", "a"])
    assert result.exit_code == 2
    assert path.read_text(encoding="utf-8") == tampered_text


def test_cli_rotate_fails_closed_on_stale_approval(tmp_path):
    """An approved lock whose approved_digest no longer binds the surface is
    refused (exit 2, no write)."""
    path = tmp_path / "warden.lock"
    write_lock(build_lock(_surface(), [], approve=True, approver="orig@x.invalid"), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["pin"]["approved_digest"] = "sha256:" + "2" * 64  # stale
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tampered_text = path.read_text(encoding="utf-8")

    result = runner.invoke(app, ["lock", "rotate", str(path), "--actor", "a"])
    assert result.exit_code == 2
    assert path.read_text(encoding="utf-8") == tampered_text


def test_cli_rotate_overlong_note_rejected(tmp_path):
    path = tmp_path / "warden.lock"
    write_lock(build_lock(_surface(), []), path)
    original_text = path.read_text(encoding="utf-8")
    result = runner.invoke(
        app, ["lock", "rotate", str(path), "--actor", "a", "--note", "x" * (ATTESTATION_NOTE_MAX_LEN + 1)]
    )
    assert result.exit_code == 2
    # Note cap is checked AFTER the integrity gate but BEFORE write -> no change.
    assert path.read_text(encoding="utf-8") == original_text
