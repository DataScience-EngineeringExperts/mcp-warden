"""``mcp-warden lock sign`` — sign an existing unsigned lock (DSE-1530).

Same fail-closed contract as ``pin --sign``: v1/v2 statement bytes, never
overwrites or stacks a signature, no partial sidecar on a signing failure.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_warden import cli_sign, signing
from mcp_warden.cli import app
from mcp_warden.cli_sign import SIGNED_PROVENANCE_VERSION
from mcp_warden.lockfile import build_lock, read_lock, write_lock
from mcp_warden.models import CapturedSurface, CapturedTool
from mcp_warden.signing import build_statement

runner = CliRunner()
COORD = "npm:@org/srv@1.2.3"


def _write_unsigned_lock(tmp_path: Path) -> Path:
    surface = CapturedSurface(
        command="node",
        args=["./build/index.js"],
        protocol_version="2025-06-18",
        tools=[CapturedTool(name="read_file", description="Read a file", input_schema={"properties": {"path": {}}})],
    )
    lock_path = tmp_path / "warden.lock"
    write_lock(build_lock(surface, []), lock_path)
    return lock_path


@pytest.fixture
def signed_statements(monkeypatch):
    """Fake the Sigstore boundary; record every statement handed to the signer."""
    seen: list[bytes] = []
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)

    def fake_sign(statement, token):
        seen.append(statement)
        return {"stmt": statement.decode()}

    monkeypatch.setattr(cli_sign, "sign_statement", fake_sign)
    monkeypatch.setattr(cli_sign, "bundle_to_json", lambda bundle: json.dumps(bundle))
    return seen


def _sign(lock_path: Path, *extra: str):
    return runner.invoke(app, ["lock", "sign", str(lock_path), *extra])


@pytest.mark.parametrize(("extra", "coordinate"), [((), None), (("--coordinate", COORD), COORD)])
def test_sign_writes_sidecar_with_exact_statement_bytes(tmp_path, signed_statements, extra, coordinate):
    lock_path = _write_unsigned_lock(tmp_path)
    digest = read_lock(lock_path).overall_digest

    result = _sign(lock_path, *extra)

    assert result.exit_code == 0, result.output
    assert signed_statements == [build_statement(digest, coordinate)]
    sidecar = tmp_path / "warden.lock.sigstore"
    assert json.loads(sidecar.read_text()) == {"stmt": build_statement(digest, coordinate).decode()}
    signed = read_lock(lock_path)
    assert signed.overall_digest == digest
    assert signed.pin.provenance_version == SIGNED_PROVENANCE_VERSION
    pointers = [a for a in signed.pin.attestations if a.method == "sigstore-keyless"]
    assert [p.bound_digest for p in pointers] == [digest]


def test_sign_refuses_to_overwrite_an_existing_sidecar(tmp_path, signed_statements):
    lock_path = _write_unsigned_lock(tmp_path)
    sidecar = tmp_path / "warden.lock.sigstore"
    sidecar.write_text("prior-bundle")
    before = lock_path.read_bytes()

    result = _sign(lock_path)

    assert result.exit_code == 2
    assert sidecar.read_text() == "prior-bundle"
    assert lock_path.read_bytes() == before
    assert signed_statements == []


def test_sign_refuses_a_lock_that_already_carries_a_pointer(tmp_path, signed_statements):
    lock_path = _write_unsigned_lock(tmp_path)
    assert _sign(lock_path).exit_code == 0
    (tmp_path / "warden.lock.sigstore").unlink()
    before = lock_path.read_bytes()

    result = _sign(lock_path)

    assert result.exit_code == 2
    assert lock_path.read_bytes() == before
    assert len(signed_statements) == 1


def test_sign_failure_exits_1_and_leaves_the_lock_unsigned(tmp_path, monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)

    def boom(statement, token):
        raise signing.SigningError("no ambient OIDC credential available")

    monkeypatch.setattr(cli_sign, "sign_statement", boom)
    lock_path = _write_unsigned_lock(tmp_path)
    before = lock_path.read_bytes()

    result = _sign(lock_path, "--coordinate", COORD)

    assert result.exit_code == 1
    assert lock_path.read_bytes() == before
    assert not (tmp_path / "warden.lock.sigstore").exists()
    assert not (tmp_path / "warden.lock.sigstore.tmp").exists()


def test_sign_without_the_extra_exits_2(tmp_path, monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", False)
    lock_path = _write_unsigned_lock(tmp_path)

    assert _sign(lock_path).exit_code == 2
    assert not (tmp_path / "warden.lock.sigstore").exists()


def test_sign_rejects_bad_coordinate_tampered_and_missing_locks(tmp_path, signed_statements):
    lock_path = _write_unsigned_lock(tmp_path)
    assert _sign(lock_path, "--coordinate", "npm:srv").exit_code == 2

    doc = json.loads(lock_path.read_text())
    doc["overall_digest"] = "sha256:" + "1" * 64
    lock_path.write_text(json.dumps(doc))
    assert _sign(lock_path).exit_code == 2

    assert _sign(tmp_path / "absent.lock").exit_code == 2
    assert signed_statements == []
    assert not (tmp_path / "warden.lock.sigstore").exists()
