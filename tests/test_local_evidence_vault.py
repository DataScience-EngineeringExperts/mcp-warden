"""Synthetic local custody tests, including the two sides of the commit boundary."""

from __future__ import annotations

import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux local evidence vault")

if sys.platform == "linux":
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from mcp_warden import evidence_vault
    from mcp_warden.evidence_key_service import (
        EvidenceKeyServiceError,
        LocalKeyAccess,
        _Grant,
        _Keyring,
        decode_payload,
        encode_payload,
    )
    from mcp_warden.evidence_vault import LocalEvidenceVault, initialize_vault


class _Access:
    def __init__(self):
        self.peer_uid = 41234
        grants = {
            _Grant(self.peer_uid, tenant, category, action, role, purpose)
            for tenant in ("fixture", "different")
            for category in ("tool-arguments", "tool-result")
            for action, role, purpose in (
                ("capture", "recorder", "evidence-capture"), ("read", "reviewer", "test-review"),
                ("audit", "reviewer", "test-review"), ("export", "reviewer", "test-review"),
                ("hold", "custodian", "test-hold"), ("release", "custodian", "test-hold"),
                ("delete", "custodian", "test-delete"),
            )
        }
        # Production receives this clock from the custodian; tests control it
        # independently of the Linux wall clock and keep production auth/AEAD.
        self.clock = 1700000000
        self.access = LocalKeyAccess(
            self.peer_uid, frozenset(grants), _Keyring("key", {"key": AESGCM(AESGCM.generate_key(256))}),
        )

    def authorize(self, **scope):
        self.access.authorize(**scope)
        return datetime.fromtimestamp(self.clock, UTC)

    def encrypt(self, **scope):
        return self.access.encrypt(**scope)

    def decrypt(self, **scope):
        return self.access.decrypt(**scope)


def _dispatch(vault, access, action, *, category="tool-result", tenant="fixture", **fields):
    return vault.dispatch(dict(action=action, tenant=tenant, category=category, **fields), access)


@pytest.fixture
def store(tmp_path: Path) -> Path:
    directory = tmp_path / "vault"
    directory.mkdir(mode=0o700)
    initialize_vault(directory)
    return directory


def test_scope_retention_hold_and_minimized_audit(store):
    access = _Access()
    content = b'{"text":"SYNTHETIC-PAYLOAD-a18e6283b587"}'
    with LocalEvidenceVault(store, retention_seconds=10) as vault:
        first = _dispatch(vault, access, "capture", content=encode_payload(content))["object_id"]
        second = _dispatch(vault, access, "capture", content=encode_payload(content))["object_id"]
        assert first != second
        assert content not in (store / "vault.sqlite").read_bytes()
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "read", purpose="unapproved", object_id=first)
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "read", tenant="different", purpose="test-review", object_id=first)
        _dispatch(vault, access, "hold", purpose="test-hold", object_id=first)
        access.clock += 11
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "read", purpose="test-review", object_id=second)
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "delete", purpose="test-delete", object_id=first)
        read = _dispatch(vault, access, "read", purpose="test-review", object_id=first)
        assert decode_payload(read["content"]) == content
        _dispatch(vault, access, "release", purpose="test-hold", object_id=first)
        _dispatch(vault, access, "delete", purpose="test-delete", object_id=first)
        output = _dispatch(vault, access, "audit", purpose="test-review", after=0)
        assert [row["event"]["action"] for row in output["receipts"]] == [
            "capture", "capture", "hold", "read", "release", "delete",
        ]
        assert b"SYNTHETIC" not in json.dumps(output).encode()

    with LocalEvidenceVault(store, retention_seconds=10) as vault:
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "read", purpose="test-review", object_id=first)
        access.clock -= 30
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "capture", content=encode_payload(content))


@pytest.mark.parametrize("after_db_commit", [False, True])
def test_floor_recovers_interrupted_commit_without_acknowledgement(store, monkeypatch, after_db_commit):
    access = _Access()
    original = evidence_vault.write_floor

    def interrupt(path, head, pending=None):
        if (pending is None) == after_db_commit:
            raise OSError("synthetic fault at durable boundary")
        original(path, head, pending)

    # Before-commit failure is injected after the prepared floor was written.
    def fail_after_prepare(path, head, pending=None):
        original(path, head, pending)
        if pending is not None:
            raise OSError("synthetic interruption before DB commit")

    with LocalEvidenceVault(store, retention_seconds=10) as vault:
        monkeypatch.setattr(evidence_vault, "write_floor", interrupt if after_db_commit else fail_after_prepare)
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "capture", content=encode_payload(b'{"text":"synthetic"}'))
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "ready")
    monkeypatch.setattr(evidence_vault, "write_floor", original)
    with LocalEvidenceVault(store, retention_seconds=10) as vault:
        output = _dispatch(vault, access, "audit", purpose="test-review", after=0)
        assert len(output["receipts"]) == int(after_db_commit)


def test_floor_refuses_rollback_and_unsafe_database_modes(store):
    access = _Access()
    database = store / "vault.sqlite"
    snapshot = database.read_bytes()
    with LocalEvidenceVault(store, retention_seconds=10) as vault:
        _dispatch(vault, access, "capture", content=encode_payload(b'{"text":"synthetic"}'))
    database.chmod(0o644)
    with pytest.raises(evidence_vault.EvidenceVaultError):
        with LocalEvidenceVault(store, retention_seconds=10):
            pytest.fail("insecure vault opened")
    database.chmod(0o600)
    database.write_bytes(snapshot)
    with pytest.raises(evidence_vault.EvidenceVaultError, match="EVD-FLOOR"):
        with LocalEvidenceVault(store, retention_seconds=10):
            pytest.fail("rolled-back vault opened")


def test_swap_and_read_commit_failure_never_return_raw(store, monkeypatch):
    access = _Access()
    with LocalEvidenceVault(store, retention_seconds=10) as vault:
        first = _dispatch(vault, access, "capture", content=encode_payload(b'{"text":"first"}'))["object_id"]
        second = _dispatch(vault, access, "capture", content=encode_payload(b'{"text":"second"}'))["object_id"]
    with sqlite3.connect(store / "vault.sqlite") as db:
        ciphertext, = db.execute("SELECT ciphertext FROM evidence WHERE object_id=?", (first,)).fetchone()
        db.execute("UPDATE evidence SET ciphertext=? WHERE object_id=?", (ciphertext, second))

    with LocalEvidenceVault(store, retention_seconds=10) as vault:
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "read", purpose="test-review", object_id=second)
        def fail_audit_write(*_):
            raise OSError("synthetic audit write failure")

        monkeypatch.setattr(evidence_vault, "write_floor", fail_audit_write)
        with pytest.raises(EvidenceKeyServiceError):
            _dispatch(vault, access, "read", purpose="test-review", object_id=first)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "wire",
    [
        b'{"jsonrpc":"2.0","method":"other","method":"tools/call"}\n',
        b'{"jsonrpc":"2.0","params":{"arg":1,"arg":2}}\n',
        b'{"jsonrpc":"2.0","params":{"arg":1e999}}\n',
        b'{"jsonrpc":"2.0","params":{"arg":1}}',
        b'Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}',
        b'Content-Length: 2\r\n Content-Length: 2\r\n\r\n{}',
    ],
)
async def test_protected_framing_rejects_ambiguous_or_partial_bytes(wire):
    from mcp_warden.framing import FrameReader

    parts = iter((wire, b""))

    async def receive():
        return next(parts)

    frame = await FrameReader(receive, 4096, strict_evidence=True).read_frame()
    assert frame.json is None
    assert frame.raw == b""


def test_summary_verifier_rejects_replacement_key_and_duplicate_fields():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from mcp_warden.evidence_summary import parse_summary, signed_summary, verify_summary

    signer = Ed25519PrivateKey.generate()
    artifact = signed_summary(signer, captures=5, reviews=0, deletions=100)
    enrolled = signer.public_key().public_bytes_raw().hex()
    verify_summary(artifact, enrolled)
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    with pytest.raises(evidence_vault.EvidenceVaultError):
        verify_summary(artifact, other)
    duplicate = json.dumps(artifact).replace('"schema_version": 1', '"schema_version": 2, "schema_version": 1')
    with pytest.raises(evidence_vault.EvidenceVaultError):
        parse_summary(duplicate.encode())
    artifact["summary"]["capture_count_band"] = "10-99"
    with pytest.raises(evidence_vault.EvidenceVaultError):
        verify_summary(artifact, enrolled)
