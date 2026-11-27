"""Transactional custody of encrypted incident objects and a signed local audit chain."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from .evidence_key_service import EvidenceKeyServiceError, decode_payload, encode_payload
from .evidence_summary import signed_summary
from .evidence_vault_files import (
    CATEGORIES,
    INITIAL_HEAD,
    EvidenceVaultError,
    new_file,
    private_directory,
    private_file,
    reconcile_floor,
    sync_dir,
    write_floor,
)

REVIEW_ACTIONS = ("read", "export", "audit", "summary")
CUSTODIAN_ACTIONS = ("hold", "release", "delete")
_SCOPE_ID = "0" * 32
_MAX_RETENTION_SECONDS = 3660 * 86400
_SCHEMA = """
CREATE TABLE evidence (
    tenant TEXT NOT NULL, object_id TEXT NOT NULL, category TEXT NOT NULL,
    expires INTEGER NOT NULL, held INTEGER NOT NULL CHECK (held IN (0, 1)),
    ciphertext BLOB NOT NULL, PRIMARY KEY (tenant, object_id, category)
);
CREATE TABLE audit (
    sequence INTEGER PRIMARY KEY, tenant TEXT NOT NULL, category TEXT NOT NULL,
    action TEXT NOT NULL, payload BLOB NOT NULL, signature BLOB NOT NULL
);
CREATE INDEX audit_scope ON audit(tenant, category, sequence);
CREATE INDEX audit_band ON audit(tenant, category, action);
"""


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, isolation_level=None)
    try:
        if connection.execute("PRAGMA journal_mode").fetchone() != ("delete",):
            raise EvidenceVaultError("EVD-STORAGE")
        connection.execute("PRAGMA synchronous=EXTRA")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA temp_store=MEMORY")
    except BaseException:
        connection.close()
        raise
    return connection


def initialize_vault(path: Path) -> None:
    """Provision a new store inside an empty, private custodian directory."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = private_directory(path)
    if any(path.iterdir()):
        raise EvidenceVaultError("EVD-STORAGE")
    new_file(path / "lock", b"")
    new_file(path / "audit-key", Ed25519PrivateKey.generate().private_bytes_raw())
    new_file(path / "vault.sqlite", b"")
    with closing(_connect(path / "vault.sqlite")) as db:
        db.executescript("BEGIN IMMEDIATE;" + _SCHEMA + "COMMIT;")
    new_file(path / "floor", json.dumps([INITIAL_HEAD, None]).encode("ascii"))
    sync_dir(path)


def _json(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _audit_digest(payload: bytes, signature: bytes) -> str:
    return hashlib.sha256(b"warden.local-evidence.audit.v1\0" + payload + signature).hexdigest()


def load_signing_key(path: Path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_path = private_directory(path) / "audit-key"
    private_file(key_path)
    with key_path.open("rb") as stream:
        return Ed25519PrivateKey.from_private_bytes(stream.read(33))


class LocalEvidenceVault:
    """Sole active writer, under the service account, with no network output."""

    def __init__(self, path: Path, *, retention_seconds: int):
        if type(retention_seconds) is not int or not 1 <= retention_seconds <= _MAX_RETENTION_SECONDS:
            raise EvidenceVaultError("EVD-POLICY")
        self.path = path
        self.retention_seconds = retention_seconds
        self._failed = False

    def __enter__(self):
        path = private_directory(self.path)
        for name in ("lock", "audit-key", "vault.sqlite", "floor"):
            private_file(path / name)
        journal = path / "vault.sqlite-journal"
        if journal.exists() or journal.is_symlink():
            private_file(journal)
        if any(os.path.lexists(path / ("vault.sqlite" + extension)) for extension in ("-wal", "-shm")):
            raise EvidenceVaultError("EVD-STORAGE")
        self._lock = (path / "lock").open("rb")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._key = load_signing_key(path)
            self._db = _connect(path / "vault.sqlite")
            try:
                self._verify_and_recover()
            except BaseException:
                self._db.close()
                raise
        except BaseException:
            self._lock.close()
            raise
        return self

    def __exit__(self, *_exc) -> None:
        try:
            self._db.close()
        finally:
            self._lock.close()

    def _verify_and_recover(self) -> None:
        from cryptography.exceptions import InvalidSignature

        previous = None
        head = INITIAL_HEAD
        expected: dict[tuple[str, str, str], tuple[int, int]] = {}
        verify_key = self._key.public_key()
        try:
            for seq, tenant, category, action, payload, signature in self._db.execute(
                "SELECT sequence, tenant, category, action, payload, signature FROM audit ORDER BY sequence"
            ):
                verify_key.verify(signature, payload)
                entry = json.loads(payload)
                if (
                    entry["previous"] != head[1] or entry["sequence"] != seq or seq != head[0] + 1
                    or (entry["tenant"], entry["category"]) != (tenant, category)
                    or entry["time"] < head[2] or entry["action"] != action
                ):
                    raise EvidenceVaultError("EVD-AUDIT")
                identity = (tenant, entry["object_id"], category)
                if action == "capture":
                    if identity in expected:
                        raise EvidenceVaultError("EVD-AUDIT")
                    expected[identity] = (entry["expires"], 0)
                elif action in ("hold", "release"):
                    expected[identity] = (expected[identity][0], int(action == "hold"))
                elif action == "delete":
                    del expected[identity]
                previous, head = head, (seq, _audit_digest(payload, signature), entry["time"])
        except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
            raise EvidenceVaultError("EVD-AUDIT") from exc
        objects = {
            (tenant, object_id, category): (expires, held)
            for tenant, object_id, category, expires, held in self._db.execute(
                "SELECT tenant, object_id, category, expires, held FROM evidence"
            )
        }
        if expected != objects:
            raise EvidenceVaultError("EVD-AUDIT")
        reconcile_floor(self.path / "floor", head, previous)
        self._head = head

    def dispatch(self, request: dict[str, object], access) -> dict[str, object]:
        try:
            return self._dispatch(request, access)
        except (EvidenceVaultError, OSError, sqlite3.Error, OverflowError, ValueError):
            raise EvidenceKeyServiceError("EVD-REFUSED") from None

    def _dispatch(self, request: dict[str, object], access) -> dict[str, object]:
        if self._failed:
            raise EvidenceVaultError("EVD-STORAGE")
        action = request.get("action")
        tenant, category = request.get("tenant"), request.get("category")
        if type(action) is not str or type(tenant) is not str or category not in CATEGORIES:
            raise EvidenceVaultError("EVD-POLICY")
        if action == "ready" and set(request) == {"action", "tenant", "category"}:
            access.authorize(tenant=tenant, object_id=_SCOPE_ID, category=category, action="capture",
                             role="recorder", purpose="evidence-capture")
            return {"ready": True}
        if action == "capture" and set(request) == {"action", "tenant", "category", "content"}:
            return self._capture(access, tenant, category, decode_payload(request["content"]))
        expected_fields = {"action", "tenant", "category", "purpose"}
        if action == "audit":
            expected_fields.add("after")
        elif action != "summary":
            expected_fields.add("object_id")
        if set(request) != expected_fields or (
            action not in REVIEW_ACTIONS and action not in CUSTODIAN_ACTIONS
        ):
            raise EvidenceVaultError("EVD-POLICY")
        purpose = request["purpose"]
        object_id = _SCOPE_ID if action in ("audit", "summary") else request["object_id"]
        if type(object_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", object_id):
            raise EvidenceVaultError("EVD-POLICY")
        role = "reviewer" if action in REVIEW_ACTIONS else "custodian"
        scope = dict(tenant=tenant, object_id=object_id, category=category, action=action,
                     role=role, purpose=purpose)
        now = self._timestamp(access.authorize(**scope))
        if action == "audit":
            return self._audit(tenant, category, request["after"])
        if action == "summary":
            return self._summary(tenant, category)
        return self._apply(access, scope, now)

    def _timestamp(self, value: datetime) -> int:
        if not isinstance(value, datetime) or value.utcoffset() is None:
            raise EvidenceVaultError("EVD-CLOCK")
        timestamp = int(value.timestamp())
        if timestamp < self._head[2] or timestamp <= 0:
            raise EvidenceVaultError("EVD-CLOCK")
        return timestamp

    def _capture(self, access, tenant, category, content: bytes) -> dict[str, object]:
        object_id = secrets.token_hex(16)
        scope = dict(tenant=tenant, object_id=object_id, category=category)
        now = self._timestamp(access.authorize(**scope, action="capture", role="recorder",
                                               purpose="evidence-capture"))
        ciphertext = access.encrypt(**scope, plaintext=content)
        expires = now + self.retention_seconds
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute(
                "INSERT INTO evidence VALUES (?, ?, ?, ?, 0, ?)",
                (tenant, object_id, category, expires, ciphertext),
            )
            self._commit(access.peer_uid, scope, "capture", now, expires=expires)
        finally:
            if self._db.in_transaction:
                self._db.rollback()
        return {"object_id": object_id}

    def _apply(self, access, scope: dict, now: int) -> dict[str, object]:
        identity = (scope["tenant"], scope["object_id"], scope["category"])
        action = scope["action"]
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute(
                "SELECT expires, held FROM evidence WHERE tenant=? AND object_id=? AND category=?",
                identity,
            ).fetchone()
            if row is None:
                raise EvidenceVaultError("EVD-POLICY")
            expires, held = row
            result: dict[str, object] = {"applied": True}
            if action in ("read", "export"):
                if now >= expires and not held:
                    raise EvidenceVaultError("EVD-POLICY")
                ciphertext, = self._db.execute(
                    "SELECT ciphertext FROM evidence WHERE tenant=? AND object_id=? AND category=?",
                    identity,
                ).fetchone()
                result = {"content": encode_payload(access.decrypt(**scope, ciphertext=ciphertext))}
            elif action in ("hold", "release"):
                self._db.execute(
                    "UPDATE evidence SET held=? WHERE tenant=? AND object_id=? AND category=?",
                    (int(action == "hold"), *identity),
                )
            else:
                if held or now < expires:
                    raise EvidenceVaultError("EVD-POLICY")
                self._db.execute("DELETE FROM evidence WHERE tenant=? AND object_id=? AND category=?", identity)
            self._commit(access.peer_uid, scope, action, now)
        finally:
            if self._db.in_transaction:
                self._db.rollback()
        return result

    def _audit(self, tenant: str, category: str, after: object) -> dict[str, object]:
        if type(after) is not int or not 0 <= after < 2**63 - 1:
            raise EvidenceVaultError("EVD-POLICY")
        receipts = [
            {"event": json.loads(payload), "signature": signature.hex()}
            for payload, signature in self._db.execute(
                "SELECT payload, signature FROM audit WHERE tenant=? AND category=? AND sequence>? "
                "ORDER BY sequence LIMIT 100",
                (tenant, category, after),
            )
        ]
        return {"verification_key": self._key.public_key().public_bytes_raw().hex(), "receipts": receipts}

    def _summary(self, tenant: str, category: str) -> dict[str, object]:
        counts = {}
        for action in ("capture", "read", "export", "delete"):
            counts[action], = self._db.execute(
                "SELECT count(*) FROM (SELECT 1 FROM audit WHERE tenant=? AND category=? AND action=? LIMIT 100)",
                (tenant, category, action),
            ).fetchone()
        return signed_summary(self._key, captures=counts["capture"], reviews=counts["read"] + counts["export"],
                              deletions=counts["delete"])

    def _commit(self, uid: int, scope: dict, action: str, now: int, *, expires: int | None = None) -> None:
        seq = self._head[0] + 1
        payload = _json({
            "schema_version": 1, "sequence": seq, "previous": self._head[1],
            "tenant": scope["tenant"], "category": scope["category"], "object_id": scope["object_id"],
            "action": action, "time": now, "expires": expires, "uid": uid,
            "role": scope.get("role", "recorder"), "purpose": scope.get("purpose", "evidence-capture"),
        })
        signature = self._key.sign(payload)
        self._db.execute(
            "INSERT INTO audit VALUES (?, ?, ?, ?, ?, ?)",
            (seq, scope["tenant"], scope["category"], action, payload, signature)
        )
        head = (seq, _audit_digest(payload, signature), now)
        try:
            write_floor(self.path / "floor", self._head, head)
            self._db.commit()
            write_floor(self.path / "floor", head)
        except BaseException:
            self._failed = True
            raise
        self._head = head
