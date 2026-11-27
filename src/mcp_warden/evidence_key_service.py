"""Customer-operated Linux Unix socket boundary for the local evidence vault."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import socket
import stat
import struct
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_EVIDENCE_BYTES = 1024 * 1024
_MAX_FRAME = 2 * MAX_EVIDENCE_BYTES
_MAX_CONFIG = 64 * 1024
_TIMEOUT = 3.0
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_CATEGORIES = frozenset({"tool-arguments", "tool-result"})
_ROLES = {
    "capture": "recorder",
    "read": "reviewer",
    "export": "reviewer",
    "audit": "reviewer",
    "hold": "custodian",
    "release": "custodian",
    "delete": "custodian",
}
_CAPTURE_PURPOSE = "evidence-capture"
_CIPHERTEXT_VERSION = b"\x01"
_NONCE_BYTES = 12
_TAG_BYTES = 16
_CREDENTIALS = struct.Struct("@iII")
_LENGTH = struct.Struct("!I")


class EvidenceKeyServiceError(RuntimeError):
    """A request or local service operation could not be safely completed."""


def _linux_only() -> None:
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise EvidenceKeyServiceError("local evidence requires Linux Unix peer credentials")


def _label(value: object) -> str:
    if type(value) is not str or not _LABEL.fullmatch(value):
        raise EvidenceKeyServiceError("invalid evidence label")
    return value


def _uid(value: object) -> int:
    if type(value) is not int or not 0 <= value < 2**32 - 1:
        raise EvidenceKeyServiceError("invalid Unix identity")
    return value


def _category(value: object) -> str:
    category = _label(value)
    if category not in _CATEGORIES:
        raise EvidenceKeyServiceError("invalid evidence category")
    return category


def _purpose(action: str, role: object, value: object) -> str:
    if _ROLES.get(action) != _label(role):
        raise EvidenceKeyServiceError("invalid evidence action or role")
    purpose = _label(value)
    if action == "capture" and purpose != _CAPTURE_PURPOSE:
        raise EvidenceKeyServiceError("invalid evidence capture purpose")
    return purpose


def encode_payload(data: bytes) -> str:
    if type(data) is not bytes or len(data) > MAX_EVIDENCE_BYTES:
        raise EvidenceKeyServiceError("invalid evidence payload")
    return base64.b64encode(data).decode("ascii")


def decode_payload(value: object) -> bytes:
    if type(value) is not str or len(value) > 4 * ((MAX_EVIDENCE_BYTES + 2) // 3):
        raise EvidenceKeyServiceError("invalid evidence payload")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise EvidenceKeyServiceError("invalid evidence payload") from None
    if len(data) > MAX_EVIDENCE_BYTES:
        raise EvidenceKeyServiceError("invalid evidence payload")
    return data


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceKeyServiceError("duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(_: str) -> object:
    raise EvidenceKeyServiceError("invalid JSON value")


def _object(data: bytes) -> dict[str, object]:
    try:
        result = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (ValueError, RecursionError):
        raise EvidenceKeyServiceError("invalid JSON object") from None
    if type(result) is not dict:
        raise EvidenceKeyServiceError("invalid JSON object")
    return result


def _absolute_path(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise EvidenceKeyServiceError("local evidence requires an absolute path")
    return path


def _open_directory(path: Path) -> int:
    """Open an owner-controlled directory through trusted, nonsymlink ancestors."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            # A root-owned sticky directory protects the next root/service-owned entry.
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not sticky):
                raise EvidenceKeyServiceError("untrusted local evidence path")
        return directory
    except (OSError, EvidenceKeyServiceError):
        os.close(directory)
        raise


def _read_config(path: Path) -> dict[str, object]:
    path = _absolute_path(path)
    owner = os.geteuid()
    try:
        directory = _open_directory(path.parent)
        try:
            parent = os.fstat(directory)
            if parent.st_uid != owner or stat.S_IMODE(parent.st_mode) != 0o700:
                raise EvidenceKeyServiceError("invalid evidence configuration directory")
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=directory,
            )
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != owner
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
                    or info.st_size > _MAX_CONFIG
                ):
                    raise EvidenceKeyServiceError("invalid evidence configuration file")
                raw = stream.read(_MAX_CONFIG + 1)
        finally:
            os.close(directory)
    except OSError:
        raise EvidenceKeyServiceError("evidence configuration unavailable") from None
    if len(raw) > _MAX_CONFIG:
        raise EvidenceKeyServiceError("evidence configuration exceeds size limit")
    result = _object(raw)
    if type(result.get("version")) is not int or result["version"] != 1:
        raise EvidenceKeyServiceError("unsupported evidence configuration version")
    return result


@dataclass(frozen=True, slots=True)
class _Grant:
    uid: int
    tenant: str
    category: str
    action: str
    role: str
    purpose: str


def _load_policy(path: Path) -> frozenset[_Grant]:
    config = _read_config(path)
    rows = config.get("grants")
    if set(config) != {"version", "grants"} or type(rows) is not list or not rows:
        raise EvidenceKeyServiceError("invalid evidence grant policy")
    grants: set[_Grant] = set()
    for row in rows:
        if type(row) is not dict or set(row) != {
            "uid",
            "tenant",
            "category",
            "action",
            "role",
            "purpose",
        }:
            raise EvidenceKeyServiceError("invalid evidence grant")
        action = _label(row["action"])
        role = _label(row["role"])
        grant = _Grant(
            _uid(row["uid"]),
            _label(row["tenant"]),
            _category(row["category"]),
            action,
            role,
            _purpose(action, role, row["purpose"]),
        )
        if grant.uid in {0, os.geteuid()}:
            raise EvidenceKeyServiceError("evidence grant requires a distinct non-root client UID")
        if grant in grants:
            raise EvidenceKeyServiceError("duplicate evidence grant")
        grants.add(grant)
    return frozenset(grants)


@dataclass(frozen=True, slots=True)
class _Keyring:
    active: str
    keys: dict[str, AESGCM] = field(repr=False)


def _load_keyring(path: Path) -> _Keyring:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise EvidenceKeyServiceError("evidence encryption dependency unavailable") from None

    config = _read_config(path)
    values = config.get("keys")
    if set(config) != {"version", "active", "keys"} or type(values) is not dict:
        raise EvidenceKeyServiceError("invalid evidence key ring")
    active = _label(config["active"])
    keys: dict[str, AESGCM] = {}
    seen_keys: set[str] = set()
    for name, value in values.items():
        if type(value) is not str or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise EvidenceKeyServiceError("invalid evidence encryption key")
        if value in seen_keys:
            raise EvidenceKeyServiceError("evidence key IDs require distinct key material")
        seen_keys.add(value)
        keys[_label(name)] = AESGCM(bytes.fromhex(value))
    if active not in keys:
        raise EvidenceKeyServiceError("active evidence encryption key unavailable")
    return _Keyring(active, keys)


def _aad(key_id: str, tenant: str, object_id: str, category: str) -> bytes:
    binding = ["warden-local-evidence", 1, key_id, tenant, object_id, category]
    return json.dumps(binding, separators=(",", ":")).encode("ascii")


@dataclass(frozen=True, slots=True)
class LocalKeyAccess:
    """Private daemon-side capability bound to a kernel-authenticated client."""

    peer_uid: int
    _grants: frozenset[_Grant] = field(repr=False)
    _keyring: _Keyring = field(repr=False)

    def authorize(
        self, *, tenant: str, object_id: str, category: str, action: str, role: str, purpose: str
    ) -> datetime:
        _label(object_id)
        action = _label(action)
        grant = _Grant(
            self.peer_uid,
            _label(tenant),
            _category(category),
            action,
            _label(role),
            _purpose(action, role, purpose),
        )
        if grant not in self._grants:
            raise EvidenceKeyServiceError("evidence access denied")
        return datetime.now(UTC)

    def encrypt(self, *, tenant: str, object_id: str, category: str, plaintext: bytes) -> bytes:
        self.authorize(
            tenant=tenant,
            object_id=object_id,
            category=category,
            action="capture",
            role="recorder",
            purpose=_CAPTURE_PURPOSE,
        )
        if type(plaintext) is not bytes or len(plaintext) > MAX_EVIDENCE_BYTES:
            raise EvidenceKeyServiceError("invalid evidence payload")
        key_id = self._keyring.active
        key_label = key_id.encode("ascii")
        nonce = os.urandom(_NONCE_BYTES)
        encrypted = self._keyring.keys[key_id].encrypt(
            nonce, plaintext, _aad(key_id, tenant, object_id, category)
        )
        return _CIPHERTEXT_VERSION + bytes([len(key_label)]) + key_label + nonce + encrypted

    def decrypt(
        self,
        *,
        tenant: str,
        object_id: str,
        category: str,
        ciphertext: bytes,
        action: str,
        role: str,
        purpose: str,
    ) -> bytes:
        from cryptography.exceptions import InvalidTag

        if action not in ("read", "export"):
            raise EvidenceKeyServiceError("evidence access denied")
        self.authorize(
            tenant=tenant,
            object_id=object_id,
            category=category,
            action=action,
            role=role,
            purpose=purpose,
        )
        minimum = 2 + 1 + _NONCE_BYTES + _TAG_BYTES
        maximum = 2 + 128 + _NONCE_BYTES + _TAG_BYTES + MAX_EVIDENCE_BYTES
        if (
            type(ciphertext) is not bytes
            or not minimum <= len(ciphertext) <= maximum
            or ciphertext[:1] != _CIPHERTEXT_VERSION
        ):
            raise EvidenceKeyServiceError("invalid encrypted evidence")
        key_length = ciphertext[1]
        start = 2 + key_length
        if not 1 <= key_length <= 128 or len(ciphertext) < start + _NONCE_BYTES + _TAG_BYTES:
            raise EvidenceKeyServiceError("invalid encrypted evidence")
        try:
            key_id = ciphertext[2:start].decode("ascii")
            key = self._keyring.keys[key_id]
            nonce = ciphertext[start : start + _NONCE_BYTES]
            return key.decrypt(
                nonce, ciphertext[start + _NONCE_BYTES :], _aad(key_id, tenant, object_id, category)
            )
        except (KeyError, UnicodeDecodeError, InvalidTag):
            raise EvidenceKeyServiceError("cannot authenticate encrypted evidence") from None


def _peer_uid(connection: socket.socket) -> int:
    _, uid, _ = _CREDENTIALS.unpack(
        connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size)
    )
    return _uid(uid)


def _read_exact(connection: socket.socket, size: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EvidenceKeyServiceError("local evidence request timed out")
        connection.settimeout(remaining)
        chunk = connection.recv(min(size - len(data), 65536))
        if not chunk:
            raise EvidenceKeyServiceError("incomplete local evidence frame")
        data.extend(chunk)
    return bytes(data)


def _receive(connection: socket.socket) -> dict[str, object]:
    deadline = time.monotonic() + _TIMEOUT
    (size,) = _LENGTH.unpack(_read_exact(connection, _LENGTH.size, deadline))
    if not 1 <= size <= _MAX_FRAME:
        raise EvidenceKeyServiceError("invalid local evidence frame length")
    return _object(_read_exact(connection, size, deadline))


def _send(connection: socket.socket, message: dict[str, object]) -> None:
    try:
        data = json.dumps(message, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise EvidenceKeyServiceError("invalid local evidence message") from None
    if not 1 <= len(data) <= _MAX_FRAME:
        raise EvidenceKeyServiceError("invalid local evidence frame length")
    connection.settimeout(_TIMEOUT)
    connection.sendall(_LENGTH.pack(len(data)) + data)


class LocalServiceClient:
    """Authenticate the configured daemon UID before sending any evidence."""

    def __init__(self, socket_path: Path, *, service_uid: int):
        _linux_only()
        self._path = _absolute_path(socket_path)
        self._service_uid = _uid(service_uid)
        if self._service_uid in {0, os.geteuid()}:
            raise EvidenceKeyServiceError("evidence daemon requires a distinct non-root UID")

    def request(self, payload: dict[str, object]) -> dict[str, object]:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(_TIMEOUT)
                connection.connect(str(self._path))
                if _peer_uid(connection) != self._service_uid:
                    raise EvidenceKeyServiceError("local evidence service identity mismatch")
                _send(connection, {"version": 1, "request": payload})
                response = _receive(connection)
        except OSError:
            raise EvidenceKeyServiceError("local evidence service unavailable") from None
        if (
            set(response) != {"version", "result"}
            or type(response["version"]) is not int
            or response["version"] != 1
            or type(response["result"]) is not dict
        ):
            raise EvidenceKeyServiceError("local evidence request denied")
        return response["result"]


class LocalKeyService:
    """Single-request Linux daemon transport, with key access confined to its dispatcher."""

    def __init__(
        self,
        socket_path: Path,
        *,
        keyring_path: Path,
        policy_path: Path,
        dispatch: Callable[[dict[str, object], LocalKeyAccess], dict[str, object]],
    ):
        _linux_only()
        if os.geteuid() == 0:
            raise EvidenceKeyServiceError("evidence daemon requires a dedicated non-root UID")
        self._path = _absolute_path(socket_path)
        self._grants = _load_policy(policy_path)
        self._uids = frozenset(grant.uid for grant in self._grants)
        self._keyring = _load_keyring(keyring_path)
        self._dispatch = dispatch
        self._listener: socket.socket | None = None
        self._socket_identity: tuple[int, int] | None = None

    def __enter__(self) -> LocalKeyService:
        if self._listener is not None:
            raise EvidenceKeyServiceError("local evidence service already listening")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            directory = _open_directory(self._path.parent)
            try:
                parent = os.fstat(directory)
                if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
                    raise EvidenceKeyServiceError("invalid evidence socket directory")
                listener.bind(str(self._path))
                info = os.stat(self._path.name, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                    raise EvidenceKeyServiceError("invalid evidence socket")
                self._socket_identity = (info.st_dev, info.st_ino)
                os.chmod(self._path.name, 0o660, dir_fd=directory)
            finally:
                os.close(directory)
            listener.listen(8)
        except (OSError, EvidenceKeyServiceError):
            listener.close()
            self._remove_socket()
            raise EvidenceKeyServiceError("cannot start local evidence service") from None
        self._listener = listener
        return self

    def _remove_socket(self) -> None:
        if self._socket_identity is None:
            return
        try:
            info = self._path.lstat()
            if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == self._socket_identity:
                self._path.unlink()
        except OSError:
            pass
        self._socket_identity = None

    def __exit__(self, *_: object) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        self._remove_socket()

    def serve_once(self, timeout: float | None = None) -> None:
        if self._listener is None:
            raise EvidenceKeyServiceError("local evidence service is closed")
        self._listener.settimeout(timeout)
        connection, _ = self._listener.accept()
        with connection:
            try:
                uid = _peer_uid(connection)
                if uid not in self._uids:
                    return
                envelope = _receive(connection)
                if (
                    set(envelope) != {"version", "request"}
                    or type(envelope["version"]) is not int
                    or envelope["version"] != 1
                    or type(envelope["request"]) is not dict
                ):
                    raise EvidenceKeyServiceError("invalid local evidence message")
                access = LocalKeyAccess(uid, self._grants, self._keyring)
                result = self._dispatch(envelope["request"], access)
                _send(connection, {"version": 1, "result": result})
            except Exception:
                # Never serialize or log exceptions that may carry evidence from a request.
                try:
                    _send(connection, {"version": 1, "error": "denied"})
                except (EvidenceKeyServiceError, OSError):
                    pass

    def serve_forever(self) -> None:
        while self._listener is not None:
            self.serve_once()
