"""Linux custodian filesystem and crash recovery for the local evidence vault."""

from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path

CATEGORIES = ("tool-arguments", "tool-result")
ZERO_DIGEST = "0" * 64
INITIAL_HEAD = (0, ZERO_DIGEST, 0)


class EvidenceVaultError(ValueError):
    """Closed failure returned at the operator and guard boundaries."""


def private_directory(path: Path) -> Path:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise EvidenceVaultError("EVD-STORAGE")
    directory = path.stat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid() or (
        stat.S_IMODE(directory.st_mode) != 0o700
    ):
        raise EvidenceVaultError("EVD-STORAGE")
    for parent in path.parents:
        metadata = parent.stat()
        if metadata.st_uid not in {0, os.geteuid()} or (
            metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX
        ):
            raise EvidenceVaultError("EVD-STORAGE")
    return path


def private_file(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or (
        stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
    ):
        raise EvidenceVaultError("EVD-STORAGE")


def new_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_floor(path: Path, current: tuple, pending: tuple | None = None) -> None:
    # A prepared head survives a crash before or after the SQLite commit. Only
    # those two verified states are valid until finalization.
    candidate = path.with_name(".floor-" + secrets.token_hex(16))
    try:
        new_file(candidate, json.dumps([current, pending], separators=(",", ":")).encode("ascii"))
        os.replace(candidate, path)
        sync_dir(path.parent)
    finally:
        candidate.unlink(missing_ok=True)


def reconcile_floor(path: Path, actual: tuple, previous: tuple | None) -> None:
    private_file(path)
    with path.open("rb") as stream:
        raw = stream.read(512)
    current, pending = json.loads(raw)
    if pending is not None:
        if list(actual) == pending and previous is not None and list(previous) == current:
            write_floor(path, actual)
            return
        if list(actual) == current:
            write_floor(path, actual)
            return
    elif list(actual) == current:
        return
    raise EvidenceVaultError("EVD-FLOOR")
