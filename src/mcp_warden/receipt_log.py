"""Locked framed file evidence: durable and tamper-evident, never rollback-resistant."""

from __future__ import annotations

import fcntl
import os
import struct
from pathlib import Path
from typing import Literal, Protocol

from pydantic import StrictInt

from mcp_warden.decision_receipts import serialize_signed_receipt
from mcp_warden.receipt_kernel import (
    ZERO_DIGEST,
    ReceiptError,
    ReceiptModel,
    canonical,
    exact,
    parse_canonical,
    receipt_digest,
)

FRAME_CAP = 512 * 1024
LOG_CAP = 64 * 1024 * 1024
MAGIC = b"WRD717\x01"


class LogTailV1(ReceiptModel):
    sequence: StrictInt
    entry_digest: str


class DurableAppendEvidenceV1(ReceiptModel):
    schema_version: Literal[1] = 1
    store_identity_digest: str
    payload_digest: str
    tail: LogTailV1


class PrimaryReceiptStoreV1(Protocol):
    store_identity_digest: str

    def read_tail(self) -> LogTailV1: ...
    def append(self, record, *, expected_tail: LogTailV1) -> DurableAppendEvidenceV1: ...


class FallbackEvidenceStoreV1(Protocol):
    store_identity_digest: str

    def read_tail(self) -> LogTailV1: ...
    def append(self, event, *, expected_tail: LogTailV1) -> DurableAppendEvidenceV1: ...


def entry_digest(payload: bytes, *, sequence: int, previous_entry_digest: str) -> str:
    return receipt_digest(
        canonical(
            {
                "payload_digest": receipt_digest(payload, "log-entry"),
                "sequence": sequence,
                "previous_entry_digest": previous_entry_digest,
            }
        ),
        "log-entry",
    )


class FileEvidenceStoreV1:
    """Reference persistence with an injected mandatory semantic/signature validator.

    The validator must independently verify signed primary records on every scan.
    This TCB port is trusted; a permissive validator is suitable only for tests.
    Same-UID tampering and restoration of a whole log require independent state.
    """

    protection_capability = "file-durability-only"

    def __init__(self, path: Path, *, store_identity_digest: str, validate_payload):
        if type(path) is not Path and not isinstance(path, Path):
            raise ReceiptError("RCT-MALFORMED")
        LogTailV1(sequence=0, entry_digest=store_identity_digest)
        if not callable(validate_payload):
            raise ReceiptError("RCT-MALFORMED")
        self.path = path
        self.store_identity_digest = store_identity_digest
        self._validate = validate_payload

    def _scan(self, fd):
        size = os.fstat(fd).st_size
        if size > LOG_CAP:
            raise ReceiptError("RCT-OVER-CAP")
        os.lseek(fd, 0, os.SEEK_SET)
        data = bytearray()
        while len(data) < size:
            chunk = os.read(fd, min(size - len(data), 65536))
            if not chunk:
                raise ReceiptError("RCT-INTEGRITY")
            data.extend(chunk)
        if not data:
            return LogTailV1(sequence=0, entry_digest=ZERO_DIGEST), ()
        if not data.startswith(MAGIC):
            raise ReceiptError("RCT-INTEGRITY")
        pos = len(MAGIC)
        tail = LogTailV1(sequence=0, entry_digest=ZERO_DIGEST)
        payloads = []
        while pos < len(data):
            if pos + 4 > len(data):
                raise ReceiptError("RCT-INTEGRITY")
            length = struct.unpack(">I", data[pos : pos + 4])[0]
            pos += 4
            if not 0 < length <= FRAME_CAP or pos + length > len(data):
                raise ReceiptError("RCT-INTEGRITY")
            frame = parse_canonical(bytes(data[pos : pos + length]))
            pos += length
            if set(frame) != {"sequence", "previous_entry_digest", "entry_digest", "payload_hex"}:
                raise ReceiptError("RCT-INTEGRITY")
            payload = bytes.fromhex(frame["payload_hex"])
            parse_canonical(payload)
            self._validate(payload)
            digest = entry_digest(
                payload, sequence=tail.sequence + 1, previous_entry_digest=tail.entry_digest
            )
            if (
                type(frame["sequence"]) is not int
                or frame["sequence"] != tail.sequence + 1
                or frame["previous_entry_digest"] != tail.entry_digest
                or frame["entry_digest"] != digest
            ):
                raise ReceiptError("RCT-INTEGRITY")
            tail = LogTailV1(sequence=tail.sequence + 1, entry_digest=digest)
            payloads.append(payload)
        return tail, tuple(payloads)

    def _operation(self, payload=None, expected_tail=None):
        failed = False
        result = None
        fd = None
        dir_fd = None
        try:
            # Lock the actual log inode; its independently protected tail detects replacement.
            dir_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            existed = self.path.exists()
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            tail, payloads = self._scan(fd)
            if payload is None:
                result = (tail, payloads)
            else:
                exact(expected_tail, LogTailV1)
                if tail != expected_tail:
                    raise ReceiptError("RCT-TAIL-MISMATCH")
                parse_canonical(payload)
                self._validate(payload)
                digest = entry_digest(
                    payload, sequence=tail.sequence + 1, previous_entry_digest=tail.entry_digest
                )
                frame = canonical(
                    {
                        "sequence": tail.sequence + 1,
                        "previous_entry_digest": tail.entry_digest,
                        "entry_digest": digest,
                        "payload_hex": payload.hex(),
                    }
                )
                if len(frame) > FRAME_CAP:
                    raise ReceiptError("RCT-OVER-CAP")
                append = (
                    (MAGIC if os.fstat(fd).st_size == 0 else b"")
                    + struct.pack(">I", len(frame))
                    + frame
                )
                if os.fstat(fd).st_size + len(append) > LOG_CAP:
                    raise ReceiptError("RCT-OVER-CAP")
                os.lseek(fd, 0, os.SEEK_END)
                offset = 0
                while offset < len(append):
                    written = os.write(fd, append[offset:])
                    if written <= 0:
                        raise ReceiptError("RCT-APPEND-FAILED")
                    offset += written
                os.fsync(fd)
                if not existed:
                    os.fsync(dir_fd)
                result = DurableAppendEvidenceV1(
                    store_identity_digest=self.store_identity_digest,
                    payload_digest=receipt_digest(payload, "log-entry"),
                    tail=LogTailV1(sequence=tail.sequence + 1, entry_digest=digest),
                )
        except Exception as error:
            failed = error.code if type(error) is ReceiptError else "RCT-PROVIDER-UNAVAILABLE"
        finally:
            for descriptor in (fd, dir_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        failed = "RCT-PROVIDER-UNAVAILABLE"
        if failed:
            raise ReceiptError(failed) from None
        return result

    def read_tail(self):
        return self._operation()[0]

    def read_payloads(self):
        return self._operation()[1]

    def append_payload(self, payload: bytes, *, expected_tail: LogTailV1):
        return self._operation(payload, expected_tail)


class FilePrimaryReceiptStoreV1(FileEvidenceStoreV1):
    def append(self, record, *, expected_tail):
        return self.append_payload(serialize_signed_receipt(record), expected_tail=expected_tail)


class FileFallbackEvidenceStoreV1(FileEvidenceStoreV1):
    def append(self, event, *, expected_tail):
        from mcp_warden.evidence_models import FallbackEventV1

        exact(event, FallbackEventV1)
        return self.append_payload(canonical(event), expected_tail=expected_tail)
