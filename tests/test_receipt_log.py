import pytest

from mcp_warden.receipt_kernel import ZERO_DIGEST, ReceiptError
from mcp_warden.receipt_log import FileEvidenceStoreV1, LogTailV1


def test_durable_expected_tail_restart_and_truncation(tmp_path):
    path = tmp_path / "evidence"

    def validate(payload):
        return None

    store = FileEvidenceStoreV1(path, store_identity_digest=ZERO_DIGEST, validate_payload=validate)
    tail = LogTailV1(sequence=0, entry_digest=ZERO_DIGEST)
    proof = store.append_payload(b"{}", expected_tail=tail)
    assert proof.tail.sequence == 1
    assert (
        FileEvidenceStoreV1(
            path, store_identity_digest=ZERO_DIGEST, validate_payload=validate
        ).read_tail()
        == proof.tail
    )
    with pytest.raises(ReceiptError, match="RCT-TAIL-MISMATCH"):
        store.append_payload(b"{}", expected_tail=tail)
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(ReceiptError):
        store.read_tail()


def test_payload_validation_failure_does_not_append(tmp_path):
    def reject(payload):
        raise ValueError("secret provider text")

    store = FileEvidenceStoreV1(
        tmp_path / "e", store_identity_digest=ZERO_DIGEST, validate_payload=reject
    )
    with pytest.raises(ReceiptError) as error:
        store.append_payload(b"{}", expected_tail=LogTailV1(sequence=0, entry_digest=ZERO_DIGEST))
    assert "secret" not in str(error.value)
    assert error.value.__context__ is None


def test_signed_inner_order_cannot_be_reframed_by_unsigned_headers(tmp_path):
    import struct

    from mcp_warden.receipt_kernel import canonical
    from mcp_warden.receipt_log import MAGIC, FilePrimaryReceiptStoreV1, entry_digest
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, x, p = coordinator_fixture()
    c.record_decision(x)
    c.record_decision(x)
    payload = p["primary"].payloads[1]
    digest = entry_digest(payload, sequence=1, previous_entry_digest=ZERO_DIGEST)
    frame = canonical(
        {
            "sequence": 1,
            "previous_entry_digest": ZERO_DIGEST,
            "entry_digest": digest,
            "payload_hex": payload.hex(),
        }
    )
    path = tmp_path / "reframed"
    path.write_bytes(MAGIC + struct.pack(">I", len(frame)) + frame)
    store = FilePrimaryReceiptStoreV1(
        path,
        store_identity_digest=p["primary"].store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=c.authorization, verifier=c.verifier, snapshot=p["state"].read
        ),
    )
    with pytest.raises(ReceiptError):
        store.read_tail()


def test_full_write_loop_and_file_directory_fsync(tmp_path, monkeypatch):
    import os

    from mcp_warden import receipt_log

    original_write = os.write
    writes = []
    syncs = []

    def short_write(fd, payload):
        writes.append(len(payload))
        return original_write(fd, payload[:7])

    original_sync = os.fsync

    def sync(fd):
        syncs.append(fd)
        return original_sync(fd)

    monkeypatch.setattr(receipt_log.os, "write", short_write)
    monkeypatch.setattr(receipt_log.os, "fsync", sync)
    store = FileEvidenceStoreV1(
        tmp_path / "short", store_identity_digest=ZERO_DIGEST, validate_payload=lambda payload: None
    )
    proof = store.append_payload(
        b"{}", expected_tail=LogTailV1(sequence=0, entry_digest=ZERO_DIGEST)
    )
    assert len(writes) > 1 and len(set(syncs)) == 2
    assert store.read_tail() == proof.tail


def test_fallback_reframe_and_store_separation_are_checked(tmp_path):
    from mcp_warden.evidence_models import FallbackEventV1
    from mcp_warden.receipt_kernel import receipt_digest
    from mcp_warden.receipt_log import FileFallbackEvidenceStoreV1

    def validate(payload):
        from mcp_warden.receipt_kernel import parse_canonical

        FallbackEventV1(**parse_canonical(payload))

    left = FileFallbackEvidenceStoreV1(
        tmp_path / "left",
        store_identity_digest=receipt_digest(b"left", "fallback"),
        validate_payload=validate,
    )
    right = FileFallbackEvidenceStoreV1(
        tmp_path / "right",
        store_identity_digest=receipt_digest(b"right", "fallback"),
        validate_payload=validate,
    )
    event = FallbackEventV1(
        sequence=1,
        failed_receipt_digest=ZERO_DIGEST,
        failure_code="RCT-INTEGRITY",
        trusted_time_digest=ZERO_DIGEST,
        previous_entry_digest=ZERO_DIGEST,
        recovery_generation=0,
    )
    tail = LogTailV1(sequence=0, entry_digest=ZERO_DIGEST)
    left_proof = left.append(event, expected_tail=tail)
    right_proof = right.append(event, expected_tail=tail)
    # The design's fallback payload has no store ID/signature. Identical
    # payloads share a digest; independently protected identity/tail binding
    # supplies stream separation. Proof identities remain distinct.
    assert (
        left_proof.payload_digest == right_proof.payload_digest
        and left_proof.store_identity_digest != right_proof.store_identity_digest
    )
    with pytest.raises(ReceiptError):
        right.append(event, expected_tail=right_proof.tail)  # inner sequence/previous mismatch
