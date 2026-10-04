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
