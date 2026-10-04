"""Signature and complete-chain verification; historical evidence grants no authority."""

from mcp_warden.decision_receipts import serialize_signed_receipt, serialize_unsigned_receipt
from mcp_warden.evidence_reference import validate_protected_state
from mcp_warden.evidence_state import validate_floor
from mcp_warden.receipt_kernel import (
    ZERO_DIGEST,
    ReceiptError,
    exact,
    parse_canonical,
    receipt_digest,
)
from mcp_warden.receipt_log import entry_digest
from mcp_warden.receipt_models import SignatureEvidenceV1, SignedReceiptV1, UnsignedReceiptV1
from mcp_warden.signer_authorization import verify_authorized_artifact


def parse_signed_receipt(payload: bytes) -> SignedReceiptV1:
    data = parse_canonical(payload)
    bad = False
    record = None
    try:
        if (
            set(data) != {"receipt", "evidence", "receipt_digest"}
            or type(data["evidence"]) is not dict
        ):
            raise ValueError
        e = dict(data["evidence"])
        encoded = e.pop("signature_hex")
        if type(encoded) is not str or len(encoded) != 128 or encoded.lower() != encoded:
            raise ValueError
        e["signature"] = bytes.fromhex(encoded)
        record = SignedReceiptV1(
            receipt=UnsignedReceiptV1(**data["receipt"]),
            evidence=SignatureEvidenceV1(**e),
            receipt_digest=data["receipt_digest"],
        )
        if serialize_signed_receipt(record) != payload:
            raise ValueError
    except Exception:
        bad = True
    if bad:
        raise ReceiptError("RCT-INTEGRITY") from None
    return record


def verify_signed_receipt(record, *, authorization, verifier, snapshot):
    exact(record, SignedReceiptV1)
    receipt = record.receipt
    payload = serialize_unsigned_receipt(receipt)
    if (
        receipt_digest(payload, "receipt") != record.receipt_digest
        or receipt.signer_authorization_digest != authorization.digest
        or receipt.signer_authorization_generation != authorization.bundle.generation
        or receipt.signer_identity_digest != record.evidence.signer_identity_digest
        or receipt.trust_root_digest != authorization.bundle.trust_root_digest
    ):
        raise ReceiptError("RCT-INTEGRITY")
    verify_authorized_artifact(
        payload=payload,
        evidence=record.evidence,
        authorization=authorization,
        artifact_kind="receipt",
        role="receipt-signer",
        verifier=verifier,
        snapshot=snapshot,
        now=receipt.trusted_time,
    )
    return True


def verify_receipt_chain(payloads, *, authorization, verifier, snapshot, store_identity_digest):
    if type(payloads) is not tuple or len(payloads) > 100000:
        raise ReceiptError("RCT-MALFORMED")
    validate_protected_state(snapshot)
    sequence = 0
    tail = ZERO_DIGEST
    for payload in payloads:
        record = parse_signed_receipt(payload)
        verify_signed_receipt(
            record, authorization=authorization, verifier=verifier, snapshot=snapshot
        )
        receipt = record.receipt
        if (
            receipt.sequence != sequence + 1
            or receipt.previous_entry_digest != tail
            or receipt.store_identity_digest != store_identity_digest
        ):
            raise ReceiptError("RCT-INTEGRITY")
        sequence += 1
        tail = entry_digest(payload, sequence=sequence, previous_entry_digest=tail)
    if sequence != snapshot.primary_sequence or tail != snapshot.primary_tail_digest:
        raise ReceiptError("RCT-TAIL-MISMATCH")
    validate_floor(snapshot, kind="receipt-log", generation=sequence, digest=tail)
    return True


def primary_payload_validator(*, authorization, verifier, snapshot):
    """Build a mandatory file-store scan validator from independently pinned authority.

    `snapshot` is a TCB-owned callable returning current protected state. Signature
    validation is separate from log-floor checking, which the coordinator owns.
    """

    def validate(payload):
        return verify_signed_receipt(
            parse_signed_receipt(payload),
            authorization=authorization,
            verifier=verifier,
            snapshot=snapshot(),
        )

    return validate
