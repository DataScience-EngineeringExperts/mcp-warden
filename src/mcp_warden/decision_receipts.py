"""Unsigned receipt construction and signing; no provider owns canonical bytes."""

from typing import Protocol

from mcp_warden.receipt_kernel import ReceiptError, canonical, exact, receipt_digest
from mcp_warden.receipt_models import SignatureEvidenceV1, SignedReceiptV1, UnsignedReceiptV1


class ReceiptSignerV1(Protocol):
    def sign(
        self, *, payload: bytes, artifact_kind: str, role: str, authorization_digest: str
    ) -> SignatureEvidenceV1: ...


def create_unsigned_receipt(**values) -> UnsignedReceiptV1:
    return UnsignedReceiptV1(**values)


def serialize_unsigned_receipt(receipt: UnsignedReceiptV1) -> bytes:
    exact(receipt, UnsignedReceiptV1)
    return canonical(receipt)


def signature_frame(
    *,
    payload: bytes,
    artifact_kind: str,
    role: str,
    signer_identity_digest: str,
    authorization_digest: str,
) -> bytes:
    if type(payload) is not bytes:
        raise ReceiptError("RCT-MALFORMED")
    return canonical(
        {
            "domain": "mcp-warden/dse717-signature/v1",
            "artifact_kind": artifact_kind,
            "role": role,
            "signer_identity_digest": signer_identity_digest,
            "authorization_digest": authorization_digest,
            "payload_hex": payload.hex(),
        }
    )


def sign_receipt(
    receipt: UnsignedReceiptV1,
    *,
    signer: ReceiptSignerV1,
    authorization,
    verifier,
    snapshot,
    now: int,
) -> SignedReceiptV1:
    from mcp_warden.signer_authorization import verify_authorized_artifact

    payload = serialize_unsigned_receipt(receipt)
    evidence = None
    failed = False
    try:
        evidence = signer.sign(
            payload=payload,
            artifact_kind="receipt",
            role="receipt-signer",
            authorization_digest=authorization.digest,
        )
    except Exception:
        failed = True
    if failed:
        raise ReceiptError("RCT-PROVIDER-UNAVAILABLE") from None
    exact(evidence, SignatureEvidenceV1)
    if (
        evidence.signer_identity_digest != receipt.signer_identity_digest
        or evidence.authorization_digest != receipt.signer_authorization_digest
    ):
        raise ReceiptError("RCT-SIGNER-UNAUTHORIZED")
    verify_authorized_artifact(
        payload=payload,
        evidence=evidence,
        authorization=authorization,
        artifact_kind="receipt",
        role="receipt-signer",
        verifier=verifier,
        snapshot=snapshot,
        now=now,
    )
    return SignedReceiptV1(
        receipt=receipt, evidence=evidence, receipt_digest=receipt_digest(payload, "receipt")
    )


def serialize_signed_receipt(record: SignedReceiptV1) -> bytes:
    exact(record, SignedReceiptV1)
    if (
        receipt_digest(serialize_unsigned_receipt(record.receipt), "receipt")
        != record.receipt_digest
    ):
        raise ReceiptError("RCT-INTEGRITY")
    evidence = record.evidence.model_dump(exclude={"signature"})
    evidence["signature_hex"] = record.evidence.signature.hex()
    return canonical(
        {
            "receipt": record.receipt.model_dump(mode="json"),
            "evidence": evidence,
            "receipt_digest": record.receipt_digest,
        }
    )
