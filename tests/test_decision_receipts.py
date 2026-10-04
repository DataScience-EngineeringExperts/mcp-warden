import pytest

from mcp_warden.decision_receipts import receipt_digest
from mcp_warden.receipt_models import ReceiptError, ReceiptEventContextV1

D = "sha256:" + "a" * 64


def test_limit_is_reserved_and_unsupported():
    with pytest.raises(ReceiptError, match="RCT-LIMIT-UNSUPPORTED"):
        ReceiptEventContextV1(kind="limit")


def test_event_union_requires_exact_binding():
    with pytest.raises(ReceiptError):
        ReceiptEventContextV1(kind="override")
    with pytest.raises(ReceiptError):
        ReceiptEventContextV1(kind="deny", actor_digest=D)


def test_domain_separation_is_deterministic():
    assert receipt_digest(b"{}", "receipt") == receipt_digest(b"{}", "receipt")
    assert receipt_digest(b"{}", "receipt") != receipt_digest(b"{}", "rule")


def test_independent_root_activation_and_role_substitution():
    from mcp_warden.signer_authorization import verify_authorized_artifact
    from tests.receipt_fixtures import authority

    auth, verifier, signer, snapshot = authority()
    payload = b"{}"
    signature = signer.sign(
        payload=payload,
        artifact_kind="receipt",
        role="receipt-signer",
        authorization_digest=auth.digest,
    )
    verify_authorized_artifact(
        payload=payload,
        evidence=signature,
        authorization=auth,
        artifact_kind="receipt",
        role="receipt-signer",
        verifier=verifier,
        snapshot=snapshot,
        now=10,
    )
    with pytest.raises(ReceiptError, match="RCT-SIGNER-UNAUTHORIZED"):
        verify_authorized_artifact(
            payload=payload,
            evidence=signature,
            authorization=auth,
            artifact_kind="rule",
            role="rule-publisher",
            verifier=verifier,
            snapshot=snapshot,
            now=10,
        )


def test_signature_and_authorization_tamper_are_rejected():
    from mcp_warden.signer_authorization import verify_authorized_artifact
    from tests.receipt_fixtures import authority

    auth, verifier, signer, snapshot = authority()
    signature = signer.sign(
        payload=b"{}",
        artifact_kind="receipt",
        role="receipt-signer",
        authorization_digest=auth.digest,
    )
    with pytest.raises(ReceiptError, match="RCT-SIGNATURE-INVALID"):
        verify_authorized_artifact(
            payload=b'{"tampered":true}',
            evidence=signature,
            authorization=auth,
            artifact_kind="receipt",
            role="receipt-signer",
            verifier=verifier,
            snapshot=snapshot,
            now=10,
        )
    with pytest.raises(ReceiptError, match="RCT-AUTHORIZATION-UNAVAILABLE"):
        verify_authorized_artifact(
            payload=b"{}",
            evidence=signature,
            authorization=object(),
            artifact_kind="receipt",
            role="receipt-signer",
            verifier=verifier,
            snapshot=snapshot,
            now=10,
        )
