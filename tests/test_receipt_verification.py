import pytest

from mcp_warden.receipt_kernel import ReceiptError, canonical, parse_canonical
from mcp_warden.receipt_verification import parse_signed_receipt, verify_receipt_chain
from tests.receipt_fixtures import coordinator_fixture


def test_signed_chain_integrity_and_protected_tail():
    c, x, p = coordinator_fixture()
    assert c.record_decision(x).mode == "primary-durable"
    assert verify_receipt_chain(
        tuple(p["primary"].payloads),
        authorization=c.authorization,
        verifier=c.verifier,
        snapshot=p["state"].read(),
        store_identity_digest=p["primary"].store_identity_digest,
    )
    data = parse_canonical(p["primary"].payloads[0])
    data["receipt"]["effective_verdict"] = "deny"
    with pytest.raises(ReceiptError):
        parse_signed_receipt(canonical(data))
    with pytest.raises(ReceiptError):
        verify_receipt_chain(
            (),
            authorization=c.authorization,
            verifier=c.verifier,
            snapshot=p["state"].read(),
            store_identity_digest=p["primary"].store_identity_digest,
        )
