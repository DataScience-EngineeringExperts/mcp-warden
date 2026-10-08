"""Council regressions for historical signer pins and strict live floor admission."""

import pytest

from mcp_warden.receipt_verification import parse_signed_receipt
from tests.dse717_council_fixtures import _rotate_receipt_authority


def test_historical_pin_reads_after_live_signer_and_root_floor_advance(tmp_path):
    from mcp_warden.receipt_log import FilePrimaryReceiptStoreV1
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    store = FilePrimaryReceiptStoreV1(
        tmp_path / "primary",
        store_identity_digest=p["primary"].store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=c.authorization, verifier=c.verifier, snapshot=p["state"].read
        ),
    )
    c.primary = p["primary"] = store
    assert c.record_decision(context).mode == "primary-durable"
    tail = store.read_tail()
    _rotate_receipt_authority(c, p)
    assert store.read_tail() == tail


def test_signer_rotation_supports_subsequent_append_and_reopen(tmp_path):
    from mcp_warden.evidence_models import create_evidence_context
    from mcp_warden.evidence_state import StateError
    from mcp_warden.receipt_kernel import ReceiptError
    from mcp_warden.receipt_log import FilePrimaryReceiptStoreV1
    from mcp_warden.receipt_verification import (
        primary_payload_validator,
        verify_receipt_chain,
        verify_signed_receipt,
    )
    from mcp_warden.signer_authorization import check_authorization
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    old_auth, old_verifier = c.authorization, c.verifier
    path = tmp_path / "primary"
    old_store = FilePrimaryReceiptStoreV1(
        path,
        store_identity_digest=p["primary"].store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=old_auth, verifier=old_verifier, snapshot=p["state"].read
        ),
    )
    c.primary = p["primary"] = old_store
    assert c.record_decision(context).mode == "primary-durable"
    old_payload = old_store.read_payloads()[0]
    old_tail = old_store.read_tail()
    authorization, verifier, signer = _rotate_receipt_authority(c, p)
    # A retained pin can still read historical evidence after its live retirement.
    assert old_store.read_tail() == old_tail
    with pytest.raises(StateError, match="STATE-FLOOR-ROLLBACK"):
        check_authorization(old_auth, snapshot=p["state"].read(), now=10)
    with pytest.raises(StateError, match="STATE-FLOOR-ROLLBACK"):
        verify_signed_receipt(
            parse_signed_receipt(old_payload),
            authorization=old_auth,
            verifier=old_verifier,
            snapshot=p["state"].read(),
        )
    c.authorization, c.verifier, c.signer = authorization, verifier, signer
    c.signer_identity_digest = signer.identity
    pins = ((old_auth, old_verifier),)

    def reopened():
        return FilePrimaryReceiptStoreV1(
            path,
            store_identity_digest=old_store.store_identity_digest,
            validate_payload=primary_payload_validator(
                authorization=authorization,
                verifier=verifier,
                snapshot=p["state"].read,
                historical_authorities=pins,
            ),
        )

    c.primary = p["primary"] = reopened()
    assert c.primary.read_tail() == old_tail
    new_context = create_evidence_context(
        decision=context.decision,
        effect_digest=context.effect_digest,
        trusted_time=30,
        trusted_time_valid_until=40,
        signer_authorization_digest=authorization.digest,
    )
    result = c.record_decision(new_context)
    assert result.mode == "primary-durable" and result.sequence == 2
    reopened_store = reopened()
    assert reopened_store.read_tail() == c.primary.read_tail()
    payloads = reopened_store.read_payloads()
    assert payloads[0] == old_payload and len(payloads) == 2
    assert (
        parse_signed_receipt(payloads[1]).receipt.signer_authorization_digest
        == authorization.digest
    )
    assert verify_receipt_chain(
        payloads,
        authorization=authorization,
        verifier=verifier,
        snapshot=p["state"].read(),
        store_identity_digest=old_store.store_identity_digest,
        historical_authorities=pins,
    )
    # The new pin alone cannot authorize an older frame; logs never enroll keys.
    unpinned = FilePrimaryReceiptStoreV1(
        path,
        store_identity_digest=old_store.store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=authorization, verifier=verifier, snapshot=p["state"].read
        ),
    )
    with pytest.raises(ReceiptError):
        unpinned.read_tail()


def test_retired_live_signer_cannot_append_permit_after_rotation(tmp_path):
    from mcp_warden.receipt_log import FilePrimaryReceiptStoreV1
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    store = FilePrimaryReceiptStoreV1(
        tmp_path / "primary",
        store_identity_digest=p["primary"].store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=c.authorization, verifier=c.verifier, snapshot=p["state"].read
        ),
    )
    c.primary = p["primary"] = store
    assert c.record_decision(context).mode == "primary-durable"
    _rotate_receipt_authority(c, p)
    before = store.read_payloads()
    result = c.record_decision(context)
    assert result.mode == "unavailable"
    assert store.read_payloads() == before


@pytest.mark.parametrize("bad_pins", [[], ((object(), object()),), ((),), (object(),)])
def test_historical_authority_registry_rejects_unactivated_or_malformed_pins(bad_pins):
    from mcp_warden.receipt_kernel import ReceiptError
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, _, p = coordinator_fixture()
    with pytest.raises(ReceiptError) as error:
        primary_payload_validator(
            authorization=c.authorization,
            verifier=c.verifier,
            snapshot=p["state"].read,
            historical_authorities=bad_pins,
        )
    assert error.value.__context__ is None
    assert "object" not in str(error.value)


def test_historical_pin_does_not_accept_wrong_root_verifier_or_modified_signature():
    from mcp_warden.receipt_kernel import ReceiptError, canonical, parse_canonical
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    assert c.record_decision(context).mode == "primary-durable"
    old_auth, old_verifier, payload = c.authorization, c.verifier, p["primary"].payloads[0]
    _, new_verifier, _ = _rotate_receipt_authority(c, p)
    wrong = primary_payload_validator(
        authorization=old_auth, verifier=new_verifier, snapshot=p["state"].read
    )
    with pytest.raises(ReceiptError, match="RCT-SIGNATURE-INVALID"):
        wrong(payload)
    validator = primary_payload_validator(
        authorization=old_auth, verifier=old_verifier, snapshot=p["state"].read
    )
    data = parse_canonical(payload)
    data["evidence"]["signature_hex"] = "00" * 64
    with pytest.raises(ReceiptError, match="RCT-SIGNATURE-INVALID"):
        validator(canonical(data))


def test_historical_receipt_still_requires_signing_time_validity():
    from mcp_warden.decision_receipts import serialize_signed_receipt, serialize_unsigned_receipt
    from mcp_warden.receipt_kernel import ReceiptError, receipt_digest
    from mcp_warden.receipt_models import SignedReceiptV1
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    assert c.record_decision(context).mode == "primary-durable"
    record = parse_signed_receipt(p["primary"].payloads[0])
    expired = record.receipt.model_copy(update={"trusted_time": c.authorization.bundle.valid_until})
    payload = serialize_unsigned_receipt(expired)
    evidence = c.signer.sign(
        payload=payload,
        artifact_kind="receipt",
        role="receipt-signer",
        authorization_digest=c.authorization.digest,
    )
    candidate = SignedReceiptV1(
        receipt=expired, evidence=evidence, receipt_digest=receipt_digest(payload, "receipt")
    )
    validator = primary_payload_validator(
        authorization=c.authorization, verifier=c.verifier, snapshot=p["state"].read
    )
    with pytest.raises(ReceiptError, match="RCT-STALE"):
        validator(serialize_signed_receipt(candidate))
