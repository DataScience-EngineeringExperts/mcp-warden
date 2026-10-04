"""Deterministic property evidence for canonical events and authorized signatures."""

from __future__ import annotations

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from mcp_warden.receipt_kernel import ReceiptError, canonical, parse_canonical, receipt_digest
from mcp_warden.receipt_models import ReceiptEventContextV1
from mcp_warden.signer_authorization import verify_authorized_artifact
from tests.receipt_fixtures import authority

DIGEST = "sha256:" + "a" * 64


def _event(kind: str, value: int) -> ReceiptEventContextV1:
    fields: dict[str, object] = {"kind": kind}
    if kind == "override":
        fields.update(
            actor_digest=DIGEST, scope_digest=DIGEST, authority_digest=DIGEST, expires_at=value
        )
    elif kind == "revoke":
        fields.update(
            artifact_kind="rule",
            artifact_digest=DIGEST,
            artifact_generation=value,
            revocation_generation=value,
        )
    elif kind == "expiry":
        fields.update(artifact_kind="rule", artifact_digest=DIGEST, validity_boundary=value)
    elif kind == "recovery-exit":
        fields.update(authority_digest=DIGEST)
    return ReceiptEventContextV1(**fields)


@given(
    st.sampled_from(
        ["allow", "deny", "quarantine", "override", "revoke", "expiry", "recovery-exit"]
    ),
    st.integers(min_value=0, max_value=2**53 - 1),
)
def test_canonical_event_round_trip_is_repeatable(kind: str, value: int) -> None:
    left, right = _event(kind, value), _event(kind, value)
    payload = canonical(left)
    assert payload == canonical(right)
    assert canonical(ReceiptEventContextV1(**parse_canonical(payload))) == payload
    assert receipt_digest(payload, "receipt") != receipt_digest(payload, "rule")


@given(st.binary(max_size=512))
@example(b'{"duplicate":1,"duplicate":2}')
@example(b'{"number":NaN}')
@example(b"[" * 256)
def test_bounded_malformed_json_has_only_closed_errors(payload: bytes) -> None:
    try:
        parsed = parse_canonical(payload)
    except ReceiptError as error:
        assert str(error) in {"RCT-NONCANONICAL", "RCT-OVER-CAP", "RCT-MALFORMED"}
        assert error.__context__ is None
    else:
        assert type(parsed) is dict
        assert canonical(parsed) == payload


@given(st.binary(min_size=1, max_size=256), st.integers(min_value=0, max_value=255))
def test_single_byte_tamper_never_verifies(payload: bytes, position: int) -> None:
    auth, verifier, signer, snapshot = authority()
    evidence = signer.sign(
        payload=payload,
        artifact_kind="receipt",
        role="receipt-signer",
        authorization_digest=auth.digest,
    )
    position %= len(payload)
    tampered = bytearray(payload)
    tampered[position] ^= 1
    with pytest.raises(ReceiptError, match="^RCT-SIGNATURE-INVALID$"):
        verify_authorized_artifact(
            payload=bytes(tampered),
            evidence=evidence,
            authorization=auth,
            artifact_kind="receipt",
            role="receipt-signer",
            verifier=verifier,
            snapshot=snapshot,
            now=10,
        )


@given(
    st.sampled_from(
        [
            ("rule", "rule-publisher"),
            ("override", "override-authorizer"),
            ("recovery", "recovery-administrator"),
        ]
    ),
    st.binary(max_size=128),
)
def test_receipt_signature_cannot_be_reused_for_other_roles(target, payload: bytes) -> None:
    auth, verifier, signer, snapshot = authority()
    evidence = signer.sign(
        payload=payload,
        artifact_kind="receipt",
        role="receipt-signer",
        authorization_digest=auth.digest,
    )
    with pytest.raises(ReceiptError, match="^RCT-SIGNER-UNAUTHORIZED$"):
        verify_authorized_artifact(
            payload=payload,
            evidence=evidence,
            authorization=auth,
            artifact_kind=target[0],
            role=target[1],
            verifier=verifier,
            snapshot=snapshot,
            now=10,
        )
