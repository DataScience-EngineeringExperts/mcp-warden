import pytest

from mcp_warden.evidence_state import ArtifactFloorV1, StateError, validate_floor
from mcp_warden.receipt_kernel import ReceiptError
from mcp_warden.receipt_models import (
    ReceiptEventContextV1,
    SignerAuthorizationBundleV1,
    SignerGrantV1,
)
from tests.receipt_fixtures import authority

D = "sha256:" + "a" * 64


class DigestSubclass(str):
    pass


def test_schema_bool_and_digest_subclasses_rejected():
    grant = SignerGrantV1(signer_identity_digest=D, role="receipt-signer", artifact_kind="receipt")
    with pytest.raises(ReceiptError):
        SignerAuthorizationBundleV1(
            schema_version=True,
            generation=1,
            valid_from=0,
            valid_until=10,
            trust_root_digest=D,
            grants=(grant,),
        )
    with pytest.raises(ReceiptError):
        SignerGrantV1(
            signer_identity_digest=DigestSubclass(D), role="receipt-signer", artifact_kind="receipt"
        )


def test_optional_event_boundary_is_capped():
    with pytest.raises(ReceiptError):
        ReceiptEventContextV1(
            kind="expiry", artifact_kind="rule", artifact_digest=D, validity_boundary=2**53
        )


def test_forged_nested_state_floor_rejected():
    _, _, _, state = authority()
    bad = ArtifactFloorV1.model_construct(kind="rule", generation=-1, digest=D)
    forged = state.model_copy(update={"floors": (bad,)})
    with pytest.raises(StateError, match="RCT-STATE-MALFORMED"):
        validate_floor(forged, kind="rule", generation=1, digest=D)


def test_state_error_code_is_closed_and_latch_digest_types_are_exact():
    from pydantic import ValidationError

    from mcp_warden.evidence_state import RecoveryLatchSnapshotV1

    assert str(StateError("secret provider detail")) == "RCT-STATE-MALFORMED"
    with pytest.raises(ValidationError):
        RecoveryLatchSnapshotV1(generation=1, latched=True, event_digest=DigestSubclass(D))
