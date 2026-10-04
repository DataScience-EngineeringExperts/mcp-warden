"""Deterministic test-only private signing providers. Never imported by production."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_warden.decision_receipts import signature_frame
from mcp_warden.evidence_state import (
    FLOOR_KINDS,
    ArtifactFloorV1,
    ProtectedStateModeV1,
    ProtectedStateSnapshotV1,
)
from mcp_warden.receipt_kernel import ZERO_DIGEST, canonical, receipt_digest
from mcp_warden.receipt_models import (
    SignatureEvidenceV1,
    SignerAuthorizationBundleV1,
    SignerGrantV1,
)


class TestSigner:
    def __init__(self, key, identity):
        self.key, self.identity = key, identity

    def sign(self, *, payload, artifact_kind, role, authorization_digest):
        signature = self.key.sign(
            signature_frame(
                payload=payload,
                artifact_kind=artifact_kind,
                role=role,
                signer_identity_digest=self.identity,
                authorization_digest=authorization_digest,
            )
        )
        return SignatureEvidenceV1(
            role=role,
            artifact_kind=artifact_kind,
            signer_identity_digest=self.identity,
            authorization_digest=authorization_digest,
            signature=signature,
        )


def authority():
    from mcp_warden.signer_authorization import (
        PinnedGovernanceVerifierV1,
        activate_signer_authorization,
    )

    root = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    identity = receipt_digest(key.public_key().public_bytes_raw(), "trust-root")
    trust = receipt_digest(root.public_key().public_bytes_raw(), "trust-root")
    verifier = PinnedGovernanceVerifierV1(
        root_public_key=root.public_key().public_bytes_raw(),
        signer_public_keys=((identity, key.public_key().public_bytes_raw()),),
    )
    roles = ("override-authorizer", "receipt-signer", "recovery-administrator", "rule-publisher")
    kinds = {
        "receipt-signer": "receipt",
        "rule-publisher": "rule",
        "override-authorizer": "override",
        "recovery-administrator": "recovery",
    }
    bundle = SignerAuthorizationBundleV1(
        generation=1,
        valid_from=0,
        valid_until=1000,
        trust_root_digest=trust,
        grants=tuple(
            SignerGrantV1(signer_identity_digest=identity, role=r, artifact_kind=kinds[r])
            for r in roles
        ),
    )
    auth_digest = receipt_digest(canonical(bundle), "authorization")
    floors = tuple(ArtifactFloorV1(kind=k, generation=0, digest=ZERO_DIGEST) for k in FLOOR_KINDS)
    floors = tuple(
        f.model_copy(
            update={
                "generation": 1,
                "digest": auth_digest if f.kind == "signer-authorization" else trust,
            }
        )
        if f.kind in {"signer-authorization", "trust-root"}
        else f
        for f in floors
    )
    snapshot = ProtectedStateSnapshotV1(
        state_generation=0,
        state_digest=ZERO_DIGEST,
        primary_sequence=0,
        primary_tail_digest=ZERO_DIGEST,
        fallback_sequence=0,
        fallback_tail_digest=ZERO_DIGEST,
        receipt_generation_floor=0,
        rule_generation_floor=0,
        override_generation_floor=0,
        mode=ProtectedStateModeV1.HEALTHY,
        floors=floors,
    )
    frame = signature_frame(
        payload=canonical(bundle),
        artifact_kind="signer-authorization",
        role="trust-root",
        signer_identity_digest=trust,
        authorization_digest=trust,
    )
    auth = activate_signer_authorization(
        bundle,
        signature=root.sign(frame),
        verifier=verifier,
        snapshot=snapshot,
        now=10,
        trust_root_generation=1,
    )
    return auth, verifier, TestSigner(key, identity), snapshot
