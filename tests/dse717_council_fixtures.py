"""Shared deterministic, independently trusted council test authority fixtures."""


def _rotate_receipt_authority(c, p):
    """TCB rotation of root, signer key, authorization and protected floors."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from mcp_warden.decision_receipts import signature_frame
    from mcp_warden.evidence_floor import ArtifactFloorV1
    from mcp_warden.evidence_reference import advance_state
    from mcp_warden.receipt_kernel import canonical, receipt_digest
    from mcp_warden.signer_authorization import (
        PinnedGovernanceVerifierV1,
        activate_signer_authorization,
    )
    from tests.receipt_fixtures import TestSigner

    root = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(3, 35)))
    public = key.public_key().public_bytes_raw()
    identity = receipt_digest(public, "trust-root")
    verifier = PinnedGovernanceVerifierV1(
        root_public_key=root.public_key().public_bytes_raw(),
        signer_public_keys=((identity, public),),
    )
    bundle = c.authorization.bundle.model_copy(
        update={
            "generation": 2,
            "valid_from": 20,
            "trust_root_digest": verifier.trust_root_digest,
            "grants": tuple(
                g.model_copy(update={"signer_identity_digest": identity})
                for g in c.authorization.bundle.grants
            ),
        }
    )
    digest = receipt_digest(canonical(bundle), "authorization")
    old = p["state"].read()
    floors = tuple(
        ArtifactFloorV1(
            kind=f.kind,
            generation=2,
            digest=digest if f.kind == "signer-authorization" else verifier.trust_root_digest,
        )
        if f.kind in {"signer-authorization", "trust-root"}
        else f
        for f in old.floors
    )
    advanced = advance_state(old, floors=floors)
    p["state"].compare_and_advance(old, advanced)
    frame = signature_frame(
        payload=canonical(bundle),
        artifact_kind="signer-authorization",
        role="trust-root",
        signer_identity_digest=verifier.trust_root_digest,
        authorization_digest=verifier.trust_root_digest,
    )
    authorization = activate_signer_authorization(
        bundle,
        signature=root.sign(frame),
        verifier=verifier,
        snapshot=advanced,
        now=30,
        trust_root_generation=2,
    )
    return authorization, verifier, TestSigner(key, identity)
