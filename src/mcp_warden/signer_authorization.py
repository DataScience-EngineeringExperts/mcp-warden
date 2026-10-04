"""Separately pinned governance verification, without broadening DSE-716 artifact kinds."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from mcp_warden.decision_receipts import signature_frame
from mcp_warden.evidence_state import ProtectedStateSnapshotV1, validate_floor
from mcp_warden.receipt_kernel import ReceiptError, canonical, exact, receipt_digest
from mcp_warden.receipt_models import SignatureEvidenceV1, SignerAuthorizationBundleV1


class GovernanceVerifierV1(Protocol):
    trust_root_digest: str

    def verify_root(self, *, payload: bytes, signature: bytes) -> bool: ...
    def verify(self, *, payload: bytes, evidence: SignatureEvidenceV1) -> bool: ...


class PinnedGovernanceVerifierV1:
    """Public-key-only verifier. Private signing remains an injected TCB port."""

    __slots__ = ("trust_root_digest", "_root", "_keys")

    def __init__(
        self, *, root_public_key: bytes, signer_public_keys: tuple[tuple[str, bytes], ...]
    ):
        bad = False
        keys = {}
        root = None
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            if (
                type(root_public_key) is not bytes
                or len(root_public_key) != 32
                or type(signer_public_keys) is not tuple
            ):
                raise ValueError
            root = Ed25519PublicKey.from_public_bytes(root_public_key)
            for identity, key in signer_public_keys:
                if (
                    type(key) is not bytes
                    or len(key) != 32
                    or identity in keys
                    or identity != receipt_digest(key, "trust-root")
                ):
                    raise ValueError
                keys[identity] = Ed25519PublicKey.from_public_bytes(key)
            if len(keys) > 256:
                raise ValueError
        except Exception:
            bad = True
        if bad:
            raise ReceiptError("RCT-MALFORMED") from None
        object.__setattr__(self, "trust_root_digest", receipt_digest(root_public_key, "trust-root"))
        object.__setattr__(self, "_root", root)
        object.__setattr__(self, "_keys", MappingProxyType(keys))

    def __setattr__(self, name, value):
        raise ReceiptError("RCT-MALFORMED")

    def verify_root(self, *, payload: bytes, signature: bytes) -> bool:
        valid = False
        try:
            frame = signature_frame(
                payload=payload,
                artifact_kind="signer-authorization",
                role="trust-root",
                signer_identity_digest=self.trust_root_digest,
                authorization_digest=self.trust_root_digest,
            )
            self._root.verify(signature, frame)
            valid = True
        except Exception:
            pass
        return valid

    def verify(self, *, payload: bytes, evidence: SignatureEvidenceV1) -> bool:
        exact(evidence, SignatureEvidenceV1)
        valid = False
        try:
            frame = signature_frame(
                payload=payload,
                artifact_kind=evidence.artifact_kind,
                role=evidence.role,
                signer_identity_digest=evidence.signer_identity_digest,
                authorization_digest=evidence.authorization_digest,
            )
            self._keys[evidence.signer_identity_digest].verify(evidence.signature, frame)
            valid = True
        except Exception:
            pass
        return valid


_AUTH_SEAL = object()


@dataclass(frozen=True, slots=True)
class ActivatedSignerAuthorizationV1:
    bundle: SignerAuthorizationBundleV1
    digest: str
    trust_root_generation: int
    _seal: object

    def __post_init__(self):
        if self._seal is not _AUTH_SEAL:
            raise ReceiptError("RCT-AUTHORIZATION-UNAVAILABLE")


def check_authorization(authorization, *, snapshot: ProtectedStateSnapshotV1, now: int) -> None:
    if (
        type(authorization) is not ActivatedSignerAuthorizationV1
        or authorization._seal is not _AUTH_SEAL
    ):
        raise ReceiptError("RCT-AUTHORIZATION-UNAVAILABLE")
    exact(authorization.bundle, SignerAuthorizationBundleV1)
    if (
        type(now) is not int
        or not authorization.bundle.valid_from <= now < authorization.bundle.valid_until
    ):
        raise ReceiptError("RCT-STALE")
    if receipt_digest(canonical(authorization.bundle), "authorization") != authorization.digest:
        raise ReceiptError("RCT-INTEGRITY")
    validate_floor(
        snapshot,
        kind="signer-authorization",
        generation=authorization.bundle.generation,
        digest=authorization.digest,
    )
    validate_floor(
        snapshot,
        kind="trust-root",
        generation=authorization.trust_root_generation,
        digest=authorization.bundle.trust_root_digest,
    )


def activate_signer_authorization(
    bundle: SignerAuthorizationBundleV1,
    *,
    signature: bytes,
    verifier: GovernanceVerifierV1,
    snapshot: ProtectedStateSnapshotV1,
    now: int,
    trust_root_generation: int,
) -> ActivatedSignerAuthorizationV1:
    exact(bundle, SignerAuthorizationBundleV1)
    payload = canonical(bundle)
    bad = False
    verified = False
    try:
        if verifier.trust_root_digest == bundle.trust_root_digest:
            verified = verifier.verify_root(payload=payload, signature=signature)
    except Exception:
        bad = True
    if bad or verified is not True:
        raise ReceiptError("RCT-SIGNATURE-INVALID") from None
    active = ActivatedSignerAuthorizationV1(
        bundle, receipt_digest(payload, "authorization"), trust_root_generation, _AUTH_SEAL
    )
    check_authorization(active, snapshot=snapshot, now=now)
    return active


def verify_authorized_artifact(
    *,
    payload: bytes,
    evidence: SignatureEvidenceV1,
    authorization: ActivatedSignerAuthorizationV1,
    artifact_kind: str,
    role: str,
    verifier: GovernanceVerifierV1,
    snapshot: ProtectedStateSnapshotV1,
    now: int,
) -> None:
    check_authorization(authorization, snapshot=snapshot, now=now)
    exact(evidence, SignatureEvidenceV1)
    if (
        type(payload) is not bytes
        or evidence.artifact_kind != artifact_kind
        or evidence.role != role
        or evidence.authorization_digest != authorization.digest
        or not any(
            g.signer_identity_digest == evidence.signer_identity_digest
            and g.role == role
            and g.artifact_kind == artifact_kind
            for g in authorization.bundle.grants
        )
    ):
        raise ReceiptError("RCT-SIGNER-UNAUTHORIZED")
    valid = False
    failed = False
    try:
        valid = (
            verifier.trust_root_digest == authorization.bundle.trust_root_digest
            and verifier.verify(payload=payload, evidence=evidence)
        )
    except Exception:
        failed = True
    if failed or valid is not True:
        raise ReceiptError("RCT-SIGNATURE-INVALID") from None
