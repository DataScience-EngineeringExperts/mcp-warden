"""Opt-in public-key verification for DSE-716's external verifier port.

No private-key operations live here. The configured root digest must come from
a consumer-controlled boundary outside agent-editable inputs and state.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from types import MappingProxyType

import rfc8785

from mcp_warden.artifact_payload import (
    ArtifactTrustError,
    bounded_json,
    canonical_artifact_payload,
)
from mcp_warden.decision_models import DIGEST_RE, ArtifactKindV1, VerificationAlgorithmV1

MAX_ROOTS_BYTES = 64 * 1024
MAX_TRUST_KEYS = 64
_PUBLIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_FRAME = b"mcp-warden/artifact-signature/v1\x00"


def _hash(domain: bytes, payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\x00" + payload).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedArtifactKeyV1:
    public_key: bytes
    artifact_kinds: tuple[ArtifactKindV1, ...]

    def __post_init__(self) -> None:
        if (
            type(self.public_key) is not bytes
            or len(self.public_key) != 32
            or type(self.artifact_kinds) is not tuple
            or not self.artifact_kinds
            or len(self.artifact_kinds) > len(ArtifactKindV1)
            or any(type(kind) is not ArtifactKindV1 for kind in self.artifact_kinds)
            or self.artifact_kinds != tuple(sorted(set(self.artifact_kinds)))
        ):
            raise ArtifactTrustError("TRUST-ROOTS-MALFORMED") from None

    @property
    def signer_identity(self) -> str:
        return _hash(b"mcp-warden/artifact-signature/v1/key-id", self.public_key)


def canonical_roots_bytes(roots: tuple[TrustedArtifactKeyV1, ...]) -> bytes:
    if (
        type(roots) is not tuple
        or not roots
        or len(roots) > MAX_TRUST_KEYS
        or any(type(root) is not TrustedArtifactKeyV1 for root in roots)
    ):
        raise ArtifactTrustError("TRUST-ROOTS-MALFORMED") from None
    # Rebuild records to reject mutated/forged dataclass instances.
    validated = tuple(TrustedArtifactKeyV1(root.public_key, root.artifact_kinds) for root in roots)
    if len({root.signer_identity for root in validated}) != len(validated):
        raise ArtifactTrustError("TRUST-ROOTS-MALFORMED") from None
    return rfc8785.dumps(
        {
            "schema_version": 1,
            "keys": [
                {
                    "public_key": root.public_key.hex(),
                    "artifact_kinds": [kind.value for kind in root.artifact_kinds],
                }
                for root in sorted(validated, key=lambda item: item.signer_identity)
            ],
        }
    )


def roots_digest(roots: tuple[TrustedArtifactKeyV1, ...]) -> str:
    return _hash(b"mcp-warden/artifact-signature/v1/roots", canonical_roots_bytes(roots))


def parse_roots(payload: bytes) -> tuple[TrustedArtifactKeyV1, ...]:
    parsed = bounded_json(payload, cap=MAX_ROOTS_BYTES, code="TRUST-ROOTS-MALFORMED")
    roots = None
    try:
        if (
            type(parsed) is not dict
            or set(parsed) != {"schema_version", "keys"}
            or type(parsed["schema_version"]) is not int
            or parsed["schema_version"] != 1
            or type(parsed["keys"]) is not list
            or not 0 < len(parsed["keys"]) <= MAX_TRUST_KEYS
        ):
            raise ValueError
        records = []
        for item in parsed["keys"]:
            if (
                type(item) is not dict
                or set(item) != {"public_key", "artifact_kinds"}
                or type(item["public_key"]) is not str
                or _PUBLIC_KEY_RE.fullmatch(item["public_key"]) is None
                or type(item["artifact_kinds"]) is not list
                or any(type(kind) is not str for kind in item["artifact_kinds"])
            ):
                raise ValueError
            records.append(
                TrustedArtifactKeyV1(
                    bytes.fromhex(item["public_key"]),
                    tuple(ArtifactKindV1(kind) for kind in item["artifact_kinds"]),
                )
            )
        candidate = tuple(sorted(records, key=lambda item: item.signer_identity))
        canonical_roots_bytes(candidate)
        roots = candidate
    except Exception:
        pass
    if roots is None:
        raise ArtifactTrustError("TRUST-ROOTS-MALFORMED") from None
    return roots


def artifact_signing_bytes(kind: ArtifactKindV1, signer_identity: str, payload: bytes) -> bytes:
    if (
        type(kind) is not ArtifactKindV1
        or type(signer_identity) is not str
        or DIGEST_RE.fullmatch(signer_identity) is None
    ):
        raise ArtifactTrustError("TRUST-ARTIFACT-MALFORMED") from None
    if canonical_artifact_payload(kind, payload) != payload:
        raise ArtifactTrustError("TRUST-ARTIFACT-NONCANONICAL") from None
    return (
        _FRAME
        + kind.value.encode("ascii")
        + b"\x00"
        + signer_identity.encode("ascii")
        + b"\x00"
        + payload
    )


def _public_key_type():
    key_type = None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key_type = Ed25519PublicKey
    except ImportError:
        pass
    if key_type is None:
        raise ArtifactTrustError("TRUST-CRYPTO-UNAVAILABLE") from None
    return key_type


class Ed25519ArtifactVerifierV1:
    """Pinned keys and explicit kind roles; bool-only fail-closed verification.

    This implements ArtifactVerifierV1, not a policy decision or evidence gate.
    A consumer must protect the pin and perform all existing activation checks.
    """

    __slots__ = ("_roots",)

    def __init__(self, roots: tuple[TrustedArtifactKeyV1, ...], *, expected_roots_digest: str):
        if (
            type(expected_roots_digest) is not str
            or DIGEST_RE.fullmatch(expected_roots_digest) is None
            or roots_digest(roots) != expected_roots_digest
        ):
            raise ArtifactTrustError("TRUST-ROOT-PIN-MISMATCH") from None
        key_type = _public_key_type()
        records = {}
        failed = False
        try:
            for root in roots:
                records[root.signer_identity] = (
                    key_type.from_public_bytes(root.public_key),
                    frozenset(root.artifact_kinds),
                )
        except Exception:
            failed = True
        if failed:
            raise ArtifactTrustError("TRUST-CRYPTO-UNAVAILABLE") from None
        object.__setattr__(self, "_roots", MappingProxyType(records))

    def __setattr__(self, name: str, value: object) -> None:
        raise ArtifactTrustError("TRUST-IMMUTABLE") from None

    def __delattr__(self, name: str) -> None:
        raise ArtifactTrustError("TRUST-IMMUTABLE") from None

    def verify(
        self,
        *,
        artifact_kind: ArtifactKindV1,
        algorithm: VerificationAlgorithmV1,
        signer_identity: str,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        if (
            type(artifact_kind) is not ArtifactKindV1
            or type(algorithm) is not VerificationAlgorithmV1
            or algorithm is not VerificationAlgorithmV1.EXTERNAL_V1
            or type(signer_identity) is not str
            or type(signature) is not bytes
            or len(signature) != 64
        ):
            return False
        try:
            key, kinds = self._roots[signer_identity]
            if artifact_kind not in kinds:
                return False
            key.verify(signature, artifact_signing_bytes(artifact_kind, signer_identity, payload))
        except Exception:
            return False
        return True
