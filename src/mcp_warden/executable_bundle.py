"""Signed executable-bundle activation gate for DSE-716."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import rfc8785
from pydantic import BaseModel, ConfigDict, StrictInt, ValidationError, field_validator

from mcp_warden.content_models import (
    MAX_BUNDLE_COMPONENT_BYTES,
    MAX_DEPENDENCIES,
    BundleEvidenceInput,
    BundleEvidenceV1,
    DigestDomain,
)
from mcp_warden.decision_models import (
    DIGEST_RE,
    IDENTIFIER_RE,
    MAX_SIGNATURE_BYTES,
    ArtifactKindV1,
    DecisionDigestDomain,
    VerificationAlgorithmV1,
    digest_decision_bytes,
)
from mcp_warden.hashing import hash_bytes
from mcp_warden.policy_decision import ActivatedPolicyV1, ArtifactVerifierV1

VERSION_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?$")
MAX_BUNDLE_MANIFEST_BYTES = 256 * 1024


class BundleActivationError(Exception):
    """Stable code-only bundle activation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code


def _digest(value: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise ValueError
    return value


class _BundleModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError:
            raise BundleActivationError("PEP-BUNDLE-MANIFEST-MALFORMED") from None

    def __setattr__(self, name: str, value: Any) -> None:
        try:
            super().__setattr__(name, value)
        except ValidationError:
            raise BundleActivationError("PEP-BUNDLE-MANIFEST-MALFORMED") from None

    def __delattr__(self, name: str) -> None:
        try:
            super().__delattr__(name)
        except (TypeError, ValidationError):
            raise BundleActivationError("PEP-BUNDLE-MANIFEST-MALFORMED") from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        try:
            return super().model_validate(obj, **kwargs)
        except ValidationError:
            raise BundleActivationError("PEP-BUNDLE-MANIFEST-MALFORMED") from None


class ExecutableBundleManifestV1(_BundleModel):
    """Signed authority for one exact executable bundle and policy/adapter pair."""

    schema_version: StrictInt
    bundle_id: str
    bundle_version: str
    publisher_identity: str
    artifact_digest: str
    signature_evidence_digest: str | None
    version_claims_digest: str
    publisher_claims_digest: str
    dependency_digests: tuple[str, ...]
    policy_binding_claims_digest: str
    policy_id: str
    policy_generation: StrictInt
    adapter_manifest_digest: str

    _publisher = field_validator("publisher_identity")(_digest)
    _artifact = field_validator("artifact_digest")(_digest)
    _version_claims = field_validator("version_claims_digest")(_digest)
    _publisher_claims = field_validator("publisher_claims_digest")(_digest)
    _policy_claims = field_validator("policy_binding_claims_digest")(_digest)
    _policy = field_validator("policy_id")(_digest)
    _adapter = field_validator("adapter_manifest_digest")(_digest)

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: int) -> int:
        if value != 1:
            raise ValueError
        return value

    @field_validator("bundle_id")
    @classmethod
    def _bundle_id(cls, value: str) -> str:
        if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
            raise ValueError
        return value

    @field_validator("bundle_version")
    @classmethod
    def _version(cls, value: str) -> str:
        if type(value) is not str or VERSION_RE.fullmatch(value) is None:
            raise ValueError
        return value

    @field_validator("signature_evidence_digest")
    @classmethod
    def _signature(cls, value: str | None) -> str | None:
        return None if value is None else _digest(value)

    @field_validator("dependency_digests")
    @classmethod
    def _dependencies(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_DEPENDENCIES or value != tuple(sorted(set(value))):
            raise ValueError
        for item in value:
            _digest(item)
        return value

    @field_validator("policy_generation")
    @classmethod
    def _generation(cls, value: int) -> int:
        if value < 0:
            raise ValueError
        return value


@dataclass(frozen=True, slots=True)
class SignedExecutableBundleCandidateV1:
    manifest: ExecutableBundleManifestV1
    evidence: BundleEvidenceInput
    algorithm: VerificationAlgorithmV1
    signer_identity: str
    signature: bytes

    def __post_init__(self) -> None:
        if (
            type(self.manifest) is not ExecutableBundleManifestV1
            or type(self.evidence) is not BundleEvidenceInput
            or type(self.algorithm) is not VerificationAlgorithmV1
            or type(self.signature) is not bytes
            or not self.signature
            or len(self.signature) > MAX_SIGNATURE_BYTES
        ):
            raise BundleActivationError("PEP-BUNDLE-CANDIDATE-MALFORMED") from None
        try:
            _digest(self.signer_identity)
        except ValueError:
            raise BundleActivationError("PEP-BUNDLE-CANDIDATE-MALFORMED") from None


def _manifest_dict(manifest: ExecutableBundleManifestV1) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "bundle_id": manifest.bundle_id,
        "bundle_version": manifest.bundle_version,
        "publisher_identity": manifest.publisher_identity,
        "artifact_digest": manifest.artifact_digest,
        "signature_evidence_digest": manifest.signature_evidence_digest,
        "version_claims_digest": manifest.version_claims_digest,
        "publisher_claims_digest": manifest.publisher_claims_digest,
        "dependency_digests": list(manifest.dependency_digests),
        "policy_binding_claims_digest": manifest.policy_binding_claims_digest,
        "policy_id": manifest.policy_id,
        "policy_generation": manifest.policy_generation,
        "adapter_manifest_digest": manifest.adapter_manifest_digest,
    }


def canonical_bundle_manifest_bytes(manifest: ExecutableBundleManifestV1) -> bytes:
    try:
        if type(manifest) is not ExecutableBundleManifestV1:
            raise ValueError
        ExecutableBundleManifestV1.model_validate(manifest)
        payload = rfc8785.dumps(_manifest_dict(manifest))
    except Exception:
        raise BundleActivationError("PEP-BUNDLE-MANIFEST-MALFORMED") from None
    if len(payload) > MAX_BUNDLE_MANIFEST_BYTES:
        raise BundleActivationError("PEP-BUNDLE-MANIFEST-OVER-CAP") from None
    return payload


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError


def _metadata_digest(value: bytes, domain: DigestDomain) -> str:
    if type(value) is not bytes or len(value) > MAX_BUNDLE_COMPONENT_BYTES:
        raise BundleActivationError("PEP-BUNDLE-INTEGRITY") from None
    try:
        parsed = json.loads(
            value.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if rfc8785.dumps(parsed) != value:
            raise ValueError
    except Exception:
        raise BundleActivationError("PEP-BUNDLE-INTEGRITY") from None
    return hash_bytes(value, domain=domain)


def bundle_evidence_from_input(value: BundleEvidenceInput) -> BundleEvidenceV1:
    if type(value) is not BundleEvidenceInput:
        raise BundleActivationError("PEP-BUNDLE-INTEGRITY") from None
    dependencies = tuple(
        sorted(
            {_metadata_digest(item, DigestDomain.BUNDLE_DEPENDENCY) for item in value.dependencies}
        )
    )
    signature_digest = None
    if value.signature_evidence is not None:
        if len(value.signature_evidence) > MAX_BUNDLE_COMPONENT_BYTES:
            raise BundleActivationError("PEP-BUNDLE-INTEGRITY") from None
        signature_digest = hash_bytes(
            value.signature_evidence, domain=DigestDomain.BUNDLE_SIGNATURE
        )
    try:
        return BundleEvidenceV1(
            artifact_digest=_metadata_digest(value.artifact, DigestDomain.BUNDLE_ARTIFACT),
            signature_evidence_digest=signature_digest,
            version_claims_digest=_metadata_digest(
                value.version_claims, DigestDomain.BUNDLE_VERSION
            ),
            publisher_claims_digest=_metadata_digest(
                value.publisher_claims, DigestDomain.BUNDLE_PUBLISHER
            ),
            dependency_digests=dependencies,
            policy_binding_claims_digest=_metadata_digest(
                value.policy_binding_claims, DigestDomain.BUNDLE_POLICY_BINDING
            ),
        )
    except (ValidationError, TypeError, ValueError):
        raise BundleActivationError("PEP-BUNDLE-INTEGRITY") from None


_BUNDLE_SEAL = object()


class ActivatedExecutableBundleV1:
    __slots__ = ("manifest", "manifest_digest", "evidence", "policy_digest", "_seal")

    def __init__(
        self,
        *,
        manifest: ExecutableBundleManifestV1,
        manifest_digest: str,
        evidence: BundleEvidenceV1,
        policy_digest: str,
        _seal: object,
    ) -> None:
        if _seal is not _BUNDLE_SEAL:
            raise BundleActivationError("PEP-BUNDLE-UNAVAILABLE") from None
        object.__setattr__(self, "manifest", manifest)
        object.__setattr__(self, "manifest_digest", manifest_digest)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "policy_digest", policy_digest)
        object.__setattr__(self, "_seal", _seal)

    def __setattr__(self, name: str, value: object) -> None:
        raise BundleActivationError("PEP-BUNDLE-IMMUTABLE") from None

    def __delattr__(self, name: str) -> None:
        raise BundleActivationError("PEP-BUNDLE-IMMUTABLE") from None


def is_activated_bundle(value: object) -> bool:
    try:
        return (
            type(value) is ActivatedExecutableBundleV1
            and object.__getattribute__(value, "_seal") is _BUNDLE_SEAL
        )
    except Exception:
        return False


def activate_executable_bundle(
    candidate: SignedExecutableBundleCandidateV1,
    *,
    verifier: ArtifactVerifierV1,
    policy: ActivatedPolicyV1,
    adapter_manifest_digest: str,
) -> ActivatedExecutableBundleV1:
    if (
        type(candidate) is not SignedExecutableBundleCandidateV1
        or type(policy) is not ActivatedPolicyV1
    ):
        raise BundleActivationError("PEP-BUNDLE-CANDIDATE-MALFORMED") from None
    manifest = candidate.manifest
    evidence = bundle_evidence_from_input(candidate.evidence)
    evidence_fields = {
        "artifact_digest": evidence.artifact_digest,
        "signature_evidence_digest": evidence.signature_evidence_digest,
        "version_claims_digest": evidence.version_claims_digest,
        "publisher_claims_digest": evidence.publisher_claims_digest,
        "dependency_digests": evidence.dependency_digests,
        "policy_binding_claims_digest": evidence.policy_binding_claims_digest,
    }
    if any(getattr(manifest, name) != value for name, value in evidence_fields.items()):
        raise BundleActivationError("PEP-BUNDLE-INTEGRITY") from None
    if manifest.publisher_identity != candidate.signer_identity:
        raise BundleActivationError("PEP-BUNDLE-PUBLISHER") from None
    if (
        manifest.policy_id != policy.policy.policy_id
        or manifest.policy_generation != policy.policy.policy_generation
        or manifest.adapter_manifest_digest != adapter_manifest_digest
    ):
        raise BundleActivationError("PEP-BUNDLE-POLICY-BINDING") from None
    payload = canonical_bundle_manifest_bytes(manifest)
    try:
        verified = verifier.verify(
            artifact_kind=ArtifactKindV1.BUNDLE,
            algorithm=candidate.algorithm,
            signer_identity=candidate.signer_identity,
            payload=payload,
            signature=candidate.signature,
        )
    except Exception:
        verified = False
    if verified is not True:
        raise BundleActivationError("PEP-BUNDLE-VERIFICATION") from None
    return ActivatedExecutableBundleV1(
        manifest=manifest,
        manifest_digest=digest_decision_bytes(payload, domain=DecisionDigestDomain.BUNDLE_MANIFEST),
        evidence=evidence,
        policy_digest=policy.policy_digest,
        _seal=_BUNDLE_SEAL,
    )
