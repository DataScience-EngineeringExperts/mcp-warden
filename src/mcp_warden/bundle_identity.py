"""Versioned, offline comparison of attested MCP deployment evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal

import rfc8785
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from mcp_warden.corpus_coordinate import parse_explicit
from mcp_warden.decision_models import (
    DIGEST_RE,
    ArtifactKindV1,
    DecisionDigestDomain,
    VerificationAlgorithmV1,
    digest_decision_bytes,
)
from mcp_warden.policy_decision import ArtifactVerifierV1

MAX_IDENTITY_BYTES = 512 * 1024
MAX_CAPABILITIES = 2048

Digest = Annotated[str, Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$")]
CapabilityKind = Literal["tool", "resource", "prompt"]
_PACKAGE_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_NPM_NAME = re.compile(r"(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*")
_NPM_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_PYPI_VERSION = re.compile(
    r"[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?"
    r"(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:\.[a-z0-9]+)*)?"
)


class IdentityError(ValueError):
    """Code-only validation failure."""


class _IdentityModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="forbid",
        hide_input_in_errors=True,
        revalidate_instances="always",
    )


class PackageIdentityV1(_IdentityModel):
    coordinate: Annotated[str, Field(max_length=320)] | None = None
    artifact_digest: Digest | None = None
    publisher_identity_digest: Digest | None = None
    signer_identity_digest: Digest | None = None
    provenance_digest: Digest | None = None
    dependency_closure_digest: Digest | None = None
    sbom_digest: Digest | None = None

    @field_validator("coordinate")
    @classmethod
    def _coordinate(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = parse_explicit(value)
        if parsed is None:
            raise ValueError("expected a pinned package coordinate")
        _, _, raw_name = value.rpartition("@")[0].partition(":")
        if parsed.ecosystem == "pypi":
            name_pattern, version_pattern = _PACKAGE_NAME, _PYPI_VERSION
        else:
            name_pattern, version_pattern = _NPM_NAME, _NPM_VERSION
        if not name_pattern.fullmatch(raw_name) or not version_pattern.fullmatch(parsed.version):
            raise ValueError("expected a pinned package coordinate")
        return str(parsed)


class TransportIdentityV1(_IdentityModel):
    kind: Literal["stdio", "streamable-http"]
    binding_digest: Digest


class CapabilityIdentityV1(_IdentityModel):
    kind: CapabilityKind
    identifier_digest: Digest
    entry_digest: Digest

    @property
    def key(self) -> tuple[str, str]:
        return self.kind, self.identifier_digest


class BehaviorIdentityV1(_IdentityModel):
    profile_digest: Digest
    evidence_digest: Digest


class DeploymentIdentityV1(_IdentityModel):
    schema_version: Annotated[int, Field(ge=1, le=1)]
    package: PackageIdentityV1 = Field(default_factory=PackageIdentityV1)
    server_identity_digest: Digest | None = None
    configuration_digest: Digest | None = None
    transport: TransportIdentityV1 | None = None
    capabilities: (
        Annotated[tuple[CapabilityIdentityV1, ...], Field(max_length=MAX_CAPABILITIES)] | None
    ) = None
    policy_binding_digest: Digest | None = None
    behavior: BehaviorIdentityV1 | None = None

    @field_validator("capabilities", mode="before")
    @classmethod
    def _array(cls, value: object) -> object:
        if type(value) is list:
            if len(value) > MAX_CAPABILITIES:
                raise ValueError("capabilities exceed limit")
            return tuple(value)
        return value

    @field_validator("capabilities")
    @classmethod
    def _capability_order(
        cls, value: tuple[CapabilityIdentityV1, ...] | None
    ) -> tuple[CapabilityIdentityV1, ...] | None:
        if value is None:
            return None
        return _ordered_capabilities(value)


def _ordered_capabilities(
    value: tuple[CapabilityIdentityV1, ...],
) -> tuple[CapabilityIdentityV1, ...]:
    if len({item.key for item in value}) != len(value):
        raise ValueError("duplicate capability identifier")
    return tuple(sorted(value, key=lambda item: item.key))


def parse_deployment_identity(payload: bytes) -> DeploymentIdentityV1:
    # The artifact registry calls this parser for observation signature framing.
    from mcp_warden.artifact_payload import ArtifactTrustError, bounded_json

    try:
        data = bounded_json(payload, cap=MAX_IDENTITY_BYTES, code="IDENTITY-MALFORMED")
        return DeploymentIdentityV1.model_validate(data)
    except (ArtifactTrustError, ValidationError):
        pass
    raise IdentityError("IDENTITY-MALFORMED")


def _validated_identity(identity: DeploymentIdentityV1) -> DeploymentIdentityV1:
    if type(identity) is DeploymentIdentityV1:
        try:
            return DeploymentIdentityV1.model_validate(identity)
        except ValidationError:
            pass
    raise IdentityError("IDENTITY-MALFORMED")


def _canonical_bytes(validated: DeploymentIdentityV1) -> bytes:
    payload = rfc8785.dumps(validated.model_dump(mode="json"))
    if len(payload) > MAX_IDENTITY_BYTES:
        raise IdentityError("IDENTITY-MALFORMED")
    return payload


def canonical_deployment_identity_bytes(identity: DeploymentIdentityV1) -> bytes:
    return _canonical_bytes(_validated_identity(identity))


@dataclass(frozen=True, slots=True)
class IdentityObservationV1:
    identity: DeploymentIdentityV1
    signer_identity: str | None = None
    signature: bytes | None = None


class IdentityComparisonStatus(StrEnum):
    MATCH = "match"
    DRIFT = "drift"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class IdentityDigestsV1:
    package_digest: str
    deployment_digest: str


@dataclass(frozen=True, slots=True)
class IdentityComparisonV1:
    status: IdentityComparisonStatus
    reasons: tuple[str, ...]
    baseline: IdentityDigestsV1 | None
    current: IdentityDigestsV1 | None


def _verified(
    observation: IdentityObservationV1, payload: bytes, verifier: ArtifactVerifierV1 | None
) -> bool:
    if (
        verifier is None
        or type(observation.signer_identity) is not str
        or DIGEST_RE.fullmatch(observation.signer_identity) is None
        or type(observation.signature) is not bytes
        or len(observation.signature) != 64
    ):
        return False
    try:
        return (
            verifier.verify(
                artifact_kind=ArtifactKindV1.DEPLOYMENT_OBSERVATION,
                algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
                signer_identity=observation.signer_identity,
                payload=payload,
                signature=observation.signature,
            )
            is True
        )
    except Exception:
        return False


def _assess(
    label: str, observation: IdentityObservationV1, verifier: ArtifactVerifierV1 | None
) -> tuple[dict[str, object], tuple[str, ...], IdentityDigestsV1 | None]:
    if type(observation) is not IdentityObservationV1:
        raise IdentityError("IDENTITY-MALFORMED")
    identity = _validated_identity(observation.identity)
    payload = _canonical_bytes(identity)
    package = identity.package.model_dump(mode="json")
    fields = package | identity.model_dump(mode="json", exclude={"schema_version", "package"})
    gaps = tuple(f"{label}_{name}_missing" for name, value in fields.items() if value is None)
    if not _verified(observation, payload, verifier):
        gaps = (f"{label}_unverified", *gaps)
    if gaps:
        return fields, gaps, None
    return (
        fields,
        (),
        IdentityDigestsV1(
            package_digest=digest_decision_bytes(
                rfc8785.dumps({"schema_version": 1, **package}),
                domain=DecisionDigestDomain.PACKAGE_IDENTITY,
            ),
            deployment_digest=digest_decision_bytes(
                payload, domain=DecisionDigestDomain.DEPLOYMENT_IDENTITY
            ),
        ),
    )


def compare_deployment_identities(
    baseline: IdentityObservationV1,
    current: IdentityObservationV1,
    *,
    verifier: ArtifactVerifierV1 | None = None,
) -> IdentityComparisonV1:
    """Compare observations using a caller-owned verifier. This produces evidence only."""
    before, baseline_gaps, baseline_digests = _assess("baseline", baseline, verifier)
    after, current_gaps, current_digests = _assess("current", current, verifier)
    changes = tuple(
        f"{name}_changed"
        for name in before
        if before[name] is not None and after[name] is not None and before[name] != after[name]
    )
    if baseline_gaps or current_gaps:
        status = IdentityComparisonStatus.INDETERMINATE
    elif changes:
        status = IdentityComparisonStatus.DRIFT
    else:
        status = IdentityComparisonStatus.MATCH
    return IdentityComparisonV1(
        status, baseline_gaps + current_gaps + changes, baseline_digests, current_digests
    )
