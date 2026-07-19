"""Strict V1 models for deterministic policy decisions.

The models carry digests and bounded metadata only.  They never carry raw
identity, content, argument, signature, or exception text in public outputs.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictInt,
    ValidationError,
    field_validator,
    model_validator,
)

from mcp_warden.content_models import TAINT_REGISTRY_V1, ContentEnvelopeV1

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")

MAX_POLICY_BYTES = 512 * 1024
MAX_RUNTIME_BYTES = 64 * 1024
MAX_DECISION_BYTES = 16 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_GRANTS = 4_096
MAX_REVOCATIONS = 4_096


class DecisionError(Exception):
    """Stable code-only decision failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code

    def __repr__(self) -> str:
        return self.code


class DecisionDigestDomain(StrEnum):
    CLAIM = "mcp-warden/decision/v1/claim"
    IDENTITY_BINDING = "mcp-warden/decision/v1/identity-binding"
    DATA_SCOPE = "mcp-warden/decision/v1/data-scope"
    PURPOSE = "mcp-warden/decision/v1/purpose"
    EFFECT_ARGUMENTS = "mcp-warden/decision/v1/effect-arguments"
    POLICY_ID = "mcp-warden/decision/v1/policy-id"
    RULE_SET = "mcp-warden/decision/v1/rule-set"
    TRUST_ROOT = "mcp-warden/decision/v1/trust-root"
    LEASE_ID = "mcp-warden/decision/v1/lease-id"
    REQUEST_BINDING = "mcp-warden/decision/v1/request-binding"
    LEASE = "mcp-warden/decision/v1/lease"
    REQUEST = "mcp-warden/decision/v1/request"
    POLICY = "mcp-warden/decision/v1/policy"
    RUNTIME = "mcp-warden/decision/v1/runtime"
    REVOCATION = "mcp-warden/decision/v1/revocation"
    DECISION = "mcp-warden/decision/v1/decision"
    INVALID_INPUT = "mcp-warden/decision/v1/invalid-input"
    ADAPTER_MANIFEST = "mcp-warden/decision/v1/adapter-manifest"
    ADAPTER_IMPLEMENTATION = "mcp-warden/decision/v1/adapter-implementation"
    ADAPTER_DEPENDENCY = "mcp-warden/decision/v1/adapter-dependency"
    HANDLER_IMPLEMENTATION = "mcp-warden/decision/v1/handler-implementation"
    EFFECT_EVIDENCE = "mcp-warden/decision/v1/effect-evidence"
    CONFORMANCE_REPORT = "mcp-warden/decision/v1/conformance-report"
    BUNDLE_MANIFEST = "mcp-warden/decision/v1/bundle-manifest"


def digest_decision_bytes(payload: bytes, *, domain: DecisionDigestDomain) -> str:
    """Hash exact bytes under a closed decision-domain namespace."""
    if type(payload) is not bytes or type(domain) is not DecisionDigestDomain:
        raise TypeError("PDP-DIGEST-TYPE")
    value = hashlib.sha256(domain.value.encode("ascii") + b"\x00" + payload).hexdigest()
    return "sha256:" + value


class ArtifactKindV1(StrEnum):
    POLICY = "policy"
    RUNTIME = "runtime"
    ADAPTER = "adapter"
    BUNDLE = "bundle"


class VerificationAlgorithmV1(StrEnum):
    EXTERNAL_V1 = "external-v1"


class AuthorityHealthV1(StrEnum):
    HEALTHY = "healthy"
    RECOVERY_ONLY = "recovery-only"


class CapabilityV1(StrEnum):
    READ = "read"
    DISCLOSE = "disclose"
    TRANSFORM = "transform"
    COMMUNICATE = "communicate"
    EXECUTE = "execute"
    ADMINISTER_POLICY = "administer-policy"
    REPAIR_RECOVERY = "repair-recovery"


class DecisionVerdictV1(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    QUARANTINE = "quarantine"


class DecisionReasonV1(StrEnum):
    ALLOW_EXACT_GRANT = "PDP-ALLOW-EXACT-GRANT"
    DENY_DEFAULT = "PDP-DENY-DEFAULT"
    INPUT_MALFORMED = "PDP-INPUT-MALFORMED"
    REQUEST_INTEGRITY = "PDP-REQUEST-INTEGRITY"
    AUTHORITY_UNAVAILABLE = "PDP-AUTHORITY-UNAVAILABLE"
    RECOVERY_ONLY = "PDP-RECOVERY-ONLY"
    TRUSTED_TIME_STALE = "PDP-TRUSTED-TIME-STALE"
    POLICY_STALE = "PDP-POLICY-STALE"
    POLICY_ROLLBACK = "PDP-POLICY-ROLLBACK"
    ENVELOPE_INVALID = "PDP-ENVELOPE-INVALID"
    CRITICAL_TAINT = "PDP-CRITICAL-TAINT"
    UNINSPECTABLE_DATA = "PDP-UNINSPECTABLE-DATA"
    PRIVILEGED_PATH_REQUIRED = "PDP-PRIVILEGED-PATH-REQUIRED"
    EXECUTABLE_CONTENT = "PDP-EXECUTABLE-CONTENT"
    LEASE_NOT_YET_VALID = "PDP-LEASE-NOT-YET-VALID"
    LEASE_EXPIRED = "PDP-LEASE-EXPIRED"
    LEASE_REVOKED = "PDP-LEASE-REVOKED"
    LEASE_BINDING = "PDP-LEASE-BINDING"
    POLICY_BINDING = "PDP-POLICY-BINDING"
    INTERNAL_ERROR = "PDP-INTERNAL-ERROR"


class DecisionRecoveryV1(StrEnum):
    NONE = "none"
    REFRESH_AUTHORITY = "refresh-authority"
    OBTAIN_NEW_LEASE = "obtain-new-lease"
    REAUTHENTICATE = "reauthenticate"
    QUARANTINE_INPUT = "quarantine-input"
    DISABLE_ADAPTER = "disable-adapter"
    RECOVERY_ONLY = "recovery-only"


def _digest(value: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise ValueError("invalid digest")
    return value


def _identifier(value: str) -> str:
    if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError("invalid identifier")
    return value


class _DecisionModel(BaseModel):
    _validation_code: ClassVar[str] = "PDP-INPUT-MALFORMED"
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    def __init__(self, **data: Any) -> None:
        invalid = False
        try:
            super().__init__(**data)
        except ValidationError:
            invalid = True
        if invalid:
            raise DecisionError(self._validation_code) from None

    def __setattr__(self, name: str, value: Any) -> None:
        invalid = False
        try:
            super().__setattr__(name, value)
        except ValidationError:
            invalid = True
        if invalid:
            raise DecisionError(self._validation_code) from None

    def __delattr__(self, name: str) -> None:
        invalid = False
        try:
            super().__delattr__(name)
        except ValidationError:
            invalid = True
        if invalid:
            raise DecisionError(self._validation_code) from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        invalid = False
        result: Any = None
        try:
            result = super().model_validate(obj, **kwargs)
        except ValidationError:
            invalid = True
        if invalid:
            raise DecisionError(cls._validation_code) from None
        return result


class IdentityBindingV1(_DecisionModel):
    user_digest: str
    agent_digest: str
    device_digest: str
    session_digest: str

    _user = field_validator("user_digest")(_digest)
    _agent = field_validator("agent_digest")(_digest)
    _device = field_validator("device_digest")(_digest)
    _session = field_validator("session_digest")(_digest)


class OperationBindingV1(_DecisionModel):
    adapter_id: str
    adapter_manifest_digest: str
    operation_id: str
    capability: str
    arguments_digest: str
    destination_digest: str
    bundle_manifest_digest: str | None

    _adapter = field_validator("adapter_id")(_identifier)
    _adapter_manifest = field_validator("adapter_manifest_digest")(_digest)
    _operation = field_validator("operation_id")(_identifier)
    _arguments = field_validator("arguments_digest")(_digest)
    _destination = field_validator("destination_digest")(_digest)

    @field_validator("bundle_manifest_digest")
    @classmethod
    def _bundle_manifest(cls, value: str | None) -> str | None:
        return None if value is None else _digest(value)

    @field_validator("capability")
    @classmethod
    def _capability(cls, value: str) -> str:
        if value not in {item.value for item in CapabilityV1}:
            raise ValueError("invalid capability")
        return value

    @model_validator(mode="after")
    def _bundle_required_for_execute(self) -> OperationBindingV1:
        if (self.capability == CapabilityV1.EXECUTE.value) != (
            self.bundle_manifest_digest is not None
        ):
            raise ValueError("invalid bundle binding")
        return self


class CapabilityLeaseV1(_DecisionModel):
    _validation_code: ClassVar[str] = "PDP-LEASE-MALFORMED"
    schema_version: Literal[1]
    lease_id: str
    request_binding_digest: str
    policy_id: str
    policy_generation: StrictInt
    not_before: StrictInt
    expires_at: StrictInt
    revocation_generation: StrictInt
    lease_digest: str

    _lease_id = field_validator("lease_id")(_digest)
    _binding = field_validator("request_binding_digest")(_digest)
    _policy = field_validator("policy_id")(_digest)
    _self_digest = field_validator("lease_digest")(_digest)

    @model_validator(mode="after")
    def _valid_lease(self) -> CapabilityLeaseV1:
        if (
            self.policy_generation < 0
            or self.revocation_generation < 0
            or self.not_before < 0
            or self.expires_at <= self.not_before
        ):
            raise ValueError("invalid lease bounds")
        return self


class PolicyGrantV1(_DecisionModel):
    _validation_code: ClassVar[str] = "PDP-POLICY-MALFORMED"
    lease_digest: str

    _lease = field_validator("lease_digest")(_digest)


class PolicyBundleV1(_DecisionModel):
    _validation_code: ClassVar[str] = "PDP-POLICY-MALFORMED"
    schema_version: Literal[1]
    policy_id: str
    policy_generation: StrictInt
    valid_from: StrictInt
    valid_until: StrictInt
    rule_set_digest: str
    trust_root_digest: str
    critical_floor_version: Literal["atk-critical-v1"]
    revocation_generation: StrictInt
    grants: tuple[PolicyGrantV1, ...]
    revoked_lease_digests: tuple[str, ...]

    _policy_id = field_validator("policy_id")(_digest)
    _rules = field_validator("rule_set_digest")(_digest)
    _trust = field_validator("trust_root_digest")(_digest)

    @field_validator("grants")
    @classmethod
    def _grants(cls, value: tuple[PolicyGrantV1, ...]) -> tuple[PolicyGrantV1, ...]:
        if len(value) > MAX_GRANTS or any(type(item) is not PolicyGrantV1 for item in value):
            raise ValueError("invalid grants")
        if value != tuple(sorted(value, key=lambda item: item.lease_digest)):
            raise ValueError("unsorted grants")
        if len({item.lease_digest for item in value}) != len(value):
            raise ValueError("duplicate grants")
        return value

    @field_validator("revoked_lease_digests")
    @classmethod
    def _revocations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_REVOCATIONS or value != tuple(sorted(set(value))):
            raise ValueError("invalid revocations")
        for item in value:
            _digest(item)
        return value

    @model_validator(mode="after")
    def _valid_policy(self) -> PolicyBundleV1:
        if (
            self.policy_generation < 0
            or self.revocation_generation < 0
            or self.valid_from < 0
            or self.valid_until <= self.valid_from
        ):
            raise ValueError("invalid policy bounds")
        return self


class RuntimeSnapshotV1(_DecisionModel):
    _validation_code: ClassVar[str] = "PDP-RUNTIME-MALFORMED"
    schema_version: Literal[1]
    health: str
    trusted_time: StrictInt
    trusted_time_valid_until: StrictInt
    policy_generation_floor: StrictInt
    policy_digest_at_floor: str
    revocation_generation_floor: StrictInt
    revocation_digest_at_floor: str

    _policy = field_validator("policy_digest_at_floor")(_digest)
    _revocation = field_validator("revocation_digest_at_floor")(_digest)

    @field_validator("health")
    @classmethod
    def _health(cls, value: str) -> str:
        if value not in {item.value for item in AuthorityHealthV1}:
            raise ValueError("invalid health")
        return value

    @model_validator(mode="after")
    def _valid_runtime(self) -> RuntimeSnapshotV1:
        if (
            self.trusted_time < 0
            or self.trusted_time_valid_until < 0
            or self.policy_generation_floor < 0
            or self.revocation_generation_floor < 0
        ):
            raise ValueError("invalid runtime bounds")
        return self


class DecisionRequestV1(_DecisionModel):
    schema_version: Literal[1]
    identity: IdentityBindingV1
    envelope: ContentEnvelopeV1
    data_scope_digest: str
    operation: OperationBindingV1
    purpose_digest: str
    lease: CapabilityLeaseV1
    request_digest: str

    _scope = field_validator("data_scope_digest")(_digest)
    _purpose = field_validator("purpose_digest")(_digest)
    _request = field_validator("request_digest")(_digest)

    @model_validator(mode="after")
    def _exact_nested_types(self) -> DecisionRequestV1:
        if (
            type(self.identity) is not IdentityBindingV1
            or type(self.envelope) is not ContentEnvelopeV1
            or type(self.operation) is not OperationBindingV1
            or type(self.lease) is not CapabilityLeaseV1
        ):
            raise DecisionError("PDP-INPUT-MALFORMED") from None
        return self


class DecisionV1(_DecisionModel):
    _validation_code: ClassVar[str] = "PDP-DECISION-MALFORMED"
    schema_version: Literal[1]
    request_digest: str
    policy_digest: str
    runtime_digest: str
    policy_generation: StrictInt
    revocation_generation: StrictInt
    verdict: str
    reason: str
    recovery: str
    decision_digest: str

    _request = field_validator("request_digest")(_digest)
    _policy = field_validator("policy_digest")(_digest)
    _runtime = field_validator("runtime_digest")(_digest)
    _decision = field_validator("decision_digest")(_digest)

    @field_validator("verdict")
    @classmethod
    def _verdict(cls, value: str) -> str:
        if value not in {item.value for item in DecisionVerdictV1}:
            raise ValueError("invalid verdict")
        return value

    @field_validator("reason")
    @classmethod
    def _reason(cls, value: str) -> str:
        if value not in {item.value for item in DecisionReasonV1}:
            raise ValueError("invalid reason")
        return value

    @field_validator("recovery")
    @classmethod
    def _recovery(cls, value: str) -> str:
        if value not in {item.value for item in DecisionRecoveryV1}:
            raise ValueError("invalid recovery")
        return value


@dataclass(frozen=True, slots=True)
class SignedPolicyCandidateV1:
    policy: PolicyBundleV1
    algorithm: VerificationAlgorithmV1
    signer_identity: str
    signature: bytes

    def __post_init__(self) -> None:
        if (
            type(self.policy) is not PolicyBundleV1
            or type(self.algorithm) is not VerificationAlgorithmV1
            or type(self.signature) is not bytes
            or not self.signature
            or len(self.signature) > MAX_SIGNATURE_BYTES
        ):
            raise DecisionError("PDP-CANDIDATE-MALFORMED") from None
        invalid_signer = False
        try:
            _digest(self.signer_identity)
        except ValueError:
            invalid_signer = True
        if invalid_signer:
            raise DecisionError("PDP-CANDIDATE-MALFORMED") from None


@dataclass(frozen=True, slots=True)
class SignedRuntimeCandidateV1:
    runtime: RuntimeSnapshotV1
    algorithm: VerificationAlgorithmV1
    signer_identity: str
    signature: bytes

    def __post_init__(self) -> None:
        if (
            type(self.runtime) is not RuntimeSnapshotV1
            or type(self.algorithm) is not VerificationAlgorithmV1
            or type(self.signature) is not bytes
            or not self.signature
            or len(self.signature) > MAX_SIGNATURE_BYTES
        ):
            raise DecisionError("PDP-CANDIDATE-MALFORMED") from None
        invalid_signer = False
        try:
            _digest(self.signer_identity)
        except ValueError:
            invalid_signer = True
        if invalid_signer:
            raise DecisionError("PDP-CANDIDATE-MALFORMED") from None


TAINTS_V1 = frozenset(TAINT_REGISTRY_V1)
