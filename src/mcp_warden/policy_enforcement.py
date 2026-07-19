"""Structural V1 policy enforcement point and signed adapter registry."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Protocol

import rfc8785
from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    ValidationError,
    field_validator,
    model_validator,
)

from mcp_warden.content_envelope import to_public_bytes, to_public_dict
from mcp_warden.content_models import ContentEnvelopeV1
from mcp_warden.decision_models import (
    DIGEST_RE,
    IDENTIFIER_RE,
    MAX_SIGNATURE_BYTES,
    ArtifactKindV1,
    CapabilityV1,
    DecisionDigestDomain,
    DecisionRequestV1,
    DecisionV1,
    DecisionVerdictV1,
    VerificationAlgorithmV1,
    digest_decision_bytes,
)
from mcp_warden.executable_bundle import (
    ActivatedExecutableBundleV1,
    is_activated_bundle,
)
from mcp_warden.handler_identity import (
    HandlerIdentityError,
    digest_handler,
    freeze_handler,
)
from mcp_warden.policy_decision import (
    ActivatedPolicyV1,
    ActivatedRuntimeV1,
    ArtifactVerifierV1,
    PolicyDecisionPointV1,
)

MAX_EFFECT_BYTES = 1024 * 1024
MAX_HANDLER_IMPLEMENTATION_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_MANIFEST_OPERATIONS = 1_024
MAX_ADAPTER_DEPENDENCIES = 1_024
MAX_ENFORCEMENT_RESULT_BYTES = 128 * 1024
VERSION_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?$")


class EnforcementError(Exception):
    """Stable code-only enforcement failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code

    def __repr__(self) -> str:
        return self.code


class EnforcementCodeV1(StrEnum):
    EXECUTED = "PEP-EXECUTED"
    DECISION_BLOCKED = "PEP-DECISION-BLOCKED"
    EFFECT_MALFORMED = "PEP-EFFECT-MALFORMED"
    EFFECT_DIGEST_MISMATCH = "PEP-EFFECT-DIGEST-MISMATCH"
    ADAPTER_MISMATCH = "PEP-ADAPTER-MISMATCH"
    BUNDLE_UNAVAILABLE = "PEP-BUNDLE-UNAVAILABLE"
    BUNDLE_MISMATCH = "PEP-BUNDLE-MISMATCH"
    OPERATION_UNKNOWN = "PEP-OPERATION-UNKNOWN"
    EVIDENCE_UNAVAILABLE = "PEP-EVIDENCE-UNAVAILABLE"
    EVIDENCE_MISMATCH = "PEP-EVIDENCE-MISMATCH"
    SINK_FAILED = "PEP-SINK-FAILED"
    OUTPUT_INVALID = "PEP-OUTPUT-INVALID"
    INTERNAL_ERROR = "PEP-INTERNAL-ERROR"


class EffectOutcomeV1(StrEnum):
    BLOCKED = "blocked"
    COMPLETED = "completed"
    INDETERMINATE = "indeterminate"


def _digest(value: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise ValueError("invalid digest")
    return value


def _identifier(value: str) -> str:
    if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError("invalid identifier")
    return value


class _EnforcementModel(BaseModel):
    _validation_code: ClassVar[str] = "PEP-MALFORMED"
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
            raise EnforcementError(self._validation_code) from None

    def __setattr__(self, name: str, value: Any) -> None:
        invalid = False
        try:
            super().__setattr__(name, value)
        except ValidationError:
            invalid = True
        if invalid:
            raise EnforcementError(self._validation_code) from None

    def __delattr__(self, name: str) -> None:
        invalid = False
        try:
            super().__delattr__(name)
        except (TypeError, ValidationError):
            invalid = True
        if invalid:
            raise EnforcementError(self._validation_code) from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        invalid = False
        result: Any = None
        try:
            result = super().model_validate(obj, **kwargs)
        except ValidationError:
            invalid = True
        if invalid:
            raise EnforcementError(cls._validation_code) from None
        return result


class ManifestOperationV1(_EnforcementModel):
    _validation_code: ClassVar[str] = "PEP-MANIFEST-MALFORMED"
    operation_id: str
    capability: str
    handler_digest: str

    _operation = field_validator("operation_id")(_identifier)
    _handler = field_validator("handler_digest")(_digest)

    @field_validator("capability")
    @classmethod
    def _capability(cls, value: str) -> str:
        if value not in {item.value for item in CapabilityV1}:
            raise ValueError("invalid capability")
        return value


class AdapterManifestV1(_EnforcementModel):
    _validation_code: ClassVar[str] = "PEP-MANIFEST-MALFORMED"
    schema_version: int
    adapter_id: str
    adapter_version: str
    implementation_digest: str
    dependency_digests: tuple[str, ...]
    policy_id: str
    policy_generation: int
    operations: tuple[ManifestOperationV1, ...]

    _adapter = field_validator("adapter_id")(_identifier)
    _implementation = field_validator("implementation_digest")(_digest)
    _policy = field_validator("policy_id")(_digest)

    @field_validator("dependency_digests")
    @classmethod
    def _dependencies(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_ADAPTER_DEPENDENCIES or value != tuple(sorted(set(value))):
            raise ValueError("invalid dependencies")
        for item in value:
            _digest(item)
        return value

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: int) -> int:
        if type(value) is not int or value != 1:
            raise ValueError("unknown schema")
        return value

    @field_validator("adapter_version")
    @classmethod
    def _version(cls, value: str) -> str:
        if type(value) is not str or VERSION_RE.fullmatch(value) is None:
            raise ValueError("invalid version")
        return value

    @field_validator("policy_generation")
    @classmethod
    def _generation(cls, value: int) -> int:
        if type(value) is not int or value < 0:
            raise ValueError("invalid generation")
        return value

    @field_validator("operations")
    @classmethod
    def _operations(cls, value: tuple[ManifestOperationV1, ...]) -> tuple[ManifestOperationV1, ...]:
        if (
            not value
            or len(value) > MAX_MANIFEST_OPERATIONS
            or any(type(item) is not ManifestOperationV1 for item in value)
        ):
            raise ValueError("invalid operations")
        if value != tuple(sorted(value, key=lambda item: item.operation_id)):
            raise ValueError("unsorted operations")
        if len({item.operation_id for item in value}) != len(value):
            raise ValueError("duplicate operations")
        return value


class EvidenceResultV1(_EnforcementModel):
    _validation_code: ClassVar[str] = "PEP-EVIDENCE-MALFORMED"
    schema_version: int
    request_digest: str
    decision_digest: str
    manifest_digest: str
    policy_digest: str
    evidence_digest: str

    _request = field_validator("request_digest")(_digest)
    _decision = field_validator("decision_digest")(_digest)
    _manifest = field_validator("manifest_digest")(_digest)
    _policy = field_validator("policy_digest")(_digest)
    _evidence = field_validator("evidence_digest")(_digest)

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: int) -> int:
        if type(value) is not int or value != 1:
            raise ValueError("unknown schema")
        return value


class EnforcementResultV1(_EnforcementModel):
    _validation_code: ClassVar[str] = "PEP-RESULT-MALFORMED"
    schema_version: int
    invoked: StrictBool
    outcome: str
    code: str
    manifest_digest: str
    decision: DecisionV1 | None
    evidence_digest: str | None
    output: ContentEnvelopeV1 | None
    result_digest: str

    _manifest = field_validator("manifest_digest")(_digest)
    _result = field_validator("result_digest")(_digest)

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: int) -> int:
        if type(value) is not int or value != 1:
            raise ValueError("unknown schema")
        return value

    @field_validator("outcome")
    @classmethod
    def _outcome(cls, value: str) -> str:
        if value not in {item.value for item in EffectOutcomeV1}:
            raise ValueError("invalid outcome")
        return value

    @field_validator("code")
    @classmethod
    def _code(cls, value: str) -> str:
        if value not in {item.value for item in EnforcementCodeV1}:
            raise ValueError("invalid code")
        return value

    @field_validator("evidence_digest")
    @classmethod
    def _optional_evidence(cls, value: str | None) -> str | None:
        return None if value is None else _digest(value)

    @model_validator(mode="after")
    def _nested_exact(self) -> EnforcementResultV1:
        if self.decision is not None and type(self.decision) is not DecisionV1:
            raise ValueError("invalid decision")
        if self.output is not None and type(self.output) is not ContentEnvelopeV1:
            raise ValueError("invalid output")
        return self


@dataclass(frozen=True, slots=True)
class EffectInputV1:
    arguments: bytes
    arguments_digest: str

    def __post_init__(self) -> None:
        if type(self.arguments) is not bytes or len(self.arguments) > MAX_EFFECT_BYTES:
            raise EnforcementError("PEP-EFFECT-MALFORMED") from None
        invalid_digest = False
        try:
            _digest(self.arguments_digest)
        except ValueError:
            invalid_digest = True
        if invalid_digest:
            raise EnforcementError("PEP-EFFECT-MALFORMED") from None


@dataclass(frozen=True, slots=True)
class EnforcementTraceV1:
    """Code-only trace emitted only by the conformance execution path."""

    events: tuple[str, ...]
    output_channels: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class SignedAdapterCandidateV1:
    manifest: AdapterManifestV1
    implementation: bytes
    dependencies: tuple[bytes, ...]
    algorithm: VerificationAlgorithmV1
    signer_identity: str
    signature: bytes

    def __post_init__(self) -> None:
        if (
            type(self.manifest) is not AdapterManifestV1
            or type(self.implementation) is not bytes
            or len(self.implementation) > MAX_HANDLER_IMPLEMENTATION_BYTES
            or type(self.dependencies) is not tuple
            or len(self.dependencies) > MAX_ADAPTER_DEPENDENCIES
            or any(type(item) is not bytes for item in self.dependencies)
            or type(self.algorithm) is not VerificationAlgorithmV1
            or type(self.signature) is not bytes
            or not self.signature
            or len(self.signature) > MAX_SIGNATURE_BYTES
        ):
            raise EnforcementError("PEP-CANDIDATE-MALFORMED") from None
        invalid_signer = False
        try:
            _digest(self.signer_identity)
        except ValueError:
            invalid_signer = True
        if invalid_signer:
            raise EnforcementError("PEP-CANDIDATE-MALFORMED") from None


def _manifest_dict(manifest: AdapterManifestV1) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "adapter_id": manifest.adapter_id,
        "adapter_version": manifest.adapter_version,
        "implementation_digest": manifest.implementation_digest,
        "dependency_digests": list(manifest.dependency_digests),
        "policy_id": manifest.policy_id,
        "policy_generation": manifest.policy_generation,
        "operations": [
            {
                "operation_id": operation.operation_id,
                "capability": operation.capability,
                "handler_digest": operation.handler_digest,
            }
            for operation in manifest.operations
        ],
    }


def _revalidate(value: object, expected: type, code: str) -> None:
    if type(value) is not expected:
        raise EnforcementError(code) from None
    invalid = False
    try:
        expected.model_validate(value)
    except Exception:
        invalid = True
    if invalid:
        raise EnforcementError(code) from None


def canonical_manifest_bytes(manifest: AdapterManifestV1) -> bytes:
    _revalidate(manifest, AdapterManifestV1, "PEP-MANIFEST-MALFORMED")
    invalid = False
    payload: bytes | None = None
    try:
        payload = rfc8785.dumps(_manifest_dict(manifest))
    except Exception:
        invalid = True
    if invalid or payload is None:
        raise EnforcementError("PEP-MANIFEST-MALFORMED") from None
    if len(payload) > MAX_MANIFEST_BYTES:
        raise EnforcementError("PEP-MANIFEST-OVER-CAP") from None
    return payload


def digest_handler_implementation(handler: object) -> str:
    """Digest executable evidence derived from the actual supported callable."""
    try:
        return digest_handler(handler)
    except HandlerIdentityError:
        raise EnforcementError("PEP-HANDLER-MALFORMED") from None


def digest_adapter_implementation(implementation: bytes) -> str:
    if type(implementation) is not bytes or len(implementation) > MAX_HANDLER_IMPLEMENTATION_BYTES:
        raise EnforcementError("PEP-ADAPTER-INTEGRITY") from None
    return digest_decision_bytes(implementation, domain=DecisionDigestDomain.ADAPTER_IMPLEMENTATION)


def digest_adapter_dependency(dependency: bytes) -> str:
    if type(dependency) is not bytes or len(dependency) > MAX_HANDLER_IMPLEMENTATION_BYTES:
        raise EnforcementError("PEP-ADAPTER-INTEGRITY") from None
    return digest_decision_bytes(dependency, domain=DecisionDigestDomain.ADAPTER_DEPENDENCY)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError


def create_effect_input(arguments: bytes) -> EffectInputV1:
    if type(arguments) is not bytes or len(arguments) > MAX_EFFECT_BYTES:
        raise EnforcementError("PEP-EFFECT-MALFORMED") from None
    invalid = False
    canonical: bytes | None = None
    try:
        parsed = json.loads(
            arguments.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        canonical = rfc8785.dumps(parsed)
    except Exception:
        invalid = True
    if invalid or canonical is None:
        raise EnforcementError("PEP-EFFECT-MALFORMED") from None
    if canonical != arguments:
        raise EnforcementError("PEP-EFFECT-NONCANONICAL") from None
    return EffectInputV1(
        arguments=arguments,
        arguments_digest=digest_decision_bytes(
            arguments, domain=DecisionDigestDomain.EFFECT_ARGUMENTS
        ),
    )


class AdapterRegistryV1:
    """One-shot finite registration builder consumed by adapter activation."""

    __slots__ = ("_registrations", "_frozen")

    def __init__(self) -> None:
        self._registrations: dict[str, tuple[Callable[[bytes], object], str]] = {}
        self._frozen = False

    def register(self, *, operation_id: str, handler: Callable[[bytes], object]) -> None:
        if self._frozen:
            raise EnforcementError("PEP-REGISTRY-FROZEN") from None
        invalid_operation = False
        try:
            _identifier(operation_id)
        except ValueError:
            invalid_operation = True
        if invalid_operation:
            raise EnforcementError("PEP-REGISTRATION-MALFORMED") from None
        if operation_id in self._registrations or not callable(handler):
            raise EnforcementError("PEP-REGISTRATION-MALFORMED") from None
        try:
            frozen_handler = freeze_handler(handler)
            handler_digest = digest_handler(frozen_handler)
        except HandlerIdentityError:
            raise EnforcementError("PEP-HANDLER-MALFORMED") from None
        self._registrations[operation_id] = (frozen_handler, handler_digest)

    def _snapshot(self) -> dict[str, tuple[Callable[[bytes], object], str]]:
        if self._frozen:
            raise EnforcementError("PEP-REGISTRY-FROZEN") from None
        return dict(self._registrations)

    def _freeze(self) -> None:
        self._frozen = True


_ADAPTER_SEAL = object()


class ActivatedAdapterV1:
    __slots__ = (
        "manifest",
        "manifest_digest",
        "policy_digest",
        "_handlers",
        "_seal",
        "_locked",
    )

    def __init__(
        self,
        *,
        manifest: AdapterManifestV1,
        manifest_digest: str,
        policy_digest: str,
        handlers: dict[str, tuple[Callable[[bytes], object], str]],
        _seal: object,
    ) -> None:
        if _seal is not _ADAPTER_SEAL:
            raise EnforcementError("PEP-ADAPTER-UNAVAILABLE") from None
        object.__setattr__(self, "manifest", manifest)
        object.__setattr__(self, "manifest_digest", manifest_digest)
        object.__setattr__(self, "policy_digest", policy_digest)
        object.__setattr__(self, "_handlers", MappingProxyType(dict(handlers)))
        object.__setattr__(self, "_seal", _seal)
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        raise EnforcementError("PEP-ADAPTER-IMMUTABLE") from None

    def __delattr__(self, name: str) -> None:
        raise EnforcementError("PEP-ADAPTER-IMMUTABLE") from None

    def _handler(self, operation_id: str) -> Callable[[bytes], object]:
        missing = False
        registration: tuple[Callable[[bytes], object], str] | None = None
        try:
            registration = self._handlers[operation_id]
        except KeyError:
            missing = True
        if missing or registration is None:
            raise EnforcementError("PEP-OPERATION-UNKNOWN") from None
        handler, expected_digest = registration
        try:
            current_digest = digest_handler(handler)
        except HandlerIdentityError:
            raise EnforcementError("PEP-ADAPTER-MISMATCH") from None
        if current_digest != expected_digest:
            raise EnforcementError("PEP-ADAPTER-MISMATCH") from None
        return handler

    @property
    def registration_operations(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))


def activate_adapter(
    candidate: SignedAdapterCandidateV1,
    *,
    registry: AdapterRegistryV1,
    verifier: ArtifactVerifierV1,
    policy: ActivatedPolicyV1,
) -> ActivatedAdapterV1:
    if (
        type(candidate) is not SignedAdapterCandidateV1
        or type(registry) is not AdapterRegistryV1
        or type(policy) is not ActivatedPolicyV1
    ):
        raise EnforcementError("PEP-CANDIDATE-MALFORMED") from None
    manifest = candidate.manifest
    payload = canonical_manifest_bytes(manifest)
    dependency_digests = tuple(
        sorted(digest_adapter_dependency(item) for item in candidate.dependencies)
    )
    if (
        len(set(dependency_digests)) != len(candidate.dependencies)
        or manifest.implementation_digest != digest_adapter_implementation(candidate.implementation)
        or manifest.dependency_digests != dependency_digests
    ):
        raise EnforcementError("PEP-ADAPTER-INTEGRITY") from None
    if (
        manifest.policy_id != policy.policy.policy_id
        or manifest.policy_generation != policy.policy.policy_generation
    ):
        raise EnforcementError("PEP-POLICY-BINDING") from None
    registrations = registry._snapshot()
    expected = {item.operation_id: item for item in manifest.operations}
    if set(registrations) != set(expected) or any(
        registrations[name][1] != expected[name].handler_digest for name in expected
    ):
        raise EnforcementError("PEP-MANIFEST-REGISTRY-MISMATCH") from None
    verification_failed = False
    verified: object = False
    try:
        verified = verifier.verify(
            artifact_kind=ArtifactKindV1.ADAPTER,
            algorithm=candidate.algorithm,
            signer_identity=candidate.signer_identity,
            payload=payload,
            signature=candidate.signature,
        )
    except Exception:
        verification_failed = True
    if verification_failed or verified is not True:
        raise EnforcementError("PEP-ADAPTER-VERIFICATION") from None
    registry._freeze()
    return ActivatedAdapterV1(
        manifest=manifest,
        manifest_digest=digest_decision_bytes(
            payload, domain=DecisionDigestDomain.ADAPTER_MANIFEST
        ),
        policy_digest=policy.policy_digest,
        handlers=registrations,
        _seal=_ADAPTER_SEAL,
    )


def _evidence_body(result: EvidenceResultV1) -> dict[str, object]:
    return {
        "schema_version": result.schema_version,
        "request_digest": result.request_digest,
        "decision_digest": result.decision_digest,
        "manifest_digest": result.manifest_digest,
        "policy_digest": result.policy_digest,
    }


def create_evidence_result(*, decision: DecisionV1, manifest_digest: str) -> EvidenceResultV1:
    if type(decision) is not DecisionV1:
        raise EnforcementError("PEP-EVIDENCE-MALFORMED") from None
    provisional = EvidenceResultV1(
        schema_version=1,
        request_digest=decision.request_digest,
        decision_digest=decision.decision_digest,
        manifest_digest=manifest_digest,
        policy_digest=decision.policy_digest,
        evidence_digest=digest_decision_bytes(
            b"provisional", domain=DecisionDigestDomain.EFFECT_EVIDENCE
        ),
    )
    payload = rfc8785.dumps(_evidence_body(provisional))
    return provisional.model_copy(
        update={
            "evidence_digest": digest_decision_bytes(
                payload, domain=DecisionDigestDomain.EFFECT_EVIDENCE
            )
        }
    )


class EvidenceGateV1(Protocol):
    def record(self, *, decision: DecisionV1, manifest_digest: str) -> EvidenceResultV1: ...


class FailClosedEvidenceGateV1:
    __slots__ = ()

    def record(self, *, decision: DecisionV1, manifest_digest: str) -> EvidenceResultV1:
        raise EnforcementError("PEP-EVIDENCE-UNAVAILABLE") from None


def _result_body(result: EnforcementResultV1) -> dict[str, object]:
    decision = None if result.decision is None else result.decision.model_dump(mode="python")
    output = None if result.output is None else to_public_dict(result.output)
    return {
        "schema_version": result.schema_version,
        "invoked": result.invoked,
        "outcome": result.outcome,
        "code": result.code,
        "manifest_digest": result.manifest_digest,
        "decision": decision,
        "evidence_digest": result.evidence_digest,
        "output": output,
    }


def _make_result(
    *,
    invoked: bool,
    outcome: EffectOutcomeV1,
    code: EnforcementCodeV1,
    manifest_digest: str,
    decision: DecisionV1 | None = None,
    evidence_digest: str | None = None,
    output: ContentEnvelopeV1 | None = None,
) -> EnforcementResultV1:
    provisional = EnforcementResultV1(
        schema_version=1,
        invoked=invoked,
        outcome=outcome.value,
        code=code.value,
        manifest_digest=manifest_digest,
        decision=decision,
        evidence_digest=evidence_digest,
        output=output,
        result_digest=digest_decision_bytes(
            b"provisional", domain=DecisionDigestDomain.EFFECT_EVIDENCE
        ),
    )
    payload = rfc8785.dumps(_result_body(provisional))
    return provisional.model_copy(
        update={
            "result_digest": digest_decision_bytes(
                payload, domain=DecisionDigestDomain.EFFECT_EVIDENCE
            )
        }
    )


def serialize_enforcement_result(result: EnforcementResultV1) -> bytes:
    _revalidate(result, EnforcementResultV1, "PEP-RESULT-MALFORMED")
    expected = digest_decision_bytes(
        rfc8785.dumps(_result_body(result)), domain=DecisionDigestDomain.EFFECT_EVIDENCE
    )
    if result.result_digest != expected:
        raise EnforcementError("PEP-RESULT-INTEGRITY") from None
    payload = rfc8785.dumps(_result_body(result) | {"result_digest": result.result_digest})
    if len(payload) > MAX_ENFORCEMENT_RESULT_BYTES:
        raise EnforcementError("PEP-RESULT-OVER-CAP") from None
    return payload


class PolicyEnforcementPointV1:
    """Only supported operation-to-sink route for an activated adapter."""

    __slots__ = ("_pdp", "_adapter", "_bundles", "_evidence_gate", "_locked")

    def __init__(
        self,
        pdp: PolicyDecisionPointV1,
        adapter: ActivatedAdapterV1,
        *,
        evidence_gate: EvidenceGateV1 | None = None,
        executable_bundles: tuple[ActivatedExecutableBundleV1, ...] = (),
    ) -> None:
        marker_valid = False
        if type(adapter) is ActivatedAdapterV1:
            try:
                marker_valid = object.__getattribute__(adapter, "_seal") is _ADAPTER_SEAL
            except (AttributeError, TypeError):
                marker_valid = False
        if type(pdp) is not PolicyDecisionPointV1 or not marker_valid:
            raise EnforcementError("PEP-UNAVAILABLE") from None
        if pdp.policy_digest != adapter.policy_digest:
            raise EnforcementError("PEP-POLICY-BINDING") from None
        if (
            type(executable_bundles) is not tuple
            or any(not is_activated_bundle(item) for item in executable_bundles)
            or len({item.manifest_digest for item in executable_bundles}) != len(executable_bundles)
            or any(
                item.policy_digest != pdp.policy_digest
                or item.manifest.adapter_manifest_digest != adapter.manifest_digest
                for item in executable_bundles
            )
        ):
            raise EnforcementError("PEP-BUNDLE-UNAVAILABLE") from None
        object.__setattr__(self, "_pdp", pdp)
        object.__setattr__(self, "_adapter", adapter)
        object.__setattr__(
            self,
            "_bundles",
            MappingProxyType({item.manifest_digest: item for item in executable_bundles}),
        )
        object.__setattr__(
            self,
            "_evidence_gate",
            FailClosedEvidenceGateV1() if evidence_gate is None else evidence_gate,
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        raise EnforcementError("PEP-IMMUTABLE") from None

    def __delattr__(self, name: str) -> None:
        raise EnforcementError("PEP-IMMUTABLE") from None

    @property
    def manifest(self) -> AdapterManifestV1:
        return self._adapter.manifest

    @property
    def manifest_digest(self) -> str:
        return self._adapter.manifest_digest

    @property
    def registration_operations(self) -> tuple[str, ...]:
        return self._adapter.registration_operations

    def execute(
        self,
        request: object,
        *,
        runtime: ActivatedRuntimeV1,
        effect: object,
    ) -> EnforcementResultV1:
        return self._execute(request, runtime=runtime, effect=effect, trace=None)

    def _execute_instrumented(
        self,
        request: object,
        *,
        runtime: ActivatedRuntimeV1,
        effect: object,
    ) -> tuple[EnforcementResultV1, EnforcementTraceV1]:
        events: list[str] = []
        result = self._execute(request, runtime=runtime, effect=effect, trace=events)
        events.append("result:" + result.code)
        event_channel = rfc8785.dumps(events)
        return result, EnforcementTraceV1(
            events=tuple(events),
            output_channels=(serialize_enforcement_result(result), event_channel),
        )

    def _execute(
        self,
        request: object,
        *,
        runtime: ActivatedRuntimeV1,
        effect: object,
        trace: list[str] | None,
    ) -> EnforcementResultV1:
        manifest_digest = self._adapter.manifest_digest
        if type(effect) is not EffectInputV1:
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.EFFECT_MALFORMED,
                manifest_digest=manifest_digest,
            )
        try:
            canonical_effect = create_effect_input(effect.arguments)
        except Exception:
            canonical_effect = None
        if canonical_effect is None or canonical_effect.arguments_digest != effect.arguments_digest:
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.EFFECT_MALFORMED,
                manifest_digest=manifest_digest,
            )
        if trace is not None:
            trace.append("effect")
        request_valid = True
        try:
            if type(request) is not DecisionRequestV1:
                raise ValueError
            DecisionRequestV1.model_validate(request)
        except Exception:
            request_valid = False
        if not request_valid:
            decision = self._pdp.evaluate(request, runtime=runtime)
            if trace is not None:
                trace.append("decision")
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.DECISION_BLOCKED,
                manifest_digest=manifest_digest,
                decision=decision,
            )
        if trace is not None:
            trace.append("request")
        request_operation = request.operation
        request_arguments_digest = request_operation.arguments_digest
        if effect.arguments_digest != request_arguments_digest:
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.EFFECT_DIGEST_MISMATCH,
                manifest_digest=manifest_digest,
            )
        manifest = self._adapter.manifest
        if (
            request_operation.adapter_id != manifest.adapter_id
            or request_operation.adapter_manifest_digest != manifest_digest
        ):
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.ADAPTER_MISMATCH,
                manifest_digest=manifest_digest,
            )
        if trace is not None:
            trace.append("adapter")
        if request_operation.capability == CapabilityV1.EXECUTE.value:
            bundle_digest = request_operation.bundle_manifest_digest
            bundle = self._bundles.get(bundle_digest)
            if bundle is None:
                return _make_result(
                    invoked=False,
                    outcome=EffectOutcomeV1.BLOCKED,
                    code=EnforcementCodeV1.BUNDLE_UNAVAILABLE,
                    manifest_digest=manifest_digest,
                )
            if request.envelope.bundle != bundle.evidence:
                return _make_result(
                    invoked=False,
                    outcome=EffectOutcomeV1.BLOCKED,
                    code=EnforcementCodeV1.BUNDLE_MISMATCH,
                    manifest_digest=manifest_digest,
                )
            if trace is not None:
                trace.append("bundle")
        operations = {item.operation_id: item for item in manifest.operations}
        manifest_operation = operations.get(request_operation.operation_id)
        if (
            manifest_operation is None
            or manifest_operation.capability != request_operation.capability
        ):
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.OPERATION_UNKNOWN,
                manifest_digest=manifest_digest,
            )
        decision = self._pdp.evaluate(request, runtime=runtime)
        if trace is not None:
            trace.append("decision")
        if decision.verdict != DecisionVerdictV1.ALLOW.value:
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.DECISION_BLOCKED,
                manifest_digest=manifest_digest,
                decision=decision,
            )
        try:
            evidence = self._evidence_gate.record(
                decision=decision, manifest_digest=manifest_digest
            )
        except Exception:
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.EVIDENCE_UNAVAILABLE,
                manifest_digest=manifest_digest,
                decision=decision,
            )
        if type(evidence) is not EvidenceResultV1:
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.EVIDENCE_MISMATCH,
                manifest_digest=manifest_digest,
                decision=decision,
            )
        evidence_valid = True
        try:
            _revalidate(evidence, EvidenceResultV1, "PEP-EVIDENCE-MALFORMED")
            evidence_payload = rfc8785.dumps(_evidence_body(evidence))
            evidence_digest = digest_decision_bytes(
                evidence_payload, domain=DecisionDigestDomain.EFFECT_EVIDENCE
            )
        except Exception:
            evidence_valid = False
            evidence_digest = ""
        if not evidence_valid or (
            evidence.request_digest != request.request_digest
            or evidence.decision_digest != decision.decision_digest
            or evidence.manifest_digest != manifest_digest
            or evidence.policy_digest != decision.policy_digest
            or evidence.evidence_digest != evidence_digest
        ):
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.EVIDENCE_MISMATCH,
                manifest_digest=manifest_digest,
                decision=decision,
            )
        if trace is not None:
            trace.append("evidence")
        try:
            handler = self._adapter._handler(request_operation.operation_id)
        except Exception:
            return _make_result(
                invoked=False,
                outcome=EffectOutcomeV1.BLOCKED,
                code=EnforcementCodeV1.ADAPTER_MISMATCH,
                manifest_digest=manifest_digest,
                decision=decision,
                evidence_digest=evidence.evidence_digest,
            )
        try:
            if trace is not None:
                trace.append("sink")
            output = handler(effect.arguments)
        except Exception:
            return _make_result(
                invoked=True,
                outcome=EffectOutcomeV1.INDETERMINATE,
                code=EnforcementCodeV1.SINK_FAILED,
                manifest_digest=manifest_digest,
                decision=decision,
                evidence_digest=evidence.evidence_digest,
            )
        if trace is not None:
            trace.append("output")
        if output is not None and type(output) is not ContentEnvelopeV1:
            return _make_result(
                invoked=True,
                outcome=EffectOutcomeV1.INDETERMINATE,
                code=EnforcementCodeV1.OUTPUT_INVALID,
                manifest_digest=manifest_digest,
                decision=decision,
                evidence_digest=evidence.evidence_digest,
            )
        if output is not None:
            try:
                to_public_bytes(output)
            except Exception:
                return _make_result(
                    invoked=True,
                    outcome=EffectOutcomeV1.INDETERMINATE,
                    code=EnforcementCodeV1.OUTPUT_INVALID,
                    manifest_digest=manifest_digest,
                    decision=decision,
                    evidence_digest=evidence.evidence_digest,
                )
        return _make_result(
            invoked=True,
            outcome=EffectOutcomeV1.COMPLETED,
            code=EnforcementCodeV1.EXECUTED,
            manifest_digest=manifest_digest,
            decision=decision,
            evidence_digest=evidence.evidence_digest,
            output=output,
        )
