"""Deterministic fail-closed V1 policy decision point."""

from __future__ import annotations

from typing import Protocol

import rfc8785

from mcp_warden.content_envelope import to_public_bytes, to_public_dict
from mcp_warden.content_models import ContentEnvelopeV1, TaintV1
from mcp_warden.decision_models import (
    DIGEST_RE,
    MAX_DECISION_BYTES,
    MAX_POLICY_BYTES,
    MAX_RUNTIME_BYTES,
    ArtifactKindV1,
    AuthorityHealthV1,
    CapabilityLeaseV1,
    CapabilityV1,
    DecisionDigestDomain,
    DecisionError,
    DecisionReasonV1,
    DecisionRecoveryV1,
    DecisionRequestV1,
    DecisionV1,
    DecisionVerdictV1,
    IdentityBindingV1,
    OperationBindingV1,
    PolicyBundleV1,
    RuntimeSnapshotV1,
    SignedPolicyCandidateV1,
    SignedRuntimeCandidateV1,
    VerificationAlgorithmV1,
    digest_decision_bytes,
)


class ArtifactVerifierV1(Protocol):
    def verify(
        self,
        *,
        artifact_kind: ArtifactKindV1,
        algorithm: VerificationAlgorithmV1,
        signer_identity: str,
        payload: bytes,
        signature: bytes,
    ) -> bool: ...


_ACTIVATION_SEAL = object()
_INVALID_REQUEST_DIGEST = digest_decision_bytes(
    b"invalid", domain=DecisionDigestDomain.INVALID_INPUT
)
_INVALID_RUNTIME_DIGEST = digest_decision_bytes(
    b"invalid-runtime", domain=DecisionDigestDomain.INVALID_INPUT
)


def _identity_dict(identity: IdentityBindingV1) -> dict[str, str]:
    return {
        "user_digest": identity.user_digest,
        "agent_digest": identity.agent_digest,
        "device_digest": identity.device_digest,
        "session_digest": identity.session_digest,
    }


def _operation_dict(operation: OperationBindingV1) -> dict[str, str]:
    return {
        "adapter_id": operation.adapter_id,
        "adapter_manifest_digest": operation.adapter_manifest_digest,
        "operation_id": operation.operation_id,
        "capability": operation.capability,
        "arguments_digest": operation.arguments_digest,
        "destination_digest": operation.destination_digest,
        "bundle_manifest_digest": operation.bundle_manifest_digest,
    }


def _lease_body(lease: CapabilityLeaseV1) -> dict[str, object]:
    return {
        "schema_version": lease.schema_version,
        "lease_id": lease.lease_id,
        "request_binding_digest": lease.request_binding_digest,
        "policy_id": lease.policy_id,
        "policy_generation": lease.policy_generation,
        "not_before": lease.not_before,
        "expires_at": lease.expires_at,
        "revocation_generation": lease.revocation_generation,
    }


def _lease_dict(lease: CapabilityLeaseV1) -> dict[str, object]:
    body = _lease_body(lease)
    body["lease_digest"] = lease.lease_digest
    return body


def _policy_dict(policy: PolicyBundleV1) -> dict[str, object]:
    return {
        "schema_version": policy.schema_version,
        "policy_id": policy.policy_id,
        "policy_generation": policy.policy_generation,
        "valid_from": policy.valid_from,
        "valid_until": policy.valid_until,
        "rule_set_digest": policy.rule_set_digest,
        "trust_root_digest": policy.trust_root_digest,
        "critical_floor_version": policy.critical_floor_version,
        "revocation_generation": policy.revocation_generation,
        "grants": [{"lease_digest": grant.lease_digest} for grant in policy.grants],
        "revoked_lease_digests": list(policy.revoked_lease_digests),
    }


def _runtime_dict(runtime: RuntimeSnapshotV1) -> dict[str, object]:
    return {
        "schema_version": runtime.schema_version,
        "health": runtime.health,
        "trusted_time": runtime.trusted_time,
        "trusted_time_valid_until": runtime.trusted_time_valid_until,
        "policy_generation_floor": runtime.policy_generation_floor,
        "policy_digest_at_floor": runtime.policy_digest_at_floor,
        "revocation_generation_floor": runtime.revocation_generation_floor,
        "revocation_digest_at_floor": runtime.revocation_digest_at_floor,
    }


def _revalidate(value: object, expected: type, code: str) -> None:
    if type(value) is not expected:
        raise DecisionError(code) from None
    invalid = False
    try:
        expected.model_validate(value)
    except Exception:
        invalid = True
    if invalid:
        raise DecisionError(code) from None


def canonical_policy_bytes(policy: PolicyBundleV1) -> bytes:
    _revalidate(policy, PolicyBundleV1, "PDP-POLICY-MALFORMED")
    invalid = False
    encoded: bytes | None = None
    try:
        encoded = rfc8785.dumps(_policy_dict(policy))
    except Exception:
        invalid = True
    if invalid or encoded is None:
        raise DecisionError("PDP-POLICY-MALFORMED") from None
    if len(encoded) > MAX_POLICY_BYTES:
        raise DecisionError("PDP-POLICY-OVER-CAP") from None
    return encoded


def canonical_runtime_bytes(runtime: RuntimeSnapshotV1) -> bytes:
    _revalidate(runtime, RuntimeSnapshotV1, "PDP-RUNTIME-MALFORMED")
    invalid = False
    encoded: bytes | None = None
    try:
        encoded = rfc8785.dumps(_runtime_dict(runtime))
    except Exception:
        invalid = True
    if invalid or encoded is None:
        raise DecisionError("PDP-RUNTIME-MALFORMED") from None
    if len(encoded) > MAX_RUNTIME_BYTES:
        raise DecisionError("PDP-RUNTIME-OVER-CAP") from None
    return encoded


class ActivatedPolicyV1:
    __slots__ = ("policy", "policy_digest", "revocation_digest", "_seal", "_locked")

    def __init__(
        self,
        policy: PolicyBundleV1,
        policy_digest: str,
        revocation_digest: str,
        *,
        _seal: object,
    ) -> None:
        if _seal is not _ACTIVATION_SEAL:
            raise DecisionError("PDP-AUTHORITY-UNAVAILABLE") from None
        object.__setattr__(self, "policy", policy)
        object.__setattr__(self, "policy_digest", policy_digest)
        object.__setattr__(self, "revocation_digest", revocation_digest)
        object.__setattr__(self, "_seal", _seal)
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        raise DecisionError("PDP-AUTHORITY-IMMUTABLE") from None

    def __delattr__(self, name: str) -> None:
        raise DecisionError("PDP-AUTHORITY-IMMUTABLE") from None


class ActivatedRuntimeV1:
    __slots__ = ("runtime", "runtime_digest", "_seal", "_locked")

    def __init__(self, runtime: RuntimeSnapshotV1, runtime_digest: str, *, _seal: object) -> None:
        if _seal is not _ACTIVATION_SEAL:
            raise DecisionError("PDP-AUTHORITY-UNAVAILABLE") from None
        object.__setattr__(self, "runtime", runtime)
        object.__setattr__(self, "runtime_digest", runtime_digest)
        object.__setattr__(self, "_seal", _seal)
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        raise DecisionError("PDP-AUTHORITY-IMMUTABLE") from None

    def __delattr__(self, name: str) -> None:
        raise DecisionError("PDP-AUTHORITY-IMMUTABLE") from None


def _verify_candidate(
    *,
    verifier: ArtifactVerifierV1,
    artifact_kind: ArtifactKindV1,
    algorithm: VerificationAlgorithmV1,
    signer_identity: str,
    payload: bytes,
    signature: bytes,
    failure_code: str,
) -> None:
    failed = False
    result: object = False
    try:
        verify = verifier.verify
        result = verify(
            artifact_kind=artifact_kind,
            algorithm=algorithm,
            signer_identity=signer_identity,
            payload=payload,
            signature=signature,
        )
    except Exception:
        failed = True
    if failed or result is not True:
        raise DecisionError(failure_code) from None


def activate_policy(
    candidate: SignedPolicyCandidateV1, *, verifier: ArtifactVerifierV1
) -> ActivatedPolicyV1:
    if type(candidate) is not SignedPolicyCandidateV1:
        raise DecisionError("PDP-CANDIDATE-MALFORMED") from None
    payload = canonical_policy_bytes(candidate.policy)
    _verify_candidate(
        verifier=verifier,
        artifact_kind=ArtifactKindV1.POLICY,
        algorithm=candidate.algorithm,
        signer_identity=candidate.signer_identity,
        payload=payload,
        signature=candidate.signature,
        failure_code="PDP-POLICY-VERIFICATION",
    )
    policy_digest = digest_decision_bytes(payload, domain=DecisionDigestDomain.POLICY)
    revocation_payload = rfc8785.dumps(
        {
            "generation": candidate.policy.revocation_generation,
            "revoked_lease_digests": list(candidate.policy.revoked_lease_digests),
        }
    )
    revocation_digest = digest_decision_bytes(
        revocation_payload, domain=DecisionDigestDomain.REVOCATION
    )
    return ActivatedPolicyV1(
        candidate.policy,
        policy_digest,
        revocation_digest,
        _seal=_ACTIVATION_SEAL,
    )


def activate_runtime(
    candidate: SignedRuntimeCandidateV1, *, verifier: ArtifactVerifierV1
) -> ActivatedRuntimeV1:
    if type(candidate) is not SignedRuntimeCandidateV1:
        raise DecisionError("PDP-CANDIDATE-MALFORMED") from None
    payload = canonical_runtime_bytes(candidate.runtime)
    _verify_candidate(
        verifier=verifier,
        artifact_kind=ArtifactKindV1.RUNTIME,
        algorithm=candidate.algorithm,
        signer_identity=candidate.signer_identity,
        payload=payload,
        signature=candidate.signature,
        failure_code="PDP-RUNTIME-VERIFICATION",
    )
    return ActivatedRuntimeV1(
        candidate.runtime,
        digest_decision_bytes(payload, domain=DecisionDigestDomain.RUNTIME),
        _seal=_ACTIVATION_SEAL,
    )


def compute_request_binding_digest(
    *,
    identity: IdentityBindingV1,
    envelope: ContentEnvelopeV1,
    data_scope_digest: str,
    operation: OperationBindingV1,
    purpose_digest: str,
) -> str:
    _revalidate(identity, IdentityBindingV1, "PDP-INPUT-MALFORMED")
    _revalidate(operation, OperationBindingV1, "PDP-INPUT-MALFORMED")
    if type(envelope) is not ContentEnvelopeV1:
        raise DecisionError("PDP-INPUT-MALFORMED") from None
    invalid = False
    payload: bytes | None = None
    try:
        envelope_dict = to_public_dict(envelope)
        body = {
            "identity": _identity_dict(identity),
            "envelope": envelope_dict,
            "data_scope_digest": data_scope_digest,
            "operation": _operation_dict(operation),
            "purpose_digest": purpose_digest,
        }
        payload = rfc8785.dumps(body)
    except Exception:
        invalid = True
    if invalid or payload is None:
        raise DecisionError("PDP-INPUT-MALFORMED") from None
    return digest_decision_bytes(payload, domain=DecisionDigestDomain.REQUEST_BINDING)


def create_capability_lease(
    *,
    lease_id: str,
    request_binding_digest: str,
    policy_id: str,
    policy_generation: int,
    not_before: int,
    expires_at: int,
    revocation_generation: int,
) -> CapabilityLeaseV1:
    provisional = CapabilityLeaseV1(
        schema_version=1,
        lease_id=lease_id,
        request_binding_digest=request_binding_digest,
        policy_id=policy_id,
        policy_generation=policy_generation,
        not_before=not_before,
        expires_at=expires_at,
        revocation_generation=revocation_generation,
        lease_digest=digest_decision_bytes(b"provisional", domain=DecisionDigestDomain.LEASE),
    )
    payload = rfc8785.dumps(_lease_body(provisional))
    return provisional.model_copy(
        update={"lease_digest": digest_decision_bytes(payload, domain=DecisionDigestDomain.LEASE)}
    )


def _request_body(request: DecisionRequestV1) -> dict[str, object]:
    return {
        "schema_version": request.schema_version,
        "identity": _identity_dict(request.identity),
        "envelope": to_public_dict(request.envelope),
        "data_scope_digest": request.data_scope_digest,
        "operation": _operation_dict(request.operation),
        "purpose_digest": request.purpose_digest,
        "lease": _lease_dict(request.lease),
    }


def create_decision_request(
    *,
    identity: IdentityBindingV1,
    envelope: ContentEnvelopeV1,
    data_scope_digest: str,
    operation: OperationBindingV1,
    purpose_digest: str,
    lease: CapabilityLeaseV1,
) -> DecisionRequestV1:
    binding = compute_request_binding_digest(
        identity=identity,
        envelope=envelope,
        data_scope_digest=data_scope_digest,
        operation=operation,
        purpose_digest=purpose_digest,
    )
    if type(lease) is not CapabilityLeaseV1 or binding != lease.request_binding_digest:
        raise DecisionError("PDP-LEASE-BINDING") from None
    provisional = DecisionRequestV1(
        schema_version=1,
        identity=identity,
        envelope=envelope,
        data_scope_digest=data_scope_digest,
        operation=operation,
        purpose_digest=purpose_digest,
        lease=lease,
        request_digest=_INVALID_REQUEST_DIGEST,
    )
    payload = rfc8785.dumps(_request_body(provisional))
    return provisional.model_copy(
        update={
            "request_digest": digest_decision_bytes(payload, domain=DecisionDigestDomain.REQUEST)
        }
    )


def _decision_body(decision: DecisionV1) -> dict[str, object]:
    return {
        "schema_version": decision.schema_version,
        "request_digest": decision.request_digest,
        "policy_digest": decision.policy_digest,
        "runtime_digest": decision.runtime_digest,
        "policy_generation": decision.policy_generation,
        "revocation_generation": decision.revocation_generation,
        "verdict": decision.verdict,
        "reason": decision.reason,
        "recovery": decision.recovery,
    }


def _make_decision(
    *,
    request_digest: str,
    active_policy: ActivatedPolicyV1,
    runtime_digest: str,
    verdict: DecisionVerdictV1,
    reason: DecisionReasonV1,
    recovery: DecisionRecoveryV1,
) -> DecisionV1:
    provisional = DecisionV1(
        schema_version=1,
        request_digest=request_digest,
        policy_digest=active_policy.policy_digest,
        runtime_digest=runtime_digest,
        policy_generation=active_policy.policy.policy_generation,
        revocation_generation=active_policy.policy.revocation_generation,
        verdict=verdict.value,
        reason=reason.value,
        recovery=recovery.value,
        decision_digest=digest_decision_bytes(b"provisional", domain=DecisionDigestDomain.DECISION),
    )
    payload = rfc8785.dumps(_decision_body(provisional))
    return provisional.model_copy(
        update={
            "decision_digest": digest_decision_bytes(payload, domain=DecisionDigestDomain.DECISION)
        }
    )


def serialize_decision(decision: DecisionV1) -> bytes:
    _revalidate(decision, DecisionV1, "PDP-DECISION-MALFORMED")
    expected = digest_decision_bytes(
        rfc8785.dumps(_decision_body(decision)), domain=DecisionDigestDomain.DECISION
    )
    if decision.decision_digest != expected:
        raise DecisionError("PDP-DECISION-INTEGRITY") from None
    payload = rfc8785.dumps(
        _decision_body(decision) | {"decision_digest": decision.decision_digest}
    )
    if len(payload) > MAX_DECISION_BYTES:
        raise DecisionError("PDP-DECISION-OVER-CAP") from None
    return payload


def _has_activation_marker(value: object, expected: type) -> bool:
    if type(value) is not expected:
        return False
    try:
        return object.__getattribute__(value, "_seal") is _ACTIVATION_SEAL
    except (AttributeError, TypeError):
        return False


def _request_preflight(request: DecisionRequestV1) -> bool:
    try:
        storage = object.__getattribute__(request, "__dict__")
    except (AttributeError, TypeError):
        return False
    required = frozenset(DecisionRequestV1.model_fields)
    return (
        type(storage) is dict
        and required.issubset(storage)
        and type(storage["identity"]) is IdentityBindingV1
        and type(storage["envelope"]) is ContentEnvelopeV1
        and type(storage["operation"]) is OperationBindingV1
        and type(storage["lease"]) is CapabilityLeaseV1
        and type(storage["request_digest"]) is str
        and DIGEST_RE.fullmatch(storage["request_digest"]) is not None
    )


def _safe_request_digest(request: object) -> str:
    if type(request) is not DecisionRequestV1:
        return _INVALID_REQUEST_DIGEST
    try:
        value = object.__getattribute__(request, "request_digest")
    except (AttributeError, TypeError):
        return _INVALID_REQUEST_DIGEST
    if type(value) is str and DIGEST_RE.fullmatch(value) is not None:
        return value
    return _INVALID_REQUEST_DIGEST


class PolicyDecisionPointV1:
    """Pure deterministic PDP over activated policy and explicit runtime state."""

    __slots__ = ("_policy", "_locked")

    def __init__(self, policy: ActivatedPolicyV1) -> None:
        if not _has_activation_marker(policy, ActivatedPolicyV1):
            raise DecisionError("PDP-AUTHORITY-UNAVAILABLE") from None
        object.__setattr__(self, "_policy", policy)
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        raise DecisionError("PDP-AUTHORITY-IMMUTABLE") from None

    def __delattr__(self, name: str) -> None:
        raise DecisionError("PDP-AUTHORITY-IMMUTABLE") from None

    @property
    def policy_digest(self) -> str:
        return self._policy.policy_digest

    @property
    def policy_id(self) -> str:
        return self._policy.policy.policy_id

    @property
    def policy_generation(self) -> int:
        return self._policy.policy.policy_generation

    def _result(
        self,
        request_digest: str,
        runtime_digest: str,
        verdict: DecisionVerdictV1,
        reason: DecisionReasonV1,
        recovery: DecisionRecoveryV1,
    ) -> DecisionV1:
        return _make_decision(
            request_digest=request_digest,
            active_policy=self._policy,
            runtime_digest=runtime_digest,
            verdict=verdict,
            reason=reason,
            recovery=recovery,
        )

    def evaluate(self, request: object, *, runtime: object) -> DecisionV1:
        runtime_digest = _INVALID_RUNTIME_DIGEST
        try:
            if type(request) is not DecisionRequestV1:
                return self._result(
                    _INVALID_REQUEST_DIGEST,
                    runtime_digest,
                    DecisionVerdictV1.DENY,
                    DecisionReasonV1.INPUT_MALFORMED,
                    DecisionRecoveryV1.REAUTHENTICATE,
                )
            if not _request_preflight(request):
                return self._result(
                    _INVALID_REQUEST_DIGEST,
                    runtime_digest,
                    DecisionVerdictV1.DENY,
                    DecisionReasonV1.INPUT_MALFORMED,
                    DecisionRecoveryV1.REAUTHENTICATE,
                )
            if not _has_activation_marker(runtime, ActivatedRuntimeV1):
                return self._result(
                    _safe_request_digest(request),
                    runtime_digest,
                    DecisionVerdictV1.DENY,
                    DecisionReasonV1.AUTHORITY_UNAVAILABLE,
                    DecisionRecoveryV1.REFRESH_AUTHORITY,
                )
            runtime_digest = runtime.runtime_digest
            return self._evaluate_validated(request, runtime)
        except Exception:
            return self._result(
                _safe_request_digest(request),
                runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.INTERNAL_ERROR,
                DecisionRecoveryV1.RECOVERY_ONLY,
            )

    def _evaluate_validated(
        self, request: DecisionRequestV1, runtime: ActivatedRuntimeV1
    ) -> DecisionV1:
        policy = self._policy.policy
        runtime_model = runtime.runtime
        _revalidate(policy, PolicyBundleV1, "PDP-POLICY-MALFORMED")
        _revalidate(runtime_model, RuntimeSnapshotV1, "PDP-RUNTIME-MALFORMED")
        if (
            digest_decision_bytes(
                canonical_policy_bytes(policy), domain=DecisionDigestDomain.POLICY
            )
            != self._policy.policy_digest
        ):
            raise DecisionError("PDP-POLICY-INTEGRITY") from None
        if (
            digest_decision_bytes(
                canonical_runtime_bytes(runtime_model), domain=DecisionDigestDomain.RUNTIME
            )
            != runtime.runtime_digest
        ):
            raise DecisionError("PDP-RUNTIME-INTEGRITY") from None

        envelope_invalid = False
        try:
            to_public_bytes(request.envelope)
        except Exception:
            envelope_invalid = True
        if envelope_invalid:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.QUARANTINE,
                DecisionReasonV1.ENVELOPE_INVALID,
                DecisionRecoveryV1.QUARANTINE_INPUT,
            )

        try:
            _revalidate(request, DecisionRequestV1, "PDP-INPUT-MALFORMED")
            request_payload = rfc8785.dumps(_request_body(request))
        except Exception:
            return self._result(
                _INVALID_REQUEST_DIGEST,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.INPUT_MALFORMED,
                DecisionRecoveryV1.REAUTHENTICATE,
            )
        computed_request = digest_decision_bytes(
            request_payload, domain=DecisionDigestDomain.REQUEST
        )
        if computed_request != request.request_digest:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.REQUEST_INTEGRITY,
                DecisionRecoveryV1.REAUTHENTICATE,
            )

        if runtime_model.health == AuthorityHealthV1.RECOVERY_ONLY.value:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.RECOVERY_ONLY,
                DecisionRecoveryV1.RECOVERY_ONLY,
            )
        now = runtime_model.trusted_time
        if now >= runtime_model.trusted_time_valid_until:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.TRUSTED_TIME_STALE,
                DecisionRecoveryV1.REFRESH_AUTHORITY,
            )
        if now < policy.valid_from or now >= policy.valid_until:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.POLICY_STALE,
                DecisionRecoveryV1.REFRESH_AUTHORITY,
            )
        if policy.policy_generation < runtime_model.policy_generation_floor or (
            policy.policy_generation == runtime_model.policy_generation_floor
            and self._policy.policy_digest != runtime_model.policy_digest_at_floor
        ):
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.POLICY_ROLLBACK,
                DecisionRecoveryV1.RECOVERY_ONLY,
            )
        if policy.revocation_generation < runtime_model.revocation_generation_floor or (
            policy.revocation_generation == runtime_model.revocation_generation_floor
            and self._policy.revocation_digest != runtime_model.revocation_digest_at_floor
        ):
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.POLICY_ROLLBACK,
                DecisionRecoveryV1.RECOVERY_ONLY,
            )

        taints = frozenset(request.envelope.taints)
        if taints & {TaintV1.CRITICAL.value, TaintV1.AUTHORITY_INJECTION.value}:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.QUARANTINE,
                DecisionReasonV1.CRITICAL_TAINT,
                DecisionRecoveryV1.QUARANTINE_INPUT,
            )
        if taints & {TaintV1.MALFORMED.value, TaintV1.UNINSPECTABLE.value}:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.QUARANTINE,
                DecisionReasonV1.UNINSPECTABLE_DATA,
                DecisionRecoveryV1.QUARANTINE_INPUT,
            )
        if request.operation.capability in {
            CapabilityV1.ADMINISTER_POLICY.value,
            CapabilityV1.REPAIR_RECOVERY.value,
        }:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.PRIVILEGED_PATH_REQUIRED,
                DecisionRecoveryV1.REAUTHENTICATE,
            )
        if (
            request.operation.capability == CapabilityV1.EXECUTE.value
            and TaintV1.EXECUTABLE.value in taints
        ):
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.QUARANTINE,
                DecisionReasonV1.EXECUTABLE_CONTENT,
                DecisionRecoveryV1.QUARANTINE_INPUT,
            )

        lease = request.lease
        lease_payload = rfc8785.dumps(_lease_body(lease))
        if (
            digest_decision_bytes(lease_payload, domain=DecisionDigestDomain.LEASE)
            != lease.lease_digest
        ):
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.LEASE_BINDING,
                DecisionRecoveryV1.OBTAIN_NEW_LEASE,
            )
        if (
            lease.policy_id != policy.policy_id
            or lease.policy_generation != policy.policy_generation
        ):
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.POLICY_BINDING,
                DecisionRecoveryV1.OBTAIN_NEW_LEASE,
            )
        if lease.revocation_generation > policy.revocation_generation:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.POLICY_BINDING,
                DecisionRecoveryV1.REFRESH_AUTHORITY,
            )
        if now < lease.not_before:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.LEASE_NOT_YET_VALID,
                DecisionRecoveryV1.OBTAIN_NEW_LEASE,
            )
        if now >= lease.expires_at:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.LEASE_EXPIRED,
                DecisionRecoveryV1.OBTAIN_NEW_LEASE,
            )
        if lease.lease_digest in policy.revoked_lease_digests:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.LEASE_REVOKED,
                DecisionRecoveryV1.OBTAIN_NEW_LEASE,
            )
        binding = compute_request_binding_digest(
            identity=request.identity,
            envelope=request.envelope,
            data_scope_digest=request.data_scope_digest,
            operation=request.operation,
            purpose_digest=request.purpose_digest,
        )
        if binding != lease.request_binding_digest:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.LEASE_BINDING,
                DecisionRecoveryV1.REAUTHENTICATE,
            )
        if lease.lease_digest not in {grant.lease_digest for grant in policy.grants}:
            return self._result(
                request.request_digest,
                runtime.runtime_digest,
                DecisionVerdictV1.DENY,
                DecisionReasonV1.DENY_DEFAULT,
                DecisionRecoveryV1.OBTAIN_NEW_LEASE,
            )
        return self._result(
            request.request_digest,
            runtime.runtime_digest,
            DecisionVerdictV1.ALLOW,
            DecisionReasonV1.ALLOW_EXACT_GRANT,
            DecisionRecoveryV1.NONE,
        )
