from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

import pytest

from mcp_warden.content_envelope import create_ingress
from mcp_warden.content_models import (
    IngressKindV1,
    MediaTypeV1,
    TaintV1,
    TransformKindV1,
)
from mcp_warden.decision_models import (
    MAX_GRANTS,
    MAX_SIGNATURE_BYTES,
    ArtifactKindV1,
    AuthorityHealthV1,
    CapabilityV1,
    DecisionDigestDomain,
    DecisionError,
    DecisionReasonV1,
    DecisionRecoveryV1,
    DecisionVerdictV1,
    IdentityBindingV1,
    OperationBindingV1,
    PolicyBundleV1,
    PolicyGrantV1,
    RuntimeSnapshotV1,
    SignedPolicyCandidateV1,
    SignedRuntimeCandidateV1,
    VerificationAlgorithmV1,
    digest_decision_bytes,
)
from mcp_warden.policy_decision import (
    ActivatedPolicyV1,
    PolicyDecisionPointV1,
    activate_policy,
    activate_runtime,
    canonical_policy_bytes,
    canonical_runtime_bytes,
    compute_request_binding_digest,
    create_capability_lease,
    create_decision_request,
    serialize_decision,
)


def _digest(label: str, domain: DecisionDigestDomain = DecisionDigestDomain.CLAIM) -> str:
    return digest_decision_bytes(label.encode("ascii"), domain=domain)


class RecordingVerifier:
    def __init__(self, *, accept: bool = True, raises: bool = False) -> None:
        self.accept = accept
        self.raises = raises
        self.calls: list[tuple[object, ...]] = []

    def verify(
        self,
        *,
        artifact_kind: ArtifactKindV1,
        algorithm: VerificationAlgorithmV1,
        signer_identity: str,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        self.calls.append((artifact_kind, algorithm, signer_identity, payload, signature))
        if self.raises:
            raise RuntimeError("secret verifier detail")
        return self.accept and signature == b"valid-signature"


def _envelope(*, taints: tuple[TaintV1, ...] = ()):
    return create_ingress(
        content=b'{"safe":true}',
        media_type=MediaTypeV1.APPLICATION_JSON,
        source_kind=IngressKindV1.TOOL_RESULT,
        source_identity=b'{"server":"fixture"}',
        source_claims=b'{"tool":"read"}',
        capture_kind=TransformKindV1.INGRESS_CAPTURE,
        capture_implementation=b'{"name":"fixture","version":"1"}',
        capture_parameters=b'{"mode":"exact"}',
        added_taints=taints,
    )


def _identity() -> IdentityBindingV1:
    return IdentityBindingV1(
        user_digest=_digest("user"),
        agent_digest=_digest("agent"),
        device_digest=_digest("device"),
        session_digest=_digest("session"),
    )


def _operation() -> OperationBindingV1:
    return OperationBindingV1(
        adapter_id="fixture.adapter",
        adapter_manifest_digest=_digest("adapter-manifest"),
        operation_id="document.read",
        capability=CapabilityV1.READ.value,
        arguments_digest=_digest("arguments", DecisionDigestDomain.EFFECT_ARGUMENTS),
        destination_digest=_digest("destination"),
        bundle_manifest_digest=None,
    )


def _policy_bundle(*, lease_digest: str | None, revoked: tuple[str, ...] = ()) -> PolicyBundleV1:
    grants = () if lease_digest is None else (PolicyGrantV1(lease_digest=lease_digest),)
    return PolicyBundleV1(
        schema_version=1,
        policy_id=_digest("policy-id", DecisionDigestDomain.POLICY_ID),
        policy_generation=7,
        valid_from=100,
        valid_until=500,
        rule_set_digest=_digest("rules", DecisionDigestDomain.RULE_SET),
        trust_root_digest=_digest("trust-root", DecisionDigestDomain.TRUST_ROOT),
        critical_floor_version="atk-critical-v1",
        revocation_generation=3,
        grants=grants,
        revoked_lease_digests=revoked,
    )


def _activate_policy(bundle: PolicyBundleV1):
    verifier = RecordingVerifier()
    candidate = SignedPolicyCandidateV1(
        policy=bundle,
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("policy-signer"),
        signature=b"valid-signature",
    )
    active = activate_policy(candidate, verifier=verifier)
    return active, verifier


def _activate_runtime(active_policy, *, now: int = 200, health=AuthorityHealthV1.HEALTHY):
    runtime = RuntimeSnapshotV1(
        schema_version=1,
        health=health.value,
        trusted_time=now,
        trusted_time_valid_until=300,
        policy_generation_floor=7,
        policy_digest_at_floor=active_policy.policy_digest,
        revocation_generation_floor=3,
        revocation_digest_at_floor=active_policy.revocation_digest,
    )
    verifier = RecordingVerifier()
    candidate = SignedRuntimeCandidateV1(
        runtime=runtime,
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("runtime-signer"),
        signature=b"valid-signature",
    )
    return activate_runtime(candidate, verifier=verifier), verifier


def _request_and_policy(*, taints: tuple[TaintV1, ...] = (), grant: bool = True):
    envelope = _envelope(taints=taints)
    identity = _identity()
    operation = _operation()
    purpose = _digest("purpose", DecisionDigestDomain.PURPOSE)
    scope = _digest("scope", DecisionDigestDomain.DATA_SCOPE)
    policy_id = _digest("policy-id", DecisionDigestDomain.POLICY_ID)
    binding = compute_request_binding_digest(
        identity=identity,
        envelope=envelope,
        data_scope_digest=scope,
        operation=operation,
        purpose_digest=purpose,
    )
    lease = create_capability_lease(
        lease_id=_digest("lease-id", DecisionDigestDomain.LEASE_ID),
        request_binding_digest=binding,
        policy_id=policy_id,
        policy_generation=7,
        not_before=150,
        expires_at=250,
        revocation_generation=3,
    )
    bundle = _policy_bundle(lease_digest=lease.lease_digest if grant else None)
    active_policy, policy_verifier = _activate_policy(bundle)
    active_runtime, runtime_verifier = _activate_runtime(active_policy)
    request = create_decision_request(
        identity=identity,
        envelope=envelope,
        data_scope_digest=scope,
        operation=operation,
        purpose_digest=purpose,
        lease=lease,
    )
    return request, active_policy, active_runtime, policy_verifier, runtime_verifier


def test_activation_verifies_exact_canonical_payload_once() -> None:
    request, active_policy, active_runtime, policy_verifier, runtime_verifier = (
        _request_and_policy()
    )
    assert request.schema_version == 1
    assert len(policy_verifier.calls) == 1
    assert policy_verifier.calls[0][0] is ArtifactKindV1.POLICY
    assert policy_verifier.calls[0][3] == canonical_policy_bytes(active_policy.policy)
    assert len(runtime_verifier.calls) == 1
    assert runtime_verifier.calls[0][0] is ArtifactKindV1.RUNTIME
    assert runtime_verifier.calls[0][3] == canonical_runtime_bytes(active_runtime.runtime)


@pytest.mark.parametrize("accept,raises", [(False, False), (True, True)])
def test_failed_candidate_activation_is_code_only_and_returns_no_replacement(
    accept: bool, raises: bool
) -> None:
    bundle = _policy_bundle(lease_digest=None)
    candidate = SignedPolicyCandidateV1(
        policy=bundle,
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("signer"),
        signature=b"valid-signature",
    )
    verifier = RecordingVerifier(accept=accept, raises=raises)
    with pytest.raises(DecisionError, match="PDP-POLICY-VERIFICATION") as caught:
        activate_policy(candidate, verifier=verifier)
    assert str(caught.value) == "PDP-POLICY-VERIFICATION"
    assert "secret" not in repr(caught.value)


def test_identical_explicit_inputs_produce_byte_identical_allow_decision() -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy()
    pdp = PolicyDecisionPointV1(active_policy)
    first = pdp.evaluate(request, runtime=active_runtime)
    second = pdp.evaluate(request, runtime=active_runtime)
    assert first == second
    assert serialize_decision(first) == serialize_decision(second)
    assert first.verdict == DecisionVerdictV1.ALLOW.value
    assert first.reason == DecisionReasonV1.ALLOW_EXACT_GRANT.value
    assert first.recovery == DecisionRecoveryV1.NONE.value


def test_no_exact_policy_grant_denies_by_default() -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy(grant=False)
    decision = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=active_runtime)
    assert decision.verdict == DecisionVerdictV1.DENY.value
    assert decision.reason == DecisionReasonV1.DENY_DEFAULT.value
    assert decision.recovery == DecisionRecoveryV1.OBTAIN_NEW_LEASE.value


@pytest.mark.parametrize(
    "field",
    ["user_digest", "agent_digest", "device_digest", "session_digest"],
)
def test_every_identity_dimension_is_bound(field: str) -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy()
    forged_identity = request.identity.model_copy(update={field: _digest(f"other-{field}")})
    forged = request.model_copy(update={"identity": forged_identity})
    decision = PolicyDecisionPointV1(active_policy).evaluate(forged, runtime=active_runtime)
    assert decision.verdict == DecisionVerdictV1.DENY.value
    assert decision.reason == DecisionReasonV1.REQUEST_INTEGRITY.value


@pytest.mark.parametrize(
    "field,value",
    [
        ("adapter_id", "other.adapter"),
        ("operation_id", "other.operation"),
        ("capability", CapabilityV1.EXECUTE.value),
        ("arguments_digest", _digest("other-args")),
        ("destination_digest", _digest("other-destination")),
    ],
)
def test_every_operation_dimension_is_bound(field: str, value: str) -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy()
    update = {field: value}
    if field == "capability" and value == CapabilityV1.EXECUTE.value:
        update["bundle_manifest_digest"] = _digest("bundle-manifest")
    forged_operation = request.operation.model_copy(update=update)
    forged = request.model_copy(update={"operation": forged_operation})
    decision = PolicyDecisionPointV1(active_policy).evaluate(forged, runtime=active_runtime)
    assert decision.verdict == DecisionVerdictV1.DENY.value
    assert decision.reason == DecisionReasonV1.REQUEST_INTEGRITY.value


def test_scope_purpose_and_envelope_are_bound() -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy()
    changes = (
        {"data_scope_digest": _digest("other-scope")},
        {"purpose_digest": _digest("other-purpose")},
        {"envelope": _envelope(taints=(TaintV1.SENSITIVE,))},
    )
    for change in changes:
        forged = request.model_copy(update=change)
        decision = PolicyDecisionPointV1(active_policy).evaluate(forged, runtime=active_runtime)
        assert decision.verdict == DecisionVerdictV1.DENY.value
        assert decision.reason == DecisionReasonV1.REQUEST_INTEGRITY.value


@pytest.mark.parametrize(
    "now,reason,recovery",
    [
        (149, DecisionReasonV1.LEASE_NOT_YET_VALID, DecisionRecoveryV1.OBTAIN_NEW_LEASE),
        (250, DecisionReasonV1.LEASE_EXPIRED, DecisionRecoveryV1.OBTAIN_NEW_LEASE),
        (251, DecisionReasonV1.LEASE_EXPIRED, DecisionRecoveryV1.OBTAIN_NEW_LEASE),
        (300, DecisionReasonV1.TRUSTED_TIME_STALE, DecisionRecoveryV1.REFRESH_AUTHORITY),
        (301, DecisionReasonV1.TRUSTED_TIME_STALE, DecisionRecoveryV1.REFRESH_AUTHORITY),
    ],
)
def test_time_failures_deny_with_stable_recovery(now, reason, recovery) -> None:
    request, active_policy, _, _, _ = _request_and_policy()
    active_runtime, _ = _activate_runtime(active_policy, now=now)
    decision = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=active_runtime)
    assert decision.verdict == DecisionVerdictV1.DENY.value
    assert decision.reason == reason.value
    assert decision.recovery == recovery.value


def test_revoked_lease_denies() -> None:
    request, _, _, _, _ = _request_and_policy()
    active_policy, _ = _activate_policy(
        _policy_bundle(
            lease_digest=request.lease.lease_digest, revoked=(request.lease.lease_digest,)
        )
    )
    active_runtime, _ = _activate_runtime(active_policy)
    decision = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=active_runtime)
    assert decision.reason == DecisionReasonV1.LEASE_REVOKED.value
    assert decision.recovery == DecisionRecoveryV1.OBTAIN_NEW_LEASE.value


@pytest.mark.parametrize(
    "taint,reason",
    [
        (TaintV1.CRITICAL, DecisionReasonV1.CRITICAL_TAINT),
        (TaintV1.AUTHORITY_INJECTION, DecisionReasonV1.CRITICAL_TAINT),
        (TaintV1.MALFORMED, DecisionReasonV1.UNINSPECTABLE_DATA),
        (TaintV1.UNINSPECTABLE, DecisionReasonV1.UNINSPECTABLE_DATA),
    ],
)
def test_mandatory_critical_floor_cannot_be_granted(taint, reason) -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy(taints=(taint,))
    decision = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=active_runtime)
    assert decision.verdict == DecisionVerdictV1.QUARANTINE.value
    assert decision.reason == reason.value
    assert decision.recovery == DecisionRecoveryV1.QUARANTINE_INPUT.value


@pytest.mark.parametrize(
    "capability",
    [CapabilityV1.ADMINISTER_POLICY, CapabilityV1.REPAIR_RECOVERY],
)
def test_normal_pdp_never_grants_privileged_activation_or_recovery_paths(capability) -> None:
    request, _, _, _, _ = _request_and_policy()
    operation = request.operation.model_copy(update={"capability": capability.value})
    binding = compute_request_binding_digest(
        identity=request.identity,
        envelope=request.envelope,
        data_scope_digest=request.data_scope_digest,
        operation=operation,
        purpose_digest=request.purpose_digest,
    )
    lease = create_capability_lease(
        lease_id=request.lease.lease_id,
        request_binding_digest=binding,
        policy_id=request.lease.policy_id,
        policy_generation=request.lease.policy_generation,
        not_before=request.lease.not_before,
        expires_at=request.lease.expires_at,
        revocation_generation=request.lease.revocation_generation,
    )
    active_policy, _ = _activate_policy(_policy_bundle(lease_digest=lease.lease_digest))
    runtime, _ = _activate_runtime(active_policy)
    privileged = create_decision_request(
        identity=request.identity,
        envelope=request.envelope,
        data_scope_digest=request.data_scope_digest,
        operation=operation,
        purpose_digest=request.purpose_digest,
        lease=lease,
    )
    decision = PolicyDecisionPointV1(active_policy).evaluate(privileged, runtime=runtime)
    assert decision.verdict == DecisionVerdictV1.DENY.value
    assert decision.reason == DecisionReasonV1.PRIVILEGED_PATH_REQUIRED.value


def test_untrusted_executable_content_cannot_be_granted_execute_authority() -> None:
    request, _, _, _, _ = _request_and_policy(taints=(TaintV1.EXECUTABLE,))
    operation = request.operation.model_copy(
        update={
            "capability": CapabilityV1.EXECUTE.value,
            "bundle_manifest_digest": _digest("bundle-manifest"),
        }
    )
    binding = compute_request_binding_digest(
        identity=request.identity,
        envelope=request.envelope,
        data_scope_digest=request.data_scope_digest,
        operation=operation,
        purpose_digest=request.purpose_digest,
    )
    lease = create_capability_lease(
        lease_id=request.lease.lease_id,
        request_binding_digest=binding,
        policy_id=request.lease.policy_id,
        policy_generation=request.lease.policy_generation,
        not_before=request.lease.not_before,
        expires_at=request.lease.expires_at,
        revocation_generation=request.lease.revocation_generation,
    )
    active_policy, _ = _activate_policy(_policy_bundle(lease_digest=lease.lease_digest))
    runtime, _ = _activate_runtime(active_policy)
    executable = create_decision_request(
        identity=request.identity,
        envelope=request.envelope,
        data_scope_digest=request.data_scope_digest,
        operation=operation,
        purpose_digest=request.purpose_digest,
        lease=lease,
    )
    decision = PolicyDecisionPointV1(active_policy).evaluate(executable, runtime=runtime)
    assert decision.verdict == DecisionVerdictV1.QUARANTINE.value
    assert decision.reason == DecisionReasonV1.EXECUTABLE_CONTENT.value


def test_recovery_only_runtime_denies_all_normal_requests() -> None:
    request, active_policy, _, _, _ = _request_and_policy()
    runtime, _ = _activate_runtime(active_policy, health=AuthorityHealthV1.RECOVERY_ONLY)
    decision = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=runtime)
    assert decision.reason == DecisionReasonV1.RECOVERY_ONLY.value
    assert decision.recovery == DecisionRecoveryV1.RECOVERY_ONLY.value


def test_runtime_policy_floor_mismatch_denies_as_rollback() -> None:
    request, active_policy, runtime, _, _ = _request_and_policy()
    forged_runtime = runtime.runtime.model_copy(
        update={"policy_digest_at_floor": _digest("other-policy")}
    )
    candidate = SignedRuntimeCandidateV1(
        runtime=forged_runtime,
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("runtime-signer"),
        signature=b"valid-signature",
    )
    activated = activate_runtime(candidate, verifier=RecordingVerifier())
    decision = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=activated)
    assert decision.reason == DecisionReasonV1.POLICY_ROLLBACK.value
    assert decision.recovery == DecisionRecoveryV1.RECOVERY_ONLY.value


def test_hostile_or_constructed_inputs_fail_closed_without_echo() -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy()

    class HostileRequest(type(request)):
        pass

    hostile = HostileRequest.model_construct(**request.model_dump())
    incomplete = type(request).model_construct(schema_version=1)
    pdp = PolicyDecisionPointV1(active_policy)
    for candidate in (hostile, incomplete, object()):
        decision = pdp.evaluate(candidate, runtime=active_runtime)
        encoded = serialize_decision(decision)
        assert decision.verdict == DecisionVerdictV1.DENY.value
        assert decision.reason == DecisionReasonV1.INPUT_MALFORMED.value
        assert b"secret" not in encoded

    malformed_digest = request.model_copy(
        update={
            "envelope": request.envelope.model_copy(update={"trust_state": "trusted"}),
            "request_digest": "secret-invalid-digest",
        }
    )
    decision = pdp.evaluate(malformed_digest, runtime=active_runtime)
    encoded = serialize_decision(decision)
    assert decision.reason == DecisionReasonV1.INPUT_MALFORMED.value
    assert b"secret" not in encoded


def test_models_are_strict_frozen_and_unknown_fields_fail_code_only() -> None:
    with pytest.raises(DecisionError) as caught:
        IdentityBindingV1(
            user_digest=_digest("user"),
            agent_digest=_digest("agent"),
            device_digest=_digest("device"),
            session_digest=_digest("session"),
            surprise="secret",  # type: ignore[call-arg]
        )
    assert "secret" not in str(caught.value)
    assert caught.value.__context__ is None
    identity = _identity()
    with pytest.raises((DecisionError, TypeError)):
        identity.user_digest = _digest("other")  # type: ignore[misc]


def test_candidate_dataclasses_reject_wrong_exact_types() -> None:
    with pytest.raises(DecisionError, match="PDP-CANDIDATE-MALFORMED"):
        SignedPolicyCandidateV1(
            policy=_policy_bundle(lease_digest=None),
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=_digest("signer"),
            signature=bytearray(b"valid-signature"),  # type: ignore[arg-type]
        )


def test_decision_modules_have_no_network_clock_environment_or_legacy_canon_imports() -> None:
    root = Path(__file__).parents[1] / "src/mcp_warden"
    forbidden_imports = {"requests", "httpx", "socket", "urllib", "time", "datetime", "os"}
    for name in ("decision_models.py", "policy_decision.py"):
        tree = ast.parse((root / name).read_text())
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        assert not (imports & forbidden_imports)
        source = (root / name).read_text()
        assert "hash_value(" not in source
        assert "canon(" not in source


def test_request_copy_without_recomputed_digest_is_rejected_before_lease_checks() -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy()
    forged = (
        replace(request, purpose_digest=_digest("forged"))
        if hasattr(request, "__dataclass_fields__")
        else request.model_copy(update={"purpose_digest": _digest("forged")})
    )
    decision = PolicyDecisionPointV1(active_policy).evaluate(forged, runtime=active_runtime)
    assert decision.reason == DecisionReasonV1.REQUEST_INTEGRITY.value


def test_forged_activated_policy_without_private_activation_marker_is_rejected() -> None:
    _, active_policy, _, _, _ = _request_and_policy()
    forged = object.__new__(ActivatedPolicyV1)
    object.__setattr__(forged, "policy", active_policy.policy)
    object.__setattr__(forged, "policy_digest", active_policy.policy_digest)
    object.__setattr__(forged, "revocation_digest", active_policy.revocation_digest)
    object.__setattr__(forged, "_locked", True)
    with pytest.raises(DecisionError, match="PDP-AUTHORITY-UNAVAILABLE"):
        PolicyDecisionPointV1(forged)


def test_forged_activated_runtime_without_private_activation_marker_denies() -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy()
    forged = object.__new__(type(active_runtime))
    object.__setattr__(forged, "runtime", active_runtime.runtime)
    object.__setattr__(forged, "runtime_digest", active_runtime.runtime_digest)
    object.__setattr__(forged, "_locked", True)
    decision = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=forged)
    assert decision.reason == DecisionReasonV1.AUTHORITY_UNAVAILABLE.value


def test_invalid_envelope_quarantines_before_stale_request_digest() -> None:
    request, active_policy, runtime, _, _ = _request_and_policy()
    invalid_envelope = request.envelope.model_copy(update={"trust_state": "trusted"})
    forged = request.model_copy(update={"envelope": invalid_envelope})
    decision = PolicyDecisionPointV1(active_policy).evaluate(forged, runtime=runtime)
    assert decision.verdict == DecisionVerdictV1.QUARANTINE.value
    assert decision.reason == DecisionReasonV1.ENVELOPE_INVALID.value


def test_policy_validity_and_revocation_floor_fail_closed() -> None:
    request, active_policy, _, _, _ = _request_and_policy()
    for now, runtime_change, expected in (
        (99, {}, DecisionReasonV1.POLICY_STALE),
        (500, {}, DecisionReasonV1.POLICY_STALE),
        (
            200,
            {
                "revocation_digest_at_floor": _digest("wrong-revocation"),
            },
            DecisionReasonV1.POLICY_ROLLBACK,
        ),
    ):
        runtime_model = RuntimeSnapshotV1(
            schema_version=1,
            health=AuthorityHealthV1.HEALTHY.value,
            trusted_time=now,
            trusted_time_valid_until=600,
            policy_generation_floor=7,
            policy_digest_at_floor=active_policy.policy_digest,
            revocation_generation_floor=3,
            revocation_digest_at_floor=active_policy.revocation_digest,
        ).model_copy(update=runtime_change)
        activated = activate_runtime(
            SignedRuntimeCandidateV1(
                runtime=runtime_model,
                algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
                signer_identity=_digest("runtime-signer"),
                signature=b"valid-signature",
            ),
            verifier=RecordingVerifier(),
        )
        decision = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=activated)
        assert decision.reason == expected.value


def test_lease_policy_and_future_revocation_generation_mismatch_deny() -> None:
    request, _, _, _, _ = _request_and_policy()
    for policy_id, revocation_generation, expected_recovery in (
        (_digest("other-policy"), 3, DecisionRecoveryV1.OBTAIN_NEW_LEASE),
        (request.lease.policy_id, 4, DecisionRecoveryV1.REFRESH_AUTHORITY),
    ):
        binding = compute_request_binding_digest(
            identity=request.identity,
            envelope=request.envelope,
            data_scope_digest=request.data_scope_digest,
            operation=request.operation,
            purpose_digest=request.purpose_digest,
        )
        lease = create_capability_lease(
            lease_id=request.lease.lease_id,
            request_binding_digest=binding,
            policy_id=policy_id,
            policy_generation=7,
            not_before=150,
            expires_at=250,
            revocation_generation=revocation_generation,
        )
        active_policy, _ = _activate_policy(_policy_bundle(lease_digest=lease.lease_digest))
        runtime, _ = _activate_runtime(active_policy)
        candidate = create_decision_request(
            identity=request.identity,
            envelope=request.envelope,
            data_scope_digest=request.data_scope_digest,
            operation=request.operation,
            purpose_digest=request.purpose_digest,
            lease=lease,
        )
        decision = PolicyDecisionPointV1(active_policy).evaluate(candidate, runtime=runtime)
        assert decision.reason == DecisionReasonV1.POLICY_BINDING.value
        assert decision.recovery == expected_recovery.value


def test_pdp_authority_cannot_be_replaced_after_construction() -> None:
    _, active_policy, _, _, _ = _request_and_policy()
    pdp = PolicyDecisionPointV1(active_policy)
    with pytest.raises(DecisionError, match="PDP-AUTHORITY-IMMUTABLE"):
        pdp._policy = active_policy  # type: ignore[misc]
    with pytest.raises(DecisionError, match="PDP-AUTHORITY-IMMUTABLE"):
        del pdp._policy  # type: ignore[misc]
    with pytest.raises(DecisionError, match="PDP-AUTHORITY-IMMUTABLE"):
        del active_policy.policy  # type: ignore[misc]


def test_decision_serializer_rejects_self_digest_forgery() -> None:
    request, active_policy, active_runtime, _, _ = _request_and_policy()
    decision = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=active_runtime)
    forged = decision.model_copy(update={"reason": DecisionReasonV1.DENY_DEFAULT.value})
    with pytest.raises(DecisionError, match="PDP-DECISION-INTEGRITY"):
        serialize_decision(forged)


def test_policy_grant_and_signature_caps_accept_cap_and_reject_cap_plus_one() -> None:
    grants = tuple(
        sorted(
            (
                PolicyGrantV1(lease_digest=_digest(f"lease-cap-{index}"))
                for index in range(MAX_GRANTS)
            ),
            key=lambda item: item.lease_digest,
        )
    )
    bundle = PolicyBundleV1(
        schema_version=1,
        policy_id=_digest("policy-id", DecisionDigestDomain.POLICY_ID),
        policy_generation=7,
        valid_from=100,
        valid_until=500,
        rule_set_digest=_digest("rules", DecisionDigestDomain.RULE_SET),
        trust_root_digest=_digest("root", DecisionDigestDomain.TRUST_ROOT),
        critical_floor_version="atk-critical-v1",
        revocation_generation=3,
        grants=grants,
        revoked_lease_digests=(),
    )
    assert len(canonical_policy_bytes(bundle)) > 0
    SignedPolicyCandidateV1(
        policy=bundle,
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("signer"),
        signature=b"x" * MAX_SIGNATURE_BYTES,
    )
    with pytest.raises(DecisionError, match="PDP-POLICY-MALFORMED"):
        PolicyBundleV1(
            **(
                bundle.model_dump()
                | {"grants": grants + (PolicyGrantV1(lease_digest=_digest("plus-one")),)}
            )
        )
    with pytest.raises(DecisionError, match="PDP-CANDIDATE-MALFORMED"):
        SignedPolicyCandidateV1(
            policy=bundle,
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=_digest("signer"),
            signature=b"x" * (MAX_SIGNATURE_BYTES + 1),
        )
