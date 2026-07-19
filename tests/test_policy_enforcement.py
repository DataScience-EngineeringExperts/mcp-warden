from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from mcp_warden.content_envelope import create_ingress
from mcp_warden.content_models import (
    BundleEvidenceInput,
    IngressKindV1,
    MediaTypeV1,
    TransformKindV1,
)
from mcp_warden.decision_models import (
    ArtifactKindV1,
    AuthorityHealthV1,
    CapabilityV1,
    DecisionDigestDomain,
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
from mcp_warden.executable_bundle import (
    ExecutableBundleManifestV1,
    SignedExecutableBundleCandidateV1,
    activate_executable_bundle,
    bundle_evidence_from_input,
    canonical_bundle_manifest_bytes,
)
from mcp_warden.policy_decision import (
    PolicyDecisionPointV1,
    activate_policy,
    activate_runtime,
    compute_request_binding_digest,
    create_capability_lease,
    create_decision_request,
)
from mcp_warden.policy_enforcement import (
    MAX_ADAPTER_DEPENDENCIES,
    MAX_EFFECT_BYTES,
    MAX_MANIFEST_OPERATIONS,
    AdapterManifestV1,
    AdapterRegistryV1,
    EffectOutcomeV1,
    EnforcementCodeV1,
    EnforcementError,
    ManifestOperationV1,
    PolicyEnforcementPointV1,
    SignedAdapterCandidateV1,
    activate_adapter,
    canonical_manifest_bytes,
    create_effect_input,
    create_evidence_result,
    digest_adapter_dependency,
    digest_adapter_implementation,
    digest_handler_implementation,
    serialize_enforcement_result,
)


def _digest(label: str, domain: DecisionDigestDomain = DecisionDigestDomain.CLAIM) -> str:
    return digest_decision_bytes(label.encode("ascii"), domain=domain)


class Verifier:
    def __init__(self, *, accept: bool = True) -> None:
        self.accept = accept
        self.calls: list[tuple[object, ...]] = []

    def verify(self, **kwargs) -> bool:
        self.calls.append(tuple(kwargs.values()))
        return self.accept and kwargs["signature"] == b"valid-signature"


def _envelope():
    return create_ingress(
        content=b'{"safe":true}',
        media_type=MediaTypeV1.APPLICATION_JSON,
        source_kind=IngressKindV1.TOOL_RESULT,
        source_identity=b'{"server":"fixture"}',
        source_claims=b'{"tool":"read"}',
        capture_kind=TransformKindV1.INGRESS_CAPTURE,
        capture_implementation=b'{"name":"fixture","version":"1"}',
        capture_parameters=b'{"mode":"exact"}',
    )


def _noop_handler(_: bytes) -> None:
    return None


def _different_handler(_: bytes) -> None:
    return None


def _original_code_handler(_: bytes) -> None:
    return None


def _drifted_code_handler(_: bytes) -> bytes:
    return b"drifted"


def _raw_output_handler(_: bytes) -> bytes:
    return b"secret raw output"


def _raising_handler(_: bytes):
    return 1 // 0


_MUTABLE_DELEGATES = [_noop_handler]


def _mutable_global_delegate_handler(value: bytes):
    return _MUTABLE_DELEGATES[0](value)


_NESTED_DELEGATES = [_noop_handler]


def _nested_mutable_delegate_handler(value: bytes):
    return (lambda: _NESTED_DELEGATES[0](value))()


def _active_components(
    *,
    grant: bool = True,
    operation_id: str = "document.read",
    handler=_noop_handler,
):
    effect = create_effect_input(b'{"document_id":"42"}')
    identity = IdentityBindingV1(
        user_digest=_digest("user"),
        agent_digest=_digest("agent"),
        device_digest=_digest("device"),
        session_digest=_digest("session"),
    )
    policy_id = _digest("policy-id", DecisionDigestDomain.POLICY_ID)
    manifest = _manifest(handler, policy_id=policy_id)
    operation = OperationBindingV1(
        adapter_id="fixture.adapter",
        adapter_manifest_digest=digest_decision_bytes(
            canonical_manifest_bytes(manifest), domain=DecisionDigestDomain.ADAPTER_MANIFEST
        ),
        operation_id=operation_id,
        capability=CapabilityV1.READ.value,
        arguments_digest=effect.arguments_digest,
        destination_digest=_digest("destination"),
        bundle_manifest_digest=None,
    )
    envelope = _envelope()
    purpose = _digest("purpose", DecisionDigestDomain.PURPOSE)
    scope = _digest("scope", DecisionDigestDomain.DATA_SCOPE)
    binding = compute_request_binding_digest(
        identity=identity,
        envelope=envelope,
        data_scope_digest=scope,
        operation=operation,
        purpose_digest=purpose,
    )
    lease = create_capability_lease(
        lease_id=_digest("lease", DecisionDigestDomain.LEASE_ID),
        request_binding_digest=binding,
        policy_id=policy_id,
        policy_generation=7,
        not_before=100,
        expires_at=300,
        revocation_generation=3,
    )
    grants = (PolicyGrantV1(lease_digest=lease.lease_digest),) if grant else ()
    policy = PolicyBundleV1(
        schema_version=1,
        policy_id=policy_id,
        policy_generation=7,
        valid_from=50,
        valid_until=400,
        rule_set_digest=_digest("rules", DecisionDigestDomain.RULE_SET),
        trust_root_digest=_digest("root", DecisionDigestDomain.TRUST_ROOT),
        critical_floor_version="atk-critical-v1",
        revocation_generation=3,
        grants=grants,
        revoked_lease_digests=(),
    )
    policy_candidate = SignedPolicyCandidateV1(
        policy=policy,
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("policy-signer"),
        signature=b"valid-signature",
    )
    active_policy = activate_policy(policy_candidate, verifier=Verifier())
    runtime = RuntimeSnapshotV1(
        schema_version=1,
        health=AuthorityHealthV1.HEALTHY.value,
        trusted_time=200,
        trusted_time_valid_until=250,
        policy_generation_floor=7,
        policy_digest_at_floor=active_policy.policy_digest,
        revocation_generation_floor=3,
        revocation_digest_at_floor=active_policy.revocation_digest,
    )
    active_runtime = activate_runtime(
        SignedRuntimeCandidateV1(
            runtime=runtime,
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=_digest("runtime-signer"),
            signature=b"valid-signature",
        ),
        verifier=Verifier(),
    )
    request = create_decision_request(
        identity=identity,
        envelope=envelope,
        data_scope_digest=scope,
        operation=operation,
        purpose_digest=purpose,
        lease=lease,
    )
    return effect, request, active_policy, active_runtime


def _manifest(handler, *, policy_id: str) -> AdapterManifestV1:
    adapter_implementation = b"fixture-adapter-binary"
    dependencies = (b"dependency-a", b"dependency-b")
    return AdapterManifestV1(
        schema_version=1,
        adapter_id="fixture.adapter",
        adapter_version="1.0.0",
        implementation_digest=digest_adapter_implementation(adapter_implementation),
        dependency_digests=tuple(sorted(digest_adapter_dependency(item) for item in dependencies)),
        policy_id=policy_id,
        policy_generation=7,
        operations=(
            ManifestOperationV1(
                operation_id="document.read",
                capability=CapabilityV1.READ.value,
                handler_digest=digest_handler_implementation(handler),
            ),
        ),
    )


def _activated_adapter(active_policy, handler):
    manifest = _manifest(handler, policy_id=active_policy.policy.policy_id)
    registry = AdapterRegistryV1()
    registry.register(
        operation_id="document.read",
        handler=handler,
    )
    verifier = Verifier()
    candidate = SignedAdapterCandidateV1(
        manifest=manifest,
        implementation=b"fixture-adapter-binary",
        dependencies=(b"dependency-a", b"dependency-b"),
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("adapter-signer"),
        signature=b"valid-signature",
    )
    activated = activate_adapter(
        candidate,
        registry=registry,
        verifier=verifier,
        policy=active_policy,
    )
    return activated, registry, verifier


class PermitGate:
    def __init__(self, trace: list[str], *, mismatch: str | None = None, raises=False) -> None:
        self.trace = trace
        self.mismatch = mismatch
        self.raises = raises
        self.calls = 0

    def record(self, *, decision, manifest_digest: str):
        self.calls += 1
        self.trace.append("evidence")
        if self.raises:
            raise RuntimeError("secret evidence detail")
        result = create_evidence_result(decision=decision, manifest_digest=manifest_digest)
        if self.mismatch:
            return result.model_copy(update={self.mismatch: _digest("forged")})
        return result


def test_adapter_activation_verifies_exact_manifest_and_freezes_registry() -> None:
    _, _, active_policy, _ = _active_components()
    activated, registry, verifier = _activated_adapter(active_policy, _noop_handler)
    assert len(verifier.calls) == 1
    assert verifier.calls[0][0] is ArtifactKindV1.ADAPTER
    assert verifier.calls[0][3] == canonical_manifest_bytes(activated.manifest)
    with pytest.raises(EnforcementError, match="PEP-REGISTRY-FROZEN"):
        registry.register(
            operation_id="other",
            handler=_noop_handler,
        )


@pytest.mark.parametrize("mode", ["missing", "extra", "digest"])
def test_manifest_registry_mismatch_fails_activation(mode: str) -> None:
    _, _, active_policy, _ = _active_components()
    manifest = _manifest(_noop_handler, policy_id=active_policy.policy.policy_id)
    registry = AdapterRegistryV1()
    if mode != "missing":
        registry.register(
            operation_id="document.read" if mode == "digest" else "other.operation",
            handler=_different_handler if mode == "digest" else _noop_handler,
        )
    candidate = SignedAdapterCandidateV1(
        manifest=manifest,
        implementation=b"fixture-adapter-binary",
        dependencies=(b"dependency-a", b"dependency-b"),
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("signer"),
        signature=b"valid-signature",
    )
    with pytest.raises(EnforcementError, match="PEP-MANIFEST-REGISTRY-MISMATCH"):
        activate_adapter(candidate, registry=registry, verifier=Verifier(), policy=active_policy)


def test_adapter_policy_binding_mismatch_fails_activation() -> None:
    _, _, active_policy, _ = _active_components()
    manifest = _manifest(_noop_handler, policy_id=_digest("other-policy"))
    registry = AdapterRegistryV1()
    registry.register(operation_id="document.read", handler=_noop_handler)
    candidate = SignedAdapterCandidateV1(
        manifest=manifest,
        implementation=b"fixture-adapter-binary",
        dependencies=(b"dependency-a", b"dependency-b"),
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("signer"),
        signature=b"valid-signature",
    )
    with pytest.raises(EnforcementError, match="PEP-POLICY-BINDING"):
        activate_adapter(candidate, registry=registry, verifier=Verifier(), policy=active_policy)


def test_bad_adapter_signature_returns_code_only_failure() -> None:
    _, _, active_policy, _ = _active_components()
    manifest = _manifest(_noop_handler, policy_id=active_policy.policy.policy_id)
    registry = AdapterRegistryV1()
    registry.register(operation_id="document.read", handler=_noop_handler)
    candidate = SignedAdapterCandidateV1(
        manifest=manifest,
        implementation=b"fixture-adapter-binary",
        dependencies=(b"dependency-a", b"dependency-b"),
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("signer"),
        signature=b"valid-signature",
    )
    with pytest.raises(EnforcementError, match="PEP-ADAPTER-VERIFICATION") as caught:
        activate_adapter(
            candidate, registry=registry, verifier=Verifier(accept=False), policy=active_policy
        )
    assert "secret" not in repr(caught.value)


def test_adapter_verifier_exception_has_no_retained_secret_context() -> None:
    _, _, active_policy, _ = _active_components()
    manifest = _manifest(_noop_handler, policy_id=active_policy.policy.policy_id)
    registry = AdapterRegistryV1()
    registry.register(operation_id="document.read", handler=_noop_handler)
    candidate = SignedAdapterCandidateV1(
        manifest=manifest,
        implementation=b"fixture-adapter-binary",
        dependencies=(b"dependency-a", b"dependency-b"),
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("signer"),
        signature=b"valid-signature",
    )

    class RaisingVerifier:
        def verify(self, **_):
            raise RuntimeError("secret verifier detail")

    with pytest.raises(EnforcementError, match="PEP-ADAPTER-VERIFICATION") as caught:
        activate_adapter(
            candidate, registry=registry, verifier=RaisingVerifier(), policy=active_policy
        )
    assert caught.value.__context__ is None


def test_default_evidence_gate_blocks_even_an_allow_decision() -> None:
    effect, request, active_policy, runtime = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    pep = PolicyEnforcementPointV1(PolicyDecisionPointV1(active_policy), adapter)
    result = pep.execute(request, runtime=runtime, effect=effect)
    assert result.invoked is False
    assert result.code == EnforcementCodeV1.EVIDENCE_UNAVAILABLE.value


def test_allow_order_is_evidence_then_sink_and_output_is_enveloped() -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    gate = PermitGate(trace)
    pep = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=gate
    )
    result, instrumentation = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert trace == ["evidence"]
    assert instrumentation.events.index("decision") < instrumentation.events.index("evidence")
    assert instrumentation.events.index("evidence") < instrumentation.events.index("sink")
    assert result.invoked is True
    assert result.outcome == EffectOutcomeV1.COMPLETED.value
    assert result.code == EnforcementCodeV1.EXECUTED.value
    assert result.output is None


def test_deny_never_calls_evidence_or_sink() -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components(grant=False)
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    gate = PermitGate(trace)
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=gate
    ).execute(request, runtime=runtime, effect=effect)
    assert result.code == EnforcementCodeV1.DECISION_BLOCKED.value
    assert result.invoked is False
    assert trace == []
    assert gate.calls == 0


def test_effect_argument_substitution_is_rejected_before_evidence_or_sink() -> None:
    trace: list[str] = []
    _, request, active_policy, runtime = _active_components()
    forged_effect = create_effect_input(b'{"document_id":"43"}')
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    gate = PermitGate(trace)
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=gate
    ).execute(request, runtime=runtime, effect=forged_effect)
    assert result.code == EnforcementCodeV1.EFFECT_DIGEST_MISMATCH.value
    assert trace == []


def test_unknown_operation_is_rejected_before_evidence_or_sink() -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components(operation_id="unknown.operation")
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    gate = PermitGate(trace)
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=gate
    ).execute(request, runtime=runtime, effect=effect)
    assert result.code == EnforcementCodeV1.OPERATION_UNKNOWN.value
    assert trace == []


@pytest.mark.parametrize(
    "mismatch",
    ["request_digest", "decision_digest", "manifest_digest", "policy_digest"],
)
def test_evidence_result_substitution_never_reaches_sink(mismatch: str) -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    gate = PermitGate(trace, mismatch=mismatch)
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=gate
    ).execute(request, runtime=runtime, effect=effect)
    assert result.code == EnforcementCodeV1.EVIDENCE_MISMATCH.value
    assert result.invoked is False
    assert trace == ["evidence"]


def test_evidence_exception_is_code_only_and_never_reaches_sink() -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy),
        adapter,
        evidence_gate=PermitGate(trace, raises=True),
    ).execute(request, runtime=runtime, effect=effect)
    assert result.code == EnforcementCodeV1.EVIDENCE_UNAVAILABLE.value
    assert b"secret" not in serialize_enforcement_result(result)
    assert trace == ["evidence"]


def test_sink_exception_is_indeterminate_invoked_and_not_retried() -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components(handler=_raising_handler)
    adapter, _, _ = _activated_adapter(active_policy, _raising_handler)
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=PermitGate(trace)
    ).execute(request, runtime=runtime, effect=effect)
    assert trace == ["evidence"]
    assert result.invoked is True
    assert result.outcome == EffectOutcomeV1.INDETERMINATE.value
    assert result.code == EnforcementCodeV1.SINK_FAILED.value
    assert b"secret" not in serialize_enforcement_result(result)


def test_raw_sink_output_is_rejected_without_echo() -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components(handler=_raw_output_handler)
    adapter, _, _ = _activated_adapter(active_policy, _raw_output_handler)
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=PermitGate(trace)
    ).execute(request, runtime=runtime, effect=effect)
    assert result.invoked is True
    assert result.code == EnforcementCodeV1.OUTPUT_INVALID.value
    assert b"secret" not in serialize_enforcement_result(result)


def test_execute_api_never_accepts_a_caller_decision() -> None:
    parameters = inspect.signature(PolicyEnforcementPointV1.execute).parameters
    assert "decision" not in parameters


def test_effect_input_rejects_noncanonical_and_over_cap_content() -> None:
    with pytest.raises(EnforcementError, match="PEP-EFFECT-NONCANONICAL"):
        create_effect_input(b'{"b": 2, "a": 1}')
    with pytest.raises(EnforcementError, match="PEP-EFFECT-MALFORMED") as caught:
        create_effect_input(b'{"secret":NaN}')
    assert "secret" not in str(caught.value)
    assert caught.value.__context__ is None


def test_direct_noncanonical_effect_dataclass_is_rejected_by_pep() -> None:
    from mcp_warden.policy_enforcement import EffectInputV1

    _, request, active_policy, runtime = _active_components()
    arguments = b'{"b":2,"a":1}'
    forged = EffectInputV1(
        arguments=arguments,
        arguments_digest=digest_decision_bytes(
            arguments, domain=DecisionDigestDomain.EFFECT_ARGUMENTS
        ),
    )
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=PermitGate([])
    ).execute(request, runtime=runtime, effect=forged)
    assert result.code == EnforcementCodeV1.EFFECT_MALFORMED.value


def test_hostile_constructed_request_and_effect_fail_closed_in_pep() -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    pep = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=PermitGate(trace)
    )

    incomplete_request = type(request).model_construct(schema_version=1)
    request_result = pep.execute(incomplete_request, runtime=runtime, effect=effect)
    assert request_result.code == EnforcementCodeV1.DECISION_BLOCKED.value
    assert request_result.invoked is False

    hostile_operation = request.model_copy(update={"operation": object()})
    operation_result = pep.execute(hostile_operation, runtime=runtime, effect=effect)
    assert operation_result.code == EnforcementCodeV1.DECISION_BLOCKED.value
    assert operation_result.invoked is False

    incomplete_effect = object.__new__(type(effect))
    effect_result = pep.execute(request, runtime=runtime, effect=incomplete_effect)
    assert effect_result.code == EnforcementCodeV1.EFFECT_MALFORMED.value
    assert effect_result.invoked is False
    assert trace == []


def test_hostile_nested_request_value_cannot_escape_pep_as_raw_exception() -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    pep = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=PermitGate(trace)
    )

    class HostileDigest:
        def __eq__(self, _other):
            raise RuntimeError("PLANTED-PEP-NESTED-SECRET-716")

    hostile_operation = OperationBindingV1.model_construct(
        adapter_id="fixture.adapter",
        adapter_manifest_digest=request.operation.adapter_manifest_digest,
        operation_id="document.read",
        capability=CapabilityV1.READ.value,
        arguments_digest=HostileDigest(),
        destination_digest=_digest("destination"),
        bundle_manifest_digest=None,
    )
    hostile_request = request.model_copy(update={"operation": hostile_operation})

    result = pep.execute(hostile_request, runtime=runtime, effect=effect)
    assert result.code == EnforcementCodeV1.DECISION_BLOCKED.value
    assert result.invoked is False
    assert b"PLANTED-PEP-NESTED-SECRET-716" not in serialize_enforcement_result(result)
    assert trace == []


def test_hostile_constructed_evidence_fails_closed_before_sink() -> None:
    trace: list[str] = []
    effect, request, active_policy, runtime = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)

    class HostileEvidenceGate:
        def record(self, **_):
            from mcp_warden.policy_enforcement import EvidenceResultV1

            return EvidenceResultV1.model_construct(schema_version=1)

    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=HostileEvidenceGate()
    ).execute(request, runtime=runtime, effect=effect)
    assert result.code == EnforcementCodeV1.EVIDENCE_MISMATCH.value
    assert result.invoked is False
    assert trace == []


def test_adapter_candidate_binds_actual_implementation_and_dependencies() -> None:
    _, _, active_policy, _ = _active_components()
    manifest = _manifest(_noop_handler, policy_id=active_policy.policy.policy_id)
    registry = AdapterRegistryV1()
    registry.register(operation_id="document.read", handler=_noop_handler)
    candidate = SignedAdapterCandidateV1(
        manifest=manifest,
        implementation=b"substituted-adapter",
        dependencies=(b"dependency-a", b"dependency-b"),
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("signer"),
        signature=b"valid-signature",
    )
    with pytest.raises(EnforcementError, match="PEP-ADAPTER-INTEGRITY"):
        activate_adapter(candidate, registry=registry, verifier=Verifier(), policy=active_policy)


def test_post_activation_handler_code_drift_never_executes_drifted_code() -> None:
    original_code = _original_code_handler.__code__
    evidence_trace: list[str] = []
    effect, request, active_policy, runtime = _active_components(handler=_original_code_handler)
    adapter, _, _ = _activated_adapter(active_policy, _original_code_handler)
    try:
        _original_code_handler.__code__ = _drifted_code_handler.__code__
        result = PolicyEnforcementPointV1(
            PolicyDecisionPointV1(active_policy),
            adapter,
            evidence_gate=PermitGate(evidence_trace),
        ).execute(request, runtime=runtime, effect=effect)
    finally:
        _original_code_handler.__code__ = original_code

    assert result.code == EnforcementCodeV1.EXECUTED.value


def test_closure_controlled_handler_is_rejected_before_registration() -> None:
    delegated = _noop_handler

    def closure_handler(value: bytes):
        return delegated(value)

    registry = AdapterRegistryV1()
    with pytest.raises(EnforcementError, match="PEP-HANDLER-MALFORMED"):
        registry.register(operation_id="document.read", handler=closure_handler)


def test_mutable_global_delegate_handler_is_rejected_before_registration() -> None:
    registry = AdapterRegistryV1()
    with pytest.raises(EnforcementError, match="PEP-HANDLER-MALFORMED"):
        registry.register(operation_id="document.read", handler=_mutable_global_delegate_handler)


def test_nested_code_cannot_hide_mutable_global_delegate() -> None:
    registry = AdapterRegistryV1()
    with pytest.raises(EnforcementError, match="PEP-HANDLER-MALFORMED"):
        registry.register(operation_id="document.read", handler=_nested_mutable_delegate_handler)


def test_one_lease_cannot_execute_against_two_adapter_manifest_versions() -> None:
    effect, request, active_policy, runtime = _active_components()
    v1, _, _ = _activated_adapter(active_policy, _noop_handler)

    v2_manifest = _manifest(_noop_handler, policy_id=active_policy.policy.policy_id).model_copy(
        update={"adapter_version": "2.0.0"}
    )
    v2_registry = AdapterRegistryV1()
    v2_registry.register(operation_id="document.read", handler=_noop_handler)
    v2 = activate_adapter(
        SignedAdapterCandidateV1(
            manifest=v2_manifest,
            implementation=b"fixture-adapter-binary",
            dependencies=(b"dependency-a", b"dependency-b"),
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=_digest("adapter-signer"),
            signature=b"valid-signature",
        ),
        registry=v2_registry,
        verifier=Verifier(),
        policy=active_policy,
    )

    v1_result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), v1, evidence_gate=PermitGate([])
    ).execute(request, runtime=runtime, effect=effect)
    v2_result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), v2, evidence_gate=PermitGate([])
    ).execute(request, runtime=runtime, effect=effect)

    assert v1_result.code == EnforcementCodeV1.EXECUTED.value
    assert v2_result.code == EnforcementCodeV1.ADAPTER_MISMATCH.value


def test_attacker_bundle_metadata_and_exact_execute_lease_do_not_authorize_load() -> None:
    effect = create_effect_input(b'{"entrypoint":"main"}')
    bundle_input = BundleEvidenceInput(
        artifact=b'{"artifact":"attacker"}',
        signature_evidence=b'{"signature":"attacker"}',
        version_claims=b'{"version":"9.9.9"}',
        publisher_claims=b'{"publisher":"attacker"}',
        dependencies=(b'{"dependency":"attacker"}',),
        policy_binding_claims=b'{"policy":"claimed"}',
    )
    envelope = create_ingress(
        content=b'{"bundle":"attacker-authored"}',
        media_type=MediaTypeV1.APPLICATION_JSON,
        source_kind=IngressKindV1.BUNDLE_METADATA,
        source_identity=b'{"source":"attacker"}',
        source_claims=b'{"claim":"self-signed"}',
        capture_kind=TransformKindV1.INGRESS_CAPTURE,
        capture_implementation=b'{"name":"fixture","version":"1"}',
        capture_parameters=b'{"mode":"exact"}',
        bundle=bundle_input,
    )
    identity = IdentityBindingV1(
        user_digest=_digest("user"),
        agent_digest=_digest("agent"),
        device_digest=_digest("device"),
        session_digest=_digest("session"),
    )
    policy_id = _digest("policy-id", DecisionDigestDomain.POLICY_ID)
    bundle_handler = _noop_handler
    base_manifest = _manifest(bundle_handler, policy_id=policy_id)
    manifest = AdapterManifestV1(
        **(
            base_manifest.model_dump()
            | {
                "operations": (
                    ManifestOperationV1(
                        operation_id="bundle.execute",
                        capability=CapabilityV1.EXECUTE.value,
                        handler_digest=digest_handler_implementation(bundle_handler),
                    ),
                )
            }
        )
    )
    manifest_digest = digest_decision_bytes(
        canonical_manifest_bytes(manifest), domain=DecisionDigestDomain.ADAPTER_MANIFEST
    )
    assert envelope.bundle is not None
    bundle_publisher = _digest("attacker-bundle-publisher")
    bundle_manifest = ExecutableBundleManifestV1(
        schema_version=1,
        bundle_id="attacker.bundle",
        bundle_version="9.9.9",
        publisher_identity=bundle_publisher,
        artifact_digest=envelope.bundle.artifact_digest,
        signature_evidence_digest=envelope.bundle.signature_evidence_digest,
        version_claims_digest=envelope.bundle.version_claims_digest,
        publisher_claims_digest=envelope.bundle.publisher_claims_digest,
        dependency_digests=envelope.bundle.dependency_digests,
        policy_binding_claims_digest=envelope.bundle.policy_binding_claims_digest,
        policy_id=policy_id,
        policy_generation=7,
        adapter_manifest_digest=manifest_digest,
    )
    bundle_manifest_digest = digest_decision_bytes(
        canonical_bundle_manifest_bytes(bundle_manifest),
        domain=DecisionDigestDomain.BUNDLE_MANIFEST,
    )
    operation = OperationBindingV1(
        adapter_id="fixture.adapter",
        adapter_manifest_digest=manifest_digest,
        operation_id="bundle.execute",
        capability=CapabilityV1.EXECUTE.value,
        arguments_digest=effect.arguments_digest,
        destination_digest=_digest("destination"),
        bundle_manifest_digest=bundle_manifest_digest,
    )
    scope = _digest("scope", DecisionDigestDomain.DATA_SCOPE)
    purpose = _digest("purpose", DecisionDigestDomain.PURPOSE)
    binding = compute_request_binding_digest(
        identity=identity,
        envelope=envelope,
        data_scope_digest=scope,
        operation=operation,
        purpose_digest=purpose,
    )
    lease = create_capability_lease(
        lease_id=_digest("bundle-lease", DecisionDigestDomain.LEASE_ID),
        request_binding_digest=binding,
        policy_id=policy_id,
        policy_generation=7,
        not_before=100,
        expires_at=300,
        revocation_generation=3,
    )
    policy = PolicyBundleV1(
        schema_version=1,
        policy_id=policy_id,
        policy_generation=7,
        valid_from=50,
        valid_until=400,
        rule_set_digest=_digest("rules", DecisionDigestDomain.RULE_SET),
        trust_root_digest=_digest("root", DecisionDigestDomain.TRUST_ROOT),
        critical_floor_version="atk-critical-v1",
        revocation_generation=3,
        grants=(PolicyGrantV1(lease_digest=lease.lease_digest),),
        revoked_lease_digests=(),
    )
    active_policy = activate_policy(
        SignedPolicyCandidateV1(
            policy=policy,
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=_digest("policy-signer"),
            signature=b"valid-signature",
        ),
        verifier=Verifier(),
    )
    runtime = activate_runtime(
        SignedRuntimeCandidateV1(
            runtime=RuntimeSnapshotV1(
                schema_version=1,
                health=AuthorityHealthV1.HEALTHY.value,
                trusted_time=200,
                trusted_time_valid_until=250,
                policy_generation_floor=7,
                policy_digest_at_floor=active_policy.policy_digest,
                revocation_generation_floor=3,
                revocation_digest_at_floor=active_policy.revocation_digest,
            ),
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=_digest("runtime-signer"),
            signature=b"valid-signature",
        ),
        verifier=Verifier(),
    )
    request = create_decision_request(
        identity=identity,
        envelope=envelope,
        data_scope_digest=scope,
        operation=operation,
        purpose_digest=purpose,
        lease=lease,
    )
    registry = AdapterRegistryV1()
    registry.register(operation_id="bundle.execute", handler=bundle_handler)
    adapter = activate_adapter(
        SignedAdapterCandidateV1(
            manifest=manifest,
            implementation=b"fixture-adapter-binary",
            dependencies=(b"dependency-a", b"dependency-b"),
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=_digest("adapter-signer"),
            signature=b"valid-signature",
        ),
        registry=registry,
        verifier=Verifier(),
        policy=active_policy,
    )
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=PermitGate([])
    ).execute(request, runtime=runtime, effect=effect)

    assert result.code != EnforcementCodeV1.EXECUTED.value
    assert result.invoked is False

    activated_bundle = activate_executable_bundle(
        SignedExecutableBundleCandidateV1(
            manifest=bundle_manifest,
            evidence=bundle_input,
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=bundle_publisher,
            signature=b"valid-signature",
        ),
        verifier=Verifier(),
        policy=active_policy,
        adapter_manifest_digest=adapter.manifest_digest,
    )
    permitted = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy),
        adapter,
        evidence_gate=PermitGate([]),
        executable_bundles=(activated_bundle,),
    ).execute(request, runtime=runtime, effect=effect)
    assert permitted.code == EnforcementCodeV1.EXECUTED.value
    assert permitted.invoked is True


def test_executable_bundle_activation_verifies_exact_evidence_publisher_and_binding() -> None:
    _, _, active_policy, _ = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    evidence_input = BundleEvidenceInput(
        artifact=b'{"artifact":"trusted"}',
        signature_evidence=b'{"signature":"supply-chain"}',
        version_claims=b'{"version":"1.0.0"}',
        publisher_claims=b'{"publisher":"fixture"}',
        dependencies=(b'{"dependency":"fixture"}',),
        policy_binding_claims=b'{"policy_generation":7}',
    )
    evidence = bundle_evidence_from_input(evidence_input)
    publisher = _digest("bundle-publisher")
    manifest = ExecutableBundleManifestV1(
        schema_version=1,
        bundle_id="fixture.bundle",
        bundle_version="1.0.0",
        publisher_identity=publisher,
        artifact_digest=evidence.artifact_digest,
        signature_evidence_digest=evidence.signature_evidence_digest,
        version_claims_digest=evidence.version_claims_digest,
        publisher_claims_digest=evidence.publisher_claims_digest,
        dependency_digests=evidence.dependency_digests,
        policy_binding_claims_digest=evidence.policy_binding_claims_digest,
        policy_id=active_policy.policy.policy_id,
        policy_generation=active_policy.policy.policy_generation,
        adapter_manifest_digest=adapter.manifest_digest,
    )
    verifier = Verifier()
    activated = activate_executable_bundle(
        SignedExecutableBundleCandidateV1(
            manifest=manifest,
            evidence=evidence_input,
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=publisher,
            signature=b"valid-signature",
        ),
        verifier=verifier,
        policy=active_policy,
        adapter_manifest_digest=adapter.manifest_digest,
    )

    assert activated.evidence == evidence
    assert verifier.calls[0][0] is ArtifactKindV1.BUNDLE
    assert verifier.calls[0][3] == canonical_bundle_manifest_bytes(manifest)


def test_activated_handler_map_and_pep_bindings_are_immutable() -> None:
    _, _, active_policy, _ = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    with pytest.raises(TypeError):
        adapter._handlers["document.read"] = lambda _: None  # type: ignore[index]
    pep = PolicyEnforcementPointV1(PolicyDecisionPointV1(active_policy), adapter)
    with pytest.raises(EnforcementError, match="PEP-IMMUTABLE"):
        pep._adapter = adapter  # type: ignore[misc]
    with pytest.raises(EnforcementError, match="PEP-IMMUTABLE"):
        del pep._adapter  # type: ignore[misc]
    with pytest.raises(EnforcementError, match="PEP-ADAPTER-IMMUTABLE"):
        del adapter.manifest  # type: ignore[misc]


def test_enforcement_serializer_rejects_self_digest_forgery() -> None:
    effect, request, active_policy, runtime = _active_components()
    adapter, _, _ = _activated_adapter(active_policy, _noop_handler)
    result = PolicyEnforcementPointV1(
        PolicyDecisionPointV1(active_policy), adapter, evidence_gate=PermitGate([])
    ).execute(request, runtime=runtime, effect=effect)
    forged = result.model_copy(update={"code": EnforcementCodeV1.INTERNAL_ERROR.value})
    with pytest.raises(EnforcementError, match="PEP-RESULT-INTEGRITY"):
        serialize_enforcement_result(forged)


def test_effect_byte_cap_accepts_cap_and_rejects_cap_plus_one() -> None:
    at_cap = b'"' + b"a" * (MAX_EFFECT_BYTES - 2) + b'"'
    assert len(create_effect_input(at_cap).arguments) == MAX_EFFECT_BYTES
    with pytest.raises(EnforcementError, match="PEP-EFFECT-MALFORMED"):
        create_effect_input(b'"' + b"a" * (MAX_EFFECT_BYTES - 1) + b'"')


def test_manifest_operation_and_dependency_caps_are_exact() -> None:
    handler_digest = digest_handler_implementation(_noop_handler)
    operations = tuple(
        ManifestOperationV1(
            operation_id=f"operation.{index:04d}",
            capability=CapabilityV1.READ.value,
            handler_digest=handler_digest,
        )
        for index in range(MAX_MANIFEST_OPERATIONS)
    )
    dependencies = tuple(
        sorted(
            digest_adapter_dependency(f"dep-{index}".encode())
            for index in range(MAX_ADAPTER_DEPENDENCIES)
        )
    )
    manifest = AdapterManifestV1(
        schema_version=1,
        adapter_id="fixture.adapter",
        adapter_version="1.0.0",
        implementation_digest=digest_adapter_implementation(b"adapter"),
        dependency_digests=dependencies,
        policy_id=_digest("policy-id"),
        policy_generation=7,
        operations=operations,
    )
    assert len(manifest.operations) == MAX_MANIFEST_OPERATIONS
    assert len(manifest.dependency_digests) == MAX_ADAPTER_DEPENDENCIES
    with pytest.raises(EnforcementError, match="PEP-MANIFEST-MALFORMED"):
        AdapterManifestV1(
            **(
                manifest.model_dump()
                | {
                    "operations": operations
                    + (
                        ManifestOperationV1(
                            operation_id="operation.plus-one",
                            capability=CapabilityV1.READ.value,
                            handler_digest=handler_digest,
                        ),
                    )
                }
            )
        )
    with pytest.raises(EnforcementError, match="PEP-MANIFEST-MALFORMED"):
        AdapterManifestV1(
            **(
                manifest.model_dump()
                | {"dependency_digests": dependencies + (_digest("plus-one-dependency"),)}
            )
        )


def test_enforcement_module_has_no_network_clock_or_environment_imports() -> None:
    path = Path(__file__).parents[1] / "src/mcp_warden/policy_enforcement.py"
    tree = ast.parse(path.read_text())
    forbidden = {"requests", "httpx", "socket", "urllib", "time", "datetime", "os"}
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert not imports & forbidden
