"""Synthetic activated authority for pure broker tests; never production providers."""

from mcp_warden.capability_models import CapabilityIntentV1
from mcp_warden.decision_models import (
    DecisionDigestDomain,
    PolicyGrantV1,
    SignedPolicyCandidateV1,
    VerificationAlgorithmV1,
    digest_decision_bytes,
)
from mcp_warden.policy_decision import (
    PolicyDecisionPointV1,
    activate_policy,
    compute_request_binding_digest,
    create_capability_lease,
    create_decision_request,
)
from mcp_warden.policy_enforcement import (
    AdapterRegistryV1,
    SignedAdapterCandidateV1,
    activate_adapter,
    canonical_manifest_bytes,
)
from tests.test_policy_decision import _activate_runtime
from tests.test_policy_enforcement import (
    Verifier,
    _active_components,
    _digest,
    _manifest,
    _noop_handler,
)


def intent_for(request):
    return CapabilityIntentV1(
        identity=request.identity,
        envelope=request.envelope,
        capability=request.operation.capability,
        data_scope_digest=request.data_scope_digest,
        purpose_digest=request.purpose_digest,
        destination_digest=request.operation.destination_digest,
        arguments_digest=request.operation.arguments_digest,
    )


def fixture(*, windows=((100, 300),), grant=True, revoked=False, now=200, operation_ids=None):
    effect, seed, policy, _ = _active_components()
    operation_ids = operation_ids or ("document.read",) * len(windows)
    manifest = _manifest(_noop_handler, policy_id=policy.policy.policy_id)
    base_operation = manifest.operations[0]
    manifest = manifest.model_copy(update={"operations": tuple(
        base_operation.model_copy(update={"operation_id": name})
        for name in sorted(set(operation_ids))
    )})
    manifest_digest = digest_decision_bytes(
        canonical_manifest_bytes(manifest), domain=DecisionDigestDomain.ADAPTER_MANIFEST,
    )
    candidates = []
    for index, (start, end) in enumerate(windows):
        operation = seed.operation.model_copy(update={
            "adapter_manifest_digest": manifest_digest, "operation_id": operation_ids[index],
        })
        binding = compute_request_binding_digest(
            identity=seed.identity, envelope=seed.envelope, data_scope_digest=seed.data_scope_digest,
            operation=operation, purpose_digest=seed.purpose_digest,
        )
        lease = create_capability_lease(
            lease_id=_digest(f"lease-{index}"),
            request_binding_digest=binding,
            policy_id=seed.lease.policy_id,
            policy_generation=seed.lease.policy_generation,
            not_before=start,
            expires_at=end,
            revocation_generation=seed.lease.revocation_generation,
        )
        candidates.append(create_decision_request(
            identity=seed.identity, envelope=seed.envelope,
            data_scope_digest=seed.data_scope_digest, operation=operation,
            purpose_digest=seed.purpose_digest, lease=lease,
        ))
    grants = tuple(sorted(
        (PolicyGrantV1(lease_digest=c.lease.lease_digest) for c in candidates),
        key=lambda g: g.lease_digest,
    )) if grant else ()
    bundle = policy.policy.model_copy(update={
        "grants": grants,
        "revoked_lease_digests": tuple(sorted(c.lease.lease_digest for c in candidates))
        if revoked else (),
    })
    policy = activate_policy(SignedPolicyCandidateV1(
        policy=bundle, algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=_digest("signer"),
        signature=b"valid-signature",
    ), verifier=Verifier())
    runtime, _ = _activate_runtime(policy, now=now)
    registry = AdapterRegistryV1()
    for name in sorted(set(operation_ids)):
        registry.register(operation_id=name, handler=_noop_handler)
    adapter = activate_adapter(SignedAdapterCandidateV1(
        manifest=manifest, implementation=b"fixture-adapter-binary",
        dependencies=(b"dependency-a", b"dependency-b"),
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1, signer_identity=_digest("adapter-signer"),
        signature=b"valid-signature",
    ), registry=registry, verifier=Verifier(), policy=policy)
    return intent_for(seed), tuple(candidates), {
        "pdp": PolicyDecisionPointV1(policy), "adapter": adapter, "runtime": runtime,
    }, effect
