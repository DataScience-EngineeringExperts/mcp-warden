from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_warden.artifact_payload import canonical_artifact_payload
from mcp_warden.artifact_trust import (
    Ed25519ArtifactVerifierV1,
    TrustedArtifactKeyV1,
    artifact_signing_bytes,
    roots_digest,
)
from mcp_warden.content_models import BundleEvidenceInput
from mcp_warden.decision_models import (
    ArtifactKindV1,
    DecisionError,
    DecisionVerdictV1,
    SignedPolicyCandidateV1,
    SignedRuntimeCandidateV1,
    VerificationAlgorithmV1,
)
from mcp_warden.executable_bundle import (
    BundleActivationError,
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
    canonical_policy_bytes,
    canonical_runtime_bytes,
)
from mcp_warden.policy_enforcement import (
    AdapterRegistryV1,
    EnforcementCodeV1,
    PolicyEnforcementPointV1,
    SignedAdapterCandidateV1,
    activate_adapter,
    canonical_manifest_bytes,
)
from tests.test_policy_enforcement import _active_components, _manifest, _noop_handler


def real_components():
    governance = Ed25519PrivateKey.generate()
    runtime_key = Ed25519PrivateKey.generate()
    human = TrustedArtifactKeyV1(
        governance.public_key().public_bytes_raw(),
        (ArtifactKindV1.ADAPTER, ArtifactKindV1.BUNDLE, ArtifactKindV1.POLICY),
    )
    runtime_root = TrustedArtifactKeyV1(
        runtime_key.public_key().public_bytes_raw(), (ArtifactKindV1.RUNTIME,)
    )
    roots = (human, runtime_root)
    verifier = Ed25519ArtifactVerifierV1(roots, expected_roots_digest=roots_digest(roots))

    def sign(kind, payload):
        root, private = (
            (runtime_root, runtime_key) if kind is ArtifactKindV1.RUNTIME else (human, governance)
        )
        assert canonical_artifact_payload(kind, payload) == payload
        return dict(
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=root.signer_identity,
            signature=private.sign(artifact_signing_bytes(kind, root.signer_identity, payload)),
        )

    effect, request, original_policy, original_runtime = _active_components()
    policy = activate_policy(
        SignedPolicyCandidateV1(
            policy=original_policy.policy,
            **sign(ArtifactKindV1.POLICY, canonical_policy_bytes(original_policy.policy)),
        ),
        verifier=verifier,
    )
    runtime = activate_runtime(
        SignedRuntimeCandidateV1(
            runtime=original_runtime.runtime,
            **sign(ArtifactKindV1.RUNTIME, canonical_runtime_bytes(original_runtime.runtime)),
        ),
        verifier=verifier,
    )
    manifest = _manifest(_noop_handler, policy_id=policy.policy.policy_id)
    registry = AdapterRegistryV1()
    registry.register(operation_id="document.read", handler=_noop_handler)
    candidate = SignedAdapterCandidateV1(
        manifest=manifest,
        implementation=b"fixture-adapter-binary",
        dependencies=(b"dependency-a", b"dependency-b"),
        **sign(ArtifactKindV1.ADAPTER, canonical_manifest_bytes(manifest)),
    )
    adapter = activate_adapter(candidate, registry=registry, verifier=verifier, policy=policy)
    return effect, request, policy, runtime, adapter, verifier, sign


def test_real_policy_runtime_and_adapter_activate_but_default_evidence_blocks():
    effect, request, policy, runtime, adapter, _, _ = real_components()
    pdp = PolicyDecisionPointV1(policy)
    decision = pdp.evaluate(request, runtime=runtime)
    assert decision.verdict == DecisionVerdictV1.ALLOW.value
    result = PolicyEnforcementPointV1(pdp, adapter).execute(request, runtime=runtime, effect=effect)
    assert result.code == EnforcementCodeV1.EVIDENCE_UNAVAILABLE.value
    assert not result.invoked


def test_policy_mutation_and_cross_role_signature_fail_activation():
    _, _, policy, runtime, _, verifier, sign = real_components()
    signature = sign(ArtifactKindV1.POLICY, canonical_policy_bytes(policy.policy))
    changed = policy.policy.model_copy(update={"policy_generation": 8})
    with pytest.raises(DecisionError, match="PDP-POLICY-VERIFICATION"):
        activate_policy(SignedPolicyCandidateV1(policy=changed, **signature), verifier=verifier)
    signature = sign(ArtifactKindV1.POLICY, canonical_policy_bytes(policy.policy))
    with pytest.raises(DecisionError, match="PDP-RUNTIME-VERIFICATION"):
        activate_runtime(
            SignedRuntimeCandidateV1(runtime=runtime.runtime, **signature), verifier=verifier
        )


def test_real_bundle_signature_still_requires_exact_dependency_closure():
    _, _, policy, _, adapter, verifier, sign = real_components()
    source = BundleEvidenceInput(
        artifact=b'{"artifact":"reviewed"}',
        signature_evidence=b'{"signature":"reviewed"}',
        version_claims=b'{"version":"1.0.0"}',
        publisher_claims=b'{"publisher":"fixture"}',
        dependencies=(b'{"dependency":"fixture"}',),
        policy_binding_claims=b'{"policy_generation":7}',
    )
    evidence = bundle_evidence_from_input(source)
    # Publisher identity is the enrolled signing-key identity, not a claim from the bundle.
    signer = sign(ArtifactKindV1.POLICY, canonical_policy_bytes(policy.policy))["signer_identity"]
    manifest = ExecutableBundleManifestV1(
        schema_version=1,
        bundle_id="fixture.bundle",
        bundle_version="1.0.0",
        publisher_identity=signer,
        artifact_digest=evidence.artifact_digest,
        signature_evidence_digest=evidence.signature_evidence_digest,
        version_claims_digest=evidence.version_claims_digest,
        publisher_claims_digest=evidence.publisher_claims_digest,
        dependency_digests=evidence.dependency_digests,
        policy_binding_claims_digest=evidence.policy_binding_claims_digest,
        policy_id=policy.policy.policy_id,
        policy_generation=policy.policy.policy_generation,
        adapter_manifest_digest=adapter.manifest_digest,
    )
    signed = sign(ArtifactKindV1.BUNDLE, canonical_bundle_manifest_bytes(manifest))
    candidate = SignedExecutableBundleCandidateV1(manifest=manifest, evidence=source, **signed)
    active = activate_executable_bundle(
        candidate, verifier=verifier, policy=policy, adapter_manifest_digest=adapter.manifest_digest
    )
    assert active.evidence == evidence
    changed = BundleEvidenceInput(
        artifact=source.artifact,
        signature_evidence=source.signature_evidence,
        version_claims=source.version_claims,
        publisher_claims=source.publisher_claims,
        dependencies=(b'{"dependency":"substituted"}',),
        policy_binding_claims=source.policy_binding_claims,
    )
    with pytest.raises(BundleActivationError, match="PEP-BUNDLE-INTEGRITY"):
        activate_executable_bundle(
            SignedExecutableBundleCandidateV1(manifest=manifest, evidence=changed, **signed),
            verifier=verifier,
            policy=policy,
            adapter_manifest_digest=adapter.manifest_digest,
        )
