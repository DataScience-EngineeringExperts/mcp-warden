"""Bounded properties for the deterministic DSE-716 PDP/PEP boundary."""

from __future__ import annotations

import rfc8785
from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_warden.decision_models import (
    AuthorityHealthV1,
    DecisionDigestDomain,
    DecisionReasonV1,
    DecisionVerdictV1,
    RuntimeSnapshotV1,
    SignedRuntimeCandidateV1,
    VerificationAlgorithmV1,
    digest_decision_bytes,
)
from mcp_warden.policy_decision import (
    PolicyDecisionPointV1,
    activate_runtime,
    serialize_decision,
)
from mcp_warden.policy_enforcement import EnforcementError, create_effect_input
from tests.test_policy_enforcement import Verifier, _active_components


@settings(max_examples=75)
@given(
    st.sampled_from(("user_digest", "agent_digest", "device_digest", "session_digest")),
    st.binary(min_size=1, max_size=64),
)
def test_any_identity_substitution_fails_closed(field: str, marker: bytes) -> None:
    _, request, active_policy, runtime = _active_components()
    forged_identity = request.identity.model_copy(
        update={field: digest_decision_bytes(marker, domain=DecisionDigestDomain.CLAIM)}
    )
    forged = request.model_copy(update={"identity": forged_identity})
    first = PolicyDecisionPointV1(active_policy).evaluate(forged, runtime=runtime)
    second = PolicyDecisionPointV1(active_policy).evaluate(forged, runtime=runtime)
    assert first == second
    assert first.verdict == DecisionVerdictV1.DENY.value
    assert first.reason == DecisionReasonV1.REQUEST_INTEGRITY.value


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=2_048))
def test_arbitrary_effect_bytes_are_canonical_or_fail_code_only(data: bytes) -> None:
    try:
        effect = create_effect_input(data)
    except EnforcementError as error:
        assert error.code.startswith("PEP-")
        assert error.__cause__ is None
        assert error.__context__ is None
    else:
        assert rfc8785.dumps(__import__("json").loads(data)) == effect.arguments


@settings(max_examples=50)
@given(st.integers(min_value=0, max_value=600))
def test_explicit_trusted_time_has_deterministic_validity_boundary(now: int) -> None:
    _, request, active_policy, _ = _active_components()
    runtime_model = RuntimeSnapshotV1(
        schema_version=1,
        health=AuthorityHealthV1.HEALTHY.value,
        trusted_time=now,
        trusted_time_valid_until=250,
        policy_generation_floor=7,
        policy_digest_at_floor=active_policy.policy_digest,
        revocation_generation_floor=3,
        revocation_digest_at_floor=active_policy.revocation_digest,
    )
    runtime = activate_runtime(
        SignedRuntimeCandidateV1(
            runtime=runtime_model,
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=digest_decision_bytes(
                b"runtime-signer", domain=DecisionDigestDomain.CLAIM
            ),
            signature=b"valid-signature",
        ),
        verifier=Verifier(),
    )
    first = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=runtime)
    second = PolicyDecisionPointV1(active_policy).evaluate(request, runtime=runtime)
    assert serialize_decision(first) == serialize_decision(second)
    assert (first.verdict == DecisionVerdictV1.ALLOW.value) is (100 <= now < 250)


@settings(max_examples=75)
@given(st.text(min_size=1, max_size=64))
def test_raw_identity_marker_never_appears_in_decision(marker: str) -> None:
    _, request, active_policy, runtime = _active_components()
    planted = ("PLANTED-DSE716-" + marker).encode("utf-8")
    forged_identity = request.identity.model_copy(
        update={"user_digest": digest_decision_bytes(planted, domain=DecisionDigestDomain.CLAIM)}
    )
    forged = request.model_copy(update={"identity": forged_identity})
    decision = PolicyDecisionPointV1(active_policy).evaluate(forged, runtime=runtime)
    assert planted not in serialize_decision(decision)
