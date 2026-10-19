"""Pure exact-grant selection. No issuance, execution, IO or policy mutation."""

from mcp_warden.capability_models import (
    MAX_CANDIDATES,
    CapabilityError,
    CapabilityIntentV1,
    PreparedCapabilityV1,
    ToolProjectionV1,
    validate_exact,
)
from mcp_warden.content_envelope import to_public_bytes
from mcp_warden.decision_models import (
    DecisionDigestDomain,
    DecisionRequestV1,
    digest_decision_bytes,
)
from mcp_warden.policy_decision import PolicyDecisionPointV1
from mcp_warden.policy_enforcement import (
    PolicyEnforcementPointV1,
    canonical_manifest_bytes,
)


def _context_matches(intent, request):
    return (
        intent.identity == request.identity
        and to_public_bytes(intent.envelope) == to_public_bytes(request.envelope)
        and intent.capability == request.operation.capability
        and intent.data_scope_digest == request.data_scope_digest
        and intent.purpose_digest == request.purpose_digest
        and intent.destination_digest == request.operation.destination_digest
        and intent.arguments_digest == request.operation.arguments_digest
    )


def _strictly_narrower(left, right):
    # Opaque digests have no ordering. Only identical bound operations may be
    # compared, and only by strict half-open interval containment.
    a, b = left.lease, right.lease
    return (
        a.request_binding_digest == b.request_binding_digest
        and left.operation == right.operation
        and a.not_before >= b.not_before
        and a.expires_at <= b.expires_at
        and (a.not_before > b.not_before or a.expires_at < b.expires_at)
    )


def select_capability(intent, *, candidates, pdp, adapter, runtime):
    """Prepare the unique temporal minimum among currently eligible exact grants.

    Args:
        intent: Untrusted desired context bound to host-authenticated identities.
        candidates: Exact tuple of previously issued requests, not approval claims.
        pdp: Existing activated-policy PDP; evaluated without new policy or keys.
        adapter: Existing activated adapter; no handler is invoked or retained.
        runtime: Explicit activated trusted-time snapshot, never caller wall time.

    Returns:
        Advisory immutable request data, or None on no candidate or ambiguity.
        This result cannot replace fresh PEP authorization before an effect.

    Raises:
        CapabilityError: A closed code for malformed input or unavailable authority.
    """
    validate_exact(intent, CapabilityIntentV1)
    if type(candidates) is not tuple or len(candidates) > MAX_CANDIDATES:
        raise CapabilityError()
    for candidate in candidates:
        validate_exact(candidate, DecisionRequestV1)
    if len({c.request_digest for c in candidates}) != len(candidates):
        raise CapabilityError()
    failed = False
    try:
        if type(pdp) is not PolicyDecisionPointV1:
            raise ValueError
        # Reuse the existing sealed adapter/policy binding check, never execute.
        boundary = PolicyEnforcementPointV1(pdp, adapter)
        manifest = boundary.manifest
        digest = digest_decision_bytes(
            canonical_manifest_bytes(manifest), domain=DecisionDigestDomain.ADAPTER_MANIFEST,
        )
        if digest != boundary.manifest_digest:
            raise ValueError
        operations = {item.operation_id: item.capability for item in manifest.operations}
        if set(operations) != set(boundary.registration_operations):
            raise ValueError
        eligible = []
        for candidate in candidates:
            operation = candidate.operation
            if (
                operation.adapter_id != manifest.adapter_id
                or operation.adapter_manifest_digest != boundary.manifest_digest
                or operations.get(operation.operation_id) != operation.capability
                or not _context_matches(intent, candidate)
            ):
                continue
            decision = pdp.evaluate(candidate, runtime=runtime)
            if decision.verdict == "allow":
                eligible.append(candidate)
        if not eligible:
            return None
        # A minimum must be strictly below *every* other candidate. This linear
        # tournament + verification avoids a quadratic adversarial antichain.
        best = eligible[0]
        for candidate in eligible[1:]:
            if _strictly_narrower(candidate, best):
                best = candidate
        if any(other is not best and not _strictly_narrower(best, other) for other in eligible):
            return None
        return PreparedCapabilityV1(
            request=best, policy_digest=pdp.policy_digest, runtime_digest=runtime.runtime_digest,
        )
    except Exception:
        failed = True
    if failed:
        raise CapabilityError("CAP-AUTHORITY-UNAVAILABLE") from None


def project_tools(intent, *, candidates, pdp, adapter, runtime):
    """Return zero or one minimal descriptor after the same closed selection."""
    prepared = select_capability(
        intent, candidates=candidates, pdp=pdp, adapter=adapter, runtime=runtime,
    )
    if prepared is None:
        return ()
    operation = prepared.request.operation
    return (ToolProjectionV1(name=operation.operation_id, capability=operation.capability),)
