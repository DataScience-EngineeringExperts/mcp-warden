"""Pure revalidation of sealed DSE-716 activation inputs reused by DSE-717."""

from mcp_warden.decision_models import (
    DecisionDigestDomain,
    PolicyBundleV1,
    RuntimeSnapshotV1,
    digest_decision_bytes,
)
from mcp_warden.policy_decision import (
    ActivatedPolicyV1,
    ActivatedRuntimeV1,
    _has_activation_marker,
    canonical_policy_bytes,
    canonical_runtime_bytes,
)
from mcp_warden.receipt_kernel import ReceiptError, canonical, exact


def validate_policy_activation(policy):
    failed = False
    try:
        if not _has_activation_marker(policy, ActivatedPolicyV1):
            raise ValueError
        exact(policy.policy, PolicyBundleV1)
        digest = digest_decision_bytes(
            canonical_policy_bytes(policy.policy), domain=DecisionDigestDomain.POLICY
        )
        revoked = canonical(
            {
                "generation": policy.policy.revocation_generation,
                "revoked_lease_digests": list(policy.policy.revoked_lease_digests),
            }
        )
        revocation_digest = digest_decision_bytes(revoked, domain=DecisionDigestDomain.REVOCATION)
        if (
            type(policy.policy_digest) is not str
            or type(policy.revocation_digest) is not str
            or digest != policy.policy_digest
            or revocation_digest != policy.revocation_digest
        ):
            raise ValueError
    except Exception:
        failed = True
    if failed:
        raise ReceiptError("RCT-INTEGRITY") from None


def validate_runtime_activation(runtime):
    failed = False
    try:
        if not _has_activation_marker(runtime, ActivatedRuntimeV1):
            raise ValueError
        exact(runtime.runtime, RuntimeSnapshotV1)
        digest = digest_decision_bytes(
            canonical_runtime_bytes(runtime.runtime), domain=DecisionDigestDomain.RUNTIME
        )
        if type(runtime.runtime_digest) is not str or digest != runtime.runtime_digest:
            raise ValueError
    except Exception:
        failed = True
    if failed:
        raise ReceiptError("RCT-INTEGRITY") from None
