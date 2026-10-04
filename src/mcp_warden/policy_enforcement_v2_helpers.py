"""Pure structural preflight, before hostile nested inputs are consumed."""

from mcp_warden.decision_models import DecisionRequestV1
from mcp_warden.policy_decision import _request_preflight
from mcp_warden.policy_enforcement import EffectInputV1, create_effect_input


def preflight(adapter, bundles, request, effect):
    valid = False
    try:
        valid = type(request) is DecisionRequestV1 and _request_preflight(request)
    except Exception:
        pass
    if not valid:
        return "PEP-REQUEST-MALFORMED", False, False
    valid_effect = False
    try:
        valid_effect = (
            type(effect) is EffectInputV1 and create_effect_input(effect.arguments) == effect
        )
    except Exception:
        pass
    if not valid_effect:
        return "PEP-EFFECT-MALFORMED", True, False
    op = request.operation
    if effect.arguments_digest != op.arguments_digest:
        return "PEP-EFFECT-DIGEST-MISMATCH", True, True
    if (
        op.adapter_id != adapter.manifest.adapter_id
        or op.adapter_manifest_digest != adapter.manifest_digest
    ):
        return "PEP-ADAPTER-MISMATCH", True, True
    if op.capability == "execute":
        bundle = bundles.get(op.bundle_manifest_digest)
        if bundle is None:
            return "PEP-BUNDLE-UNAVAILABLE", True, True
        if request.envelope.bundle != bundle.evidence:
            return "PEP-BUNDLE-MISMATCH", True, True
    known = any(
        item.operation_id == op.operation_id and item.capability == op.capability
        for item in adapter.manifest.operations
    )
    return (None if known else "PEP-OPERATION-UNKNOWN"), True, True
