"""Client-neutral data preparation. Accepts bytes, never an SDK client."""

import json

import rfc8785

from mcp_warden.capability_models import CapabilityError
from mcp_warden.mcp_capability_adapter import prepare_mcp_call
from mcp_warden.policy_enforcement import create_effect_input


def prepare_client_call(name, arguments, intent, *, candidates, pdp, adapter, runtime):
    """Prepare one exact named operation from canonical JSON object bytes.

    The generated ID is correlation-only. All selection and binding checks are
    shared with MCP preparation; no callable or transport handle can be returned.
    """
    failed = False
    try:
        if type(name) is not str or not name or len(name) > 256:
            raise ValueError
        effect = create_effect_input(arguments)
        parsed = json.loads(effect.arguments)
        if type(parsed) is not dict:
            raise ValueError
        payload = rfc8785.dumps({
            "jsonrpc": "2.0", "id": 0, "method": "tools/call",
            "params": {"name": name, "arguments": parsed},
        })
    except Exception:
        failed = True
    if failed:
        raise CapabilityError("CAP-WIRE-REJECTED") from None
    return prepare_mcp_call(
        payload, intent, candidates=candidates, pdp=pdp, adapter=adapter, runtime=runtime,
    )
