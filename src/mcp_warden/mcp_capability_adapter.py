"""Bounded canonical MCP request preparation, without a transport or raw sink."""

import json

import rfc8785

from mcp_warden.capability_broker import project_tools, select_capability
from mcp_warden.capability_models import CapabilityError
from mcp_warden.policy_enforcement import MAX_EFFECT_BYTES, create_effect_input

# The envelope includes only bounded protocol metadata in addition to effect bytes.
MAX_WIRE_BYTES = MAX_EFFECT_BYTES + 4096
MAX_RPC_ID = 256


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _parse(payload, method):
    invalid = False
    message = None
    try:
        if type(payload) is not bytes or len(payload) > MAX_WIRE_BYTES:
            raise ValueError
        message = json.loads(payload, object_pairs_hook=_unique)
        if type(message) is not dict or rfc8785.dumps(message) != payload:
            raise ValueError
        if set(message) != {"jsonrpc", "id", "method", "params"}:
            raise ValueError
        if message["jsonrpc"] != "2.0" or message["method"] != method:
            raise ValueError
        rpc_id = message["id"]
        if type(rpc_id) is str:
            if not rpc_id or len(rpc_id.encode("utf-8")) > MAX_RPC_ID:
                raise ValueError
        elif type(rpc_id) is not int or not -(2**53 - 1) <= rpc_id <= 2**53 - 1:
            raise ValueError
        if type(message["params"]) is not dict:
            raise ValueError
    except Exception:
        invalid = True
    if invalid:
        raise CapabilityError("CAP-WIRE-REJECTED") from None
    return message


def prepare_mcp_call(payload, intent, *, candidates, pdp, adapter, runtime):
    """Validate one canonical tools/call against fresh exact-grant selection.

    The MCP name is exactly the signed manifest operation ID. IDs are correlation
    data only. Returns advisory request data and performs no execution or signing.
    """
    message = _parse(payload, "tools/call")
    params = message["params"]
    if (
        set(params) != {"name", "arguments"}
        or type(params["name"]) is not str
        or type(params["arguments"]) is not dict
    ):
        raise CapabilityError("CAP-WIRE-REJECTED")
    failed = False
    try:
        effect = create_effect_input(rfc8785.dumps(params["arguments"]))
    except Exception:
        failed = True
    if failed:
        raise CapabilityError("CAP-WIRE-REJECTED") from None
    prepared = select_capability(
        intent, candidates=candidates, pdp=pdp, adapter=adapter, runtime=runtime,
    )
    if prepared is None:
        return None
    operation = prepared.request.operation
    if params["name"] != operation.operation_id or effect.arguments_digest != operation.arguments_digest:
        return None
    return prepared


def project_mcp_tool_list(payload, intent, *, candidates, pdp, adapter, runtime):
    """Project synthetic descriptors for a canonical tools/list request.

    This is not a live MCP server response; there is no invented upstream schema.
    Pagination/extra metadata are unsupported and rejected, never forwarded.
    """
    message = _parse(payload, "tools/list")
    if message["params"]:
        raise CapabilityError("CAP-WIRE-REJECTED")
    return project_tools(intent, candidates=candidates, pdp=pdp, adapter=adapter, runtime=runtime)
