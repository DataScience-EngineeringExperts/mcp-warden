import ast
from pathlib import Path

import pytest
import rfc8785

from mcp_warden.capability_models import CapabilityError, serialize_prepared_capability
from mcp_warden.client_capability_adapter import prepare_client_call
from mcp_warden.mcp_capability_adapter import (
    MAX_WIRE_BYTES,
    prepare_mcp_call,
    project_mcp_tool_list,
)
from mcp_warden.policy_enforcement import ActivatedAdapterV1
from tests.capability_fixtures import fixture


def wire(*, name="document.read", arguments=None, rpc_id=7, method="tools/call", params=None):
    return rfc8785.dumps({
        "jsonrpc": "2.0", "id": rpc_id, "method": method,
        "params": params if params is not None else {
            "name": name, "arguments": {"document_id": "42"} if arguments is None else arguments,
        },
    })


def test_mcp_client_parity_and_ids_are_not_authority(monkeypatch):
    intent, candidates, authority, effect = fixture()

    def forbidden(*args, **kwargs):
        pytest.fail("preparation must not access the executable sink")

    monkeypatch.setattr(ActivatedAdapterV1, "_handler", forbidden)
    first = prepare_mcp_call(wire(), intent, candidates=candidates, **authority)
    second = prepare_mcp_call(wire(rpc_id="other"), intent, candidates=candidates, **authority)
    client = prepare_client_call(
        "document.read", effect.arguments, intent, candidates=candidates, **authority,
    )
    assert first is not None and first == second == client
    assert b"document_id" not in serialize_prepared_capability(first)


@pytest.mark.parametrize("change", [
    {"name": "document.alias"}, {"name": "hidden.execute"},
    {"arguments": {"document_id": "43"}},
])
def test_name_substitution_and_arguments_mismatch_prepare_nothing(change):
    intent, candidates, authority, _ = fixture()
    assert prepare_mcp_call(wire(**change), intent, candidates=candidates, **authority) is None


@pytest.mark.parametrize("payload", [
    b'{}', b'[]', b'{"jsonrpc":"2.0","id":1,"id":2}',
    b'{"jsonrpc": "2.0"}', b'NaN', b'{"x":NaN}', b'x' * (MAX_WIRE_BYTES + 1),
    wire(method="resources/read"), wire(method="prompts/get"),
    wire(method="notifications/cancelled"), wire(params={"name": "document.read"}),
    wire(params={"name": "document.read", "arguments": {}, "_meta": {"approved": True}}),
    wire(rpc_id=True), wire(rpc_id=None), wire(rpc_id=""), wire(rpc_id="x" * 257),
    wire(arguments=[]), wire(params={"name": 123, "arguments": {}}),
])
def test_malformed_extra_unimplemented_requests_rejected_without_raw_payload(payload):
    intent, candidates, authority, _ = fixture()
    with pytest.raises(CapabilityError) as caught:
        prepare_mcp_call(payload, intent, candidates=candidates, **authority)
    assert str(caught.value) == "CAP-WIRE-REJECTED"


def test_list_projection_is_minimal_context_specific_and_never_forwards_cursors():
    intent, candidates, authority, _ = fixture()
    payload = wire(method="tools/list", params={})
    projected = project_mcp_tool_list(payload, intent, candidates=candidates, **authority)
    assert [t.model_dump() for t in projected] == [{"name": "document.read", "capability": "read"}]
    assert project_mcp_tool_list(payload, intent, candidates=(), **authority) == ()
    for params in ({"cursor": "PLANTED-SECRET"}, {"_meta": {}}, {"cursor": None}):
        with pytest.raises(CapabilityError) as caught:
            project_mcp_tool_list(
                wire(method="tools/list", params=params), intent, candidates=candidates, **authority,
            )
        assert "PLANTED" not in str(caught.value)


@pytest.mark.parametrize("name,arguments", [
    (object(), b'{}'), ("x", object()), ("x", b'{ "x":1}'),
    ("x", b'[]'), ("x" * 257, b'{}'), ("x", b'{"a":1,"a":2}'),
])
def test_clients_and_noncanonical_bytes_are_rejected(name, arguments):
    intent, candidates, authority, _ = fixture()
    with pytest.raises(CapabilityError):
        prepare_client_call(name, arguments, intent, candidates=candidates, **authority)


def test_preparation_modules_have_no_io_signing_or_dynamic_execution_imports():
    root = Path(__file__).resolve().parents[1] / "src/mcp_warden"
    forbidden = {"socket", "subprocess", "httpx", "httpx2", "requests", "mcp", "cryptography"}
    for module in ("capability_models", "capability_broker", "mcp_capability_adapter", "client_capability_adapter"):
        tree = ast.parse((root / f"{module}.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name.split(".")[0] not in forbidden for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in forbidden
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"open", "eval", "exec", "__import__"}


def test_preparation_uses_revalidated_nested_models_and_serialization():
    intent, candidates, authority, _ = fixture()
    request = candidates[0]
    # A copy can hold serialized nested data even in a frozen Pydantic model.
    copied = request.model_copy(update={"operation": request.operation.model_dump()})
    copied_intent = intent.model_copy(update={"identity": intent.identity.model_dump()})
    baseline = prepare_mcp_call(wire(), intent, candidates=candidates, **authority)
    actual = prepare_mcp_call(wire(), copied_intent, candidates=(copied,), **authority)
    assert actual == baseline
    assert actual is not None
    assert type(actual.request.operation) is type(request.operation)
    serialized_copy = actual.model_copy(update={"request": actual.request.model_dump()})
    assert serialize_prepared_capability(serialized_copy) == serialize_prepared_capability(actual)
