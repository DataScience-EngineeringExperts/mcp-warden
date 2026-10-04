"""Measured handler identity rejects executable constants and unsupported runtimes."""

from __future__ import annotations

import marshal
from types import FunctionType, SimpleNamespace

import pytest

from mcp_warden import handler_identity
from mcp_warden.handler_identity import HandlerIdentityError, canonical_handler_bytes


def _noop(_: bytes) -> None:
    return None


def _constant_handler(value: object) -> FunctionType:
    return FunctionType(_noop.__code__.replace(co_consts=(None, value)), {})


@pytest.mark.parametrize("nested", [False, True])
def test_marshaled_executable_constant_is_rejected(nested: bool) -> None:
    payload = marshal.dumps(compile("pass", "reviewed-fixture", "exec"))
    value = (payload,) if nested else payload
    with pytest.raises(HandlerIdentityError, match="^PEP-HANDLER-MALFORMED$"):
        canonical_handler_bytes(_constant_handler(value))


def test_marshaled_code_in_referenced_immutable_global_is_rejected() -> None:
    namespace: dict[str, object] = {}
    exec("def handler(value):\n    return BLOB\n", namespace)
    namespace["BLOB"] = marshal.dumps(compile("pass", "reviewed-fixture", "exec"))
    with pytest.raises(HandlerIdentityError, match="^PEP-HANDLER-MALFORMED$"):
        canonical_handler_bytes(namespace["handler"])


@pytest.mark.parametrize("container", [tuple, list, dict])
def test_marshaled_container_cannot_hide_nested_code(container) -> None:
    code = compile("pass", "reviewed-fixture", "exec")
    value = {"nested": code} if container is dict else container((code,))
    with pytest.raises(HandlerIdentityError, match="^PEP-HANDLER-MALFORMED$"):
        canonical_handler_bytes(_constant_handler(marshal.dumps(value)))


def test_marshaled_recursive_noncode_data_terminates_and_remains_supported() -> None:
    value: list[object] = []
    value.append(value)
    assert canonical_handler_bytes(_constant_handler(marshal.dumps(value)))


@pytest.mark.parametrize("value", [b"ordinary bytes", b"", marshal.dumps((1, "data"))])
def test_normal_byte_constants_remain_supported(value: bytes) -> None:
    assert canonical_handler_bytes(_constant_handler(value))


@pytest.mark.parametrize(
    "implementation,version",
    [("cpython", (3, 10)), ("cpython", (3, 14)), ("cpython", (4, 0)), ("pypy", (3, 12))],
)
def test_unsupported_handler_interpreter_fails_closed(monkeypatch, implementation, version) -> None:
    reported = SimpleNamespace(
        implementation=SimpleNamespace(name=implementation), version_info=version
    )
    monkeypatch.setattr(handler_identity, "sys", reported, raising=False)
    with pytest.raises(HandlerIdentityError, match="^PEP-HANDLER-MALFORMED$"):
        canonical_handler_bytes(_noop)


@pytest.mark.parametrize("version", [(3, 11), (3, 12), (3, 13)])
def test_supported_handler_interpreter_contract(monkeypatch, version) -> None:
    reported = SimpleNamespace(implementation=SimpleNamespace(name="cpython"), version_info=version)
    monkeypatch.setattr(handler_identity, "sys", reported, raising=False)
    assert canonical_handler_bytes(_noop)


def test_oversized_byte_constants_fail_before_marshal_parsing(monkeypatch) -> None:
    called = False

    def forbidden_parser(_: bytes):
        nonlocal called
        called = True
        raise AssertionError("must reject cap before parsing")

    monkeypatch.setattr(handler_identity.marshal, "loads", forbidden_parser)
    handler = _constant_handler(b"x" * (handler_identity.MAX_HANDLER_IDENTITY_BYTES + 1))
    with pytest.raises(HandlerIdentityError, match="^PEP-HANDLER-MALFORMED$"):
        canonical_handler_bytes(handler)
    assert called is False
