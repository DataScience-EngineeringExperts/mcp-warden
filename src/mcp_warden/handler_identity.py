"""Mechanically bind and freeze supported Python adapter handlers."""

from __future__ import annotations

import builtins
import dis
import marshal
from types import CodeType, FunctionType

from mcp_warden.decision_models import DecisionDigestDomain, digest_decision_bytes


class HandlerIdentityError(Exception):
    """Stable code-only handler identity failure."""

    def __init__(self, code: str = "PEP-HANDLER-MALFORMED") -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code


MAX_HANDLER_IDENTITY_BYTES = 256 * 1024


def _encode_component(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _immutable_global_bytes(value: object) -> bytes | None:
    if value is None:
        return b"none"
    if type(value) is bool:
        return b"bool:" + (b"1" if value else b"0")
    if type(value) is int:
        return b"int:" + str(value).encode("ascii")
    if type(value) is float:
        return b"float:" + value.hex().encode("ascii")
    if type(value) is str:
        return b"str:" + value.encode("utf-8")
    if type(value) is bytes:
        return b"bytes:" + value
    if type(value) is tuple:
        parts: list[bytes] = []
        for item in value:
            encoded = _immutable_global_bytes(item)
            if encoded is None:
                return None
            parts.append(_encode_component(encoded))
        return b"tuple:" + b"".join(parts)
    if type(value) is frozenset:
        parts = []
        for item in value:
            encoded = _immutable_global_bytes(item)
            if encoded is None:
                return None
            parts.append(encoded)
        return b"frozenset:" + b"".join(_encode_component(item) for item in sorted(parts))
    return None


def _canonical_handler_bytes(handler: object, seen: frozenset[int]) -> bytes:
    """Return interpreter-native code evidence for an exact Python function.

    V1 intentionally accepts only closure-free, default-free ``FunctionType``
    handlers. Direct global function dependencies are included recursively in
    the signed digest and cloned into the activated snapshot. Referenced data
    globals must be recursively immutable and are digest bound.
    """
    if (
        type(handler) is not FunctionType
        or handler.__closure__ is not None
        or handler.__defaults__ is not None
        or handler.__kwdefaults__ is not None
    ):
        raise HandlerIdentityError() from None
    if id(handler) in seen:
        raise HandlerIdentityError() from None
    next_seen = seen | {id(handler)}
    try:
        if any(type(item) is CodeType for item in handler.__code__.co_consts):
            raise HandlerIdentityError() from None
        forbidden_opcodes = {
            "DELETE_DEREF",
            "DELETE_GLOBAL",
            "IMPORT_FROM",
            "IMPORT_NAME",
            "LOAD_BUILD_CLASS",
            "STORE_DEREF",
            "STORE_GLOBAL",
        }
        if any(item.opname in forbidden_opcodes for item in dis.get_instructions(handler)):
            raise HandlerIdentityError() from None
        code = marshal.dumps(handler.__code__)
        dependencies: list[bytes] = []
        for name in sorted(set(handler.__code__.co_names)):
            if name.startswith("__") and name.endswith("__"):
                raise HandlerIdentityError() from None
            if name in handler.__globals__:
                dependency = handler.__globals__[name]
            elif callable(vars(builtins).get(name)):
                raise HandlerIdentityError() from None
            else:
                continue
            if type(dependency) is FunctionType:
                dependency_payload = _canonical_handler_bytes(dependency, next_seen)
                dependencies.append(
                    _encode_component(name.encode("utf-8")) + _encode_component(dependency_payload)
                )
                continue
            immutable_payload = _immutable_global_bytes(dependency)
            if immutable_payload is None:
                raise HandlerIdentityError() from None
            dependencies.append(
                _encode_component(name.encode("utf-8")) + _encode_component(immutable_payload)
            )
        payload = b"mcp-warden/handler/v1\x00" + _encode_component(code) + b"".join(dependencies)
    except Exception:
        raise HandlerIdentityError() from None
    if not payload or len(payload) > MAX_HANDLER_IDENTITY_BYTES:
        raise HandlerIdentityError() from None
    return payload


def canonical_handler_bytes(handler: object) -> bytes:
    return _canonical_handler_bytes(handler, frozenset())


def digest_handler(handler: object) -> str:
    return digest_decision_bytes(
        canonical_handler_bytes(handler),
        domain=DecisionDigestDomain.HANDLER_IMPLEMENTATION,
    )


def freeze_handler(handler: object) -> FunctionType:
    """Clone a function so later mutation of the caller's object cannot drift it."""
    canonical_handler_bytes(handler)
    try:
        frozen_globals = dict(handler.__globals__)
        for name in handler.__code__.co_names:
            dependency = frozen_globals.get(name)
            if type(dependency) is FunctionType:
                frozen_globals[name] = freeze_handler(dependency)
        frozen = FunctionType(
            handler.__code__,
            frozen_globals,
            handler.__name__,
            None,
            None,
        )
    except Exception:
        raise HandlerIdentityError() from None
    return frozen
