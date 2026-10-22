"""MCP capture client — stdio and HTTP/SSE transports.

Spawns the target MCP server **over stdio as an argv array, never via a shell**
(WARDEN_LOCK_SCHEMA.md §10.4), *or* connects to an already-running server over
HTTP/SSE (Streamable HTTP), then runs ``initialize`` + ``tools/list`` +
``resources/list`` + ``prompts/list`` and captures the declared surface.

A server that hangs, crashes, or exits nonzero must produce a clear
``CaptureError``, not a traceback.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio
from mcp import ClientSession as SDKClientSession
from mcp import StdioServerParameters
from mcp import types as mcp_types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from pydantic import BaseModel, Field, field_validator

from .models import (
    CapturedPrompt,
    CapturedResource,
    CapturedSurface,
    CapturedTool,
)

logger = logging.getLogger("mcp_warden.capture")

#: Hard wall-clock timeout for the entire capture handshake (seconds).
DEFAULT_TIMEOUT_S = 30.0


class CaptureError(Exception):
    """Raised when the MCP server cannot be captured cleanly.

    Carries a human-readable message suitable for CLI display; never a raw
    traceback from the child process.
    """


def _nested_capture_error(exc: BaseException) -> CaptureError | None:
    """The first :class:`CaptureError` inside an SDK task group's ``ExceptionGroup``.

    A ``CaptureError`` raised inside the SDK's ``async with`` blocks reaches the
    caller wrapped by anyio's task group; unwrapping it keeps the specific reason
    (which section failed, and why) instead of a generic "unhandled errors" line.
    """
    if isinstance(exc, CaptureError):
        return exc
    for inner in getattr(exc, "exceptions", ()) or ():
        found = _nested_capture_error(inner)
        if found is not None:
            return found
    return None


class _WireToolsResult(BaseModel):
    """Preserve complete tool objects before SDK ToolAnnotations projection."""

    tools: list[dict[str, Any]]
    next_cursor: str | None = Field(default=None, alias="nextCursor")

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, tools):
        # Retain SDK validation without retaining its lossy projection. In
        # particular a malformed later page must never produce a partial pin.
        for tool in tools:
            mcp_types.Tool.model_validate(tool)
        return tools


class ClientSession(SDKClientSession):
    """Capture declarations, including fields unknown to the installed SDK.

    SDK 2.x's ToolAnnotations discards extension keys. A raw result model also
    preserves explicit nulls inside annotations and schemas. This session never
    calls tools, so SDK output-validation caches and tool filtering are not used.
    """

    async def list_tools(self, *, params=None):
        request = mcp_types.ListToolsRequest(params=params)
        # SDK 1.x wraps requests in a RootModel; SDK 2.x uses a union alias.
        if isinstance(mcp_types.ClientRequest, type):
            request = mcp_types.ClientRequest(request)
        return await self.send_request(request, _WireToolsResult)


def _model_dump(obj: Any) -> dict[str, Any]:
    """Wire-format dict view of an MCP SDK model: camelCase keys, no SDK-default nulls.

    Both flags are load-bearing for digest stability across the ``mcp`` major:
    the 2.x SDK renamed model fields to snake_case (``input_schema``,
    ``mime_type``, ``protocol_version``) while the protocol keys stayed camelCase,
    so a plain ``model_dump()`` under 2.x returns no ``inputSchema`` at all; and
    2.x added optional fields (``PromptArgument.title``) whose ``None`` default the
    server never sent, which would otherwise leak into ``arguments_hash``.
    ``by_alias=True, exclude_none=True`` reproduces what was on the wire and is
    identical on 1.x and 2.x (tests/test_capture_model_dump.py).
    """
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump(by_alias=True, exclude_none=True)  # pydantic v2
    if hasattr(obj, "dict"):
        return obj.dict(by_alias=True, exclude_none=True)  # pydantic v1 fallback
    return dict(obj)


def _protocol_version(init_result: Any) -> str:
    """Read the negotiated protocol version whatever the SDK calls the field.

    mcp 1.x exposes ``InitializeResult.protocolVersion``; 2.x renamed it to
    ``protocol_version``. Attribute access (not a model dump) keeps this total for
    the duck-typed session objects the HTTP tests inject.
    """
    for attr in ("protocolVersion", "protocol_version"):
        value = getattr(init_result, attr, None)
        if isinstance(value, str) and value:
            return value
    return ""


async def _capture_async(command: str, args: list[str], timeout_s: float) -> CapturedSurface:
    """Inner async capture; wrapped with a timeout by :func:`capture_surface`."""
    # StdioServerParameters passes command+args as an argv array to the OS; the
    # MCP SDK does NOT spawn through a shell. This is the §10.4 guarantee.
    params = StdioServerParameters(command=command, args=list(args))

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            protocol_version = _protocol_version(init_result)
            declared = _declared_capabilities(init_result)

            tools = await _list_tools(session, declared=declared["tools"])
            resources = await _list_resources(session, declared=declared["resources"])
            prompts = await _list_prompts(session, declared=declared["prompts"])

    return CapturedSurface(
        command=command,
        args=list(args),
        protocol_version=protocol_version,
        tools=tools,
        resources=resources,
        prompts=prompts,
    )


#: Hard cap on ``nextCursor`` pages per list call. A cursor chain that never
#: terminates is a server that never declares a surface; refuse rather than pin
#: a truncated one (CSO review of #105, F3).
MAX_LIST_PAGES = 256

#: The protocol field set of a prompt argument. Always emitted — ``null`` when the
#: server omitted the optional — because that is the byte shape the 1.x SDK's
#: ``model_dump()`` produced and every released warden hashed into
#: ``arguments_hash``. Keys outside this set (2.x's ``title``, ``_meta``) are shed
#: when null so an SDK-side default never enters the digest (CSO review of #105, F1).
_PROMPT_ARGUMENT_KEYS = ("name", "description", "required")


def _normalize_prompt_argument(arg: Any) -> dict[str, Any]:
    """Return the digest-stable dict form of a prompt argument (see ``_PROMPT_ARGUMENT_KEYS``)."""
    data = arg if isinstance(arg, dict) else _model_dump(arg)
    norm: dict[str, Any] = {key: data.get(key) for key in _PROMPT_ARGUMENT_KEYS}
    norm.update({k: v for k, v in data.items() if k not in _PROMPT_ARGUMENT_KEYS and v is not None})
    return norm


def _next_cursor(result: Any) -> str | None:
    """The ``nextCursor`` of a list result, on either SDK line; ``None`` when the page is last."""
    for attr in ("nextCursor", "next_cursor"):
        value = getattr(result, attr, None)
        if isinstance(value, str) and value:
            return value
    return None


#: JSON-RPC "Method not found" — the only error an undeclared collection may answer with.
_METHOD_NOT_FOUND = -32601

#: ``ServerCapabilities`` field gating each surface section.
_CAPABILITY_KEYS = ("tools", "resources", "prompts")


def _declared_capabilities(init_result: Any) -> dict[str, bool]:
    """Which surface sections the server declared in its ``initialize`` result.

    Unknown capabilities (no ``capabilities`` object at all) are treated as
    declared, so a failing list call fails CLOSED rather than being read as
    "this server has no such section" (DSE-1538).
    """
    caps = getattr(init_result, "capabilities", None)
    if caps is None:
        return dict.fromkeys(_CAPABILITY_KEYS, True)
    if isinstance(caps, dict):
        return {key: caps.get(key) is not None for key in _CAPABILITY_KEYS}
    # A field the installed SDK does not expose at all is unknown, not undeclared.
    return {key: not hasattr(caps, key) or getattr(caps, key) is not None for key in _CAPABILITY_KEYS}


def _is_method_not_found(exc: BaseException) -> bool:
    """True for an MCP error carrying JSON-RPC -32601, on either SDK line.

    mcp 1.x raises ``McpError`` and 2.x ``MCPError``; both carry ``.error.code``.
    """
    return getattr(getattr(exc, "error", None), "code", None) == _METHOD_NOT_FOUND


async def _list_all(method: str, list_fn: Any, key: str, *, declared: bool = True) -> list[Any] | None:
    """Drain every ``nextCursor`` page of a ``list_*`` call.

    Returns ``None`` (an empty section for the caller) only when the server did
    NOT declare the capability and the first page answers "Method not found".
    Every other failure fails CLOSED with :class:`CaptureError` — a declared
    section that errors, an undeclared one that errors any other way, or any
    later page — because a lock missing a section that ``check`` then compares
    as empty would hide a broken or evasive server (DSE-1538). A partial surface
    must never be pinned.
    """
    try:
        result = await list_fn()
    except Exception as exc:
        if not declared and _is_method_not_found(exc):
            logger.info("%s not supported (capability not declared): %s", method, exc)
            return None
        state = "declared" if declared else "undeclared"
        raise CaptureError(f"{method} failed for a {state} capability: {exc}") from exc
    items: list[Any] = list(getattr(result, key, []) or [])
    cursor = _next_cursor(result)
    pages = 1
    while cursor is not None:
        pages += 1
        if pages > MAX_LIST_PAGES:
            raise CaptureError(
                f"{method}: cursor chain exceeded {MAX_LIST_PAGES} pages; "
                "refusing to pin a surface that never terminates"
            )
        try:
            result = await list_fn(params=mcp_types.PaginatedRequestParams(cursor=cursor))
        except Exception as exc:
            raise CaptureError(f"{method}: page {pages} failed after a partial surface: {exc}") from exc
        items.extend(getattr(result, key, []) or [])
        cursor = _next_cursor(result)
    return items


async def _list_tools(session: ClientSession, *, declared: bool = True) -> list[CapturedTool]:
    """Run ``tools/list`` (all pages) and normalize results. Empty list if undeclared and unsupported."""
    items = await _list_all("tools/list", session.list_tools, "tools", declared=declared)
    if items is None:
        return []
    out: list[CapturedTool] = []
    for tool in items:
        data = _model_dump(tool)
        out.append(
            CapturedTool(
                name=str(data.get("name", "")),
                description=data.get("description"),
                input_schema=data.get("inputSchema"),
                annotations=data.get("annotations"),
                output_schema=data.get("outputSchema"),
            )
        )
    return out


async def _list_resources(session: ClientSession, *, declared: bool = True) -> list[CapturedResource]:
    """Run ``resources/list`` (all pages) and normalize results. Empty list if undeclared and unsupported."""
    items = await _list_all("resources/list", session.list_resources, "resources", declared=declared)
    if items is None:
        return []
    out: list[CapturedResource] = []
    for res in items:
        data = _model_dump(res)
        out.append(
            CapturedResource(
                uri=str(data.get("uri", "")),
                name=data.get("name"),
                description=data.get("description"),
                mime_type=data.get("mimeType"),
            )
        )
    return out


async def _list_prompts(session: ClientSession, *, declared: bool = True) -> list[CapturedPrompt]:
    """Run ``prompts/list`` (all pages) and normalize results. Empty list if undeclared and unsupported."""
    items = await _list_all("prompts/list", session.list_prompts, "prompts", declared=declared)
    if items is None:
        return []
    out: list[CapturedPrompt] = []
    for prompt in items:
        data = _model_dump(prompt)
        arguments = data.get("arguments")
        norm_args: list[dict[str, Any]] | None = None
        if isinstance(arguments, list):
            norm_args = [_normalize_prompt_argument(a) for a in arguments]
        out.append(
            CapturedPrompt(
                name=str(data.get("name", "")),
                description=data.get("description"),
                arguments=norm_args,
            )
        )
    return out


async def capture_surface(
    command: str,
    args: list[str],
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> CapturedSurface:
    """Spawn an MCP server over stdio and capture its declared surface.

    Args:
        command: ``argv[0]`` of the server launch (no shell expansion performed).
        args: Remaining argv, order preserved.
        timeout_s: Wall-clock timeout for the whole handshake.

    Returns:
        The :class:`CapturedSurface` with tools/resources/prompts.

    Raises:
        CaptureError: If the server hangs (timeout), crashes, exits nonzero, or
            the MCP handshake fails. The message is CLI-safe.
    """
    logger.debug("spawning MCP server: command=%r args=%r", command, args)
    try:
        with anyio.fail_after(timeout_s):
            return await _capture_async(command, args, timeout_s)
    except TimeoutError as exc:
        raise CaptureError(
            f"MCP server '{command}' did not complete the handshake within {timeout_s:.0f}s "
            f"(it may be hung or waiting on input)."
        ) from exc
    except CaptureError:
        raise
    except FileNotFoundError as exc:
        raise CaptureError(f"MCP server command not found: '{command}' ({exc}).") from exc
    except Exception as exc:
        nested = _nested_capture_error(exc)
        if nested is not None:
            logger.debug("capture failed inside the SDK task group: %r", exc)
            raise nested from (nested.__cause__ or exc)
        # Covers nonzero exit, broken pipe, protocol error, decode failure, etc.
        raise CaptureError(
            f"Failed to capture MCP server '{command}': {type(exc).__name__}: {exc}"
        ) from exc


def capture_surface_sync(
    command: str,
    args: list[str],
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> CapturedSurface:
    """Synchronous wrapper around :func:`capture_surface` for the CLI.

    Args:
        command: ``argv[0]`` of the server launch.
        args: Remaining argv.
        timeout_s: Wall-clock timeout.

    Returns:
        The captured surface.

    Raises:
        CaptureError: On any capture failure (see :func:`capture_surface`).
    """
    return anyio.run(capture_surface, command, args, timeout_s)


async def _capture_http_async(url: str, timeout_s: float) -> CapturedSurface:
    """Inner async HTTP/SSE capture; wrapped with a timeout by :func:`capture_surface_http`."""
    async with streamable_http_client(url) as (read_stream, write_stream, _get_session_id):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            protocol_version = _protocol_version(init_result)
            declared = _declared_capabilities(init_result)

            tools = await _list_tools(session, declared=declared["tools"])
            resources = await _list_resources(session, declared=declared["resources"])
            prompts = await _list_prompts(session, declared=declared["prompts"])

    return CapturedSurface(
        url=url,
        protocol_version=protocol_version,
        tools=tools,
        resources=resources,
        prompts=prompts,
    )


async def capture_surface_http(
    url: str,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> CapturedSurface:
    """Connect to a running MCP server over HTTP/SSE and capture its declared surface.

    Connects to ``url`` using the Streamable HTTP transport (MCP SDK
    ``streamable_http_client``). The server must already be running and
    reachable; no process is spawned.

    Args:
        url: HTTP/HTTPS endpoint of the MCP server (e.g. ``https://example.com/mcp``).
        timeout_s: Wall-clock timeout for the whole handshake.

    Returns:
        The :class:`CapturedSurface` with ``url`` set and ``command``/``args`` empty.

    Raises:
        CaptureError: On timeout, connection error, or MCP handshake failure.
    """
    logger.debug("connecting to MCP server over HTTP/SSE: url=%r", url)
    try:
        with anyio.fail_after(timeout_s):
            return await _capture_http_async(url, timeout_s)
    except TimeoutError as exc:
        raise CaptureError(
            f"MCP server at '{url}' did not complete the handshake within {timeout_s:.0f}s "
            f"(it may be unreachable or hung)."
        ) from exc
    except CaptureError:
        raise
    except Exception as exc:
        nested = _nested_capture_error(exc)
        if nested is not None:
            logger.debug("capture failed inside the SDK task group: %r", exc)
            raise nested from (nested.__cause__ or exc)
        raise CaptureError(
            f"Failed to capture MCP server at '{url}': {type(exc).__name__}: {exc}"
        ) from exc


def capture_surface_http_sync(
    url: str,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> CapturedSurface:
    """Synchronous wrapper around :func:`capture_surface_http` for the CLI.

    Args:
        url: HTTP/HTTPS endpoint URL.
        timeout_s: Wall-clock timeout.

    Returns:
        The captured surface.

    Raises:
        CaptureError: On any capture failure.
    """
    return anyio.run(capture_surface_http, url, timeout_s)
