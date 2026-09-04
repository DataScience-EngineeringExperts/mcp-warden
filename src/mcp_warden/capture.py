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
from mcp import ClientSession, StdioServerParameters
from mcp import types as mcp_types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

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

            tools = await _list_tools(session)
            resources = await _list_resources(session)
            prompts = await _list_prompts(session)

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


async def _list_all(method: str, list_fn: Any, key: str) -> list[Any] | None:
    """Drain every ``nextCursor`` page of a ``list_*`` call.

    Returns ``None`` when the FIRST page is unavailable, ``[]``-equivalent for the
    caller. That first-page swallow is a deliberate fail-OPEN: a server without the
    capability answers the request with an error, and its surface section is
    recorded as empty rather than aborting the capture. It cannot distinguish
    "no capability" from "broken server"; tightening that (capability-aware
    error handling) is DSE-1538, and hashing the Tool fields capture still
    projects away (annotations, outputSchema) is DSE-1539. Every LATER page fails CLOSED —
    a partial surface must never be pinned.
    """
    try:
        result = await list_fn()
    except Exception as exc:  # fail-open on the first page only (see docstring)
        logger.info("%s unavailable: %s", method, exc)
        return None
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


async def _list_tools(session: ClientSession) -> list[CapturedTool]:
    """Run ``tools/list`` (all pages) and normalize results. Empty list if unsupported."""
    items = await _list_all("tools/list", session.list_tools, "tools")
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
            )
        )
    return out


async def _list_resources(session: ClientSession) -> list[CapturedResource]:
    """Run ``resources/list`` (all pages) and normalize results. Empty list if unsupported."""
    items = await _list_all("resources/list", session.list_resources, "resources")
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


async def _list_prompts(session: ClientSession) -> list[CapturedPrompt]:
    """Run ``prompts/list`` (all pages) and normalize results. Empty list if unsupported."""
    items = await _list_all("prompts/list", session.list_prompts, "prompts")
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

            tools = await _list_tools(session)
            resources = await _list_resources(session)
            prompts = await _list_prompts(session)

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
