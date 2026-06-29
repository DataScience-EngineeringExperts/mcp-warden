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
    """Best-effort dict view of an MCP SDK model across pydantic versions."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump()  # pydantic v2
    if hasattr(obj, "dict"):
        return obj.dict()  # pydantic v1 fallback
    return dict(obj)


async def _capture_async(command: str, args: list[str], timeout_s: float) -> CapturedSurface:
    """Inner async capture; wrapped with a timeout by :func:`capture_surface`."""
    # StdioServerParameters passes command+args as an argv array to the OS; the
    # MCP SDK does NOT spawn through a shell. This is the §10.4 guarantee.
    params = StdioServerParameters(command=command, args=list(args))

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            protocol_version = str(getattr(init_result, "protocolVersion", "") or "")

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


async def _list_tools(session: ClientSession) -> list[CapturedTool]:
    """Run ``tools/list`` and normalize results. Empty list if unsupported."""
    try:
        result = await session.list_tools()
    except Exception as exc:  # server may not declare the tools capability
        logger.info("tools/list unavailable: %s", exc)
        return []
    out: list[CapturedTool] = []
    for tool in getattr(result, "tools", []) or []:
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
    """Run ``resources/list`` and normalize results. Empty list if unsupported."""
    try:
        result = await session.list_resources()
    except Exception as exc:
        logger.info("resources/list unavailable: %s", exc)
        return []
    out: list[CapturedResource] = []
    for res in getattr(result, "resources", []) or []:
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
    """Run ``prompts/list`` and normalize results. Empty list if unsupported."""
    try:
        result = await session.list_prompts()
    except Exception as exc:
        logger.info("prompts/list unavailable: %s", exc)
        return []
    out: list[CapturedPrompt] = []
    for prompt in getattr(result, "prompts", []) or []:
        data = _model_dump(prompt)
        arguments = data.get("arguments")
        norm_args: list[dict[str, Any]] | None = None
        if isinstance(arguments, list):
            norm_args = [a if isinstance(a, dict) else _model_dump(a) for a in arguments]
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
            protocol_version = str(getattr(init_result, "protocolVersion", "") or "")

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
