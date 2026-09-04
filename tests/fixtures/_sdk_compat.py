"""Build a stdio fixture ``Server`` that works on BOTH the mcp 1.x and 2.x SDKs.

mcp 1.x registers handlers with decorators (``@server.list_tools()``); the 2.x
low-level ``Server`` dropped those and takes ``on_list_tools=``-style callbacks
that return the full ``*Result`` models (DSE-1261, the reason ``mcp<2`` was
capped in #92). The fixture servers declare their surface as plain lists and let
this shim do the wiring, so one fixture file serves both SDK lines and the
committed ``*.warden.lock`` digests stay byte-identical across the bump.

Detection is by capability, not version: the 1.x class has the ``list_tools``
decorator factory, the 2.x class does not.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

ToolsFn = Callable[[], list[types.Tool]]
ResourcesFn = Callable[[], list[types.Resource]]
PromptsFn = Callable[[], list[types.Prompt]]
CallToolFn = Callable[[str, dict[str, Any]], list[types.TextContent]]

_LEGACY_DECORATOR_API = hasattr(Server, "list_tools")


def build_server(
    name: str,
    *,
    tools: ToolsFn | None = None,
    resources: ResourcesFn | None = None,
    prompts: PromptsFn | None = None,
    call_tool: CallToolFn | None = None,
) -> Server:
    """Return a low-level ``Server`` exposing exactly the given surface."""
    if _LEGACY_DECORATOR_API:
        return _build_1x(name, tools, resources, prompts, call_tool)
    return _build_2x(name, tools, resources, prompts, call_tool)


def _build_1x(name, tools, resources, prompts, call_tool) -> Server:  # type: ignore[no-untyped-def]
    server = Server(name)
    if tools is not None:

        async def _list_tools() -> list[types.Tool]:
            return tools()

        server.list_tools()(_list_tools)
    if resources is not None:

        async def _list_resources() -> list[types.Resource]:
            return resources()

        server.list_resources()(_list_resources)
    if prompts is not None:

        async def _list_prompts() -> list[types.Prompt]:
            return prompts()

        server.list_prompts()(_list_prompts)
    if call_tool is not None:

        async def _call_tool(tool_name: str, arguments: dict[str, Any] | None) -> list[types.TextContent]:
            return call_tool(tool_name, arguments or {})

        server.call_tool()(_call_tool)
    return server


def _build_2x(name, tools, resources, prompts, call_tool) -> Server:  # type: ignore[no-untyped-def]
    kwargs: dict[str, Any] = {}
    if tools is not None:

        async def on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
            return types.ListToolsResult(tools=tools())

        kwargs["on_list_tools"] = on_list_tools
    if resources is not None:

        async def on_list_resources(_ctx: Any, _params: Any) -> types.ListResourcesResult:
            return types.ListResourcesResult(resources=resources())

        kwargs["on_list_resources"] = on_list_resources
    if prompts is not None:

        async def on_list_prompts(_ctx: Any, _params: Any) -> types.ListPromptsResult:
            return types.ListPromptsResult(prompts=prompts())

        kwargs["on_list_prompts"] = on_list_prompts
    if call_tool is not None:

        async def on_call_tool(_ctx: Any, params: Any) -> types.CallToolResult:
            return types.CallToolResult(content=call_tool(params.name, params.arguments or {}))

        kwargs["on_call_tool"] = on_call_tool
    return Server(name, **kwargs)


async def serve_stdio(server: Server) -> None:
    """Run ``server`` over stdio — identical call shape on both SDK lines."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
