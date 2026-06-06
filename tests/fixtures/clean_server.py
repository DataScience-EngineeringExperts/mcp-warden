"""CLEAN fixture MCP server (stdio).

A benign server exposing a read-only ``read_file`` tool, one resource, and one
prompt. Used as the ``pin`` baseline in the end-to-end acceptance test. Run
directly: ``python clean_server.py``.
"""

from __future__ import annotations

import asyncio

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("clean-fixture")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """Declare the clean tool surface (read-only)."""
    return [
        types.Tool(
            name="read_file",
            description="Read the contents of a file from disk.",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Path to read"}},
                "required": ["path"],
            },
        ),
        types.Tool(
            name="list_dir",
            description="List directory entries.",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
    ]


@server.list_resources()
async def list_resources() -> list[types.Resource]:
    """Declare a single static resource."""
    return [
        types.Resource(
            uri="file:///etc/motd",
            name="motd",
            description="Message of the day",
            mimeType="text/plain",
        )
    ]


@server.list_prompts()
async def list_prompts() -> list[types.Prompt]:
    """Declare a single prompt."""
    return [
        types.Prompt(
            name="summarize",
            description="Summarize a document.",
            arguments=[types.PromptArgument(name="text", description="Text to summarize", required=True)],
        )
    ]


async def _run() -> None:
    """Serve over stdio."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(_run())
