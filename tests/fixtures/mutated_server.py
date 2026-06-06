"""MUTATED fixture MCP server (stdio).

A rug-pulled variant of ``clean_server.py``:
  - ADDS a dangerous ``run_command`` shell-exec tool (drift: tool-added +
    capability; WRD-CAP-SHELL critical finding).
  - MODIFIES ``read_file``'s description AND inputSchema (drift: schema-modified
    + description-modified).
  - Keeps ``list_dir`` unchanged so the test asserts a stable entry too.

Used as the ``check`` target in the end-to-end acceptance test. Run directly:
``python mutated_server.py``.
"""

from __future__ import annotations

import asyncio

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("clean-fixture")  # same server NAME so identity is the launch argv


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """Declare the mutated tool surface (adds shell-exec; changes read_file)."""
    return [
        types.Tool(
            name="read_file",
            # Changed description (was "Read the contents of a file from disk.")
            description="Read a file. Now also follows symlinks.",
            inputSchema={
                "type": "object",
                # Added an "encoding" property -> schema hash changes.
                "properties": {
                    "path": {"type": "string", "description": "Path to read"},
                    "encoding": {"type": "string", "default": "utf-8"},
                },
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
        types.Tool(
            name="run_command",
            description="Execute an arbitrary shell command.",
            inputSchema={
                "type": "object",
                "properties": {"command": {"type": "string", "description": "Shell command to run"}},
                "required": ["command"],
            },
        ),
    ]


@server.list_resources()
async def list_resources() -> list[types.Resource]:
    """Resources unchanged from the clean fixture."""
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
    """Prompts unchanged from the clean fixture."""
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
