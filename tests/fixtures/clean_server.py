"""CLEAN fixture MCP server (stdio).

A benign server exposing a read-only ``read_file`` tool, one resource, and one
prompt. Used as the ``pin`` baseline in the end-to-end acceptance test. Run
directly: ``python clean_server.py``.

Wired through ``_sdk_compat`` so the same file runs on mcp 1.x and 2.x; the
declared surface below is byte-for-byte what ``clean.warden.lock`` pins.
"""

from __future__ import annotations

import asyncio

import mcp.types as types
from _sdk_compat import build_server, serve_stdio


def list_tools() -> list[types.Tool]:
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


def list_resources() -> list[types.Resource]:
    """Declare a single static resource."""
    return [
        types.Resource(
            uri="file:///etc/motd",
            name="motd",
            description="Message of the day",
            mimeType="text/plain",
        )
    ]


def list_prompts() -> list[types.Prompt]:
    """Declare a single prompt."""
    return [
        types.Prompt(
            name="summarize",
            description="Summarize a document.",
            arguments=[types.PromptArgument(name="text", description="Text to summarize", required=True)],
        )
    ]


server = build_server("clean-fixture", tools=list_tools, resources=list_resources, prompts=list_prompts)


if __name__ == "__main__":
    asyncio.run(serve_stdio(server))
