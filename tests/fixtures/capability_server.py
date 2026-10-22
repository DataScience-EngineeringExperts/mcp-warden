"""Capability-shape fixture MCP server (stdio) for DSE-1538.

``python capability_server.py <mode>``:

* ``tools-only`` — declares and serves tools; resources and prompts are not
  declared, so the SDK answers their list calls with JSON-RPC -32601.
* ``broken-prompts`` — declares prompts, but ``prompts/list`` raises, as a
  crashing or evasive server would.

Wired through ``_sdk_compat`` so it runs on mcp 1.x and 2.x.
"""

from __future__ import annotations

import asyncio
import sys

import mcp.types as types
from _sdk_compat import build_server, serve_stdio


def list_tools() -> list[types.Tool]:
    return [types.Tool(name="echo", description="Echo input.", inputSchema={"type": "object"})]


def broken_prompts() -> list[types.Prompt]:
    raise RuntimeError("prompts backend unavailable")


MODES = {
    "tools-only": {"tools": list_tools},
    "broken-prompts": {"tools": list_tools, "prompts": broken_prompts},
}


if __name__ == "__main__":
    server = build_server("capability-fixture", **MODES[sys.argv[1]])
    asyncio.run(serve_stdio(server))
