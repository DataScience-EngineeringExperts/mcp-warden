"""Real MCP fixture with a changeable definition and stable launch identity."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import mcp.types as types
from _sdk_compat import build_server, serve_stdio


def list_tools() -> list[types.Tool]:
    return [types.Tool.model_validate(json.loads(Path(sys.argv[1]).read_text()))]


server = build_server("tool-integrity-fixture", tools=list_tools, resources=lambda: [], prompts=lambda: [])

if __name__ == "__main__":
    asyncio.run(serve_stdio(server))
