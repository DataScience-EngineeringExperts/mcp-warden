"""Runtime ``tools/list`` drift gate (GUARD_PROXY.md §4.3, §7.3).

When ``--lock`` is supplied, ``guard`` recomputes the tool-surface digest from an
inline ``tools/list`` **response** and compares it to the pinned ``warden.lock``.
A divergence is mid-session drift (``MCP-DRIFT`` at runtime), a BLOCK-tier
condition: in v0.3 the divergent ``tools/list`` response is blocked by default
(error-replacement) so the client never ingests the rug-pulled surface, unless
``--no-block-list-changed`` demotes it to shadow.

This reuses ``pin``'s hashing (``hashing.py``) over the live ``tools/list`` result
rather than re-spawning the server: the inline result already carries the live
``(name, description, inputSchema)`` triples for every tool.
"""

from __future__ import annotations

import logging
from typing import Any

from . import hashing
from .models import WardenLock

logger = logging.getLogger("mcp_warden.guard")


def diverges_from_lock(result: dict[str, Any], lock: WardenLock) -> tuple[bool, str]:
    """Compare an inline ``tools/list`` result's tool surface to the lock.

    Compares the set of tool names plus each tool's ``(description, inputSchema)``
    hashes (reusing :mod:`hashing`) against the pinned ``ToolEntry`` digests. Any
    added/removed tool, or any changed description/schema hash, is divergence.

    Args:
        result: The JSON-RPC ``result`` object of a ``tools/list`` response.
        lock: The loaded ``warden.lock`` baseline.

    Returns:
        ``(diverged, reason)`` — ``reason`` is a secret-free, human-readable
        summary when ``diverged`` is True (else ``""``). On any structural
        surprise the gate fails OPEN (returns ``(False, "")``) so a malformed
        list never fabricates a block; result inspection still runs elsewhere.
    """
    tools = result.get("tools")
    if not isinstance(tools, list):
        # Not a recognizable tools/list payload -> fail-open (no divergence claim).
        return False, ""

    try:
        live = _hash_live_tools(tools)
    except Exception as exc:  # malformed entry -> fail-open
        logger.debug("list-gate: could not hash live tools (fail-open): %s", exc)
        return False, ""

    baseline = {t.name: (t.description_hash, t.input_schema_hash) for t in lock.tools}

    added = sorted(set(live) - set(baseline))
    removed = sorted(set(baseline) - set(live))
    modified = sorted(name for name in (set(live) & set(baseline)) if live[name] != baseline[name])

    if not (added or removed or modified):
        return False, ""

    parts: list[str] = []
    if added:
        parts.append(f"added {added}")
    if removed:
        parts.append(f"removed {removed}")
    if modified:
        parts.append(f"modified {modified}")
    reason = "tool surface diverged from warden.lock: " + "; ".join(parts)
    return True, reason


def _hash_live_tools(tools: list[Any]) -> dict[str, tuple[str, str]]:
    """Hash each live tool entry to ``name -> (description_hash, input_schema_hash)``."""
    out: dict[str, tuple[str, str]] = {}
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name", ""))
        if not name:
            continue
        desc_hash = hashing.hash_description(tool.get("description"))
        schema_hash = hashing.hash_input_schema(tool.get("inputSchema"))
        out[name] = (desc_hash, schema_hash)
    return out
