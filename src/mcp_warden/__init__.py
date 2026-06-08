"""mcp-warden — CI-first MCP supply-chain integrity gate.

mcp-warden pins and verifies the *declared* tool/resource/prompt surface of an
MCP server (the ``(name, description, inputSchema)`` metadata returned by
``tools/list`` / ``resources/list`` / ``prompts/list``), then fails CI when that
surface drifts from an approved baseline. It operates on **definitions**, never
on runtime tool behavior or tool results. See ``docs/THREAT_MODEL.md``.
"""

__version__ = "0.3.0"
SCHEMA_VERSION = 2
#: Provenance-block version (#19). Lives INSIDE the ``pin`` block, OUTSIDE the
#: ``overall_digest`` payload, so it can evolve for #16/#23 without changing any
#: server's digest. Deliberately distinct from ``SCHEMA_VERSION`` (which is in
#: the digest payload — bumping that would falsely trip drift on v2 baselines).
PROVENANCE_VERSION = 1

__all__ = ["__version__", "SCHEMA_VERSION", "PROVENANCE_VERSION"]
