"""mcp-warden — CI-first MCP supply-chain integrity gate.

mcp-warden pins and verifies the *declared* tool/resource/prompt surface of an
MCP server (the ``(name, description, inputSchema)`` metadata returned by
``tools/list`` / ``resources/list`` / ``prompts/list``), then fails CI when that
surface drifts from an approved baseline. It operates on **definitions**, never
on runtime tool behavior or tool results. See ``docs/THREAT_MODEL.md``.
"""

__version__ = "0.3.0"
#: Lock schema version. Bumped 2 → 3 for #29 (in-document ``$ref`` resolution in
#: ``schema_diff.extract_skeleton``). Following refs changes the skeleton of any
#: ref-using tool → its ``entry_digest`` and the ``overall_digest`` (which embeds
#: ``schema_version``, lockfile.py:167). The bump makes that digest change a
#: declared schema-format migration rather than a silent surface change; drift.py
#: emits an additive ``schema-version-migrated`` advisory alongside (never in
#: place of) the ``unapproved-change`` finding so re-attestation is required.
SCHEMA_VERSION = 3
#: Provenance-block version (#19). Lives INSIDE the ``pin`` block, OUTSIDE the
#: ``overall_digest`` payload, so it can evolve for #16/#23 without changing any
#: server's digest. Deliberately distinct from ``SCHEMA_VERSION`` (which is in
#: the digest payload — bumping that would falsely trip drift on v2 baselines).
PROVENANCE_VERSION = 1

__all__ = ["__version__", "SCHEMA_VERSION", "PROVENANCE_VERSION"]
