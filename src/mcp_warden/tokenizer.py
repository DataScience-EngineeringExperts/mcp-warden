"""Normative tokenizer + capability derivation — single source of truth.

This module is the ONE place that implements ``CHECKS.md`` §3. It is shared by:
  - ``warden.lock`` capability derivation (``WARDEN_LOCK_SCHEMA.md`` §5.4),
  - the ``WRD-CAP-*`` static checks (``CHECKS.md`` §4.1),
  - policy shape recognition (``POLICY_MODEL.md`` §1).

Non-negotiables (CHECKS.md §8):
  4. Token matching is segment-exact, case-insensitive, never substring.

Tokenization rules (CHECKS.md §3):
  - Lowercase everything before matching.
  - Split identifiers on snake_case (``_``), kebab-case (``-``), camelCase
    boundaries, and dot (``.``).
  - A token match = an exact segment equals a listed keyword (no substring).
  - A property match = an ``inputSchema.properties`` key (same split + lowercase)
    contains a listed keyword as a segment.
"""

from __future__ import annotations

import re
from typing import Any

# --- Capability keyword tables (CHECKS.md §3, WARDEN_LOCK_SCHEMA.md §5.4) -----

#: name tokens that imply each capability flag.
CAP_NAME_TOKENS: dict[str, frozenset[str]] = {
    "shell-exec": frozenset(
        {"shell", "exec", "spawn", "system", "subprocess", "sudo", "bash", "sh", "cmd", "powershell"}
    ),
    "fs-write": frozenset({"write", "save", "create", "delete", "rm", "unlink", "mkdir", "chmod", "mv", "rename"}),
    "fs-read": frozenset({"read", "cat", "open", "load", "get", "list"}),
    "http-request": frozenset({"fetch", "http", "request", "curl", "download", "webhook"}),
    "sql-query": frozenset({"sql", "query", "execute", "db"}),
}

#: property-name keywords that imply each capability flag.
CAP_PROP_TOKENS: dict[str, frozenset[str]] = {
    "shell-exec": frozenset({"command", "cmd", "script", "shell"}),
    # fs-write path-like properties; require a co-occurring content/write signal.
    "fs-write": frozenset({"path", "file", "filename", "dest", "target"}),
    "fs-read": frozenset({"path", "file", "filename", "src", "source"}),
    "http-request": frozenset({"url", "uri", "endpoint", "host", "hostname"}),
    "sql-query": frozenset({"query", "sql", "statement"}),
}

#: content/write-signal property tokens that satisfy the fs-write "with a
#: content/write property" requirement (WARDEN_LOCK_SCHEMA.md §5.4 / CHECKS.md §3).
FS_WRITE_CONTENT_TOKENS: frozenset[str] = frozenset({"content", "data", "body", "text", "bytes", "payload"})

#: fs-write name tokens (separate from the flag keys for the co-occurrence logic).
_FS_WRITE_NAME = CAP_NAME_TOKENS["fs-write"]

_SEGMENT_SPLIT = re.compile(
    r"""
    [_\-.\s]+            # explicit delimiters: underscore, hyphen, dot, whitespace
    | (?<=[a-z0-9])(?=[A-Z])   # camelCase boundary: lower/digit -> Upper
    | (?<=[A-Z])(?=[A-Z][a-z]) # acronym boundary: HTTPServer -> HTTP, Server
    """,
    re.VERBOSE,
)


def tokenize(identifier: str) -> list[str]:
    """Split an identifier into lowercase segments per CHECKS.md §3.

    Splits on snake_case, kebab-case, camelCase boundaries, dots, and whitespace,
    then lowercases. Empty segments are dropped.

    Args:
        identifier: A tool name or property key, e.g. ``"runShellCommand"`` or
            ``"fs.write_file"``.

    Returns:
        The list of lowercase segments, e.g. ``["run", "shell", "command"]``.
    """
    if not identifier:
        return []
    parts = _SEGMENT_SPLIT.split(identifier)
    return [p.lower() for p in parts if p]


def has_token(identifier: str, keywords: frozenset[str]) -> bool:
    """Return True if any segment of ``identifier`` exactly equals a keyword.

    Segment-exact, case-insensitive, never substring (``"shelter"`` must not
    match ``"shell"``).

    Args:
        identifier: The name/property to tokenize.
        keywords: The set of keywords to match against (already lowercase).

    Returns:
        True if a segment exactly matches one of ``keywords``.
    """
    return bool(set(tokenize(identifier)) & keywords)


def _schema_property_names(input_schema: dict[str, Any] | None) -> list[str]:
    """Extract top-level ``properties`` keys from a JSON Schema, defensively.

    Args:
        input_schema: The tool inputSchema object, or ``None``.

    Returns:
        A list of property-name strings (empty if none / malformed).
    """
    if not isinstance(input_schema, dict):
        return []
    props = input_schema.get("properties")
    if not isinstance(props, dict):
        return []
    return [k for k in props.keys() if isinstance(k, str)]


def _has_property(prop_names: list[str], keywords: frozenset[str]) -> bool:
    """Return True if any property name has a segment matching a keyword."""
    for name in prop_names:
        if set(tokenize(name)) & keywords:
            return True
    return False


def derive_capabilities(name: str, input_schema: dict[str, Any] | None) -> list[str]:
    """Derive the sorted, deduped capability flags for a tool.

    Implements WARDEN_LOCK_SCHEMA.md §5.4 / CHECKS.md §3 exactly. Flags derive
    from the tool ``name`` tokens and ``inputSchema`` property names only — never
    from fuzzy description parsing.

    Args:
        name: The tool name.
        input_schema: The tool inputSchema object, or ``None``.

    Returns:
        Sorted, deduplicated list of capability flag strings, e.g.
        ``["fs-read", "http-request"]``.
    """
    prop_names = _schema_property_names(input_schema)
    flags: set[str] = set()

    # shell-exec: name token OR a command-like string property.
    if has_token(name, CAP_NAME_TOKENS["shell-exec"]) or _has_property(prop_names, CAP_PROP_TOKENS["shell-exec"]):
        flags.add("shell-exec")

    # fs-write: write-ish name token WITH a path-like property, OR a path-like
    # property alongside a content/write signal property.
    name_has_write = has_token(name, _FS_WRITE_NAME)
    has_path_prop = _has_property(prop_names, CAP_PROP_TOKENS["fs-write"])
    has_content_prop = _has_property(prop_names, FS_WRITE_CONTENT_TOKENS)
    if (name_has_write and has_path_prop) or (has_path_prop and has_content_prop):
        flags.add("fs-write")

    # fs-read: read-ish name token WITH a path-like property.
    if has_token(name, CAP_NAME_TOKENS["fs-read"]) and _has_property(prop_names, CAP_PROP_TOKENS["fs-read"]):
        flags.add("fs-read")

    # http-request: url-like property OR a network name token.
    if has_token(name, CAP_NAME_TOKENS["http-request"]) or _has_property(prop_names, CAP_PROP_TOKENS["http-request"]):
        flags.add("http-request")

    # sql-query: query-like property OR a sql name token.
    if has_token(name, CAP_NAME_TOKENS["sql-query"]) or _has_property(prop_names, CAP_PROP_TOKENS["sql-query"]):
        flags.add("sql-query")

    return sorted(flags)


def capability_evidence(name: str, input_schema: dict[str, Any] | None, flag: str) -> str:
    """Return a short, secret-free evidence string for a derived capability.

    Used by ``WRD-CAP-*`` finding ``snippet`` fields: names the matching token or
    property (no secret content).

    Args:
        name: The tool name.
        input_schema: The tool inputSchema object, or ``None``.
        flag: The capability flag (e.g. ``"shell-exec"``).

    Returns:
        A human-readable evidence string, e.g. ``"name token 'shell'"`` or
        ``"property 'command'"``.
    """
    prop_names = _schema_property_names(input_schema)
    name_segments = set(tokenize(name))

    name_tokens = CAP_NAME_TOKENS.get(flag, frozenset())
    matched_name = sorted(name_segments & name_tokens)
    if matched_name:
        return f"name token '{matched_name[0]}'"

    prop_tokens = CAP_PROP_TOKENS.get(flag, frozenset())
    for pname in prop_names:
        matched = set(tokenize(pname)) & prop_tokens
        if matched:
            return f"property '{pname}'"

    return f"derived capability '{flag}'"
