"""Config discovery for ``mcp-warden doctor`` — DSE-1516.

Fail-closed loading of every MCP client config in the documented set (see
``docs/DOCTOR.md``); the path enumeration lives in ``doctor_paths.py``.
Nothing here spawns, resolves, or connects.

Discovery is deliberately defensive about *where* it reads: a symlink at any
component below a candidate's base skips it, the project walk-up stops at the
first ``.git`` boundary (or the home directory), an oversized file is skipped,
and one malformed discovered file warns and is counted as a hard error rather
than aborting the scan of everything else.

It is equally defensive about *what* it reads: both ``mcpServers`` and
``servers`` are loaded from every JSON config (VS Code reads ``servers``; a
benign ``mcpServers`` decoy must not hide the map the client actually uses),
and the JSONC pass never edits the inside of a string literal, so the audited
argv is byte-for-byte what the client launches.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .doctor_paths import (
    FMT_CLAUDE_JSON,
    FMT_CODEX_TOML,
    FMT_JSON,
    FMT_JSONC,
    display,
    has_symlink_component,
    project_config_paths,
    well_known_config_paths,
)

__all__ = [
    "FMT_CLAUDE_JSON", "FMT_CODEX_TOML", "FMT_JSON", "FMT_JSONC", "MAX_CONFIG_BYTES",
    "ConfigSource", "Discovery", "DoctorError", "discover", "load_config", "load_explicit",
    "project_config_paths", "strip_jsonc", "well_known_config_paths",
]

#: A discovered config larger than this is skipped (``~/.claude.json`` carries
#: history and can reach tens of MB; a credential-bearing config never should).
MAX_CONFIG_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class ConfigSource:
    """One discovered (or explicitly given) map of MCP servers.

    ``ambiguous`` names every server declared under *both* ``mcpServers`` and
    ``servers`` with different definitions; the second definition is kept
    under ``<name>#servers`` so both get audited and the collision is reported.
    """

    client: str
    path: Path
    label: str
    servers: dict[str, dict[str, Any]]
    ambiguous: tuple[str, ...] = ()

    @property
    def explicit(self) -> bool:
        """True when the user named this file with ``--config``."""
        return self.client == "explicit"


@dataclass
class Discovery:
    """What ``discover`` found, plus the two counters that shape the exit code."""

    sources: list[ConfigSource] = field(default_factory=list)
    searched: int = 0
    hard_errors: int = 0  # malformed/unreadable discovered files -> exit 2
    skipped: int = 0  # symlink / oversized skips -> never a green exit


class DoctorError(ValueError):
    """Raised on an unreadable or malformed config (fail closed, exit 2)."""


# --- JSONC ---------------------------------------------------------------------

_STRING = r'"(?:[^"\\]|\\.)*"'
_COMMENT_PASS = re.compile(rf"{_STRING}|//[^\n]*|/\*.*?\*/", re.S)
_COMMA_PASS = re.compile(rf"{_STRING}|,(\s*[}}\]])", re.S)


def strip_jsonc(text: str) -> str:
    """Remove ``//`` / ``/* */`` comments and trailing commas — outside strings only.

    Both passes tokenise string literals first and return them verbatim, so a
    ``"//"`` or ``"echo {a, }"`` inside a value is never touched. Anything the
    tokeniser cannot pair degrades to invalid JSON, which fails closed.
    """
    no_comments = _COMMENT_PASS.sub(lambda m: m.group(0) if m.group(0)[0] == '"' else " ", text)
    return _COMMA_PASS.sub(lambda m: m.group(0) if m.group(0)[0] == '"' else m.group(1), no_comments)


# --- loaders -------------------------------------------------------------------


def _servers_from_doc(doc: Any, where: str) -> tuple[dict[str, dict[str, Any]], tuple[str, ...]]:
    """Extract ``{name: server}`` from a parsed document — the UNION of both keys.

    A name present under both ``mcpServers`` and ``servers`` with an identical
    body is loaded once. With *different* bodies both are kept — the second as
    ``<name>#servers`` — and the name is returned as ambiguous: a decoy map is
    itself a signal (``WRD-DOCTOR-AMBIGUOUS-SERVER``).
    """
    if not isinstance(doc, dict):
        raise DoctorError(f"{where}: top-level config must be an object")
    out: dict[str, dict[str, Any]] = {}
    ambiguous: list[str] = []
    for key in ("mcpServers", "servers"):
        raw = doc.get(key)
        if raw is None:
            continue
        if not isinstance(raw, dict):
            raise DoctorError(f"{where}: {key} must be an object")
        for k, v in raw.items():
            if not isinstance(v, dict):
                continue
            name = str(k)
            if name in out:
                if out[name] == v:
                    continue
                ambiguous.append(name)
                name = f"{name}#servers"
            out[name] = v
    return out, tuple(ambiguous)


def load_config(client: str, path: Path, fmt: str, display_name: str) -> list[ConfigSource]:
    """Parse one config file into zero or more :class:`ConfigSource`.

    Raises :class:`DoctorError` on an unreadable or malformed file. A file
    that parses but declares no servers yields an empty list.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DoctorError(f"cannot read {display_name}: {exc}") from exc
    try:
        if fmt == FMT_CODEX_TOML:
            doc = tomllib.loads(raw)
        else:
            doc = json.loads(strip_jsonc(raw) if fmt == FMT_JSONC else raw)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        kind = "TOML" if fmt == FMT_CODEX_TOML else "JSON"
        raise DoctorError(f"invalid {kind} in {display_name}: {exc}") from exc

    if fmt == FMT_CODEX_TOML:
        servers, amb = _servers_from_doc({"mcpServers": doc.get("mcp_servers")}, display_name)
        return [ConfigSource(client, path, display_name, servers, amb)] if servers else []

    sources: list[ConfigSource] = []
    top, amb = _servers_from_doc(doc, display_name)
    if top:
        sources.append(ConfigSource(client, path, display_name, top, amb))
    if fmt == FMT_CLAUDE_JSON and isinstance(doc.get("projects"), dict):
        for proj, pdoc in doc["projects"].items():
            if not isinstance(pdoc, dict):
                continue
            label = f"{display_name}#projects[{proj}]"
            per, amb = _servers_from_doc(pdoc, label)
            if per:
                sources.append(ConfigSource(client, path, label, per, amb))
    return sources


def discover(
    platform: str,
    home: Path,
    cwd: Path,
    env: Mapping[str, str],
    warn: Callable[[str], None],
) -> Discovery:
    """Discover + load every config in the documented set.

    A candidate that is a symlink or oversized is *skipped* (warned, counted);
    one that is unreadable or malformed is *warned and counted as a hard
    error* — the remaining candidates are still scanned so one broken file
    cannot hide the others, and the caller turns the counter into exit 2.
    """
    result = Discovery()
    seen: set[Path] = set()
    candidates = [(c, p, f, home) for c, p, f in well_known_config_paths(platform, home, env)]
    candidates += project_config_paths(cwd, home)
    for client, path, fmt, base in candidates:
        if path in seen:
            continue
        seen.add(path)
        if not path.exists() or not path.is_file():
            continue
        shown = display(path, home)
        if has_symlink_component(base, path):
            warn(f"skipping {shown}: symlink in path (pass --config to scan it)")
            result.skipped += 1
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            warn(f"cannot stat {shown}: {exc}")
            result.hard_errors += 1
            continue
        if size > MAX_CONFIG_BYTES:
            warn(f"skipping {shown}: {size} bytes exceeds the {MAX_CONFIG_BYTES}-byte cap")
            result.skipped += 1
            continue
        try:
            result.sources.extend(load_config(client, path, fmt, shown))
        except DoctorError as exc:
            warn(f"{exc} (scan continues; final exit will be 2)")
            result.hard_errors += 1
    result.searched = len(seen)
    return result


def load_explicit(path: Path, home: Path) -> list[ConfigSource]:
    """Load a user-named config; format is inferred from the filename.

    Unlike :func:`discover` this raises on any problem — the user asked for
    this exact file, so an unreadable one is an error, not a warning.
    """
    if path.name == "config.toml":
        fmt = FMT_CODEX_TOML
    elif path.name == ".claude.json":
        fmt = FMT_CLAUDE_JSON
    elif path.parent.name == ".vscode" or "Code" in path.parts:
        fmt = FMT_JSONC
    else:
        fmt = FMT_JSON
    return load_config("explicit", path, fmt, display(path, home))
