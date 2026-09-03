"""Config discovery for ``mcp-warden doctor`` — DSE-1516.

Path enumeration plus fail-closed loading of every MCP client config in the
documented set (see ``docs/DOCTOR.md``). Split from ``doctor.py`` to keep each
module under the LOC budget. Nothing here spawns, resolves, or connects.

Discovery is deliberately defensive about *where* it reads: a symlink at any
component below a candidate's base skips it, the project walk-up stops at the
first ``.git`` boundary (or the home directory), an oversized file is skipped,
and one malformed discovered file warns and is counted as a hard error rather
than aborting the scan of everything else.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Config-file formats. ``json`` accepts either the ``mcpServers`` (Claude
#: Desktop / Cursor / Windsurf / ``.mcp.json``) or ``servers`` (VS Code) key.
FMT_JSON = "json"
FMT_JSONC = "jsonc"  # VS Code mcp.json: comments + trailing commas permitted
FMT_CLAUDE_JSON = "claude-json"  # ~/.claude.json: top-level + per-project maps
FMT_CODEX_TOML = "codex-toml"  # ~/.codex/config.toml: [mcp_servers.<name>]

_WALK_MAX_LEVELS = 32
#: A discovered config larger than this is skipped (``~/.claude.json`` carries
#: history and can reach tens of MB; a credential-bearing config never should).
MAX_CONFIG_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class ConfigSource:
    """One discovered (or explicitly given) map of MCP servers."""

    client: str
    path: Path
    label: str
    servers: dict[str, dict[str, Any]]

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


def well_known_config_paths(
    platform: str, home: Path, env: Mapping[str, str]
) -> list[tuple[str, Path, str]]:
    """User-level config locations for ``platform`` (``darwin``/``linux``/``win32``).

    Pure: no filesystem access. Returns ``(client, path, format)`` triples in
    a stable order. Windows entries need ``APPDATA`` in ``env``.
    """
    out: list[tuple[str, Path, str]] = [
        ("Claude Code", home / ".claude.json", FMT_CLAUDE_JSON),
        ("Cursor", home / ".cursor" / "mcp.json", FMT_JSON),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json", FMT_JSON),
        ("Codex", home / ".codex" / "config.toml", FMT_CODEX_TOML),
    ]
    if platform == "darwin":
        app = home / "Library" / "Application Support"
        out.append(("Claude Desktop", app / "Claude" / "claude_desktop_config.json", FMT_JSON))
        out.append(("VS Code", app / "Code" / "User" / "mcp.json", FMT_JSONC))
    elif platform == "win32":
        appdata = env.get("APPDATA")
        if appdata:
            app = Path(appdata)
            out.append(("Claude Desktop", app / "Claude" / "claude_desktop_config.json", FMT_JSON))
            out.append(("VS Code", app / "Code" / "User" / "mcp.json", FMT_JSONC))
    else:
        cfg = home / ".config"
        out.append(("Claude Desktop", cfg / "Claude" / "claude_desktop_config.json", FMT_JSON))
        out.append(("VS Code", cfg / "Code" / "User" / "mcp.json", FMT_JSONC))
    return out


def project_config_paths(cwd: Path, home: Path) -> list[tuple[str, Path, str, Path]]:
    """Project-scoped config candidates, walking up from ``cwd``.

    The walk stops at the first ancestor (``cwd`` included) that contains a
    ``.git`` entry, or at ``home`` when ``cwd`` is under it — whichever comes
    first — and never climbs more than ``_WALK_MAX_LEVELS``. When ``cwd`` is
    outside home and no ``.git`` boundary exists, only ``cwd`` itself is a
    candidate: an unbounded walk from ``/tmp/x`` would otherwise read a
    world-writable ``/tmp/.mcp.json``. The fourth element is the ancestor the
    candidate hangs off — the symlink check runs from there.
    """
    chain: list[Path] = []
    d = cwd
    under_home = home == cwd or home in cwd.parents
    bounded = False
    for _ in range(_WALK_MAX_LEVELS):
        chain.append(d)
        if (d / ".git").exists() or (under_home and d == home):
            bounded = True
            break
        if d.parent == d:
            break
        d = d.parent
    if not bounded:
        chain = [cwd]
    out: list[tuple[str, Path, str, Path]] = []
    for d in chain:
        out.append(("Claude Code (project)", d / ".mcp.json", FMT_JSON, d))
        out.append(("Cursor (project)", d / ".cursor" / "mcp.json", FMT_JSON, d))
        out.append(("VS Code (project)", d / ".vscode" / "mcp.json", FMT_JSONC, d))
    return out


def _has_symlink_component(base: Path, path: Path) -> bool:
    """True if any component of ``path`` below ``base`` is a symlink."""
    try:
        rel = path.relative_to(base)
    except ValueError:
        return path.is_symlink()
    cur = base
    for part in rel.parts:
        cur = cur / part
        if cur.is_symlink():
            return True
    return False


_JSONC_TOKEN = re.compile(
    r'"(?:[^"\\]|\\.)*"'  # a string (kept verbatim)
    r"|//[^\n]*"  # line comment
    r"|/\*.*?\*/",  # block comment
    re.S,
)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def strip_jsonc(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments (outside strings) and trailing commas."""
    without = _JSONC_TOKEN.sub(lambda m: m.group(0) if m.group(0).startswith('"') else " ", text)
    return _TRAILING_COMMA.sub(r"\1", without)


def _servers_from_doc(doc: Any, where: str) -> dict[str, dict[str, Any]]:
    """Extract ``{name: server}`` from a parsed document, tolerating both keys."""
    if not isinstance(doc, dict):
        raise DoctorError(f"{where}: top-level config must be an object")
    raw = doc.get("mcpServers")
    if raw is None:
        raw = doc.get("servers")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise DoctorError(f"{where}: mcpServers/servers must be an object")
    return {str(k): v for k, v in raw.items() if isinstance(v, dict)}


def load_config(client: str, path: Path, fmt: str, display: str) -> list[ConfigSource]:
    """Parse one config file into zero or more :class:`ConfigSource`.

    Raises :class:`DoctorError` on an unreadable or malformed file. A file
    that parses but declares no servers yields an empty list.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DoctorError(f"cannot read {display}: {exc}") from exc
    try:
        if fmt == FMT_CODEX_TOML:
            doc = tomllib.loads(raw)
        else:
            doc = json.loads(strip_jsonc(raw) if fmt == FMT_JSONC else raw)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        kind = "TOML" if fmt == FMT_CODEX_TOML else "JSON"
        raise DoctorError(f"invalid {kind} in {display}: {exc}") from exc

    if fmt == FMT_CODEX_TOML:
        servers = _servers_from_doc({"mcpServers": doc.get("mcp_servers")}, display)
        return [ConfigSource(client, path, display, servers)] if servers else []

    sources: list[ConfigSource] = []
    top = _servers_from_doc(doc, display)
    if top:
        sources.append(ConfigSource(client, path, display, top))
    if fmt == FMT_CLAUDE_JSON and isinstance(doc.get("projects"), dict):
        for proj, pdoc in doc["projects"].items():
            if not isinstance(pdoc, dict):
                continue
            per = _servers_from_doc(pdoc, f"{display}#projects[{proj}]")
            if per:
                sources.append(ConfigSource(client, path, f"{display}#projects[{proj}]", per))
    return sources


def _display(path: Path, home: Path) -> str:
    try:
        return "~/" + path.relative_to(home).as_posix()
    except ValueError:
        return str(path)


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
        shown = _display(path, home)
        if _has_symlink_component(base, path):
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
    return load_config("explicit", path, fmt, _display(path, home))
