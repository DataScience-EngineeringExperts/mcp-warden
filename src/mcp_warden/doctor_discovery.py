"""Config discovery for ``mcp-warden doctor`` — DSE-1516.

Pure path enumeration plus fail-closed loading of every MCP client config in
the documented set (see ``docs/DOCTOR.md``). Split from ``doctor.py`` to keep
each module under the LOC budget. Nothing here spawns, resolves, or connects.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Config-file formats. ``json`` accepts either the ``mcpServers`` (Claude
#: Desktop / Cursor / Windsurf / ``.mcp.json``) or ``servers`` (VS Code) key.
FMT_JSON = "json"
FMT_CLAUDE_JSON = "claude-json"  # ~/.claude.json: top-level + per-project maps
FMT_CODEX_TOML = "codex-toml"  # ~/.codex/config.toml: [mcp_servers.<name>]

_WALK_MAX_LEVELS = 32


@dataclass(frozen=True)
class ConfigSource:
    """One discovered (or explicitly given) map of MCP servers."""

    client: str
    path: Path
    label: str
    servers: dict[str, dict[str, Any]]


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
        out.append(("VS Code", app / "Code" / "User" / "mcp.json", FMT_JSON))
    elif platform == "win32":
        appdata = env.get("APPDATA")
        if appdata:
            app = Path(appdata)
            out.append(("Claude Desktop", app / "Claude" / "claude_desktop_config.json", FMT_JSON))
            out.append(("VS Code", app / "Code" / "User" / "mcp.json", FMT_JSON))
    else:
        cfg = home / ".config"
        out.append(("Claude Desktop", cfg / "Claude" / "claude_desktop_config.json", FMT_JSON))
        out.append(("VS Code", cfg / "Code" / "User" / "mcp.json", FMT_JSON))
    return out


def project_config_paths(cwd: Path, home: Path) -> list[tuple[str, Path, str, Path]]:
    """Project-scoped config candidates, walking up from ``cwd``.

    Stops after the home directory (when ``cwd`` is under it) or at the
    filesystem root, whichever comes first, and never climbs more than
    ``_WALK_MAX_LEVELS``. Pure: existence is checked by the caller. The fourth
    element is the ancestor directory the candidate hangs off — the symlink
    check runs from there.
    """
    out: list[tuple[str, Path, str, Path]] = []
    d = cwd
    for _ in range(_WALK_MAX_LEVELS):
        out.append(("Claude Code (project)", d / ".mcp.json", FMT_JSON, d))
        out.append(("Cursor (project)", d / ".cursor" / "mcp.json", FMT_JSON, d))
        out.append(("VS Code (project)", d / ".vscode" / "mcp.json", FMT_JSON, d))
        if d == home or d.parent == d:
            break
        d = d.parent
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
    except OSError as exc:
        raise DoctorError(f"cannot read {display}: {exc}") from exc
    try:
        doc = tomllib.loads(raw) if fmt == FMT_CODEX_TOML else json.loads(raw)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise DoctorError(f"invalid {'TOML' if fmt == FMT_CODEX_TOML else 'JSON'} in {display}: {exc}") from exc

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
) -> tuple[list[ConfigSource], int]:
    """Discover + load every config in the documented set. Returns (sources, searched)."""
    sources: list[ConfigSource] = []
    seen: set[Path] = set()
    candidates = [(c, p, f, home) for c, p, f in well_known_config_paths(platform, home, env)]
    candidates += project_config_paths(cwd, home)
    for client, path, fmt, base in candidates:
        if path in seen:
            continue
        seen.add(path)
        if not path.exists() or not path.is_file():
            continue
        if _has_symlink_component(base, path):
            warn(f"skipping {_display(path, home)}: symlink in path (pass --config to scan it)")
            continue
        sources.extend(load_config(client, path, fmt, _display(path, home)))
    return sources, len(seen)


def load_explicit(path: Path, home: Path) -> list[ConfigSource]:
    """Load a user-named config; format is inferred from the filename."""
    if path.name == "config.toml":
        fmt = FMT_CODEX_TOML
    elif path.name == ".claude.json":
        fmt = FMT_CLAUDE_JSON
    else:
        fmt = FMT_JSON
    return load_config("explicit", path, fmt, _display(path, home))


