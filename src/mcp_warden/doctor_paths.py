"""Config path enumeration for ``mcp-warden doctor`` — DSE-1516.

Pure functions of ``(platform, home, cwd, env)``: no filesystem reads beyond
the ``.git`` boundary probe in the project walk-up. Split from
``doctor_discovery.py`` to keep each module under the LOC budget; the
loaders live there, the *where* lives here.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

#: Config-file formats. ``json`` accepts either the ``mcpServers`` (Claude
#: Desktop / Cursor / Windsurf / ``.mcp.json``) or ``servers`` (VS Code) key.
FMT_JSON = "json"
FMT_JSONC = "jsonc"  # VS Code mcp.json: comments + trailing commas permitted
FMT_CLAUDE_JSON = "claude-json"  # ~/.claude.json: top-level + per-project maps
FMT_CODEX_TOML = "codex-toml"  # ~/.codex/config.toml: [mcp_servers.<name>]

_WALK_MAX_LEVELS = 32


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


def has_symlink_component(base: Path, path: Path) -> bool:
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


def display(path: Path, home: Path) -> str:
    """``~/``-relative when under home, else the absolute path."""
    try:
        return "~/" + path.relative_to(home).as_posix()
    except ValueError:
        return str(path)
