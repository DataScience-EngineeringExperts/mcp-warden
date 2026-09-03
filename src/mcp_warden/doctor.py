"""Zero-config MCP posture scan (``mcp-warden doctor``) — DSE-1516.

Discovers every MCP client config already on the machine (Claude Code, Claude
Desktop, Cursor, VS Code, Windsurf, Codex), then runs the *existing* engines
over each configured server — the ``WRD-AUTH-*`` static auth audit, the
``WRD-SUP-*`` supply-chain checks on the launch argv, and a lock-coverage check
(``WRD-DOCTOR-NO-LOCK``) — and prints the exact ``pin`` command for anything
uncovered. It composes checks; it adds no new detection catalog.

Static by construction: discovery is a pure function of ``(platform, home, cwd,
env)`` and nothing here spawns a process, resolves a name, or opens a socket.
A discovered path that is a symlink (at any component below its base) is
skipped with a warning so a planted link cannot steer the scan outside the
documented set; an explicit ``--config`` path is trusted as given.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .auth_audit import _is_auth_key, _looks_like_secret_ref, audit_server
from .checks_secret import scan_field
from .checks_supply import check_launch_command
from .doctor_discovery import ConfigSource, DoctorError, discover, load_explicit
from .lockfile import read_lock
from .models import Finding, WardenLock

__all__ = ["ConfigSource", "DoctorError", "DoctorReport", "ServerReport", "run_doctor"]

#: Directories never descended into when looking for locks.
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".ruff_cache", ".tox"}
_LOCK_MAX_DEPTH = 4


@dataclass(frozen=True)
class ServerReport:
    """Findings for one server, plus whether a lock already pins it."""

    source: ConfigSource
    name: str
    server: dict[str, Any]
    findings: list[Finding]
    covered: bool

    @property
    def target(self) -> str:
        return f"{self.source.label}#{self.name}"


@dataclass
class DoctorReport:
    """The whole run: every source scanned, every server's verdict, warnings."""

    sources: list[ConfigSource] = field(default_factory=list)
    reports: list[ServerReport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    searched: int = 0

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.reports for f in r.findings]

    @property
    def uncovered(self) -> list[ServerReport]:
        return [r for r in self.reports if not r.covered]


# --- lock coverage -------------------------------------------------------------


def find_locks(root: Path, warn: Callable[[str], None]) -> list[tuple[Path, WardenLock]]:
    """Bounded, symlink-free search for ``warden.lock`` / ``*.warden.lock`` under ``root``."""
    found: list[tuple[Path, WardenLock]] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if depth < _LOCK_MAX_DEPTH and p.name not in _SKIP_DIRS:
                    stack.append((p, depth + 1))
            elif p.name == "warden.lock" or p.name.endswith(".warden.lock"):
                try:
                    found.append((p, read_lock(p)))
                except (OSError, ValueError) as exc:
                    warn(f"ignoring unreadable lock {p}: {exc}")
    return found


def lock_covers(lock: WardenLock, server: dict[str, Any]) -> bool:
    """Whether ``lock`` pins exactly this server's launch (url, or command+args)."""
    url = server.get("url")
    if isinstance(url, str) and url:
        return lock.server.url == url
    args = server.get("args") or []
    return lock.server.command == server.get("command") and list(lock.server.args) == list(args)


# --- composition -------------------------------------------------------------


def _retarget(findings: list[Finding], target: str) -> list[Finding]:
    return [f.model_copy(update={"target": target}) for f in findings]


def scan_server(
    source: ConfigSource, name: str, server: dict[str, Any], locks: list[tuple[Path, WardenLock]]
) -> ServerReport:
    """Run auth + supply + lock-coverage over one server (no spawn, no network)."""
    target = f"{source.label}#{name}"
    findings = _retarget(audit_server(name, server), target)
    command = server.get("command")
    if isinstance(command, str) and command:
        args = [str(a) for a in (server.get("args") or [])]
        findings += _retarget(check_launch_command(command, args), target)
    covered = any(lock_covers(lock, server) for _, lock in locks)
    if not covered:
        findings.append(
            Finding(
                rule_id="WRD-DOCTOR-NO-LOCK",
                severity="low",
                target=target,
                message="no warden.lock pins this server's declared surface; run the pin command below",
                snippet=name,
            )
        )
    findings.sort(key=lambda f: (f.target, f.rule_id, f.snippet))
    return ServerReport(source, name, server, findings, covered)


def run_doctor(
    *,
    platform: str,
    home: Path,
    cwd: Path,
    env: Mapping[str, str],
    explicit: list[Path],
    do_discover: bool,
    warn: Callable[[str], None],
) -> DoctorReport:
    """Discover, load, and scan. Raises :class:`DoctorError` on bad input."""
    report = DoctorReport()

    def _warn(msg: str) -> None:
        report.warnings.append(msg)
        warn(msg)

    if do_discover:
        report.sources, report.searched = discover(platform, home, cwd, env, _warn)
    for p in explicit:
        report.sources.extend(load_explicit(p, home))
    locks = find_locks(cwd, _warn)
    for src in report.sources:
        for name, server in src.servers.items():
            report.reports.append(scan_server(src, name, server, locks))
    return report


# --- the funnel ------------------------------------------------------------------


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "server"


def _mask_arg(prev: str, arg: str) -> bool:
    """Whether a launch argument must be masked in the printed ``pin`` command.

    A vendor-pattern hit (``sk-``/``ghp_``/AKIA/JWT/...) always masks. The
    entropy heuristic alone does **not** — a package spec such as
    ``@modelcontextprotocol/server-github`` is high-entropy and is exactly the
    token the user needs to copy. An argument that follows an auth-shaped flag
    (``--token``, ``--api-key``, ``-p``…) or that is ``KEY=value`` with an
    auth-shaped key is masked unless it is a ``${VAR}``-style reference.
    """
    if any(f.rule_id != "WRD-SEC-ENTROPY" for f in scan_field(arg, "arg")):
        return True
    key, sep, value = arg.partition("=")
    if sep and _is_auth_key(key):
        return not _looks_like_secret_ref(value)
    if prev.startswith("-") and _is_auth_key(prev.lstrip("-")):
        return not _looks_like_secret_ref(arg)
    return False


def pin_command(name: str, server: dict[str, Any]) -> str:
    """The copy-pasteable ``pin`` for one server; credential-bearing args are masked."""
    lock = f"{slug(name)}.warden.lock"
    tail = f"--approve --approver you@example.com --lock {lock}"
    url = server.get("url")
    if isinstance(url, str) and url:
        authority = url.partition("://")[2].split("/", 1)[0]
        shown = "<REDACTED: url embeds a credential>" if "@" in authority else shlex.quote(url)
        return f"mcp-warden pin --url {shown} {tail}"
    argv = [str(server.get("command") or "<command>")]
    prev = ""
    for a in server.get("args") or []:
        a = str(a)
        argv.append("<REDACTED>" if _mask_arg(prev, a) else shlex.quote(a))
        prev = a
    return f"mcp-warden pin {' '.join(argv)} {tail}"
