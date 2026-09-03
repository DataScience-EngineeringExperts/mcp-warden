"""Zero-config MCP posture scan (``mcp-warden doctor``) — DSE-1516.

Discovers every MCP client config on the machine, then runs the *existing*
engines over each configured server — ``WRD-AUTH-*``, ``WRD-SUP-*``, and a
lock-coverage check (``WRD-DOCTOR-NO-LOCK`` / ``WRD-DOCTOR-LOCK-UNAPPROVED``)
— and prints the exact ``pin`` command for anything uncovered. It composes
checks; it adds no new detection catalog. Nothing here spawns, resolves, or
connects.

Every config-controlled string that reaches a terminal passes through
:func:`safe_text` first (``doctor_funnel.py``): a cloned repo's ``.mcp.json``
must not repaint the terminal, reorder the printed line, or inject a second
line into the block the user is told to copy and run. See ``docs/DOCTOR.md``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .auth_audit import audit_server
from .checks_supply import check_launch_command
from .doctor_discovery import ConfigSource, Discovery, DoctorError, discover, load_explicit
from .doctor_funnel import lock_filename, pin_command, safe_text, slug
from .lockfile import read_lock
from .models import Finding, WardenLock

__all__ = [
    "ConfigSource", "DoctorError", "DoctorReport", "ServerReport", "coverage", "find_locks",
    "lock_covers", "lock_filename", "pin_command", "run_doctor", "safe_text", "scan_server", "slug",
]

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
    covered: bool  # any matching lock, approved or not

    @property
    def target(self) -> str:
        return safe_text(f"{self.source.label}#{self.name}")


@dataclass
class DoctorReport:
    """The whole run: every source scanned, every server's verdict, warnings."""

    sources: list[ConfigSource] = field(default_factory=list)
    reports: list[ServerReport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    searched: int = 0
    hard_errors: int = 0
    skipped: int = 0

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


def coverage(server: dict[str, Any], locks: list[tuple[Path, WardenLock]]) -> str | None:
    """``"approved"`` / ``"unapproved"`` for the best matching lock, or ``None``.

    A lock found in the tree is *unauthenticated* evidence — it says a lock
    exists, not that a human approved it. Approval is read from
    ``pin.approved``; signature verification remains ``check --verify``'s job.
    """
    states = {("approved" if lock.pin.approved else "unapproved") for _, lock in locks if lock_covers(lock, server)}
    if "approved" in states:
        return "approved"
    return "unapproved" if states else None


# --- composition -------------------------------------------------------------


def _retarget(findings: list[Finding], target: str) -> list[Finding]:
    """Rewrite ``target`` and neutralise control characters in every rendered field."""
    return [
        f.model_copy(update={"target": target, "message": safe_text(f.message), "snippet": safe_text(f.snippet)})
        for f in findings
    ]


def _finding(rule_id: str, severity: str, target: str, name: str, message: str) -> Finding:
    return Finding(rule_id=rule_id, severity=severity, target=target, snippet=safe_text(name), message=message)


def scan_server(
    source: ConfigSource, name: str, server: dict[str, Any], locks: list[tuple[Path, WardenLock]]
) -> ServerReport:
    """Run auth + supply + lock-coverage over one server (no spawn, no network)."""
    target = safe_text(f"{source.label}#{name}")
    findings = _retarget(audit_server(name, server), target)
    command = server.get("command")
    if isinstance(command, str) and command:
        args = [str(a) for a in (server.get("args") or [])]
        findings += _retarget(check_launch_command(command, args), target)
    base = name[: -len("#servers")] if name.endswith("#servers") else name
    if base in source.ambiguous:
        findings.append(_finding(
            "WRD-DOCTOR-AMBIGUOUS-SERVER", "medium", target, base,
            "declared under both mcpServers and servers with different definitions; a decoy map "
            "can hide the one the client loads from an audit — keep exactly one",
        ))
    state = coverage(server, locks)
    if state is None:
        findings.append(_finding(
            "WRD-DOCTOR-NO-LOCK", "low", target, name,
            "no warden.lock pins this server's declared surface; run the pin command below",
        ))
    elif state == "unapproved":
        findings.append(_finding(
            "WRD-DOCTOR-LOCK-UNAPPROVED", "medium", target, name,
            "a warden.lock matches this server but pin.approved is false; a human has not "
            "approved the surface (mcp-warden lock rotate <lock> --approver <id>)",
        ))
    findings.sort(key=lambda f: (f.target, f.rule_id, f.snippet))
    return ServerReport(source, name, server, findings, state is not None)


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
    """Discover, load, and scan. Raises :class:`DoctorError` only for ``--config`` paths.

    ``--config`` paths are de-duplicated by resolved path (a symlink and its
    target are one file), and an explicit path replaces the discovered source
    for the same file — naming it is what makes it ``--pin``-eligible.
    """
    report = DoctorReport()

    def _warn(msg: str) -> None:
        report.warnings.append(msg)
        warn(safe_text(msg, max_len=400))

    found = discover(platform, home, cwd, env, _warn) if do_discover else Discovery()
    report.sources, report.searched = found.sources, found.searched
    report.hard_errors, report.skipped = found.hard_errors, found.skipped
    named: set[Path] = set()
    for p in explicit:
        resolved = p.resolve()
        if resolved in named:
            _warn(f"--config {p}: same file as an earlier --config path; scanning it once")
            continue
        named.add(resolved)
        report.sources.extend(load_explicit(p, home))
    if named:
        report.sources = [s for s in report.sources if s.explicit or s.path.resolve() not in named]
    locks = find_locks(cwd, _warn)
    for src in report.sources:
        for name, server in src.servers.items():
            report.reports.append(scan_server(src, name, server, locks))
    return report
