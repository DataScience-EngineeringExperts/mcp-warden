"""Zero-config MCP posture scan (``mcp-warden doctor``) — DSE-1516.

Discovers every MCP client config on the machine, then runs the *existing*
engines over each configured server — ``WRD-AUTH-*``, ``WRD-SUP-*``, and a
lock-coverage check (``WRD-DOCTOR-NO-LOCK`` / ``WRD-DOCTOR-LOCK-UNAPPROVED``)
— and prints the exact ``pin`` command for anything uncovered. It composes
checks; it adds no new detection catalog. Nothing here spawns, resolves, or
connects.

Every config-controlled string that reaches a terminal passes through
:func:`safe_text` first: a cloned repo's ``.mcp.json`` must not repaint the
terminal (``\\x1b``) or inject a second line into the block the user is told
to copy and run (``\\n``). See ``docs/DOCTOR.md``.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .auth_audit import _is_auth_key, _looks_like_secret_ref, audit_server
from .checks_secret import scan_field, shannon_entropy
from .checks_supply import check_launch_command
from .doctor_discovery import ConfigSource, Discovery, DoctorError, discover, load_explicit
from .lockfile import read_lock
from .models import Finding, WardenLock

__all__ = ["ConfigSource", "DoctorError", "DoctorReport", "ServerReport", "run_doctor", "safe_text"]

#: Directories never descended into when looking for locks.
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".ruff_cache", ".tox"}
_LOCK_MAX_DEPTH = 4
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def safe_text(s: object, max_len: int = 200) -> str:
    """Neutralise control characters (U+FFFD) and cap length before any render."""
    t = _CONTROL.sub("�", str(s))
    return t if len(t) <= max_len else t[: max_len - 1] + "…"


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
    state = coverage(server, locks)
    if state is None:
        findings.append(Finding(
            rule_id="WRD-DOCTOR-NO-LOCK", severity="low", target=target, snippet=safe_text(name),
            message="no warden.lock pins this server's declared surface; run the pin command below",
        ))
    elif state == "unapproved":
        findings.append(Finding(
            rule_id="WRD-DOCTOR-LOCK-UNAPPROVED", severity="medium", target=target, snippet=safe_text(name),
            message="a warden.lock matches this server but pin.approved is false; a human has not "
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
    """Discover, load, and scan. Raises :class:`DoctorError` only for ``--config`` paths."""
    report = DoctorReport()

    def _warn(msg: str) -> None:
        report.warnings.append(msg)
        warn(safe_text(msg, max_len=400))

    found = discover(platform, home, cwd, env, _warn) if do_discover else Discovery()
    report.sources, report.searched = found.sources, found.searched
    report.hard_errors, report.skipped = found.hard_errors, found.skipped
    for p in explicit:
        report.sources.extend(load_explicit(p, home))
    locks = find_locks(cwd, _warn)
    for src in report.sources:
        for name, server in src.servers.items():
            report.reports.append(scan_server(src, name, server, locks))
    return report


# --- the funnel ------------------------------------------------------------------

#: Flags whose *following* value (or ``=``/``:``-joined value) is a credential.
#: Doctor-local and deliberately wider than ``auth_audit._is_auth_key``: Smithery's
#: ``--key <uuid>``, mcp-remote's ``--header "Authorization: Bearer …"``.
_AUTH_FLAGS = {
    "key", "api-key", "apikey", "token", "secret", "password", "passwd", "pat", "bearer",
    "credential", "credentials", "cookie", "auth", "authorization", "header", "h",
}
_WIN_REF = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")
_AUTH_QUERY = {"api_key", "apikey", "key", "token", "access_token", "secret", "sig", "signature", "auth"}
_PATH_ENTROPY_MIN_LEN = 20
_PATH_ENTROPY_THRESHOLD = 3.5


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "server"


def lock_filename(name: str, taken: set[str]) -> str:
    """``<slug>.warden.lock``; a slug collision gets a short hash of the raw name."""
    base = slug(name)
    fn = f"{base}.warden.lock"
    if fn in taken:
        fn = f"{base}-{hashlib.sha256(name.encode()).hexdigest()[:6]}.warden.lock"
    taken.add(fn)
    return fn


def _is_auth_flag(token: str) -> bool:
    k = token.lstrip("-").lower().replace("_", "-")
    return k in _AUTH_FLAGS or _is_auth_key(k)


def _is_ref(value: str) -> bool:
    """``${VAR}`` / ``$VAR`` / ``{{ x }}`` / ``%VAR%`` — a reference carries nothing."""
    return _looks_like_secret_ref(value) or bool(_WIN_REF.fullmatch(value.strip()))


def _json_object_with_auth_key(arg: str) -> bool:
    if not arg.lstrip().startswith("{"):
        return False
    try:
        doc = json.loads(arg)
    except ValueError:
        return False
    return isinstance(doc, dict) and any(_is_auth_flag(str(k)) for k in doc)


def _mask_arg(prev: str, arg: str) -> bool:
    """Whether a launch argument must be masked in the printed ``pin`` command.

    A vendor-pattern hit always masks. The entropy heuristic alone does **not**
    — ``@modelcontextprotocol/server-github`` is high-entropy and is exactly the
    token the user must copy. The value after an auth-shaped flag, the value of
    an auth-shaped ``KEY=value`` / ``Key: value``, and a JSON object carrying an
    auth-shaped key are masked unless the value is a ``${VAR}``-style reference.
    """
    if any(f.rule_id != "WRD-SEC-ENTROPY" for f in scan_field(arg, "arg")):
        return True
    if _json_object_with_auth_key(arg):
        return True
    for sep in ("=", ":"):
        key, found, value = arg.partition(sep)
        if found and _is_auth_flag(key.strip()):
            return not _is_ref(value)
    if prev.startswith("-") and _is_auth_flag(prev):
        return not _is_ref(arg)
    return False


def _redact_url(url: str) -> str:
    """Keep scheme + host; mask userinfo, auth-shaped query params, token-like path segments."""
    parts = urlsplit(url)
    if "@" in parts.netloc:
        return "<REDACTED: url embeds a credential>"
    segments = []
    for seg in parts.path.split("/"):
        risky = len(seg) >= _PATH_ENTROPY_MIN_LEN and (
            shannon_entropy(seg) >= _PATH_ENTROPY_THRESHOLD
            or any(f.rule_id != "WRD-SEC-ENTROPY" for f in scan_field(seg, "url"))
        )
        segments.append("REDACTED" if risky else seg)
    query = [(k, "REDACTED" if _is_auth_flag(k) or k.lower() in _AUTH_QUERY else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), urlencode(query), parts.fragment))


def pin_command(name: str, server: dict[str, Any], lock: str | None = None) -> str:
    """The copy-pasteable ``pin`` for one server; credential-bearing parts are masked."""
    lock = lock or f"{slug(name)}.warden.lock"
    tail = f"--approve --approver you@example.com --lock {lock}"
    url = server.get("url")
    if isinstance(url, str) and url:
        return f"mcp-warden pin --url {shlex.quote(_redact_url(safe_text(url, 2048)))} {tail}"
    argv = [shlex.quote(safe_text(server.get("command") or "<command>", 2048))]
    prev = ""
    for a in server.get("args") or []:
        a = str(a)
        argv.append("<REDACTED>" if _mask_arg(prev, a) else shlex.quote(safe_text(a, 2048)))
        prev = a
    return f"mcp-warden pin {' '.join(argv)} {tail}"
