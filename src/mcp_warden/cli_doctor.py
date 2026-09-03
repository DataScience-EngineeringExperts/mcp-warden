"""CLI command body for ``doctor`` (zero-config posture scan) — DSE-1516.

Split from ``cli.py`` to keep each module under the LOC budget.
``register(app, console, err_console)`` attaches the ``doctor`` command.

The default path is static — no spawn, no network, no DNS. ``--pin`` is the
one opt-in that launches servers, and it refuses to do so in a non-interactive
session unless ``--yes`` is passed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .capture import CaptureError, capture_surface_http_sync, capture_surface_sync
from .checks import run_checks
from .doctor import DoctorError, DoctorReport, ServerReport, pin_command, run_doctor, slug
from .emitters import build_sarif, findings_to_jsonl, sarif_to_json
from .lockfile import build_lock, write_lock

_ACTION_SNIPPET = """\
# .github/workflows/mcp-integrity.yml
jobs:
  mcp-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DataScience-EngineeringExperts/mcp-warden@v0
        with:
          server-cmd: "<your server launch argv>"
          lock: "<name>.warden.lock"
"""


def _platform() -> str:
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("win"):
        return "win32"
    return "linux"


def _print_report(console: Console, report: DoctorReport) -> None:
    """Human-first posture report: sources, findings, then the next command."""
    console.print(f"[bold]MCP posture[/bold] — {len(report.sources)} config source(s), "
                  f"{len(report.reports)} server(s)")
    # Labels, targets and messages carry user-controlled text (a project path such
    # as ``#projects[/repo]`` reads as a closing tag to rich) — always escape.
    for src in report.sources:
        console.print(f"  [cyan]{escape(src.client)}[/cyan]  {escape(src.label)}  ({len(src.servers)} server(s))")

    findings = report.findings
    if not findings:
        console.print("[green]doctor clean[/green] — every server is pinned and shows no posture findings")
        return

    table = Table(title=f"Posture findings ({len(findings)})")
    table.add_column("severity", no_wrap=True)
    table.add_column("rule", no_wrap=True)
    table.add_column("server")
    table.add_column("message")
    for f in sorted(findings, key=lambda f: (_rank(f.severity), f.target, f.rule_id)):
        color = {"critical": "red", "high": "red", "medium": "yellow"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.rule_id, escape(f.target), escape(f.message))
    console.print(table)

    uncovered = report.uncovered
    if uncovered:
        console.print(f"\n[bold]Next steps[/bold] — {len(uncovered)} server(s) have no warden.lock. "
                      "Pin each once, commit the lock, then wire the check into CI:")
        for r in uncovered:
            # soft_wrap: the command must survive copy-paste, never be folded to width.
            console.print(
                f"  # {r.target}\n  {pin_command(r.name, r.server)}",
                markup=False, highlight=False, soft_wrap=True,
            )
        console.print("\n[bold]Then in CI[/bold] (one job per pinned server):")
        console.print(_ACTION_SNIPPET, highlight=False, markup=False)


def _rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 4)


def _pin_uncovered(
    uncovered: list[ServerReport], cwd: Path, timeout: float, console: Console, err: Console
) -> int:
    """Pin every uncovered server into ``<slug>.warden.lock`` (unapproved TOFU).

    Returns the number of servers that could not be captured. Each failure is
    reported and the rest still run — one broken server must not hide the others.
    """
    failed = 0
    for r in uncovered:
        lock = cwd / f"{slug(r.name)}.warden.lock"
        url = r.server.get("url")
        try:
            if isinstance(url, str) and url:
                surface = capture_surface_http_sync(url, timeout_s=timeout)
            else:
                command = str(r.server.get("command") or "")
                args = [str(a) for a in (r.server.get("args") or [])]
                surface = capture_surface_sync(command, args, timeout_s=timeout)
            write_lock(build_lock(surface, run_checks(surface), approve=False, approver=None), lock)
        except (CaptureError, OSError, ValueError) as exc:
            err.print(f"[red]pin failed[/red] {escape(r.target)}: {escape(str(exc))}")
            failed += 1
            continue
        console.print(
            f"[green]pinned[/green] {escape(r.target)} -> {escape(lock.name)} (unapproved). "
            f"Approve with: mcp-warden lock rotate {lock.name} --approver you@example.com",
            soft_wrap=True,
        )
    return failed


def register(app: typer.Typer, console: Console, err_console: Console) -> None:
    """Attach the ``doctor`` command to ``app``."""

    @app.command("doctor")
    def doctor(
        config: Optional[list[Path]] = typer.Option(
            None, "--config", help="Scan this config file too (repeatable; may be a symlink)"
        ),
        no_discover: bool = typer.Option(
            False, "--no-discover", help="Skip well-known locations; scan only --config paths"
        ),
        json_out: bool = typer.Option(False, "--json", help="Emit findings as JSONL to stdout"),
        sarif: Optional[Path] = typer.Option(None, "--sarif", help="Write a SARIF report to this path"),
        pin: bool = typer.Option(
            False, "--pin", help="OPT-IN: spawn each uncovered server and write <name>.warden.lock"
        ),
        yes: bool = typer.Option(False, "--yes", help="With --pin: do not prompt (required when non-interactive)"),
        timeout: float = typer.Option(30.0, "--timeout", help="With --pin: capture timeout (seconds)"),
        home: Optional[Path] = typer.Option(None, "--home", hidden=True, help="Override home (tests)"),
        platform: Optional[str] = typer.Option(None, "--platform", hidden=True, help="Override platform (tests)"),
    ) -> None:
        """Zero-config MCP posture scan of every agent config on this machine.

        Discovers Claude Code / Claude Desktop / Cursor / VS Code / Windsurf /
        Codex configs, then runs the static auth audit (WRD-AUTH-*), the
        supply-chain launch checks (WRD-SUP-*), and a lock-coverage check
        (WRD-DOCTOR-NO-LOCK) over every configured server. Static by default:
        nothing is spawned, no network, no DNS. Prints the exact `pin` command
        for each uncovered server. Exits 0 clean; 1 on any finding; 2 on an
        unreadable or malformed config (fail closed).
        """
        home_dir = home or Path.home()
        cwd = Path.cwd()
        try:
            report = run_doctor(
                platform=platform or _platform(),
                home=home_dir,
                cwd=cwd,
                env=os.environ,
                explicit=list(config or []),
                do_discover=not no_discover,
                warn=lambda m: err_console.print(f"[yellow]warning:[/yellow] {escape(m)}"),
            )
        except DoctorError as exc:
            err_console.print(f"[red]error:[/red] {escape(str(exc))}")
            raise typer.Exit(code=2) from exc

        if not report.sources:
            console.print(
                f"[green]no MCP configs found[/green] "
                f"(searched {report.searched} well-known location(s); pass --config to add one)"
            )
            raise typer.Exit(code=0)

        if sarif is not None:
            sarif.write_text(sarif_to_json(build_sarif(report.findings)), encoding="utf-8")
        if json_out:
            console.print(findings_to_jsonl(report.findings), end="", soft_wrap=True, markup=False, highlight=False)
        else:
            _print_report(console, report)

        pin_failures = 0
        if pin and report.uncovered:
            if not yes:
                if not sys.stdin.isatty():
                    err_console.print(
                        "[red]error:[/red] --pin would spawn servers; refusing in a non-interactive "
                        "session without --yes"
                    )
                    raise typer.Exit(code=2)
                if not typer.confirm(f"Spawn {len(report.uncovered)} server(s) to pin them?", default=False):
                    raise typer.Exit(code=2)
            pin_failures = _pin_uncovered(report.uncovered, cwd, timeout, console, err_console)

        if pin_failures:
            raise typer.Exit(code=2)
        if report.findings:
            raise typer.Exit(code=1)
