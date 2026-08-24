"""CLI command body for ``auth audit`` (WRD-AUTH-*) — DSE-1258.

Split from ``cli.py`` to keep each module under the LOC budget.
``register(app, console, err_console)`` attaches an ``auth`` sub-app with a
single ``audit`` command, matching the ``policy`` sub-app idiom.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .auth_audit import AuthAuditError, audit_path
from .emitters import build_sarif, findings_to_jsonl, sarif_to_json
from .models import Finding


def _print_summary(console: Console, findings: list[Finding], scanned: int) -> None:
    if not findings:
        console.print(f"[green]auth audit clean[/green] ({scanned} config file(s), no findings)")
        return
    table = Table(title=f"MCP auth-posture findings ({scanned} config file(s))")
    table.add_column("severity", no_wrap=True)
    table.add_column("rule", no_wrap=True)
    table.add_column("target")
    table.add_column("message")
    for f in findings:
        color = {"critical": "red", "high": "red", "medium": "yellow"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.rule_id, f.target, f.message)
    console.print(table)


def register(app: typer.Typer, console: Console, err_console: Console) -> None:
    """Attach the ``auth audit`` command tree to ``app``."""
    auth_app = typer.Typer(add_completion=False, help="Static MCP auth-posture audit.")
    app.add_typer(auth_app, name="auth")

    @auth_app.command("audit")
    def audit(
        configs: list[Path] = typer.Argument(
            ..., help="MCP config file(s) to audit (claude_desktop_config.json / .mcp.json / mcp.json)"
        ),
        json_out: bool = typer.Option(False, "--json", help="Emit findings as JSONL to stdout"),
        sarif: Optional[Path] = typer.Option(None, "--sarif", help="Write a SARIF report to this path"),
    ) -> None:
        """Audit MCP client/server config for weak auth posture; fail closed.

        Static only: no server is spawned, no network is touched. Flags remote
        endpoints reachable without auth, credential literals in config,
        cleartext http:// transport, and inline secrets that should reference a
        secret manager. Exits 1 on any finding, 2 on a read/parse error.
        """
        all_findings: list[Finding] = []
        for path in configs:
            try:
                all_findings.extend(audit_path(path))
            except AuthAuditError as exc:
                err_console.print(f"[red]error:[/red] {exc}")
                raise typer.Exit(code=2) from exc

        all_findings.sort(key=lambda f: (f.target, f.rule_id, f.snippet))

        if sarif is not None:
            sarif.write_text(sarif_to_json(build_sarif(all_findings)), encoding="utf-8")

        if json_out:
            console.print(findings_to_jsonl(all_findings), end="", soft_wrap=True)
        else:
            _print_summary(console, all_findings, len(configs))

        if all_findings:
            raise typer.Exit(code=1)
