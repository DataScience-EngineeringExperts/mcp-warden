"""CLI command body for ``deploy-gate`` (WRD-GATE-*) — DSE-1257.

Split from ``cli.py`` to keep each module under the LOC budget.
``register(app, console, err_console)`` attaches the ``deploy-gate`` command.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .deploy_gate import DeployGateError, GateOutcome, run_deploy_gate
from .emitters import build_sarif, findings_to_jsonl, sarif_to_json


def _print_summary(console: Console, outcome: GateOutcome) -> None:
    if outcome.passed:
        console.print(
            f"[green]deploy gate PASS[/green] ({outcome.controls_checked} control(s) satisfied)"
        )
        return
    table = Table(title=f"Deploy gate FAILED ({outcome.controls_checked} control(s) checked)")
    table.add_column("severity", no_wrap=True)
    table.add_column("rule", no_wrap=True)
    table.add_column("control")
    table.add_column("reason")
    for f in outcome.findings:
        color = {"critical": "red", "high": "red", "medium": "yellow"}.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.rule_id, f.target, f.message)
    console.print(table)


def register(app: typer.Typer, console: Console, err_console: Console) -> None:
    """Attach the ``deploy-gate`` command to ``app``."""

    @app.command("deploy-gate")
    def deploy_gate(
        policy: Path = typer.Option(..., "--policy", help="Gate policy JSON (required controls)"),
        evidence: Path = typer.Option(
            ..., "--evidence", help="Deploy evidence JSON produced by the pipeline"
        ),
        json_out: bool = typer.Option(False, "--json", help="Emit findings as JSONL to stdout"),
        sarif: Optional[Path] = typer.Option(None, "--sarif", help="Write a SARIF report to this path"),
    ) -> None:
        """Fail-closed CI gate for agent deployments ("release_control for agents").

        Verifies a deploy's evidence against a declared gate policy: required
        eval suites met their thresholds, required guardrails are active, a
        budget/quota is declared, and a human-approval receipt is present when
        required. Any unmet or missing/malformed control fails the gate.
        Exits 0 only on a fully satisfied gate; 1 on any gate finding; 2 on a
        read/parse error (fail closed).
        """
        try:
            outcome = run_deploy_gate(policy, evidence)
        except DeployGateError as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        if sarif is not None:
            sarif.write_text(sarif_to_json(build_sarif(outcome.findings)), encoding="utf-8")

        if json_out:
            console.print(findings_to_jsonl(outcome.findings), end="")
        else:
            _print_summary(console, outcome)

        if outcome.findings:
            raise typer.Exit(code=1)
