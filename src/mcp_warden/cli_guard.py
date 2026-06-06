"""CLI command bodies for ``guard`` + ``inspect`` (GUARD_PROXY.md §8).

Split from ``cli.py`` to keep each module under the LOC budget. ``register(app,
console, err_console)`` attaches the two commands to the given typer app.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import res_rules
from .emit_res import build_result_sarif, result_findings_to_jsonl, result_sarif_to_json
from .guard import run_guard
from .guard_loop import GuardConfig
from .inspector import TraceError, analyze_trace, exit_code_for
from .lockfile import read_lock
from .policy_model import PolicyError, load_policy
from .result_inspection import severity_to_level


def register(app: typer.Typer, console: Console, err_console: Console) -> None:
    """Attach the ``guard`` and ``inspect`` commands to ``app``."""

    def _load_line_list(path: Optional[Path]) -> tuple[str, ...]:
        """Load a literal-entry file (one domain/phrase per line; '#' comments)."""
        if path is None:
            return ()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            err_console.print(f"[red]error:[/red] could not read {path}: {exc}")
            raise typer.Exit(code=2) from exc
        return tuple(ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#"))

    def _split(server_cmd: list[str]) -> tuple[str, list[str]]:
        if not server_cmd:
            err_console.print("[red]error:[/red] no server command provided")
            raise typer.Exit(code=2)
        return server_cmd[0], list(server_cmd[1:])

    @app.command()
    def guard(
        server_cmd: list[str] = typer.Argument(..., help="MCP server launch argv (e.g. node ./server.js)"),
        lock: Optional[Path] = typer.Option(None, "--lock", help="Per-tool precision + tools/list_changed gate"),
        policy_file: Optional[Path] = typer.Option(None, "--policy", help="Runtime argument policy (POLICY_MODEL.md)"),
        exfil_denylist: Optional[Path] = typer.Option(None, "--exfil-denylist", help="Org never-callback domains (merged)"),
        inject_phrases: Optional[Path] = typer.Option(None, "--inject-phrases", help="Org exact injection phrases (merged)"),
        block_ansi: bool = typer.Option(False, "--block-ansi", help="Block WRD-RES-ANSI (redact in place)"),
        block_secret_echo: bool = typer.Option(False, "--block-secret-echo", help="Block WRD-RES-SECRET-ECHO"),
        block_exfil_domain: bool = typer.Option(False, "--block-exfil-domain", help="Block WRD-RES-EXFIL-DOMAIN"),
        block_list_changed: bool = typer.Option(False, "--block-list-changed", help="Block divergent tools/list (needs --lock)"),
        block_policy: bool = typer.Option(False, "--block-policy", help="Block argument-policy deny verdicts"),
        block_inject_phrase: bool = typer.Option(False, "--block-inject-phrase", help="Block WRD-RES-INJECT-PHRASE (opt-in)"),
        block_deterministic: bool = typer.Option(False, "--block-deterministic", help="Shorthand: ansi+secret-echo+exfil+list-changed"),
        redact_secret_echo: bool = typer.Option(False, "--redact-secret-echo", help="Redact secret echoes in place vs error-replace"),
        audit_only: bool = typer.Option(False, "--audit-only", help="Force warnings; disable ALL blocking (highest precedence)"),
        sarif: Optional[Path] = typer.Option(None, "--sarif", help="Write a SARIF report on shutdown"),
        json_out: Optional[Path] = typer.Option(None, "--json", help="Write JSONL findings on shutdown"),
        record: Optional[Path] = typer.Option(None, "--record", help="Record observed frames for later inspect"),
        max_frame_bytes: int = typer.Option(8 * 1024 * 1024, "--max-frame-bytes", help="Per-frame memory cap"),
        max_inflight: int = typer.Option(1024, "--max-inflight", help="Request-correlation map bound"),
    ) -> None:
        """Run the transparent stdio guard proxy (shadow-default; opt-in blocking)."""
        command, args = _split(server_cmd)
        cfg = GuardConfig(
            block_ansi=block_ansi or block_deterministic,
            block_secret_echo=block_secret_echo or block_deterministic,
            block_exfil_domain=block_exfil_domain or block_deterministic,
            block_list_changed=block_list_changed or block_deterministic,
            block_policy=block_policy,
            block_inject_phrase=block_inject_phrase,
            redact_secret_echo=redact_secret_echo,
            audit_only=audit_only,
            max_frame_bytes=max_frame_bytes,
            max_inflight=max_inflight,
        )

        lock_doc = None
        if lock is not None:
            try:
                lock_doc = read_lock(lock)
            except (FileNotFoundError, ValueError) as exc:
                err_console.print(f"[red]error:[/red] {exc}")
                raise typer.Exit(code=2) from exc

        policy = None
        if policy_file is not None:
            try:
                policy, messages = load_policy(policy_file)
            except PolicyError as exc:
                err_console.print(f"[red]error:[/red] {exc}")
                raise typer.Exit(code=2) from exc
            if any(m.level == "error" for m in messages):
                err_console.print("[red]error:[/red] policy has lint errors; fix them before guarding")
                raise typer.Exit(code=2)

        exfil = res_rules.SEED_EXFIL_DENYLIST + _load_line_list(exfil_denylist)
        phrases = res_rules.SEED_INJECT_PHRASES + _load_line_list(inject_phrases)

        findings_sink: list = []
        record_lines: list[str] = []

        def _on_finding(f) -> None:
            findings_sink.append(f)
            err_console.print(
                f"[{severity_to_level(f.severity)}] {f.rule_id} {f.action} {f.tool} (id={f.rpc_id})",
                highlight=False,
            )

        def _record(direction: str, frame: dict) -> None:
            record_lines.append(json.dumps({"direction": direction, "frame": frame}, ensure_ascii=False))

        code = run_guard(
            command,
            args,
            cfg,
            lock=lock_doc,
            policy=policy,
            exfil_denylist=exfil,
            inject_phrases=phrases,
            on_finding=_on_finding,
            record=_record if record is not None else None,
        )

        if record is not None:
            record.write_text("\n".join(record_lines) + ("\n" if record_lines else ""), encoding="utf-8")
        if sarif is not None:
            sarif.write_text(result_sarif_to_json(build_result_sarif(findings_sink)), encoding="utf-8")
        if json_out is not None:
            json_out.write_text(result_findings_to_jsonl(findings_sink), encoding="utf-8")

        raise typer.Exit(code=code)

    @app.command()
    def inspect(
        trace: Path = typer.Argument(..., help="Recorded JSONL trace of a JSON-RPC session"),
        lock: Optional[Path] = typer.Option(None, "--lock", help="Per-tool precision from a warden.lock"),
        exfil_denylist: Optional[Path] = typer.Option(None, "--exfil-denylist", help="Org never-callback domains (merged)"),
        inject_phrases: Optional[Path] = typer.Option(None, "--inject-phrases", help="Org exact injection phrases (merged)"),
        sarif: Optional[Path] = typer.Option(None, "--sarif", help="Write a SARIF report"),
        json_out: Optional[Path] = typer.Option(None, "--json", help="Write JSONL findings"),
        audit_only: bool = typer.Option(False, "--audit-only", help="Force exit 0 regardless of findings"),
    ) -> None:
        """Run the WRD-RES-* catalog offline over a recorded trace; exit non-zero on BLOCK-tier."""
        lock_doc = None
        if lock is not None:
            try:
                lock_doc = read_lock(lock)
            except (FileNotFoundError, ValueError) as exc:
                err_console.print(f"[red]error:[/red] {exc}")
                raise typer.Exit(code=2) from exc

        exfil = res_rules.SEED_EXFIL_DENYLIST + _load_line_list(exfil_denylist)
        phrases = res_rules.SEED_INJECT_PHRASES + _load_line_list(inject_phrases)

        try:
            findings = analyze_trace(trace, lock=lock_doc, exfil_denylist=exfil, inject_phrases=phrases)
        except TraceError as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        if sarif is not None:
            sarif.write_text(result_sarif_to_json(build_result_sarif(findings)), encoding="utf-8")
        if json_out is not None:
            json_out.write_text(result_findings_to_jsonl(findings), encoding="utf-8")
        else:
            _print_result_findings(console, findings)

        raise typer.Exit(code=exit_code_for(findings, audit_only=audit_only))


def _print_result_findings(console: Console, findings) -> None:
    """Print result-inspection findings as a rich table."""
    if not findings:
        console.print("[green]OK[/green] no result findings")
        return
    table = Table(title="Result inspection findings")
    for col in ("severity", "tier", "rule", "tool", "message"):
        table.add_column(col)
    for f in findings:
        table.add_row(f.severity, f.tier, f.rule_id, f.tool, f.message)
    console.print(table)
