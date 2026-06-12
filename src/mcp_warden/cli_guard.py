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

    def _warn_deprecated(err: Console, **flags: bool) -> None:
        """Emit a one-line stderr deprecation note for each supplied v0.2 --block-* no-op.

        In v0.3 the deterministic tier blocks by default, so the v0.2 enable flags
        are inert (GUARD_PROXY_V3.md §4.5). They are accepted (old scripts keep
        working) but each prints a single deprecation line and changes nothing.
        """
        _names = {
            "block_ansi": "--block-ansi",
            "block_secret_echo": "--block-secret-echo",
            "block_exfil_domain": "--block-exfil-domain",
            "block_list_changed": "--block-list-changed",
            "block_policy": "--block-policy",
            "block_deterministic": "--block-deterministic",
        }
        for key, supplied in flags.items():
            if supplied:
                err.print(
                    f"[yellow]deprecated:[/yellow] {_names[key]} is a no-op in v0.3 "
                    f"(its category blocks by default); see GUARD_PROXY_V3.md §4.5",
                    highlight=False,
                )

    @app.command()
    def guard(
        server_cmd: list[str] = typer.Argument(..., help="MCP server launch argv (e.g. node ./server.js)"),
        lock: Optional[Path] = typer.Option(None, "--lock", help="Arms per-tool precision + tools/list_changed gate"),
        policy_file: Optional[Path] = typer.Option(None, "--policy", help="Arms runtime argument policy (POLICY_MODEL.md)"),
        exfil_denylist: Optional[Path] = typer.Option(None, "--exfil-denylist", help="Org never-callback domains (merged)"),
        inject_phrases: Optional[Path] = typer.Option(None, "--inject-phrases", help="Org exact injection phrases (merged)"),
        no_block_ansi: bool = typer.Option(False, "--no-block-ansi", help="Demote WRD-RES-ANSI to shadow"),
        no_block_secret_echo: bool = typer.Option(False, "--no-block-secret-echo", help="Demote WRD-RES-SECRET-ECHO to shadow"),
        no_block_exfil_domain: bool = typer.Option(False, "--no-block-exfil-domain", help="Demote WRD-RES-EXFIL-DOMAIN to shadow"),
        allow_exfil_domain: bool = typer.Option(False, "--allow-exfil-domain", help="Alias of --no-block-exfil-domain"),
        no_block_exfil_ip_literal: bool = typer.Option(False, "--no-block-exfil-ip-literal", help="Demote WRD-RES-EXFIL-IP-LITERAL to shadow"),
        no_block_list_changed: bool = typer.Option(False, "--no-block-list-changed", help="Demote tools/list_changed gate to shadow"),
        no_block_policy: bool = typer.Option(False, "--no-block-policy", help="Demote argument-policy deny to shadow"),
        no_block_deterministic: bool = typer.Option(False, "--no-block-deterministic", help="Demote the WHOLE deterministic tier + both gates"),
        block_inject_phrase: bool = typer.Option(False, "--block-inject-phrase", help="Opt-in block for WRD-RES-INJECT-PHRASE (fuzzy)"),
        block_ansi: bool = typer.Option(False, "--block-ansi", help="DEPRECATED no-op (now default-on)", hidden=True),
        block_secret_echo: bool = typer.Option(False, "--block-secret-echo", help="DEPRECATED no-op", hidden=True),
        block_exfil_domain: bool = typer.Option(False, "--block-exfil-domain", help="DEPRECATED no-op", hidden=True),
        block_list_changed: bool = typer.Option(False, "--block-list-changed", help="DEPRECATED no-op", hidden=True),
        block_policy: bool = typer.Option(False, "--block-policy", help="DEPRECATED no-op", hidden=True),
        block_deterministic: bool = typer.Option(False, "--block-deterministic", help="DEPRECATED no-op", hidden=True),
        redact_secret_echo: bool = typer.Option(False, "--redact-secret-echo", help="Redact secret echoes in place vs error-replace"),
        audit_only: bool = typer.Option(False, "--audit-only", help="Force warnings; disable ALL blocking (highest precedence)"),
        strict: bool = typer.Option(
            False,
            "--strict/--no-strict",
            help=(
                "Fail-CLOSED on internal inspection errors (integrity over availability): "
                "terminate the session non-zero (exit 3) if any tool-result / argument-policy "
                "/ tools-list inspection cannot complete, instead of failing open. This fires on "
                "inspection BUGS and policy CONFIGURATION errors too, not only on malicious inputs "
                "-- any uncompleted inspection ends the session (a false-positive kill is the "
                "deliberate integrity-over-availability trade-off). Default off (fail-open). "
                "Framing/EOF/over-cap stay fail-open in all modes."
            ),
        ),
        strict_frame_cap: bool = typer.Option(
            False,
            "--strict-frame-cap",
            help=(
                "Terminate the session (exit 3) if a server->client result frame exceeds "
                "--max-frame-bytes (closes the padded-frame inspection bypass). Independent "
                "of --strict. Raise --max-frame-bytes for legitimately large results -- that "
                "widens the per-frame memory cap for ALL frames."
            ),
        ),
        sarif: Optional[Path] = typer.Option(None, "--sarif", help="Write a SARIF report on shutdown"),
        json_out: Optional[Path] = typer.Option(None, "--json", help="Write JSONL findings on shutdown"),
        record: Optional[Path] = typer.Option(None, "--record", help="Record observed frames for later inspect"),
        max_frame_bytes: int = typer.Option(8 * 1024 * 1024, "--max-frame-bytes", help="Per-frame memory cap"),
        max_inflight: int = typer.Option(1024, "--max-inflight", help="Request-correlation map bound"),
    ) -> None:
        """Run the transparent stdio guard proxy (v0.3: deterministic tier blocks by default)."""
        command, args = _split(server_cmd)
        _warn_deprecated(
            err_console,
            block_ansi=block_ansi,
            block_secret_echo=block_secret_echo,
            block_exfil_domain=block_exfil_domain,
            block_list_changed=block_list_changed,
            block_policy=block_policy,
            block_deterministic=block_deterministic,
        )
        # --no-block-deterministic demotes the whole tier + both gates (§4.2);
        # --allow-exfil-domain is the sole affirmative alias of --no-block-exfil-domain.
        cfg = GuardConfig(
            no_block_ansi=no_block_ansi or no_block_deterministic,
            no_block_secret_echo=no_block_secret_echo or no_block_deterministic,
            no_block_exfil_domain=no_block_exfil_domain or allow_exfil_domain or no_block_deterministic,
            no_block_exfil_ip_literal=no_block_exfil_ip_literal or no_block_deterministic,
            no_block_list_changed=no_block_list_changed or no_block_deterministic,
            no_block_policy=no_block_policy or no_block_deterministic,
            block_inject_phrase=block_inject_phrase,
            armed_list_changed=lock is not None,
            armed_policy=policy_file is not None,
            redact_secret_echo=redact_secret_echo,
            audit_only=audit_only,
            strict=strict,
            strict_frame_cap=strict_frame_cap,
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
