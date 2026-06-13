"""mcp-warden CLI (typer).

Commands:
  pin <server-cmd...>   capture + write warden.lock (+ --approve)
  check <server-cmd...> re-capture + diff vs lock; non-zero exit on drift
  policy lint <file>    lint a policy file
  policy eval <file> <sample>  evaluate one sample call; non-zero exit on deny

Exit codes:
  check -> non-zero on any drift (WARDEN_LOCK_SCHEMA.md §10.7)
  policy eval -> non-zero on a deny verdict (POLICY_MODEL.md §6.8)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .capture import CaptureError, capture_surface_sync
from .check_core import run_check_full
from .checks import run_checks
from .cli_diff import register as register_diff_command
from .cli_guard import register as register_guard_commands
from .cli_lock import register as register_lock_commands
from .cli_sign import sign_after_pin, verify_lock_signature
from .emitters import build_sarif, findings_to_jsonl, sarif_to_json
from .lockfile import (
    DEFAULT_LOCK_NAME,
    build_lock,
    read_lock,
    write_lock,
)
from .policy_eval import evaluate_call, overall_denied
from .policy_model import (
    PolicyError,
    infer_shapes_from_arguments,
    lint_against_lock,
    load_policy,
)

logging.basicConfig(level=os.environ.get("WARDEN_LOG_LEVEL", "WARNING"), format="%(levelname)s %(name)s: %(message)s")

app = typer.Typer(add_completion=False, help="CI-first MCP supply-chain integrity gate.")
policy_app = typer.Typer(add_completion=False, help="Lint + single-sample evaluation of a policy file.")
app.add_typer(policy_app, name="policy")

console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    """Print ``mcp-warden <version>`` and exit 0 (eager ``--version`` handler)."""
    if value:
        console.print(f"mcp-warden {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the mcp-warden version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """CI-first MCP supply-chain integrity gate."""


# v0.2 runtime commands (guard/inspect) + the #19 `lock` sub-app live in their
# own modules to keep this file under the LOC budget; register them here.
register_guard_commands(app, console, err_console)
register_lock_commands(app, console, err_console)
register_diff_command(app, console, err_console)


def _split_server_cmd(server_cmd: list[str]) -> tuple[str, list[str]]:
    """Split a ``<server-cmd...>`` argv list into ``(command, args)``."""
    if not server_cmd:
        err_console.print("[red]error:[/red] no server command provided")
        raise typer.Exit(code=2)
    return server_cmd[0], list(server_cmd[1:])


@app.command()
def pin(
    server_cmd: list[str] = typer.Argument(..., help="MCP server launch argv (e.g. node ./server.js)"),
    lock: Path = typer.Option(Path(DEFAULT_LOCK_NAME), "--lock", help="Output lock path"),
    approve: bool = typer.Option(False, "--approve", help="Record a human approval attestation"),
    approver: Optional[str] = typer.Option(None, "--approver", help="Approver identity (or WARDEN_APPROVER env)"),
    json_out: bool = typer.Option(False, "--json", help="Emit findings as JSONL to stdout"),
    sarif: Optional[Path] = typer.Option(None, "--sarif", help="Write SARIF report to this path"),
    timeout: float = typer.Option(30.0, "--timeout", help="Capture timeout (seconds)"),
    sign: bool = typer.Option(False, "--sign", help="Sigstore-sign overall_digest (requires mcp-warden[sigstore])"),
    identity_token: Optional[str] = typer.Option(
        None, "--identity-token", help="Explicit OIDC token for signing (default: ambient/CI OIDC)"
    ),
) -> None:
    """Pin an MCP server's declared surface into ``warden.lock`` (TOFU baseline)."""
    command, args = _split_server_cmd(server_cmd)
    approver_id = approver or os.environ.get("WARDEN_APPROVER")
    if approve and not approver_id:
        err_console.print("[red]error:[/red] --approve requires --approver <id> or WARDEN_APPROVER env")
        raise typer.Exit(code=2)

    try:
        surface = capture_surface_sync(command, args, timeout_s=timeout)
    except CaptureError as exc:
        err_console.print(f"[red]capture failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    findings = run_checks(surface)
    lock_doc = build_lock(surface, findings, approve=approve, approver=approver_id)

    try:
        write_lock(lock_doc, lock)
    except OSError as exc:
        err_console.print(f"[red]error:[/red] could not write lock: {exc}")
        raise typer.Exit(code=2) from exc

    # #16 (opt-in): Sigstore-sign overall_digest. Fails CLOSED — on any signing
    # error the command exits non-zero and leaves no half-written sidecar. The
    # signature/bundle/pointer are all OUTSIDE overall_digest, so signing does NOT
    # change the digest of the lock written above.
    if sign:
        lock_doc = sign_after_pin(lock_doc, lock, identity_token, err_console)

    if sarif is not None:
        sarif.write_text(sarif_to_json(build_sarif(findings)), encoding="utf-8")
    if json_out:
        console.print(findings_to_jsonl(findings), end="")
    else:
        _print_pin_summary(lock_doc, findings, lock, approve)


@app.command()
def check(
    server_cmd: Optional[list[str]] = typer.Argument(
        None, help="MCP server launch argv (must match the pinned launch); omit with --verify"
    ),
    lock: Path = typer.Option(Path(DEFAULT_LOCK_NAME), "--lock", help="Baseline lock path"),
    json_out: bool = typer.Option(False, "--json", help="Emit findings+drift as JSONL to stdout"),
    sarif: Optional[Path] = typer.Option(None, "--sarif", help="Write SARIF report to this path"),
    timeout: float = typer.Option(30.0, "--timeout", help="Capture timeout (seconds)"),
    verify: bool = typer.Option(
        False, "--verify", help="Verify the lock's Sigstore signature (requires mcp-warden[sigstore])"
    ),
    certificate_identity: Optional[str] = typer.Option(
        None, "--certificate-identity", help="Expected signer identity (required with --verify)"
    ),
    certificate_oidc_issuer: Optional[str] = typer.Option(
        None, "--certificate-oidc-issuer", help="Expected OIDC issuer (required with --verify)"
    ),
    offline_bundle: Optional[Path] = typer.Option(
        None, "--offline-bundle", help="Explicit bundle path (default: <lockname>.sigstore next to the lock)"
    ),
) -> None:
    """Re-capture and verify a server against ``warden.lock``; fail on drift.

    With ``--verify`` the command ALSO/INSTEAD verifies the lock's Sigstore
    signature (a no-server-spawn cryptographic check). ``--verify`` requires
    ``--certificate-identity`` and ``--certificate-oidc-issuer`` and exits 0 only
    on a clean verify; ANY failure (bad signature, identity mismatch, missing/
    malformed bundle, TUF/network error) exits non-zero (fail closed).
    """
    if verify:
        verify_lock_signature(
            lock, certificate_identity, certificate_oidc_issuer, offline_bundle, console, err_console
        )
        return

    command, args = _split_server_cmd(server_cmd)

    try:
        # Single source of truth shared with the pre-commit wrapper (precommit.py)
        # so a local hook and CI can never disagree on a drift verdict.
        result = run_check_full(command, args, lock, timeout_s=timeout)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except CaptureError as exc:
        err_console.print(f"[red]capture failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    findings = result.findings
    drift = result.drift

    if sarif is not None:
        sarif.write_text(sarif_to_json(build_sarif(findings, drift)), encoding="utf-8")

    if json_out:
        console.print(findings_to_jsonl(findings, drift), end="")
    else:
        _print_check_summary(drift, lock)

    if drift:
        raise typer.Exit(code=1)


@policy_app.command("lint")
def policy_lint(
    policy_file: Path = typer.Argument(..., help="Policy YAML file"),
    lock: Optional[Path] = typer.Option(None, "--lock", help="Cross-check tool entries against this lock"),
    json_out: bool = typer.Option(False, "--json", help="Emit lint messages as JSON"),
) -> None:
    """Lint a policy file; non-zero exit on any lint error (fail closed)."""
    try:
        policy, messages = load_policy(policy_file)
    except PolicyError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if lock is not None:
        try:
            lock_doc = read_lock(lock)
            messages.extend(lint_against_lock(policy, lock_doc))
        except (FileNotFoundError, ValueError) as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from exc

    errors = [m for m in messages if m.level == "error"]
    if json_out:
        console.print(json.dumps([m.__dict__ for m in messages], indent=2))
    else:
        _print_lint(messages)

    if errors:
        raise typer.Exit(code=1)


@policy_app.command("eval")
def policy_eval(
    policy_file: Path = typer.Argument(..., help="Policy YAML file"),
    sample: Path = typer.Argument(..., help="Sample call JSON ({tool, arguments})"),
    lock: Optional[Path] = typer.Option(None, "--lock", help="Resolve tool shapes from this lock"),
    json_out: bool = typer.Option(False, "--json", help="Emit verdict as JSON"),
) -> None:
    """Evaluate one sample call; non-zero exit on a deny verdict (CI assertion)."""
    try:
        policy, messages = load_policy(policy_file)
    except PolicyError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    if any(m.level == "error" for m in messages):
        err_console.print("[red]error:[/red] policy has lint errors; fix them before eval")
        raise typer.Exit(code=2)

    try:
        call = json.loads(sample.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        err_console.print(f"[red]error:[/red] could not read sample call: {exc}")
        raise typer.Exit(code=2) from exc

    tool = str(call.get("tool", ""))
    arguments = call.get("arguments") or {}
    if not isinstance(arguments, dict):
        err_console.print("[red]error:[/red] sample 'arguments' must be an object")
        raise typer.Exit(code=2)

    shapes = _resolve_shapes(tool, arguments, lock)
    verdicts = evaluate_call(policy, tool, arguments, shapes)

    if json_out:
        console.print(json.dumps([v.to_dict() for v in verdicts], indent=2))
    else:
        _print_verdicts(verdicts)

    if overall_denied(verdicts):
        raise typer.Exit(code=1)


def _resolve_shapes(tool: str, arguments: dict, lock: Optional[Path]) -> list[str]:
    """Resolve tool shapes from the lock if present, else infer from arguments."""
    from .policy_model import SHAPE_TO_FLAG

    if lock is not None:
        try:
            lock_doc = read_lock(lock)
        except (FileNotFoundError, ValueError) as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        flag_to_shape = {v: k for k, v in SHAPE_TO_FLAG.items()}
        for t in lock_doc.tools:
            if t.name == tool:
                return sorted(flag_to_shape[f] for f in t.capabilities if f in flag_to_shape)
        return []
    return infer_shapes_from_arguments(arguments)


# --- human (rich) output -----------------------------------------------------


def _print_pin_summary(lock_doc, findings, lock_path: Path, approve: bool) -> None:
    """Print a pin summary table."""
    console.print(f"[green]pinned[/green] -> {lock_path}")
    console.print(f"  overall_digest: {lock_doc.overall_digest}")
    console.print(f"  tools={len(lock_doc.tools)} resources={len(lock_doc.resources)} prompts={len(lock_doc.prompts)}")
    if approve:
        console.print(f"  approved by: {lock_doc.pin.approver}")
    _print_findings_table(findings, "Findings at pin time")


def _print_findings_table(findings, title: str) -> None:
    """Print findings as a rich table."""
    if not findings:
        console.print("  no static findings")
        return
    table = Table(title=title)
    table.add_column("severity")
    table.add_column("rule")
    table.add_column("target")
    table.add_column("snippet")
    for f in findings:
        table.add_row(f.severity, f.rule_id, f.target, f.snippet)
    console.print(table)


def _print_check_summary(drift, lock_path: Path) -> None:
    """Print a check drift summary."""
    if not drift:
        console.print(f"[green]OK[/green] no drift vs {lock_path}")
        return
    console.print(f"[red]DRIFT DETECTED[/red] vs {lock_path} ({len(drift)} item(s))")
    table = Table(title="Drift")
    table.add_column("severity")
    table.add_column("class")
    table.add_column("target")
    table.add_column("message")
    for d in drift:
        table.add_row(d.severity, d.drift_class, d.target, d.message)
    console.print(table)


def _print_lint(messages) -> None:
    """Print lint messages."""
    if not messages:
        console.print("[green]OK[/green] policy is valid")
        return
    for m in messages:
        color = {"error": "red", "warning": "yellow", "note": "cyan"}.get(m.level, "white")
        console.print(f"[{color}]{m.level}[/{color}] {m.code}: {m.message}")


def _print_verdicts(verdicts) -> None:
    """Print evaluation verdicts."""
    for v in verdicts:
        color = "red" if v.verdict == "deny" else "green"
        console.print(f"[{color}]{v.verdict}[/{color}] [{v.shape}] {v.reason} ({v.constraint})")


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
