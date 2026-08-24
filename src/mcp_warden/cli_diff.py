"""CLI command body for ``warden diff`` — offline, redacted lock comparison (#20).

Split from ``cli.py`` to keep each module under the LOC budget. ``register(app,
console, err_console)`` attaches the ``diff`` command (matching the
``cli_lock.py`` idiom).

``diff`` is a **renderer over the existing drift engine** (``compute_drift``),
NOT a second ``check``: it compares two EXISTING lock files offline (no capture),
renders integrity drift grouped by severity, and surfaces #19 provenance changes
in a separate, clearly-labeled informational section. It adds NO diff logic and
changes NO contract.

Redaction contract (the security surface): the renderer consumes ONLY
:class:`~mcp_warden.drift.DriftItem` objects (safe by construction — server
identity drift is a hardcoded "launch changed" message, schema ``detail`` is
pre-redacted) plus an explicit allowlist of SAFE provenance fields
(:data:`SAFE_PROVENANCE_FIELDS`). It NEVER reads ``lock.server.command`` or
``lock.server.args`` for display (only ``command_digest``), so a secret embedded
in launch argv can never leak into any output mode.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .drift import DriftItem, compute_drift
from .emitters import build_sarif, findings_to_jsonl, sarif_to_json
from .lockfile import read_lock
from .models import WardenLock

#: Explicit allowlist of SAFE provenance fields the informational section may
#: render (M1 / LEAK-1). The provenance display is built by EXPLICIT key
#: extraction against this set (``getattr``) — NEVER ``__dict__`` /
#: ``model_dump()`` / ``asdict()`` iteration, which could surface a future
#: secret-bearing field. ``command_digest`` is read from ``lock.server``; every
#: other field is read from ``lock.pin``. ``len(attestations)`` is rendered
#: explicitly (the list itself is never iterated for display).
#:
#: MAINTENANCE: when the provenance model (PinMetadata / ServerIdentity) adds a
#: field worth showing, update this set AND the ``test_diff_redaction_leak`` test
#: deliberately — the leak test is the guard for this allowlist.
SAFE_PROVENANCE_FIELDS: frozenset = frozenset(
    {
        "command_digest",
        "approved",
        "approver",
        "approved_digest",
        "approved_at",
        "rotated_at",
        "rotation_count",
        "provenance_version",
    }
)

#: Severity -> rank for human-table ordering (most severe first).
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _safe_provenance(lock: WardenLock) -> dict[str, object]:
    """Extract ONLY the allowlisted provenance fields from a lock (M1).

    Built by explicit ``getattr`` against :data:`SAFE_PROVENANCE_FIELDS`.
    ``command_digest`` lives on ``lock.server``; the rest live on ``lock.pin``.
    ``len(attestations)`` is added explicitly (the attestation objects are never
    surfaced). NEVER touches ``lock.server.command`` / ``lock.server.args``.

    Args:
        lock: The lock document to extract from.

    Returns:
        A dict of allowlisted field name -> scalar value, plus
        ``"attestation_count"`` (an explicit ``len``).
    """
    out: dict[str, object] = {}
    for key in SAFE_PROVENANCE_FIELDS:
        if key == "command_digest":
            out[key] = getattr(lock.server, key)
        else:
            out[key] = getattr(lock.pin, key)
    out["attestation_count"] = len(lock.pin.attestations)
    return out


def _provenance_diffs(lock_a: WardenLock, lock_b: WardenLock) -> list[tuple[str, object, object]]:
    """Compute the differing safe provenance fields between A and B.

    Args:
        lock_a: Baseline (before) lock.
        lock_b: Current (after) lock.

    Returns:
        A sorted list of ``(field, a_value, b_value)`` for every allowlisted
        field whose value differs between the two locks. Empty when identical.
    """
    a = _safe_provenance(lock_a)
    b = _safe_provenance(lock_b)
    return [(k, a[k], b[k]) for k in sorted(a) if a[k] != b[k]]


def _render_drift_table(console: Console, drift: list[DriftItem], header: str) -> None:
    """Render integrity drift as a rich table (``_print_check_summary`` style).

    Rows are sorted most-severe-first then by target for stability. Reuses the
    severity/class/target/message columns of the ``check`` summary.

    Args:
        console: The stdout console.
        drift: The integrity drift items (from ``compute_drift``).
        header: The ``a.lock → b.lock`` header line (M5, resolved basenames).
    """
    console.print(f"[bold]{header}[/bold] ({len(drift)} integrity change(s))")
    rows = sorted(drift, key=lambda d: (_SEVERITY_RANK.get(d.severity, 99), d.target, d.drift_class))
    table = Table(title="Integrity drift")
    table.add_column("severity")
    table.add_column("class")
    table.add_column("target")
    table.add_column("message")
    for d in rows:
        table.add_row(d.severity, d.drift_class, d.target, d.message)
    console.print(table)


def _render_provenance_section(
    console: Console, diffs: list[tuple[str, object, object]]
) -> None:
    """Render the informational provenance section (M1 — allowlisted fields only).

    Clearly labeled as NON-integrity. Each row shows a safe field's old → new
    value. Called only with the pre-extracted, allowlisted diff list.

    Args:
        console: The stdout console.
        diffs: ``(field, a_value, b_value)`` triples from :func:`_provenance_diffs`.
    """
    console.print("[dim]Provenance (informational — not integrity drift)[/dim]")
    table = Table(title="Provenance changes (not integrity drift)")
    table.add_column("field")
    table.add_column("a (baseline)")
    table.add_column("b (current)")
    for field, a_val, b_val in diffs:
        table.add_row(field, str(a_val), str(b_val))
    console.print(table)


def register(app: typer.Typer, console: Console, err_console: Console) -> None:
    """Attach the ``diff`` command to ``app`` (cli_lock.py register idiom)."""

    @app.command("diff")
    def diff(
        lock_a: Path = typer.Argument(..., help="Lock A = baseline / before"),
        lock_b: Path = typer.Argument(..., help="Lock B = current / after"),
        json_out: bool = typer.Option(False, "--json", help="Emit drift as JSONL to stdout"),
        sarif: Optional[Path] = typer.Option(
            None,
            "--sarif",
            help=(
                "Write a SARIF report to this path. NOTE: the lock file paths you "
                "pass as arguments may appear in SARIF output — avoid paths that "
                "themselves contain secrets."
            ),
        ),
        no_provenance: bool = typer.Option(
            False, "--no-provenance", help="Suppress the informational provenance section"
        ),
        exit_code: bool = typer.Option(
            False,
            "--exit-code",
            help=(
                "git-diff-like: exit 1 when INTEGRITY DRIFT exists (default exit 0). "
                "Provenance-only differences do NOT trip it — they are informational. "
                "An 'unapproved-change' drift legitimately appears in the integrity "
                "section (it is real drift) and may double-signal with the provenance "
                "section."
            ),
        ),
    ) -> None:
        """Render a human-readable, redacted diff of two existing lock files.

        ``diff`` is an OFFLINE VIEWER over the drift engine — it never captures a
        live server (that is ``check``). It reuses ``compute_drift(A, B)`` and
        renders the result; A is the baseline/before, B is the current/after.

        Redaction: raw ``server.command`` / ``server.args`` (which can carry
        secrets) are NEVER printed in any mode. A server-identity change shows as
        the hardcoded "launch changed" message plus ``command_digest`` old → new.

        Exit codes: default 0 (it is a viewer, not a gate — ``check`` stays the
        gate). With ``--exit-code``, exit 1 IFF there is integrity drift;
        provenance-only differences do NOT trip the exit code.
        """
        try:
            a = read_lock(lock_a)
            b = read_lock(lock_b)
            drift = compute_drift(a, b)
            # Compute provenance diffs ONCE (A4): the displayed list and the M6
            # hidden-count are both derived from this single computation, so the
            # "(N hidden)" message always matches what would render. A missing
            # allowlisted field surfaces here as AttributeError (2-arg getattr in
            # _safe_provenance) and is caught below -> fail closed (exit 2).
            all_prov_diffs = _provenance_diffs(a, b)
        except (FileNotFoundError, ValueError, AttributeError) as exc:
            # Fail CLOSED: a malformed-but-parseable lock (e.g. a missing
            # allowlisted provenance field) exits 2 instead of an uncaught
            # traceback.
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        prov_diffs = [] if no_provenance else all_prov_diffs

        if sarif is not None:
            try:
                sarif.write_text(sarif_to_json(build_sarif([], drift)), encoding="utf-8")
            except OSError as exc:
                err_console.print(f"[red]error:[/red] could not write SARIF: {exc}")
                raise typer.Exit(code=2) from exc

        if json_out:
            console.print(findings_to_jsonl([], drift), end="", soft_wrap=True)
        else:
            header = f"{lock_a.name} → {lock_b.name}"
            if drift:
                _render_drift_table(console, drift, header)
            if prov_diffs:
                _render_provenance_section(console, prov_diffs)
            if not drift and not prov_diffs:
                # M6: if --no-provenance hid real provenance differences, say so
                # rather than a bare "no differences". Count comes from the
                # already-computed all_prov_diffs (A4) — no double-compute, and
                # the count matches what would have rendered.
                hidden = len(all_prov_diffs) if no_provenance else 0
                if hidden:
                    console.print(
                        f"[green]no integrity drift[/green] ({hidden} provenance "
                        "difference(s) hidden by --no-provenance)"
                    )
                else:
                    console.print(f"[green]no differences[/green] ({header})")

        if exit_code and drift:
            raise typer.Exit(code=1)
