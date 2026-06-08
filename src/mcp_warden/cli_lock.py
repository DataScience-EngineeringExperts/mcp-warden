"""CLI command body for the ``lock`` sub-app — ``warden lock rotate`` (#19).

Split from ``cli.py`` to keep each module under the LOC budget. ``register(app,
console, err_console)`` attaches a ``lock`` typer sub-app (matching the
``cli_guard.py`` idiom) carrying the ``rotate`` command.

``rotate`` re-attests an existing baseline's provenance WITHOUT re-capturing the
server surface, so ``overall_digest`` is left byte-identical (WARDEN_LOCK_SCHEMA
§8.x). It fails closed (exit 2) on a missing/invalid lock or on any internal
inconsistency (recompute-from-entries integrity gate), and writes nothing in
those cases.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .lockfile import compute_overall_digest, read_lock, write_lock
from .provenance import ProvenanceError, rotate_provenance


def _now_rfc3339() -> str:
    """Current UTC time as RFC 3339, second precision (e.g. ``2026-06-08T14:22:05Z``)."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def register(app: typer.Typer, console: Console, err_console: Console) -> None:
    """Attach the ``lock`` sub-app (with ``rotate``) to ``app``."""

    lock_app = typer.Typer(add_completion=False, help="Lifecycle ops on an existing warden.lock baseline.")
    app.add_typer(lock_app, name="lock")

    @lock_app.command("rotate")
    def rotate(
        lock: Path = typer.Argument(..., help="Path to an existing warden.lock"),
        approver: Optional[str] = typer.Option(None, "--approver", help="Re-attest as approver (re-binds scalar approval)"),
        actor: Optional[str] = typer.Option(None, "--actor", help="Human/CI principal for the refreshed pinner (or WARDEN_ACTOR env)"),
        note: Optional[str] = typer.Option(None, "--note", help="Public tamper-evident note (<=1000 chars)"),
        json_out: bool = typer.Option(False, "--json", help="Emit the rotate summary as JSON"),
    ) -> None:
        """Re-attest provenance on an existing lock; ``overall_digest`` UNCHANGED.

        Rotate is permitted on UNAPPROVED locks (legit incremental-attestation CI
        workflow) — it does NOT gate on approval. It DOES gate on integrity: a
        lock whose stored entries no longer reproduce its ``overall_digest`` (or
        whose approval no longer binds the surface) is refused (exit 2, no write).
        """
        try:
            lock_doc = read_lock(lock)
        except (FileNotFoundError, ValueError) as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        # Integrity gate (fail closed): recompute overall_digest from the lock's
        # OWN stored entries. A mismatch means the lock was hand-edited / tampered
        # — rotate must never "launder" it by re-stamping; refuse and re-pin.
        recomputed = compute_overall_digest(
            lock_doc.server, lock_doc.tools, lock_doc.resources, lock_doc.prompts
        )
        if recomputed != lock_doc.overall_digest:
            err_console.print(
                "[red]error:[/red] lock is internally inconsistent / tampered "
                "(stored entries do not reproduce overall_digest); re-pin instead of rotating"
            )
            raise typer.Exit(code=2)

        # A stale approval (surface changed since approval) must not be silently
        # re-blessed by rotate; refuse so the operator re-pins/re-approves.
        if lock_doc.pin.approved and lock_doc.pin.approved_digest != lock_doc.overall_digest:
            err_console.print(
                "[red]error:[/red] approval is stale (approved_digest does not bind the "
                "current surface); re-pin + re-approve instead of rotating"
            )
            raise typer.Exit(code=2)

        old_count = lock_doc.pin.rotation_count
        # Capture the pre-rotate digest so the "unchanged" claim is COMPUTED, not
        # asserted: rotate is digest-invariant by contract, but a future regression
        # that mutated overall_digest must be caught here, not silently reported True.
        before_digest = lock_doc.overall_digest
        now = _now_rfc3339()
        try:
            rotated = rotate_provenance(lock_doc, approver=approver, actor=actor, note=note, now=now)
        except ProvenanceError as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        try:
            write_lock(rotated, lock)
        except OSError as exc:
            err_console.print(f"[red]error:[/red] could not write lock: {exc}")
            raise typer.Exit(code=2) from exc

        attester = rotated.pin.attestations[-1].actor
        role = rotated.pin.attestations[-1].role
        digest_unchanged = rotated.overall_digest == before_digest
        if json_out:
            console.print(
                json.dumps(
                    {
                        "lock": str(lock),
                        "rotation_count": {"old": old_count, "new": rotated.pin.rotation_count},
                        "attester": attester,
                        "role": role,
                        "rotated_at": now,
                        "overall_digest": rotated.overall_digest,
                        "overall_digest_unchanged": digest_unchanged,
                    },
                    indent=2,
                ),
                soft_wrap=True,
            )
        else:
            console.print(f"[green]rotated[/green] -> {lock}")
            console.print(f"  rotation_count: {old_count} -> {rotated.pin.rotation_count}")
            console.print(f"  attester: {attester} (role={role})")
            unchanged_tag = "unchanged" if digest_unchanged else "CHANGED"
            console.print(f"  overall_digest: {rotated.overall_digest} [dim]({unchanged_tag})[/dim]")
