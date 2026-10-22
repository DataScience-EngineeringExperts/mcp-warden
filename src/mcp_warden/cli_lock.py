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

from .cli_sign import _sidecar_path_for, sign_after_pin
from .corpus_coordinate import parse_explicit as parse_coordinate
from .lockfile import compute_overall_digest, read_lock, write_lock
from .models import WardenLock
from .provenance import ProvenanceError, rotate_provenance


def _now_rfc3339() -> str:
    """Current UTC time as RFC 3339, second precision (e.g. ``2026-06-08T14:22:05Z``)."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_consistent_lock(lock: Path, err_console: Console, remedy: str) -> WardenLock:
    """Read ``lock`` and refuse (exit 2) one whose entries do not reproduce its digest.

    A mismatch means the lock was hand-edited / tampered; neither rotate nor sign
    may "launder" it by re-stamping it.
    """
    try:
        lock_doc = read_lock(lock)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    recomputed = compute_overall_digest(
        lock_doc.server, lock_doc.tools, lock_doc.resources, lock_doc.prompts,
        schema_version=lock_doc.schema_version,
    )
    if recomputed != lock_doc.overall_digest:
        err_console.print(
            "[red]error:[/red] lock is internally inconsistent / tampered "
            f"(stored entries do not reproduce overall_digest); {remedy}"
        )
        raise typer.Exit(code=2)
    return lock_doc


def register(app: typer.Typer, console: Console, err_console: Console) -> None:
    """Attach the ``lock`` sub-app (with ``rotate`` and ``sign``) to ``app``."""

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
        # Integrity gate (fail closed): recompute overall_digest from the lock's
        # OWN stored entries; refuse and re-pin on a mismatch.
        lock_doc = _read_consistent_lock(lock, err_console, "re-pin instead of rotating")

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

    @lock_app.command("sign")
    def sign(
        lock: Path = typer.Argument(..., help="Path to an existing, unsigned warden.lock"),
        coordinate: Optional[str] = typer.Option(
            None, "--coordinate",
            help="Bind the package coordinate <npm|pypi>:<name>@<version> into the signature (v2 statement)",
        ),
        identity_token: Optional[str] = typer.Option(
            None, "--identity-token", help="Explicit OIDC token for signing (default: ambient/CI OIDC)"
        ),
    ) -> None:
        """Sigstore-sign an existing lock; same fail-closed contract as ``pin --sign``.

        For attesters that capture UNSIGNED where no OIDC token is reachable (a
        ``--network none`` sandbox) and sign afterwards. Writes ``<lock>.sigstore``
        beside the lock; ``overall_digest`` is unchanged. Refuses (exit 2) a
        tampered lock, a malformed coordinate, an existing sidecar, or a lock that
        already carries a signature pointer — it never overwrites or stacks a
        signature. Signing failure exits 1 with no partial sidecar.
        """
        coord_text = None
        if coordinate is not None:
            parsed = parse_coordinate(coordinate)
            if parsed is None:
                err_console.print("[red]error:[/red] --coordinate must be <npm|pypi>:<name>@<pinned-version>")
                raise typer.Exit(code=2)
            coord_text = str(parsed)

        lock_doc = _read_consistent_lock(lock, err_console, "re-pin instead of signing")

        sidecar = _sidecar_path_for(lock)
        if sidecar.exists():
            err_console.print(f"[red]error:[/red] {sidecar} already exists; refusing to overwrite a signature")
            raise typer.Exit(code=2)
        if any(a.method == "sigstore-keyless" for a in lock_doc.pin.attestations):
            err_console.print(
                "[red]error:[/red] lock already carries a signature pointer; re-pin to produce an unsigned lock"
            )
            raise typer.Exit(code=2)

        sign_after_pin(lock_doc, lock, identity_token, err_console, coordinate=coord_text)
        statement = "v2 (coordinate-bound)" if coord_text else "v1"
        console.print(f"[green]signed[/green] -> {sidecar}")
        console.print(f"  statement: {statement}")
        console.print(f"  overall_digest: {lock_doc.overall_digest} [dim](unchanged)[/dim]")
