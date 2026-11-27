"""Operator entry points for the Linux local evidence custodian."""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import sys
from pathlib import Path
from typing import Optional

import typer

from .evidence_vault_files import EvidenceVaultError


def register(app: typer.Typer, err_console) -> None:
    evidence_app = typer.Typer(help="Manage the Linux local encrypted evidence vault.")
    app.add_typer(evidence_app, name="evidence")

    def refuse() -> None:
        err_console.print("error: EVD-REFUSED", highlight=False)
        raise typer.Exit(2) from None

    @evidence_app.command(name="init")
    def initialize(store: Path = typer.Option(..., help="Empty private vault directory")) -> None:
        """Initialize a vault using the dedicated custodian account."""
        _require_linux(refuse)
        from .evidence_vault import initialize_vault

        try:
            initialize_vault(store)
        except (OSError, ValueError, ImportError, sqlite3.Error):
            refuse()

    @evidence_app.command()
    def serve(
        store: Path = typer.Option(...),
        socket: Path = typer.Option(...),
        policy: Path = typer.Option(..., help="Private service-owned exact grant manifest"),
        keyring: Path = typer.Option(..., help="Private customer-managed service keyring"),
        retention_seconds: int = typer.Option(..., min=1, max=3660 * 86400),
    ) -> None:
        """Serve only authenticated peers on the configured Unix socket."""
        _require_linux(refuse)
        from .evidence_key_service import EvidenceKeyServiceError, LocalKeyService
        from .evidence_vault import LocalEvidenceVault

        os.umask(0o077)
        try:
            def stop(_signum, _frame):
                raise KeyboardInterrupt

            previous = signal.signal(signal.SIGTERM, stop)
            try:
                with (
                    LocalEvidenceVault(store, retention_seconds=retention_seconds) as vault,
                    LocalKeyService(socket, keyring_path=keyring, policy_path=policy, dispatch=vault.dispatch) as service,
                ):
                    service.serve_forever()
            finally:
                signal.signal(signal.SIGTERM, previous)
        except KeyboardInterrupt:
            return
        except (OSError, ValueError, ImportError, sqlite3.Error, EvidenceKeyServiceError):
            refuse()

    @evidence_app.command()
    def public_key(store: Path = typer.Option(...)) -> None:
        """Print the verification key from the vault as the custodian account."""
        _require_linux(refuse)
        from .evidence_vault import load_signing_key

        try:
            key = load_signing_key(store)
            typer.echo(key.public_key().public_bytes_raw().hex())
        except (OSError, ValueError, ImportError):
            refuse()

    @evidence_app.command()
    def verify_summary(
        artifact: Path = typer.Option(..., help="Local signed summary JSON"),
        verification_key: str = typer.Option(..., help="Previously enrolled customer vault public key in hex"),
    ) -> None:
        """Verify a summary offline with the enrolled customer verification key."""
        from .evidence_summary import MAX_SUMMARY_BYTES, parse_summary
        from .evidence_summary import verify_summary as check

        try:
            with artifact.open("rb") as stream:
                data = stream.read(MAX_SUMMARY_BYTES + 1)
            check(parse_summary(data), verification_key)
        except (OSError, ValueError, RecursionError, ImportError):
            refuse()
        typer.echo("verified")

    @evidence_app.command()
    def act(
        action: str = typer.Argument(..., help="read, export, audit, summary, hold, release or delete"),
        socket: Path = typer.Option(...),
        service_uid: int = typer.Option(...),
        tenant: str = typer.Option(...),
        category: str = typer.Option(..., help="tool-arguments or tool-result"),
        purpose: str = typer.Option(...),
        object_id: Optional[str] = typer.Option(None),
        after: int = typer.Option(0, min=0, help="Audit cursor"),
        output: Optional[Path] = typer.Option(None, help="New file in a private reviewer directory for raw export"),
    ) -> None:
        """Request one scoped operation as your authenticated local account."""
        _require_linux(refuse)
        from .evidence_key_service import (
            EvidenceKeyServiceError,
            LocalServiceClient,
            decode_payload,
        )
        from .evidence_vault import CUSTODIAN_ACTIONS, REVIEW_ACTIONS
        from .evidence_vault_files import new_file, private_directory, sync_dir

        request = {"action": action, "tenant": tenant, "category": category, "purpose": purpose}
        try:
            if action not in (*REVIEW_ACTIONS, *CUSTODIAN_ACTIONS):
                raise EvidenceVaultError("EVD-POLICY")
            if action == "read" and not sys.stdout.isatty():
                raise EvidenceVaultError("EVD-POLICY")
            if action == "export":
                if output is None or output.name in ("", ".", "..") or output.is_symlink() or output.exists():
                    raise EvidenceVaultError("EVD-POLICY")
                private_directory(output.parent)
            elif output is not None:
                raise EvidenceVaultError("EVD-POLICY")
            if action in ("audit", "summary"):
                if object_id is not None or (action == "summary" and after):
                    raise EvidenceVaultError("EVD-POLICY")
                if action == "audit":
                    request["after"] = after
            else:
                if object_id is None or after:
                    raise EvidenceVaultError("EVD-POLICY")
                request["object_id"] = object_id
            result = LocalServiceClient(socket, service_uid=service_uid).request(request)
            if action in ("read", "export"):
                if set(result) != {"content"}:
                    raise EvidenceVaultError("EVD-POLICY")
                content = decode_payload(result["content"])
                if action == "read":
                    # JSON string escaping prevents ANSI/control characters in the
                    # captured object from being interpreted by the terminal.
                    typer.echo(json.dumps(json.loads(content), ensure_ascii=True))
                else:
                    new_file(output, content)
                    sync_dir(output.parent)
            elif action == "summary":
                from .evidence_summary import checked_summary

                checked_summary(result)
                typer.echo(json.dumps(result, separators=(",", ":")))
            elif action == "audit":
                _validate_audit(result, tenant=tenant, category=category)
                typer.echo(json.dumps(result, separators=(",", ":")))
            elif result == {"applied": True}:
                typer.echo('{"applied":true}')
            else:
                raise EvidenceVaultError("EVD-POLICY")
        except (OSError, ValueError, TypeError, KeyError, ImportError, EvidenceKeyServiceError):
            refuse()


def _require_linux(refuse) -> None:
    if not sys.platform.startswith("linux"):
        refuse()


def _validate_audit(result: dict, *, tenant: str, category: str) -> None:
    """Use a closed projection and verify each signed event before writing output."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from .evidence_vault import CUSTODIAN_ACTIONS, _json

    if set(result) != {"verification_key", "receipts"} or type(result["receipts"]) is not list:
        raise EvidenceVaultError("EVD-AUDIT")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(result["verification_key"]))
    fields = {"schema_version", "sequence", "previous", "tenant", "category", "object_id",
              "action", "time", "expires", "uid", "role", "purpose"}
    for receipt in result["receipts"]:
        if set(receipt) != {"event", "signature"}:
            raise EvidenceVaultError("EVD-AUDIT")
        event = receipt["event"]
        if set(event) != fields or event["action"] not in (*CUSTODIAN_ACTIONS, "capture", "read", "export") or (
            (event["tenant"], event["category"]) != (tenant, category)
        ):
            raise EvidenceVaultError("EVD-AUDIT")
        try:
            key.verify(bytes.fromhex(receipt["signature"]), _json(event))
        except InvalidSignature:
            raise EvidenceVaultError("EVD-AUDIT") from None
