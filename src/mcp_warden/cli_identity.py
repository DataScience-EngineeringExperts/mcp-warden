"""Offline comparison of two MCP deployment observations."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict
from pathlib import Path

import typer

from mcp_warden.artifact_trust import (
    MAX_ROOTS_BYTES,
    ArtifactTrustError,
    Ed25519ArtifactVerifierV1,
    parse_roots,
)
from mcp_warden.bundle_identity import (
    MAX_IDENTITY_BYTES,
    IdentityComparisonStatus,
    IdentityComparisonV1,
    IdentityError,
    IdentityObservationV1,
    compare_deployment_identities,
    parse_deployment_identity,
)


def _read(path: Path, limit: int, code: str) -> bytes:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            if stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                data = source.read(limit + 1)
                if len(data) <= limit:
                    return data
    except OSError:
        pass
    raise IdentityError(code)


def _observation(
    path: Path, signer: str | None, signature: Path | None, label: str
) -> IdentityObservationV1:
    try:
        model = parse_deployment_identity(_read(path, MAX_IDENTITY_BYTES, "IDENTITY-UNREADABLE"))
    except IdentityError:
        pass
    else:
        if signature is None:
            return IdentityObservationV1(model)
        try:
            return IdentityObservationV1(model, signer, _read(signature, 64, "IDENTITY-UNREADABLE"))
        except IdentityError:
            raise IdentityError(f"{label}_signature_unreadable") from None
    raise IdentityError(f"{label}_malformed")


def _emit(report: IdentityComparisonV1) -> None:
    typer.echo(json.dumps(asdict(report), sort_keys=True))
    if report.status is IdentityComparisonStatus.DRIFT:
        raise typer.Exit(code=1)
    if report.status is IdentityComparisonStatus.INDETERMINATE:
        raise typer.Exit(code=2)


def register(app: typer.Typer) -> None:
    identity = typer.Typer(
        add_completion=False, help="Compare offline deployment identity evidence."
    )
    app.add_typer(identity, name="identity")

    @identity.command("compare")
    def compare(
        baseline: Path = typer.Argument(..., help="Reference observation JSON."),
        current: Path = typer.Argument(..., help="Current observation JSON."),
        roots: Path | None = typer.Option(
            None, "--roots", help="Observation public keys and roles."
        ),
        roots_pin: str | None = typer.Option(
            None, "--roots-digest", help="Independent pin for the observation roots."
        ),
        baseline_signer: str | None = typer.Option(None, help="Reference attester key identity."),
        baseline_signature: Path | None = typer.Option(
            None, help="Reference raw Ed25519 signature."
        ),
        current_signer: str | None = typer.Option(None, help="Current attester key identity."),
        current_signature: Path | None = typer.Option(None, help="Current raw Ed25519 signature."),
    ) -> None:
        """Return 0 for verified match, 1 for verified drift, or 2 for indeterminate evidence."""
        try:
            if (
                (roots is None) != (roots_pin is None)
                or (baseline_signer is None) != (baseline_signature is None)
                or (current_signer is None) != (current_signature is None)
                or (
                    roots is None
                    and (baseline_signature is not None or current_signature is not None)
                )
            ):
                raise IdentityError("verification_options_incomplete")
            verifier = None
            if roots is not None:
                verifier = Ed25519ArtifactVerifierV1(
                    parse_roots(_read(roots, MAX_ROOTS_BYTES, "roots_unreadable")),
                    expected_roots_digest=roots_pin,
                )
            reference = _observation(baseline, baseline_signer, baseline_signature, "baseline")
            observed = _observation(current, current_signer, current_signature, "current")
            report = compare_deployment_identities(reference, observed, verifier=verifier)
        except (IdentityError, ArtifactTrustError) as error:
            report = IdentityComparisonV1(
                IdentityComparisonStatus.INDETERMINATE, (str(error),), None, None
            )
        _emit(report)
