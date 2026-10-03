"""Unsigned governance review artifacts and pinned signature verification."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from mcp_warden.artifact_payload import MAX_ARTIFACT_BYTES, canonical_artifact_payload
from mcp_warden.artifact_trust import (
    MAX_ROOTS_BYTES,
    ArtifactTrustError,
    Ed25519ArtifactVerifierV1,
    artifact_signing_bytes,
    parse_roots,
    roots_digest,
)
from mcp_warden.decision_models import ArtifactKindV1, VerificationAlgorithmV1


def _read(path: Path, cap: int) -> bytes:
    payload = None
    try:
        with path.open("rb") as source:
            payload = source.read(cap + 1)
    except OSError:
        pass
    if payload is None:
        raise ArtifactTrustError("TRUST-FILE-UNAVAILABLE") from None
    if len(payload) > cap:
        raise ArtifactTrustError("TRUST-FILE-OVER-CAP") from None
    return payload


def _write_pair(source: Path, outputs: tuple[tuple[Path, bytes], ...]) -> None:
    created: list[Path] = []
    invalid = False
    try:
        paths = [path.resolve() for path, _ in outputs]
        if len(set(paths)) != len(paths) or source.resolve() in paths:
            raise OSError
        for path, payload in outputs:
            with path.open("xb") as target:
                created.append(path)
                target.write(payload)
    except OSError:
        invalid = True
    if invalid:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise ArtifactTrustError("TRUST-OUTPUT-UNAVAILABLE") from None


def register(app, console, err_console) -> None:
    trust = typer.Typer(
        add_completion=False, help="Prepare unsigned artifacts and verify external signatures."
    )
    app.add_typer(trust, name="trust")

    def fail(error: ArtifactTrustError) -> None:
        err_console.print(str(error), markup=False)
        raise typer.Exit(code=2)

    def emit(value: dict) -> None:
        typer.echo(json.dumps(value, sort_keys=True))

    @trust.command("roots-digest")
    def digest_roots(
        roots: Path = typer.Argument(..., help="Public keys and explicit artifact-kind roles."),
    ) -> None:
        """Inspect roots for independent human enrollment; this does not establish trust."""
        try:
            records = parse_roots(_read(roots, MAX_ROOTS_BYTES))
            emit(
                {
                    "roots_digest": roots_digest(records),
                    "keys": [
                        {
                            "signer_identity": item.signer_identity,
                            "artifact_kinds": [kind.value for kind in item.artifact_kinds],
                        }
                        for item in records
                    ],
                }
            )
        except ArtifactTrustError as error:
            fail(error)

    @trust.command("prepare")
    def prepare(
        kind: ArtifactKindV1 = typer.Argument(...),
        artifact: Path = typer.Argument(..., help="Unsigned artifact review draft."),
        signer: str = typer.Option(..., "--signer", help="Enrolled public-key identity digest."),
        canonical_out: Path = typer.Option(
            ..., "--canonical-out", help="New canonical artifact file."
        ),
        signing_out: Path = typer.Option(
            ..., "--signing-out", help="New exact bytes for the external signer."
        ),
    ) -> None:
        """Validate a draft and prepare bytes for review/signing outside agent access."""
        try:
            payload = canonical_artifact_payload(kind, _read(artifact, MAX_ARTIFACT_BYTES))
            frame = artifact_signing_bytes(kind, signer, payload)
            _write_pair(artifact, ((canonical_out, payload), (signing_out, frame)))
            emit(
                {
                    "status": "unsigned-review-artifact",
                    "artifact_kind": kind.value,
                    "signer_identity": signer,
                }
            )
        except ArtifactTrustError as error:
            fail(error)

    @trust.command("verify")
    def verify(
        kind: ArtifactKindV1 = typer.Argument(...),
        artifact: Path = typer.Argument(..., help="Exact canonical artifact file."),
        roots: Path = typer.Option(..., "--roots", help="Explicit public-key/role configuration."),
        roots_pin: str = typer.Option(
            ..., "--roots-digest", help="Root digest from an independent trusted boundary."
        ),
        signer: str = typer.Option(..., "--signer", help="Enrolled public-key identity digest."),
        signature: Path = typer.Option(
            ..., "--signature", help="Detached raw 64-byte Ed25519 signature."
        ),
    ) -> None:
        """Verify a signature only; activation, freshness and action authorization are separate."""
        try:
            verifier = Ed25519ArtifactVerifierV1(
                parse_roots(_read(roots, MAX_ROOTS_BYTES)), expected_roots_digest=roots_pin
            )
            if not verifier.verify(
                artifact_kind=kind,
                algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
                signer_identity=signer,
                payload=_read(artifact, MAX_ARTIFACT_BYTES),
                signature=_read(signature, 64),
            ):
                raise ArtifactTrustError("TRUST-SIGNATURE-INVALID")
            emit(
                {
                    "status": "signature-verified",
                    "artifact_kind": kind.value,
                    "signer_identity": signer,
                }
            )
        except ArtifactTrustError as error:
            fail(error)
