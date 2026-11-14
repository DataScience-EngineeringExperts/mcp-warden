"""Operator entrypoint for supplied content; public output excludes raw text."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import typer

from . import res_rules
from .content_envelope import to_public_dict
from .content_models import IngressKindV1, MediaTypeV1
from .normalization_ingress import normalize_supplied
from .normalization_inspection import inspect_normalized
from .normalization_ipc import NormalizationError
from .normalization_models import NormalizationProfileV1
from .result_inspection import InspectionPolicy


def register(app: typer.Typer) -> None:
    @app.command()
    def normalize(
        path: Path = typer.Argument(..., help="Supplied local content file; no remote retrieval"),
        media_type: str = typer.Option(..., "--media-type", help="Declared supported MIME type"),
        source_kind: str = typer.Option(..., "--source-kind", help="Declared ingress kind"),
        normalizer_image: str = typer.Option(..., "--normalizer-image", help="Qualified immutable Linux image ID"),
    ) -> None:
        """Normalize and inspect supplied content in a Linux sandbox; emit evidence, not content."""
        try:
            profile = NormalizationProfileV1(normalizer_image)
            media, kind = MediaTypeV1(media_type), IngressKindV1(source_kind)
            if not path.is_file():
                raise NormalizationError("NRM-IO")
            with path.open("rb") as stream:
                content = stream.read(profile.budget.input_bytes + 1)
            result = normalize_supplied(content, media, kind, profile)
            findings = inspect_normalized(
                result, InspectionPolicy(expected_output_charset="extended"),
                exfil_denylist=res_rules.SEED_EXFIL_DENYLIST,
                inject_phrases=res_rules.SEED_INJECT_PHRASES,
            )
        except NormalizationError as exc:
            typer.echo(json.dumps({"status": "refused", "code": exc.code}))
            raise typer.Exit(code=2) from None
        except Exception:
            typer.echo(json.dumps({"status": "refused", "code": "NRM-MALFORMED"}))
            raise typer.Exit(code=2) from None
        typer.echo(json.dumps({
            "status": "inspected", "profile_id": result.profile_id,
            "semantic_completeness_proven": False,
            "envelope": to_public_dict(result.envelope), "manifest_digest": result.manifest_digest,
            "segment_count": len(result.segments),
            "precisions": sorted({s.precision for s in result.segments}),
            "findings": [asdict(f) for f in findings],
        }, sort_keys=True))
        raise typer.Exit(code=1 if any(f.tier == "block" for f in findings) else 0)
