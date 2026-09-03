"""CLI glue for ``check --against-community`` (DSE-1515, phase 1).

Kept out of ``cli.py`` so the ``check`` body stays a thin dispatcher. Two calls:
:func:`preflight` resolves the coordinate BEFORE the server is spawned (an
unpinnable launch fails fast, exit 2) and :func:`adjudicate` runs the consensus
AFTER the normal drift check on the freshly captured ``overall_digest``.
"""

from __future__ import annotations

import typer
from rich.console import Console

from .corpus import RULE_UNRESOLVED, ConsensusResult, CorpusError, run_consensus
from .corpus_coordinate import Coordinate, resolve_coordinate


def _fail(err_console: Console, exc: CorpusError) -> None:
    err_console.print(f"[red]error:[/red] [{exc.rule_id}] {exc}")
    raise typer.Exit(code=2) from exc


def preflight(
    command: str, args: list[str], corpus: str | None, coordinate: str | None, err_console: Console
) -> Coordinate:
    """Validate the community flags and resolve the coordinate; exit 2 on failure."""
    if not corpus:
        err_console.print("[red]error:[/red] --against-community requires --corpus <path|git-url>")
        raise typer.Exit(code=2)
    coord = resolve_coordinate(command, args, coordinate)
    if coord is None:
        launch = " ".join([command, *args]).strip() or "--url"
        _fail(err_console, CorpusError(
            RULE_UNRESOLVED,
            f"cannot derive a pinned package coordinate from {launch!r}; "
            "pin the version (pkg@1.2.3 / pkg==1.2.3) or pass --coordinate <npm|pypi>:<name>@<version>",
        ))
    return coord


def adjudicate(
    observed_digest: str, coord: Coordinate, corpus: str, corpus_ref: str | None, err_console: Console
) -> ConsensusResult:
    """Run the consensus verdict; exit 2 on any fail-closed corpus condition."""
    try:
        result = run_consensus(observed_digest, coord, corpus, corpus_ref)
    except CorpusError as exc:
        _fail(err_console, exc)
    if not result.findings:
        err_console.print(
            f"consensus: {len(result.matched)} attester(s) observed the same surface for "
            f"{coord} ({', '.join(result.matched)}) — consensus attests observation, not safety"
        )
    return result
