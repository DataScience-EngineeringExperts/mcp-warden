"""CLI glue for ``check --against-community`` (DSE-1515, phase 1).

Kept out of ``cli.py`` so the ``check`` body stays a thin dispatcher. Three
calls: :func:`validate_flags` rejects community options given without the flag,
:func:`preflight` resolves the coordinate and the consumer trust pin BEFORE the
server is spawned (an unpinnable launch or an unpinned trust root fails fast,
exit 2), and :func:`adjudicate` runs the consensus AFTER the normal drift check.
"""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console
from rich.markup import escape

from .corpus import (
    NOT_SAFETY,
    RULE_UNRESOLVED,
    RULE_UNVERIFIABLE,
    ConsensusResult,
    CorpusError,
    run_consensus,
)
from .corpus_coordinate import Coordinate, resolve_coordinate
from .corpus_trust import Attester, load_consumer_pin

DEFAULT_MIN_ATTESTERS = 2


def _fail(err_console: Console, exc: CorpusError) -> NoReturn:
    err_console.print(f"[red]error:[/red] [{exc.rule_id}] {escape(str(exc))}")
    raise typer.Exit(code=2) from exc


def validate_flags(
    *, against_community: bool, verify: bool, corpus: str | None, corpus_ref: str | None,
    coordinate: str | None, attester: list[str], attesters_file: Path | None,
    min_attesters: int | None, require_consensus: bool = False, err_console: Console,
) -> None:
    """A community option without ``--against-community`` is a mistake, not a no-op (CSO L1)."""
    if against_community and verify:
        # CSO re-verify N1: --verify returns before capture, so consensus would be
        # silently skipped and the run would exit 0 having compared nothing.
        err_console.print(
            "[red]error:[/red] --verify and --against-community are mutually exclusive "
            "(--verify never spawns the server; consensus needs a live capture) — run them as two invocations"
        )
        raise typer.Exit(code=2)
    if against_community:
        return
    stray = [
        name for name, val in (
            ("--corpus", corpus), ("--corpus-ref", corpus_ref), ("--attester", attester or None),
            ("--attesters-file", attesters_file), ("--min-attesters", min_attesters),
            ("--require-consensus", require_consensus or None),
        ) if val is not None
    ]
    if coordinate is not None and not verify:  # --coordinate is also valid with --verify (v2 statements)
        stray.append("--coordinate")
    if stray:
        err_console.print(f"[red]error:[/red] {', '.join(stray)} require(s) --against-community")
        raise typer.Exit(code=2)


def preflight(
    command: str, args: list[str], corpus: str | None, coordinate: str | None,
    attester: list[str], attesters_file: Path | None, err_console: Console,
) -> tuple[Coordinate, dict[str, Attester]]:
    """Validate the community flags, resolve the coordinate and the trust pin; exit 2 on failure."""
    if not corpus:
        err_console.print("[red]error:[/red] --against-community requires --corpus <path|git-url>")
        raise typer.Exit(code=2)
    try:
        pin = load_consumer_pin(attester, attesters_file)
    except CorpusError as exc:
        _fail(err_console, exc)
    coord = resolve_coordinate(command, args, coordinate)
    if coord is None:
        launch = " ".join([command, *args]).strip() or "--url"
        _fail(err_console, CorpusError(
            RULE_UNRESOLVED,
            f"cannot derive a pinned package coordinate from {launch!r}; "
            "pin the version (pkg@1.2.3 / pkg==1.2.3) or pass --coordinate <npm|pypi>:<name>@<version>",
        ))
    return coord, pin


def adjudicate(
    observed_digest: str, coord: Coordinate, corpus: str, corpus_ref: str | None,
    pin: dict[str, Attester], min_attesters: int, err_console: Console, *, require_consensus: bool = False,
) -> ConsensusResult:
    """Run the consensus verdict; exit 2 on any fail-closed corpus condition."""
    try:
        result = run_consensus(
            observed_digest, coord, corpus, corpus_ref, pin, min_attesters, require_consensus=require_consensus
        )
    except CorpusError as exc:
        _fail(err_console, exc)
    except Exception as exc:  # noqa: BLE001 - a hostile corpus must not turn into exit 1 + traceback
        _fail(err_console, CorpusError(RULE_UNVERIFIABLE, f"corpus evaluation failed ({type(exc).__name__})"))
    for note in result.warnings:
        err_console.print(f"[yellow]warning:[/yellow] {escape(note)}", soft_wrap=True)
    if not result.findings:
        err_console.print(
            f"consensus: {len(result.matched)} trusted attester(s) observed the same surface for "
            f"{escape(str(coord))} ({', '.join(result.matched)}) — {NOT_SAFETY}",
            soft_wrap=True,
        )
    return result
