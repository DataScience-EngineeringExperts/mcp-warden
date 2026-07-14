"""``mcp-warden-precommit`` — the local pre-commit gate (issue #22).

A thin, dependency-light wrapper that runs the SAME check verdict path as
``mcp-warden check`` (via :func:`mcp_warden.check_core.run_check`) so a local
pre-commit hook and CI can never disagree on a drift verdict.

Contract::

    mcp-warden-precommit [--lock PATH] [--timeout N] [--strict] -- <server argv...>

Everything after ``--`` is the MCP server launch argv. The server command is
configured by the adopter via ``args:`` in their ``.pre-commit-config.yaml``;
pre-commit's staged filenames must NOT leak in (the hook sets
``pass_filenames: false``).

Exit codes:
  * clean                                  -> 0
  * drift                                  -> 1  (ALWAYS, both modes)
  * lock missing / invalid                 -> 2  (config error, both modes)
  * server spawn fail / CaptureError / timeout
        non-strict (default)               -> 0  + a clear stderr WARNING
        --strict                           -> 2

The non-strict server-unavailability behavior is deliberate: a developer whose
MCP server can't start locally should not be blocked from committing, while CI
stays strict (it must always be able to spawn the server). Drift verdicts stay
identical across local and CI — only infra-failure handling differs.

# INTERNAL STABILITY NOTE: this module imports ONLY the check path
# (mcp_warden.check_core). It must never import or reference the pin command,
# the --approve path, or the lock WRITER (write_lock). It never opens the lock
# file for writing. The lock-write-protection tests enforce this.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from .capture import CaptureError
from .check_core import run_check

DEFAULT_LOCK_NAME = "warden.lock"
DEFAULT_TIMEOUT = 30.0

_PROG = "mcp-warden-precommit"


def _redact_server(command: str, args: list[str]) -> str:
    """Render the server launch argv for human output WITHOUT leaking secrets.

    SECURITY (code-audit binding B3): the server argv may carry API keys/tokens
    passed as CLI args. The project forbids printing ``server.command`` /
    ``server.args`` (see ``SAFE_PROVENANCE_FIELDS`` in ``cli_diff.py``), and
    pre-commit captures stderr to logs (``~/.pre-commit-logs``), CI logs, and
    scrollback. We therefore echo ONLY the executable name (``argv[0]``) plus a
    redacted count of the remaining args — never the args themselves.
    """
    if not args:
        return command
    n = len(args)
    return f"{command} …({n} arg{'s' if n != 1 else ''} redacted)"

# Guidance shown when no server argv is supplied. pre-commit cannot know the
# adopter's server command, so it must be configured explicitly.
_NO_SERVER_MSG = (
    "error: no MCP server command supplied.\n"
    "Configure the server command via `args:` in .pre-commit-config.yaml, using\n"
    "the `--` separator to mark where the server launch argv begins, e.g.:\n\n"
    "  - repo: https://github.com/DataScience-EngineeringExperts/mcp-warden\n"
    "    rev: v1.0.1\n"
    "    hooks:\n"
    "      - id: mcp-warden-check\n"
    "        args: [--lock, warden.lock, --, python, ./server.py]\n"
)


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the wrapper's own flags."""
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description="Pre-commit gate: re-capture the MCP server surface and fail on drift vs warden.lock.",
        add_help=True,
    )
    parser.add_argument(
        "--lock",
        default=DEFAULT_LOCK_NAME,
        help=f"Baseline lock path (default: {DEFAULT_LOCK_NAME}, relative to the git repo root).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Capture timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail closed (exit 2) when the server cannot be spawned/captured, instead of warning and passing.",
    )
    return parser


def _split_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split ``argv`` at the first ``--`` into (own_args, server_cmd).

    Everything before the first ``--`` is parsed as this wrapper's own flags;
    everything after it is the MCP server launch argv. If there is no ``--``,
    the server command is empty (the caller reports the configuration error).
    """
    if "--" in argv:
        idx = argv.index("--")
        return argv[:idx], argv[idx + 1:]
    return argv, []


def _repo_root() -> Path | None:
    """Return the git repo top-level dir, or None if not in a git repo.

    cwd normalization (adversarial review binding #2): pre-commit may invoke the
    hook from any directory, but warden.lock paths and the server command are
    resolved relative to the repo root in CI. Normalizing cwd here makes the
    local hook's verdict identical to CI regardless of the invocation dir.

    DELIBERATE: returning None (not a git repo, or ``git rev-parse`` fails) makes
    the caller fall back to the current cwd — this is the INTENTIONAL non-strict
    path and MUST NOT be "fixed" into a hard block. The distinction matters:
    *can't FIND* a repo root = non-strict caller-cwd fallback; *found one but
    can't chdir into it* = fail closed (exit 2, handled in :func:`main`, B1).
    """
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        # Not a git repo, or git unavailable -> fall back to the current cwd.
        return None
    root = out.stdout.strip()
    return Path(root) if root else None


def _print_drift_summary(drift: list, lock_path: str) -> None:
    """Print a concise, pre-commit-style drift summary to stderr."""
    print(f"mcp-warden: DRIFT DETECTED vs {lock_path} ({len(drift)} item(s))", file=sys.stderr)
    for d in drift:
        print(f"  [{d.severity}] {d.drift_class} {d.target}: {d.message}", file=sys.stderr)
    print(
        "mcp-warden: the MCP server surface changed since it was pinned. "
        "Review the diff, then re-pin with `mcp-warden pin` if the change is intended.",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``mcp-warden-precommit`` console script.

    Args:
        argv: Argument vector (defaults to ``sys.argv[1:]``). Accepting it
            explicitly keeps the function unit-testable without monkeypatching
            ``sys.argv``.

    Returns:
        The process exit code (0 clean / 1 drift / 2 config-or-strict-failure).
    """
    raw = list(sys.argv[1:] if argv is None else argv)
    own_args, server_cmd = _split_argv(raw)

    parser = _build_parser()
    ns = parser.parse_args(own_args)

    if not server_cmd:
        print(_NO_SERVER_MSG, file=sys.stderr)
        return 2

    # binding #2: normalize cwd to the git repo root so the verdict matches CI.
    root = _repo_root()
    if root is not None:
        try:
            os.chdir(root)
        except OSError as exc:
            # code-audit binding B1: FAIL CLOSED. We FOUND a repo root but cannot
            # chdir into it. Continuing with the wrong cwd would resolve the lock
            # and server against the wrong directory -> could read a stale/absent
            # lock and yield a spurious clean (exit 0) on a genuinely drifted
            # surface. That is a cardinal-rule violation, so we exit 2 (infra
            # error) instead of proceeding. (Contrast: _repo_root() returning
            # None = "can't FIND a repo root" -> intentional caller-cwd fallback.)
            print(
                f"mcp-warden: error: could not chdir to repo root {root}: {exc}\n"
                "mcp-warden: refusing to run against the wrong directory (fail-closed).",
                file=sys.stderr,
            )
            return 2

    command, args = server_cmd[0], list(server_cmd[1:])
    lock_path = Path(ns.lock)
    timeout_s = float(ns.timeout)

    # code-audit binding B3: render the server identity through _redact_server so
    # secret-bearing argv (api keys/tokens) never reach stderr / pre-commit logs.
    server_str = _redact_server(command, args)

    try:
        drift = run_check(command, args, lock_path, timeout_s)
    except (FileNotFoundError, ValueError) as exc:
        # Missing/invalid lock is a configuration error in BOTH modes.
        print(f"mcp-warden: error: {exc}", file=sys.stderr)
        return 2
    except CaptureError as exc:
        msg = (
            f"mcp-warden: could not capture the MCP server surface "
            f"(timeout={timeout_s}s, server=`{server_str}`): {exc}"
        )
        if ns.strict:
            print(f"{msg}\nmcp-warden: --strict is set -> failing the commit.", file=sys.stderr)
            return 2
        print(
            f"WARNING: {msg}\n"
            "mcp-warden: the server could not start locally; SKIPPING the integrity gate "
            "for this commit (non-strict). CI will still enforce it. "
            "Use --strict to fail closed locally.",
            file=sys.stderr,
        )
        return 0
    except Exception as exc:  # noqa: BLE001 — see B2 rationale below.
        # code-audit binding B2: any OTHER exception from the check pipeline
        # (run_checks / build_lock / compute_drift — e.g. a pydantic
        # ValidationError or an AttributeError on an unexpected model shape) must
        # NOT propagate. An uncaught exception makes Python exit 1, which is
        # INDISTINGUISHABLE from a confirmed-drift verdict and poisons the
        # "exit 1 == only confirmed drift" invariant. Route it to exit 2
        # (infra/internal error). We name the exception type and message for
        # debuggability but render the server identity through _redact_server
        # (B3) so no secret-bearing argv leaks into the error.
        print(
            f"mcp-warden: internal error while checking server `{server_str}`: "
            f"{type(exc).__name__}: {exc}\n"
            "mcp-warden: this is an mcp-warden bug or environment fault, NOT a drift "
            "verdict; treating as an internal error (exit 2). Please report it.",
            file=sys.stderr,
        )
        return 2

    if drift:
        _print_drift_summary(drift, ns.lock)
        return 1

    print(f"mcp-warden: OK — no drift vs {ns.lock}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
