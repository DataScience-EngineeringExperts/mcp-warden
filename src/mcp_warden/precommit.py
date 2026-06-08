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
import shlex
import subprocess
import sys
from pathlib import Path

from .capture import CaptureError
from .check_core import run_check

DEFAULT_LOCK_NAME = "warden.lock"
DEFAULT_TIMEOUT = 30.0

_PROG = "mcp-warden-precommit"

# Guidance shown when no server argv is supplied. pre-commit cannot know the
# adopter's server command, so it must be configured explicitly.
_NO_SERVER_MSG = (
    "error: no MCP server command supplied.\n"
    "Configure the server command via `args:` in .pre-commit-config.yaml, using\n"
    "the `--` separator to mark where the server launch argv begins, e.g.:\n\n"
    "  - repo: https://github.com/ernestprovo23/mcp-warden\n"
    "    rev: v0.3.0\n"
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
            import os

            os.chdir(root)
        except OSError as exc:
            print(f"mcp-warden: warning: could not chdir to repo root {root}: {exc}", file=sys.stderr)

    command, args = server_cmd[0], list(server_cmd[1:])
    lock_path = Path(ns.lock)
    timeout_s = float(ns.timeout)

    try:
        drift = run_check(command, args, lock_path, timeout_s)
    except (FileNotFoundError, ValueError) as exc:
        # Missing/invalid lock is a configuration error in BOTH modes.
        print(f"mcp-warden: error: {exc}", file=sys.stderr)
        return 2
    except CaptureError as exc:
        server_str = shlex.join([command, *args])
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

    if drift:
        _print_drift_summary(drift, ns.lock)
        return 1

    print(f"mcp-warden: OK — no drift vs {ns.lock}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
