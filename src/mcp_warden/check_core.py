"""Shared check core: the single source of truth for the ``check`` verdict.

Both ``cli.py:check`` and the pre-commit wrapper (``precommit.py``) call
:func:`run_check` so a local hook and CI can never disagree on a drift verdict
(issue: "a hook that disagrees with CI is worse than no hook").

The sequence here mirrors what ``check`` has always done:
``read_lock`` -> ``capture_surface_sync`` -> ``run_checks`` -> ``build_lock``
(an in-memory CURRENT lock, never persisted) -> ``compute_drift``.

# INTERNAL STABILITY NOTE: the pre-commit wrapper (precommit.py) depends on this
# function's signature and exception contract (CaptureError for spawn/timeout
# failures; FileNotFoundError / ValueError for a missing/invalid lock). Do not
# change either without updating precommit.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .capture import capture_surface_sync
from .checks import run_checks
from .drift import DriftItem, compute_drift
from .lockfile import build_lock, read_lock
from .models import Finding


@dataclass(frozen=True)
class CheckResult:
    """The full result of a check run, for callers that need more than drift.

    ``findings`` are the static-check findings on the current surface (needed by
    the CLI's SARIF/JSON emitters); ``drift`` is the verdict set.
    """

    findings: list[Finding]
    drift: list[DriftItem]


def run_check_full(
    command: str,
    args: list[str],
    lock_path: Path,
    timeout_s: float,
) -> CheckResult:
    """Run the full check verdict path: read lock -> capture -> checks -> drift.

    This is the single source of truth for the ``check`` verdict. ``cli.py:check``
    calls it (and uses ``findings`` for SARIF/JSON output); the pre-commit wrapper
    calls the thinner :func:`run_check` which discards ``findings``.

    Args:
        command: The MCP server launch command (argv[0]).
        args: The remaining server launch argv.
        lock_path: Path to the baseline ``warden.lock``.
        timeout_s: Capture timeout in seconds.

    Returns:
        A :class:`CheckResult` (``drift`` empty == clean).

    Raises:
        FileNotFoundError: The lock file does not exist.
        ValueError: The lock file is invalid JSON or fails schema validation.
        CaptureError: The server could not be spawned or did not respond in time.
    """
    baseline = read_lock(lock_path)
    surface = capture_surface_sync(command, args, timeout_s=timeout_s)
    findings = run_checks(surface)
    # build_lock constructs an IN-MEMORY current lock for diffing only; it is
    # never written to disk on the check path.
    current = build_lock(surface, findings)
    drift = compute_drift(baseline, current)
    return CheckResult(findings=findings, drift=drift)


def run_check(
    command: str,
    args: list[str],
    lock_path: Path,
    timeout_s: float,
) -> list[DriftItem]:
    """Run the check path and return only the drift set (verdict).

    Convenience wrapper over :func:`run_check_full` for callers (the pre-commit
    hook) that only need the drift verdict and never the static findings.

    Raises:
        FileNotFoundError, ValueError, CaptureError: see :func:`run_check_full`.
    """
    return run_check_full(command, args, lock_path, timeout_s).drift
