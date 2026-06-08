"""Structural tests for action.yml (Issue #18).

Parses action.yml and asserts the supply-chain and safety invariants
mandated by the adversarial-review binding fixes:

  - Action is composite (not docker/node).
  - Every `uses:` value is pinned to a full 40-hex-char commit SHA.
  - Every `uses:` line has a non-empty version comment (# v...).
  - A final exit-code-propagation step exists.
  - Every `run:` step declares `shell: bash`.

Intentionally dependency-light: uses only pyyaml (already in the
mcp-warden runtime deps).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ACTION_YML = Path(__file__).parent.parent / "action.yml"

# Regex for a full 40-character lowercase hex SHA
SHA40 = re.compile(r"^[0-9a-f]{40}$")

# Regex matching the version comment on the same line as the uses: value
# Accepts formats like "# v5.6.0", "# v3.36.2", "# v1"
VERSION_COMMENT_RE = re.compile(r"#\s*v\S+")


def _load_action() -> dict:
    return yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))


def _action_yml_raw_lines() -> list[str]:
    return ACTION_YML.read_text(encoding="utf-8").splitlines()


def test_action_yml_exists() -> None:
    assert ACTION_YML.exists(), "action.yml must exist at the repo root"


def test_action_is_composite() -> None:
    action = _load_action()
    runs = action.get("runs", {})
    assert runs.get("using") == "composite", (
        f"action.yml runs.using must be 'composite', got {runs.get('using')!r}"
    )


def _collect_uses_entries() -> list[tuple[str, str]]:
    """Return (step_name, uses_value) for every step that has a `uses:` key."""
    action = _load_action()
    steps = action.get("runs", {}).get("steps", [])
    result = []
    for step in steps:
        if "uses" in step:
            result.append((step.get("name", "<unnamed>"), step["uses"]))
    return result


def test_every_uses_is_sha_pinned() -> None:
    """Every `uses:` value must end with @<40-hex-sha>."""
    for step_name, uses_val in _collect_uses_entries():
        # Extract the part after the last '@'
        parts = uses_val.rsplit("@", 1)
        assert len(parts) == 2, (
            f"Step '{step_name}': uses value {uses_val!r} has no '@' separator"
        )
        sha_part = parts[1]
        assert SHA40.match(sha_part), (
            f"Step '{step_name}': uses value {uses_val!r} — SHA part {sha_part!r} "
            f"is not a 40-char lowercase hex commit SHA. "
            f"Floating tags and @main are not permitted (adversarial review binding #8)."
        )


def test_every_uses_has_version_comment() -> None:
    """Every `uses:` line must carry a non-empty version comment (# vX.Y.Z)."""
    raw_lines = _action_yml_raw_lines()
    uses_lines = [
        (i + 1, line) for i, line in enumerate(raw_lines)
        if re.search(r"\buses:", line) and "@" in line
    ]
    assert uses_lines, "Expected at least one uses: line in action.yml"
    for lineno, line in uses_lines:
        assert VERSION_COMMENT_RE.search(line), (
            f"Line {lineno}: `uses:` entry has no version comment (# vX.Y.Z):\n"
            f"  {line.strip()}\n"
            f"Every pinned SHA must carry a version comment for human readability "
            f"(adversarial review binding #8 / #11)."
        )


def test_exit_code_propagation_step_exists() -> None:
    """A final step that propagates the exit code must be present."""
    action = _load_action()
    steps = action.get("runs", {}).get("steps", [])
    # Look for a step whose run: block contains 'exit "$code"' or 'exit $code'
    # or whose id suggests it is the propagation step.
    propagation_found = False
    for step in steps:
        run_block = step.get("run", "")
        name = step.get("name", "")
        step_id = step.get("id", "")
        if (
            "exit" in run_block
            and ("$code" in run_block or "${WARDEN_EXIT_CODE" in run_block)
        ) or step_id == "propagate":
            propagation_found = True
            break
    assert propagation_found, (
        "action.yml must contain a final step that propagates the mcp-warden "
        "exit code (e.g. `exit \"$code\"`) so exit codes 0/1/2 are surfaced "
        "verbatim to the caller (adversarial review binding #6)."
    )


def test_every_run_step_has_shell_bash() -> None:
    """Every step with a `run:` block must declare `shell: bash`.

    Required for correct exit-code propagation on Windows runners where the
    default shell is PowerShell (adversarial review binding #4).
    """
    action = _load_action()
    steps = action.get("runs", {}).get("steps", [])
    for step in steps:
        if "run" in step:
            shell = step.get("shell")
            name = step.get("name", "<unnamed>")
            assert shell == "bash", (
                f"Step '{name}': has `run:` but shell is {shell!r} (must be 'bash'). "
                f"All run steps must declare shell: bash for cross-OS compatibility "
                f"(adversarial review binding #4 / #5)."
            )
