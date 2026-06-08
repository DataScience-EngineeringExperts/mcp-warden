"""Structural tests enforcing SHA-pin discipline across all GitHub Actions workflows.

Every `uses:` entry in .github/workflows/*.yml must be pinned to a full 40-char
commit SHA with a non-empty version comment (# vX.Y.Z).  This is the same rule
already applied to action.yml by test_action_yml.py — extended to the repo's own
CI workflows so a supply-chain tool does not float tags in its own CI.

Adversarial review binding fix #3.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"

# Regex for a full 40-character lowercase hex SHA
SHA40 = re.compile(r"^[0-9a-f]{40}$")

# Regex matching the version comment on the same line as the uses: value
VERSION_COMMENT_RE = re.compile(r"#\s*v\S+")


def _collect_workflow_files() -> list[Path]:
    """Return all *.yml files under .github/workflows/."""
    if not WORKFLOWS_DIR.exists():
        return []
    return sorted(WORKFLOWS_DIR.glob("*.yml"))


def _collect_uses_lines(path: Path) -> list[tuple[int, str]]:
    """Return (lineno, line) pairs for every line containing a `uses:` with an @."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [
        (i + 1, line)
        for i, line in enumerate(lines)
        if re.search(r"\buses:", line) and "@" in line
    ]


def _extract_sha(uses_value: str) -> str:
    """Extract the SHA part after the last '@' in a uses: value."""
    parts = uses_value.rsplit("@", 1)
    if len(parts) != 2:
        return ""
    return parts[1].strip()


# Collect all (workflow_path, lineno, line, uses_value) tuples for parametrize
def _all_uses_entries() -> list[tuple[Path, int, str, str]]:
    entries = []
    for wf_path in _collect_workflow_files():
        raw_lines = wf_path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(raw_lines):
            if re.search(r"\buses:", line) and "@" in line:
                # Extract the uses: value (the part after `uses:`)
                match = re.search(r"\buses:\s*(\S+)", line)
                if match:
                    entries.append((wf_path, i + 1, line, match.group(1)))
    return entries


_ENTRIES = _all_uses_entries()


def test_workflows_dir_exists() -> None:
    assert WORKFLOWS_DIR.exists(), f".github/workflows/ must exist at {WORKFLOWS_DIR}"


def test_at_least_one_workflow_file() -> None:
    wf_files = _collect_workflow_files()
    assert wf_files, f"No .yml files found in {WORKFLOWS_DIR}"


@pytest.mark.parametrize(
    "wf_path,lineno,line,uses_value",
    _ENTRIES,
    ids=[
        f"{e[0].name}:L{e[1]}"
        for e in _ENTRIES
    ],
)
def test_uses_is_sha_pinned(wf_path: Path, lineno: int, line: str, uses_value: str) -> None:
    """Every `uses:` in a workflow file must end with a 40-hex commit SHA."""
    sha = _extract_sha(uses_value)
    assert SHA40.match(sha), (
        f"{wf_path.name} line {lineno}: `uses: {uses_value}` — "
        f"SHA part {sha!r} is not a 40-char lowercase hex commit SHA. "
        f"Floating tags and @main are not permitted. "
        f"Resolve via: gh api repos/<owner>/<repo>/git/refs/tags/<tag>"
    )


@pytest.mark.parametrize(
    "wf_path,lineno,line,uses_value",
    _ENTRIES,
    ids=[
        f"{e[0].name}:L{e[1]}"
        for e in _ENTRIES
    ],
)
def test_uses_has_version_comment(wf_path: Path, lineno: int, line: str, uses_value: str) -> None:
    """Every `uses:` line in a workflow file must carry a non-empty version comment (# vX.Y.Z)."""
    assert VERSION_COMMENT_RE.search(line), (
        f"{wf_path.name} line {lineno}: `uses:` entry has no version comment (# vX.Y.Z):\n"
        f"  {line.strip()}\n"
        f"Every pinned SHA must carry a version comment for human readability."
    )
