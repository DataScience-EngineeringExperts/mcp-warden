"""Supply-chain checks (MCP-SUPPLY) — ``WRD-SUP-*`` (CHECKS.md §4.3).

Operate on the launch command (``server.command`` + ``server.args``), tokenized
as argv. Local paths are never flagged (CHECKS.md §8.7).
"""

from __future__ import annotations

import re

from .models import Finding

_TARGET = "launch/command"

#: A full 40-char git sha (for ``git+...@<sha>`` pin recognition).
_GIT_SHA40 = re.compile(r"@[0-9a-fA-F]{40}\b")

#: npm pinned ref: pkg@<semver-or-digest>, but NOT pkg@latest and NOT a flag.
_NPM_PINNED = re.compile(r"@(\d[\w.\-+]*|sha\d+[:\-][0-9a-fA-F]+)$")


def _is_local_path(token: str) -> bool:
    """Return True if a token is a local path / file ref (never a supply ref)."""
    return (
        token.startswith("./")
        or token.startswith("../")
        or token.startswith("/")
        or token.startswith("~")
        or token.startswith("file:")
        or token == "."
    )


def _is_flag(token: str) -> bool:
    """Return True if a token is a CLI flag (starts with ``-``)."""
    return token.startswith("-")


def _npm_is_pinned(token: str) -> bool:
    """Return True if an npm package spec carries a concrete version/digest."""
    return bool(_NPM_PINNED.search(token))


def _spec_is_latest(token: str) -> bool:
    """Return True if a spec explicitly floats to ``latest``."""
    return token.endswith("@latest") or token.endswith("==latest")


def _py_is_pinned(token: str, argv: list[str]) -> bool:
    """Return True if a uv/pip package spec is pinned per CHECKS.md §4.3."""
    if "--require-hashes" in argv:
        return True
    if "==" in token:
        return True
    if _GIT_SHA40.search(token):
        return True
    return False


def _curl_pipe_shape(argv: list[str]) -> bool:
    """Detect a ``curl ... | sh`` / ``wget ... | sh`` remote-fetch-execute shape."""
    joined = " ".join(argv)
    has_fetch = any(tok in ("curl", "wget") for tok in argv) or "curl" in joined or "wget" in joined
    if not has_fetch:
        return False
    # A pipe to an interpreter anywhere in the reconstructed command line.
    return bool(re.search(r"\|\s*(sh|bash|zsh|python\d?|node)\b", joined))


def check_launch_command(command: str, args: list[str]) -> list[Finding]:
    """Run the ``WRD-SUP-*`` catalog against a launch argv.

    Args:
        command: ``argv[0]`` of the launch.
        args: Remaining argv tokens.

    Returns:
        Sorted-by-construction list of supply-chain :class:`Finding`. May be empty.
    """
    argv = [command, *args]
    findings: list[Finding] = []

    def add(rule_id: str, severity: str, message: str, snippet: str) -> None:
        findings.append(
            Finding(rule_id=rule_id, severity=severity, target=_TARGET, message=message, snippet=snippet)
        )

    # curl|sh shape first (critical), independent of package managers.
    if _curl_pipe_shape(argv):
        add(
            "WRD-SUP-CURL-PIPE",
            "critical",
            "Launch reconstructs a remote-fetch-execute (curl|sh / wget|sh) shape",
            " ".join(argv)[:120],
        )

    # Identify package-manager invocations and inspect their package-spec targets.
    for i, tok in enumerate(argv):
        low = tok.lower()

        if low == "npx":
            for spec in _package_specs_after(argv, i):
                if _spec_is_latest(spec):
                    add("WRD-SUP-LATEST-TAG", "high", "Explicit floating 'latest' tag in npx spec", spec)
                elif not _npm_is_pinned(spec):
                    add("WRD-SUP-NPX-UNPINNED", "high", "Unpinned npx package (resolves latest at run)", spec)

        elif low == "uvx":
            for spec in _package_specs_after(argv, i):
                if _spec_is_latest(spec):
                    add("WRD-SUP-LATEST-TAG", "high", "Explicit floating 'latest' tag in uvx spec", spec)
                elif not _py_is_pinned(spec, argv):
                    add("WRD-SUP-UVX-UNPINNED", "high", "Unpinned uvx package (mutable upstream)", spec)

        elif low in ("pip", "pip3") and "install" in argv[i:]:
            inst = argv.index("install", i)
            for spec in _package_specs_after(argv, inst):
                if _spec_is_latest(spec):
                    add("WRD-SUP-LATEST-TAG", "high", "Explicit floating 'latest' tag in pip spec", spec)
                elif not _py_is_pinned(spec, argv):
                    add("WRD-SUP-PIP-UNPINNED", "high", "Unpinned pip install target (mutable dependency)", spec)

    return findings


def _package_specs_after(argv: list[str], idx: int) -> list[str]:
    """Return package-spec tokens following ``argv[idx]``, skipping flags/paths.

    Stops collecting nothing special — package managers may take several
    positional package args; we consider every non-flag, non-local-path token.

    Args:
        argv: The full launch argv.
        idx: Index of the package-manager token (``npx``/``uvx``/``install``).

    Returns:
        The list of candidate package-spec tokens (possibly empty).
    """
    specs: list[str] = []
    for tok in argv[idx + 1 :]:
        if _is_flag(tok):
            continue
        if _is_local_path(tok):
            continue
        specs.append(tok)
    return specs
