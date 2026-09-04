"""Community lock corpus — multi-attester surface consensus (DSE-1515, phase 1).

``check`` answers "did the surface change since *I* approved it?". It cannot see
a server that shipped poisoned on day one (TOFU) or a surface served only to one
consumer. Both need *independent observation*: if several attesters the
consumer has chosen to trust Sigstore-signed the same surface for
``npm:@foo/server@1.2.3`` and you observe something else, that is signal a solo
lock can never produce.

Layout of a corpus checkout (``docs/COMMUNITY_CORPUS.md``)::

    attesters.json                              discovery list, NOT the trust root
    locks/<ecosystem>/<segment>/<version>/<attester-id>.lock
    locks/<ecosystem>/<segment>/<version>/<attester-id>.lock.sigstore

This module owns fetching the corpus and orchestrating a run; entry verification
lives in :mod:`corpus_verify`, trust in :mod:`corpus_trust`. Every rule fails
CLOSED: an unpinned trust root, an unknown attester, a missing or unverifiable
sidecar, an unreachable corpus, or an unpinnable launch is exit 2, never a skip.
**Consensus attests observation, not safety** — every finding says so.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from . import signing
from .corpus_coordinate import Coordinate
from .corpus_trust import Attester, CorpusError, load_corpus_attesters, resolve_trust
from .corpus_verify import (
    NOT_SAFETY,
    RULE_INSUFFICIENT,
    RULE_MISMATCH,
    RULE_NOVEL,
    RULE_SCHEMA_MISMATCH,
    RULE_SPLIT,
    RULE_UNVERIFIABLE,
    ConsensusResult,
    consensus,
    verified_digests,
)

__all__ = [
    "NOT_SAFETY", "RULE_INSUFFICIENT", "RULE_MISMATCH", "RULE_NOVEL", "RULE_SCHEMA_MISMATCH",
    "RULE_SPLIT", "RULE_UNREACHABLE", "RULE_UNRESOLVED", "RULE_UNVERIFIABLE", "Attester",
    "ConsensusResult", "CorpusError", "consensus", "fetch_corpus", "run_consensus", "verified_digests",
]

RULE_UNRESOLVED = "WRD-CONSENSUS-UNRESOLVED"
RULE_UNREACHABLE = "WRD-CONSENSUS-UNREACHABLE"

_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_GIT_TIMEOUT_S = 120.0

#: The ONLY corpus source shapes handed to ``git``. Anything else — ``ext::``
#: remote helpers, ``file://``, a bare ``host:path`` scp form, a leading ``-``
#: that git would parse as an option — is refused before a subprocess exists
#: (CSO C1). A string that is none of these is a local directory path.
_URL_PREFIXES: tuple[str, ...] = ("https://", "ssh://", "git@")

#: Hardening applied to EVERY git invocation: only https/ssh transports, no
#: hooks, no symlink checkout, no submodule recursion, no interactive prompt.
_GIT_CONFIG: list[str] = [
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "protocol.ssh.allow=always",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.symlinks=false",
    "-c", "submodule.recurse=false",
]
#: Environment git may see. Everything else (proxies, GIT_* overrides, tokens)
#: is dropped so the caller's environment cannot redirect the clone.
_GIT_ENV_KEYS = ("PATH", "HOME", "SSH_AUTH_SOCK")
#: Forwarded ONLY for ``ssh://`` / ``git@`` sources: on an https corpus it is
#: dead weight, and in CI with an attacker-writable env it is arbitrary exec
#: (CSO re-verify N4). ``SSH_AUTH_SOCK`` stays so deploy-key/agent auth works.
_GIT_ENV_SSH_KEYS = ("GIT_SSH_COMMAND",)
_SSH_PREFIXES: tuple[str, ...] = ("ssh://", "git@")

#: Oldest git whose ``ssh://`` URL handling refuses a host starting with ``-``
#: (CVE-2017-1000117); the option-injection defenses above assume it.
MIN_GIT_VERSION = (2, 14, 1)
_GIT_VERSION_RE = re.compile(r"git version (\d+)\.(\d+)(?:\.(\d+))?")

#: Resolved once per process (CSO re-verify N4): an absolute path, so a later
#: ``PATH`` change cannot swap the binary under us. ``None`` = not yet resolved.
_GIT_BIN: str | None = None
_GIT_VERSION_OK: bool | None = None


def _is_url(source: str) -> bool:
    return source.startswith(_URL_PREFIXES)


def _is_ssh(source: str) -> bool:
    return source.startswith(_SSH_PREFIXES)


def _git_binary() -> str:
    """Absolute path of ``git``, resolved once; UNREACHABLE when absent."""
    global _GIT_BIN
    if _GIT_BIN is None:
        found = shutil.which("git")
        if found is None:
            raise CorpusError(RULE_UNREACHABLE, "git is not installed; cannot fetch or inspect a corpus checkout")
        _GIT_BIN = str(Path(found).resolve())
    return _GIT_BIN


def _ensure_git_version() -> None:
    """Refuse a git older than :data:`MIN_GIT_VERSION` (checked once per process)."""
    global _GIT_VERSION_OK
    if _GIT_VERSION_OK:
        return
    try:
        out = subprocess.run(
            [_git_binary(), "--version"], check=True, capture_output=True, text=True,
            timeout=_GIT_TIMEOUT_S, env=_git_env(False),
        ).stdout
    except (subprocess.SubprocessError, OSError) as exc:
        raise CorpusError(RULE_UNREACHABLE, f"cannot determine git version ({type(exc).__name__})") from exc
    m = _GIT_VERSION_RE.search(out)
    if m is None:
        raise CorpusError(RULE_UNREACHABLE, f"cannot parse git version from {out.strip()[:60]!r}")
    have = tuple(int(x or 0) for x in m.groups())
    if have < MIN_GIT_VERSION:
        raise CorpusError(
            RULE_UNREACHABLE,
            f"git {'.'.join(map(str, have))} is older than the required "
            f"{'.'.join(map(str, MIN_GIT_VERSION))} (ssh URL option-injection defenses)",
        )
    _GIT_VERSION_OK = True


def _reject_unsafe_source(source: str) -> None:
    """Refuse anything git could read as a transport helper or an option."""
    if source.startswith("-"):
        raise CorpusError(RULE_UNREACHABLE, "corpus source may not start with '-'")
    if "::" in source or "://" in source:
        raise CorpusError(
            RULE_UNREACHABLE, "corpus URL must start with https://, ssh:// or git@ (no other transport is allowed)"
        )


def _git_env(ssh: bool) -> dict[str, str]:
    keys = (*_GIT_ENV_KEYS, *(_GIT_ENV_SSH_KEYS if ssh else ()))
    env = {k: os.environ[k] for k in keys if k in os.environ}
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _git_argv(args: list[str]) -> list[str]:
    """``<abs git> <hardening> <args>`` — the single place every git argv is built."""
    return [_git_binary(), *_GIT_CONFIG, *args]


def _git(args: list[str], cwd: Path | None = None, *, ssh: bool = False) -> str:
    """Run one git command as an argv list (never a shell); any failure is UNREACHABLE.

    ``ssh`` forwards ``GIT_SSH_COMMAND`` — only the clone of an ssh source needs it.
    """
    _ensure_git_version()
    try:
        out = subprocess.run(
            _git_argv(args), cwd=cwd, check=True, capture_output=True, text=True,
            timeout=_GIT_TIMEOUT_S, env=_git_env(ssh),
        )
    except subprocess.TimeoutExpired as exc:
        raise CorpusError(RULE_UNREACHABLE, f"git {args[0]} timed out after {_GIT_TIMEOUT_S:.0f}s") from exc
    except (subprocess.SubprocessError, OSError) as exc:
        detail = getattr(exc, "stderr", "") or type(exc).__name__
        raise CorpusError(RULE_UNREACHABLE, f"git {args[0]} failed: {str(detail).strip()[:200]}") from exc
    return out.stdout.strip()


def _head_sha(path: Path) -> str:
    return _git(["-C", str(path), "rev-parse", "HEAD"])


@contextmanager
def fetch_corpus(source: str, ref: str | None) -> Iterator[Path]:
    """Yield a corpus checkout root for ``source`` (a local path or an allowed git URL).

    A URL REQUIRES ``ref`` (40-hex commit) and is cloned into a temporary
    directory that is removed on exit. A local path is used in place; if ``ref``
    is given it must equal that checkout's ``HEAD``. Every failure is
    ``WRD-CONSENSUS-UNREACHABLE``.
    """
    if ref is not None and not _SHA40.fullmatch(ref):
        raise CorpusError(RULE_UNREACHABLE, "--corpus-ref must be a full 40-hex commit sha")
    if _is_url(source):
        if ref is None:
            raise CorpusError(RULE_UNREACHABLE, "--corpus-ref is required when --corpus is a URL")
        with tempfile.TemporaryDirectory(prefix="warden-corpus-") as tmp:
            dest = Path(tmp) / "corpus"
            _git(["clone", "--quiet", "--no-checkout", "--", source, str(dest)], ssh=_is_ssh(source))
            _git(["checkout", "--quiet", ref], cwd=dest)
            if _head_sha(dest) != ref:
                raise CorpusError(RULE_UNREACHABLE, f"corpus HEAD is not {ref} after checkout")
            yield dest
        return
    _reject_unsafe_source(source)
    root = Path(source)
    if not root.is_dir():
        raise CorpusError(RULE_UNREACHABLE, f"corpus path is not a directory: {root}")
    if ref is not None and _head_sha(root) != ref:
        raise CorpusError(RULE_UNREACHABLE, f"corpus at {root} is not at {ref}")
    yield root


def run_consensus(
    observed_digest: str,
    coord: Coordinate,
    source: str,
    ref: str | None,
    pin: dict[str, Attester],
    min_attesters: int = 2,
    require_consensus: bool = False,
) -> ConsensusResult:
    """Fetch the corpus, verify every trusted entry for ``coord``, and adjudicate.

    ``pin`` is the consumer's trust root (:func:`corpus_trust.load_consumer_pin`).
    ``require_consensus`` makes NOVEL / INSUFFICIENT blocking (see
    :func:`corpus_verify.consensus`). Raises :class:`CorpusError` (exit 2 at the
    CLI) for any fail-closed condition.
    """
    if not signing._SIGSTORE_AVAILABLE:
        raise CorpusError(RULE_UNVERIFIABLE, "sigstore is not installed; run: pip install 'mcp-warden[sigstore]'")
    with fetch_corpus(source, ref) as root:
        declared = load_corpus_attesters(root)
        trusted, warnings = resolve_trust(declared, pin)
        attested = verified_digests(root, coord, trusted, declared)
    result = consensus(
        observed_digest, coord, attested, min_attesters=min_attesters, require_consensus=require_consensus
    )
    return ConsensusResult(result.coordinate, result.findings, result.matched, warnings, strict=result.strict)
