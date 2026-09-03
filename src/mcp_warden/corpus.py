"""Community lock corpus — multi-attester surface consensus (DSE-1515, phase 1).

``check`` answers "did the surface change since *I* approved it?". It cannot see
a server that shipped poisoned on day one (TOFU) or a surface served only to one
consumer. Both need *independent observation*: if several unaffiliated attesters
Sigstore-signed the same ``overall_digest`` for ``npm:@foo/server@1.2.3`` and you
observe something else, that is signal a solo lock can never produce.

Layout of a corpus checkout (``docs/COMMUNITY_CORPUS.md``)::

    attesters.json                              [{"id","certificate_identity","oidc_issuer"}]
    locks/<ecosystem>/<segment>/<version>/<attester-id>.lock
    locks/<ecosystem>/<segment>/<version>/<attester-id>.lock.sigstore

Every rule here fails CLOSED: an unknown attester, a missing or unverifiable
sidecar, an unreachable corpus, or an unpinnable launch is exit 2, never a skip.
**Consensus attests observation, not safety** — every finding says so.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import signing
from .corpus_coordinate import Coordinate
from .lockfile import lock_is_self_consistent, read_lock, surface_digest
from .models import Finding
from .signing import build_statement, bundle_from_json, verify_statement

RULE_MISMATCH = "WRD-CONSENSUS-MISMATCH"
RULE_SPLIT = "WRD-CONSENSUS-SPLIT"
RULE_NOVEL = "WRD-CONSENSUS-NOVEL"
RULE_UNRESOLVED = "WRD-CONSENSUS-UNRESOLVED"
RULE_UNVERIFIABLE = "WRD-CONSENSUS-UNVERIFIABLE"
RULE_UNREACHABLE = "WRD-CONSENSUS-UNREACHABLE"

#: Appended to every consensus message; the one claim this feature must never overstate.
NOT_SAFETY = "consensus attests observation, not safety"

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_ATTESTER_ID = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")
_GIT_TIMEOUT_S = 120.0


class CorpusError(RuntimeError):
    """A fail-closed corpus condition; ``rule_id`` names which one."""

    def __init__(self, rule_id: str, message: str) -> None:
        super().__init__(message)
        self.rule_id = rule_id


@dataclass(frozen=True)
class Attester:
    """A declared attester identity from ``attesters.json``."""

    id: str
    certificate_identity: str
    oidc_issuer: str


@dataclass(frozen=True)
class ConsensusResult:
    """Outcome of one consensus run; ``blocking`` mirrors the exit-code contract."""

    coordinate: Coordinate
    findings: list[Finding]
    matched: list[str] = field(default_factory=list)  # attester ids agreeing with observed

    @property
    def blocking(self) -> bool:
        return any(f.rule_id in (RULE_MISMATCH, RULE_SPLIT) for f in self.findings)


def _short(digest: str) -> str:
    return digest[:19] + "…" if len(digest) > 19 else digest


def _is_url(source: str) -> bool:
    return "://" in source or source.startswith("git@")


def _git(args: list[str], cwd: Path | None = None) -> None:
    """Run one git command as an argv list (never a shell); any failure is UNREACHABLE."""
    try:
        subprocess.run(
            ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=_GIT_TIMEOUT_S
        )
    except subprocess.TimeoutExpired as exc:
        raise CorpusError(RULE_UNREACHABLE, f"git {args[0]} timed out after {_GIT_TIMEOUT_S:.0f}s") from exc
    except (subprocess.CalledProcessError, OSError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise CorpusError(RULE_UNREACHABLE, f"git {args[0]} failed: {detail.strip()[:200]}") from exc


def _head_sha(path: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=_GIT_TIMEOUT_S,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        raise CorpusError(RULE_UNREACHABLE, f"cannot read corpus HEAD at {path}: {exc}") from exc
    return out.stdout.strip()


@contextmanager
def fetch_corpus(source: str, ref: str | None) -> Iterator[Path]:
    """Yield a corpus checkout root for ``source`` (a local path or a git URL).

    A URL REQUIRES ``ref`` (40-hex commit) and is cloned into a temporary
    directory that is removed on exit. A local path is used in place; if ``ref``
    is given it must equal that checkout's ``HEAD``. Every failure is
    ``WRD-CONSENSUS-UNREACHABLE``.
    """
    if ref is not None and not _SHA40.match(ref):
        raise CorpusError(RULE_UNREACHABLE, "--corpus-ref must be a full 40-hex commit sha")
    if _is_url(source):
        if ref is None:
            raise CorpusError(RULE_UNREACHABLE, "--corpus-ref is required when --corpus is a URL")
        if shutil.which("git") is None:
            raise CorpusError(RULE_UNREACHABLE, "git is not installed; cannot fetch a corpus URL")
        with tempfile.TemporaryDirectory(prefix="warden-corpus-") as tmp:
            dest = Path(tmp) / "corpus"
            _git(["clone", "--quiet", "--no-checkout", source, str(dest)])
            _git(["checkout", "--quiet", ref], cwd=dest)
            if _head_sha(dest) != ref:
                raise CorpusError(RULE_UNREACHABLE, f"corpus HEAD is not {ref} after checkout")
            yield dest
        return
    root = Path(source)
    if not root.is_dir():
        raise CorpusError(RULE_UNREACHABLE, f"corpus path is not a directory: {root}")
    if ref is not None and _head_sha(root) != ref:
        raise CorpusError(RULE_UNREACHABLE, f"corpus at {root} is not at {ref}")
    yield root


def load_attesters(root: Path) -> dict[str, Attester]:
    """Parse ``attesters.json``; malformed or missing is UNVERIFIABLE."""
    path = root / "attesters.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CorpusError(RULE_UNVERIFIABLE, f"cannot read {path}: {exc}") from exc
    out: dict[str, Attester] = {}
    if not isinstance(raw, list):
        raise CorpusError(RULE_UNVERIFIABLE, "attesters.json must be a JSON array")
    for item in raw:
        try:
            att = Attester(str(item["id"]), str(item["certificate_identity"]), str(item["oidc_issuer"]))
        except (KeyError, TypeError) as exc:
            raise CorpusError(RULE_UNVERIFIABLE, f"attesters.json entry is malformed: {exc}") from exc
        if not _ATTESTER_ID.match(att.id) or not att.certificate_identity or not att.oidc_issuer:
            raise CorpusError(RULE_UNVERIFIABLE, f"attesters.json entry {att.id!r} is invalid")
        out[att.id] = att
    return out


def verified_digests(root: Path, coord: Coordinate, attesters: dict[str, Attester]) -> dict[str, str]:
    """Return ``{attester_id: surface_digest}`` for every entry under ``coord``.

    Each ``<id>.lock`` must (1) parse as a lock, (2) name a declared attester,
    (3) carry a ``<id>.lock.sigstore`` bundle that verifies against that
    attester's identity/issuer over the lock's OWN ``overall_digest``, and
    (4) have entries that reproduce that signed ``overall_digest`` — so the
    launch-independent :func:`~mcp_warden.lockfile.surface_digest` we then derive
    is covered by the signature. One bad entry rejects the whole coordinate — a
    corpus that cannot be verified is not evidence.
    """
    entry_dir = root / coord.relative_dir()
    if not entry_dir.is_dir():
        return {}
    out: dict[str, str] = {}
    for lock_path in sorted(entry_dir.glob("*.lock")):
        attester_id = lock_path.name[: -len(".lock")]
        att = attesters.get(attester_id)
        if att is None:
            raise CorpusError(RULE_UNVERIFIABLE, f"{lock_path.name}: attester {attester_id!r} is not declared")
        try:
            lock = read_lock(lock_path)
        except (FileNotFoundError, ValueError) as exc:
            raise CorpusError(RULE_UNVERIFIABLE, f"{lock_path.name}: {exc}") from exc
        digest = lock.overall_digest
        if not lock_is_self_consistent(lock):
            raise CorpusError(RULE_UNVERIFIABLE, f"{lock_path.name}: entries do not reproduce its overall_digest")
        sidecar = lock_path.with_name(lock_path.name + ".sigstore")
        if not sidecar.is_file():
            raise CorpusError(RULE_UNVERIFIABLE, f"{lock_path.name}: signature sidecar is missing")
        try:
            bundle = bundle_from_json(sidecar.read_text(encoding="utf-8"))
            verify_statement(build_statement(digest), bundle, att.certificate_identity, att.oidc_issuer)
        except Exception as exc:  # noqa: BLE001 - any verify failure is fail-closed
            raise CorpusError(RULE_UNVERIFIABLE, f"{lock_path.name}: signature did not verify: {exc}") from exc
        out[attester_id] = surface_digest(lock)
    return out


def consensus(observed_digest: str, coord: Coordinate, attested: dict[str, str]) -> ConsensusResult:
    """Compare the observed digest against verified attestations."""
    target = f"corpus/{coord}"
    if not attested:
        return ConsensusResult(coord, [Finding(
            rule_id=RULE_NOVEL, severity="low", target=target,
            message=f"no attestation exists for {coord}; nothing to compare — {NOT_SAFETY}",
            snippet=f"observed={_short(observed_digest)}",
        )])
    findings: list[Finding] = []
    distinct = sorted(set(attested.values()))
    matched = sorted(a for a, d in attested.items() if d == observed_digest)
    if len(distinct) > 1:
        who = ", ".join(f"{a}→{_short(d)}" for a, d in sorted(attested.items()))
        findings.append(Finding(
            rule_id=RULE_SPLIT, severity="high", target=target,
            message=f"attesters disagree on {coord} ({who}); corpus or upstream may be compromised — {NOT_SAFETY}",
            snippet=f"observed={_short(observed_digest)}",
        ))
    if not matched:
        findings.append(Finding(
            rule_id=RULE_MISMATCH, severity="high", target=target,
            message=(f"observed surface differs from every attested digest for {coord} "
                     f"({len(attested)} attester(s): {', '.join(sorted(attested))}) — {NOT_SAFETY}"),
            snippet=f"observed={_short(observed_digest)} attested={','.join(_short(d) for d in distinct)}",
        ))
    return ConsensusResult(coord, findings, matched)


def run_consensus(observed_digest: str, coord: Coordinate, source: str, ref: str | None) -> ConsensusResult:
    """Fetch the corpus, verify every entry for ``coord``, and adjudicate.

    Raises :class:`CorpusError` (exit 2 at the CLI) for any fail-closed condition.
    """
    if not signing._SIGSTORE_AVAILABLE:
        raise CorpusError(RULE_UNVERIFIABLE, "sigstore is not installed; run: pip install 'mcp-warden[sigstore]'")
    with fetch_corpus(source, ref) as root:
        attesters = load_attesters(root)
        attested = verified_digests(root, coord, attesters)
    return consensus(observed_digest, coord, attested)
