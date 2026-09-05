"""Entry verification + verdict for the community lock corpus (DSE-1515, phase 1).

For one coordinate, every ``<id>.lock`` under the corpus directory must:

1. sit INSIDE the corpus root after symlink resolution (CSO L3);
2. fit the size caps (CSO M3) and parse as a lock at the implemented
   ``SCHEMA_VERSION`` (CSO L2);
3. name an attester the CONSUMER pinned (:mod:`corpus_trust`);
4. carry a ``<id>.lock.sigstore`` bundle that verifies, against that attester's
   identity/issuer, over the v2 statement ``{digest, coordinate}`` built from
   the coordinate that DETERMINES the directory being read (the caller's
   ``coord``, whose ``relative_dir()`` is the only place entries are looked
   for) — so a genuine signature relocated under another package's directory
   is checked against that package's coordinate and fails (CSO C2);
5. reproduce its signed ``overall_digest`` from its entries, so the derived
   launch-independent :func:`~mcp_warden.lockfile.surface_digest` is covered.

One bad entry rejects the whole coordinate — a corpus that cannot be verified is
not evidence. **Consensus attests observation, not safety.**

What consensus canNOT see: an absent directory is indistinguishable from "nobody
attested this" — a hostile or forked corpus can turn an exit-1 MISMATCH into a
NOVEL by withholding entries. Pin ``--corpus-ref`` to an audited commit, and use
``--require-consensus`` where the coordinate is expected to be attested.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import SCHEMA_VERSION
from .corpus_coordinate import Coordinate
from .corpus_trust import RULE_UNVERIFIABLE, Attester, CorpusError
from .lockfile import lock_is_self_consistent, read_lock, surface_digest
from .models import Finding
from .signing import build_statement, bundle_from_json, make_verifier, verify_statement

RULE_MISMATCH = "WRD-CONSENSUS-MISMATCH"
RULE_SPLIT = "WRD-CONSENSUS-SPLIT"
RULE_NOVEL = "WRD-CONSENSUS-NOVEL"
RULE_INSUFFICIENT = "WRD-CONSENSUS-INSUFFICIENT"
RULE_SCHEMA_MISMATCH = "WRD-CONSENSUS-SCHEMA-MISMATCH"

#: Appended to every consensus message; the one claim this feature must never overstate.
NOT_SAFETY = "consensus attests observation, not safety"

MAX_LOCK_BYTES = 1024 * 1024
MAX_SIDECAR_BYTES = 256 * 1024
MAX_ENTRIES_PER_COORDINATE = 64


@dataclass(frozen=True)
class ConsensusResult:
    """Outcome of one consensus run; ``blocking`` mirrors the exit-code contract."""

    coordinate: Coordinate
    findings: list[Finding]
    matched: list[str] = field(default_factory=list)  # attester ids agreeing with observed
    warnings: list[str] = field(default_factory=list)  # non-fatal notes for stderr
    strict: bool = False  # --require-consensus: NOVEL / INSUFFICIENT block too

    @property
    def blocking(self) -> bool:
        rules = (RULE_MISMATCH, RULE_SPLIT, RULE_NOVEL, RULE_INSUFFICIENT) if self.strict \
            else (RULE_MISMATCH, RULE_SPLIT)
        return any(f.rule_id in rules for f in self.findings)


def _short(digest: str) -> str:
    return digest[:19] + "…" if len(digest) > 19 else digest


def _fail(message: str) -> CorpusError:
    return CorpusError(RULE_UNVERIFIABLE, message)


def _confined(root: Path, path: Path, what: str) -> Path:
    """Resolve ``path`` and refuse it unless it stays under ``root`` (symlink escapes)."""
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _fail(f"{what}: cannot resolve ({type(exc).__name__})") from exc
    if not resolved.is_relative_to(root.resolve()):
        raise _fail(f"{what}: escapes the corpus root")
    return resolved


def _check_bounded(path: Path, cap: int, what: str) -> None:
    """The size cap is enforced by ``stat()``; nothing is read here."""
    if not path.is_file():
        raise _fail(f"{what}: not a regular file")
    if path.stat().st_size > cap:
        raise _fail(f"{what}: exceeds {cap} bytes")


def _read_bounded(path: Path, cap: int, what: str) -> str:
    _check_bounded(path, cap, what)
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _fail(f"{what}: cannot read ({type(exc).__name__})") from exc


def _error_locus(exc: BaseException) -> str:
    """Field paths only — a pydantic message would echo the hostile input back."""
    cause = exc.__cause__ if exc.__cause__ is not None else exc
    errors = getattr(cause, "errors", None)
    if callable(errors):
        try:
            locs = [".".join(str(x) for x in e.get("loc", ())) for e in errors()[:5]]
            return ", ".join(x for x in locs if x) or type(cause).__name__
        except Exception:  # noqa: BLE001 - locus is best-effort, never load-bearing
            pass
    return type(cause).__name__


def verified_digests(
    root: Path, coord: Coordinate, trusted: dict[str, Attester], declared: dict[str, Attester] | None = None
) -> dict[str, str]:
    """Return ``{attester_id: surface_digest}`` for every trusted entry under ``coord``.

    ``declared`` is the corpus discovery list: an entry from an id the corpus never
    declared rejects the coordinate; one the corpus declared but the consumer did
    not pin is skipped (never verified). Without ``declared`` the trusted set is
    also the declared set.
    """
    declared = trusted if declared is None else declared
    entry_dir = root / coord.relative_dir()
    if not entry_dir.is_dir():
        return {}
    entry_dir = _confined(root, entry_dir, f"{coord}")
    verifier = make_verifier()
    statement = build_statement  # bound below with the DIRECTORY-derived coordinate
    lock_paths = sorted(p for p in entry_dir.glob("*.lock") if not p.name.startswith("."))
    if len(lock_paths) > MAX_ENTRIES_PER_COORDINATE:
        raise _fail(f"{coord}: more than {MAX_ENTRIES_PER_COORDINATE} entries")
    out: dict[str, str] = {}
    for lock_path in lock_paths:
        name = lock_path.name
        attester_id = name[: -len(".lock")]
        if attester_id not in declared:
            raise _fail(f"{name}: attester {attester_id!r} is not declared by the corpus")
        att = trusted.get(attester_id)
        if att is None:
            continue  # declared but not in the consumer pin: ignored, never verified (CSO C3)
        lock_path = _confined(root, lock_path, name)
        _check_bounded(lock_path, MAX_LOCK_BYTES, name)  # stat only; read_lock reads once
        try:
            lock = read_lock(lock_path)
        except (FileNotFoundError, ValueError) as exc:
            raise _fail(f"{name}: lock does not parse ({_error_locus(exc)})") from exc
        if lock.schema_version != SCHEMA_VERSION:
            raise CorpusError(
                RULE_SCHEMA_MISMATCH,
                f"{name}: lock schema_version {lock.schema_version} != implemented {SCHEMA_VERSION}; "
                "the corpus entry and this mcp-warden do not speak the same lock format",
            )
        if not lock_is_self_consistent(lock):
            raise _fail(f"{name}: entries do not reproduce its overall_digest")
        sidecar = lock_path.with_name(name + ".sigstore")
        if not sidecar.is_file():
            raise _fail(f"{name}: signature sidecar is missing")
        sidecar = _confined(root, sidecar, sidecar.name)
        bundle_text = _read_bounded(sidecar, MAX_SIDECAR_BYTES, sidecar.name)
        try:
            bundle = bundle_from_json(bundle_text)
            verify_statement(
                statement(lock.overall_digest, str(coord)), bundle,
                att.certificate_identity, att.oidc_issuer, verifier=verifier,
            )
        except Exception as exc:  # noqa: BLE001 - any verify failure is fail-closed
            raise _fail(f"{name}: signature did not verify ({type(exc).__name__})") from exc
        out[attester_id] = surface_digest(lock)
    return out


def consensus(
    observed_digest: str, coord: Coordinate, attested: dict[str, str], *,
    min_attesters: int = 2, require_consensus: bool = False,
) -> ConsensusResult:
    """Compare the observed digest against verified attestations.

    With ``require_consensus`` (``--require-consensus``) NOVEL and INSUFFICIENT are
    ``high`` and blocking: a CI job that expects the coordinate to be attested must
    not pass because the corpus (or a fork of it) simply has no entry.
    """
    target = f"corpus/{coord}"
    snippet = f"observed={_short(observed_digest)}"
    soft = "low" if not require_consensus else "high"
    strict_note = "" if not require_consensus else " (--require-consensus: blocking)"
    if not attested:
        return ConsensusResult(coord, [Finding(
            rule_id=RULE_NOVEL, severity=soft, target=target, snippet=snippet,
            message=f"no attestation exists for {coord}; nothing to compare{strict_note} — {NOT_SAFETY}",
        )], strict=require_consensus)
    findings: list[Finding] = []
    distinct = sorted(set(attested.values()))
    matched = sorted(a for a, d in attested.items() if d == observed_digest)
    if len(distinct) > 1:
        who = ", ".join(f"{a}→{_short(d)}" for a, d in sorted(attested.items()))
        findings.append(Finding(
            rule_id=RULE_SPLIT, severity="high", target=target, snippet=snippet,
            message=f"attesters disagree on {coord} ({who}); corpus or upstream may be compromised — {NOT_SAFETY}",
        ))
    if not matched:
        findings.append(Finding(
            rule_id=RULE_MISMATCH, severity="high", target=target,
            message=(f"observed surface differs from every attested digest for {coord} "
                     f"({len(attested)} attester(s): {', '.join(sorted(attested))}) — {NOT_SAFETY}"),
            snippet=f"{snippet} attested={','.join(_short(d) for d in distinct)}",
        ))
    elif not findings and len(matched) < min_attesters:
        findings.append(Finding(
            rule_id=RULE_INSUFFICIENT, severity=soft, target=target, snippet=snippet,
            message=(f"only {len(matched)} trusted attester(s) observed this surface for {coord}; "
                     f"{min_attesters} required for consensus{strict_note} — {NOT_SAFETY}"),
        ))
    return ConsensusResult(coord, findings, matched, strict=require_consensus)
