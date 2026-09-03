"""Attester trust for the community lock corpus (DSE-1515, phase 1).

Two lists take part in every consensus run and they are deliberately NOT the
same thing:

* the corpus's own ``attesters.json`` is a **discovery** list — it says which
  ids file entries and what identity each claims;
* the **consumer pin** (``--attester`` / ``--attesters-file``) is the **trust
  root** — the identities the consumer has decided to believe.

A corpus that could name its own trust root would verify anything it signed for
itself (CSO C3), so the pin is REQUIRED and the corpus list is only ever
intersected with it: an id the consumer did not pin is ignored (with a warning),
an id whose corpus-declared identity differs from the pin is a hard error, and a
duplicate id in either list is a hard error.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RULE_TRUST = "WRD-CONSENSUS-UNPINNED-TRUST"
RULE_UNVERIFIABLE = "WRD-CONSENSUS-UNVERIFIABLE"

#: ``attesters.json`` (corpus or consumer file) may not exceed this many bytes.
MAX_ATTESTERS_BYTES = 256 * 1024
_ATTESTER_ID = re.compile(r"[A-Za-z0-9._\-]{1,64}\Z")

_HOW_TO_PIN = (
    "pin the attesters you trust with --attester <id>=<certificate_identity>@<oidc_issuer> "
    "(repeatable) or --attesters-file <path>"
)


class CorpusError(RuntimeError):
    """A fail-closed corpus condition; ``rule_id`` names which one (exit 2 at the CLI)."""

    def __init__(self, rule_id: str, message: str) -> None:
        super().__init__(message)
        self.rule_id = rule_id


class TrustError(CorpusError):
    """A trust-configuration failure (a :class:`CorpusError` whose rule is usually ``RULE_TRUST``)."""


@dataclass(frozen=True)
class Attester:
    """One attester identity: ``id`` plus the exact Sigstore identity/issuer pair."""

    id: str
    certificate_identity: str
    oidc_issuer: str


def _attester_from_item(item: Any, rule_id: str, source: str) -> Attester:
    try:
        att = Attester(str(item["id"]), str(item["certificate_identity"]), str(item["oidc_issuer"]))
    except (KeyError, TypeError) as exc:
        raise TrustError(rule_id, f"{source}: attester entry is malformed ({type(exc).__name__})") from exc
    if not _ATTESTER_ID.fullmatch(att.id) or not att.certificate_identity or not att.oidc_issuer:
        raise TrustError(rule_id, f"{source}: attester entry {att.id!r} is invalid")
    return att


def _parse_attesters(text: str, rule_id: str, source: str) -> dict[str, Attester]:
    try:
        raw = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise TrustError(rule_id, f"{source}: not valid JSON ({type(exc).__name__})") from exc
    if not isinstance(raw, list):
        raise TrustError(rule_id, f"{source}: must be a JSON array")
    out: dict[str, Attester] = {}
    for item in raw:
        att = _attester_from_item(item, rule_id, source)
        if att.id in out:
            # Last-wins would let a second `alice` row silently substitute an identity.
            raise TrustError(rule_id, f"{source}: duplicate attester id {att.id!r}")
        out[att.id] = att
    return out


def _read_bounded(path: Path, rule_id: str) -> str:
    if not path.is_file():
        raise TrustError(rule_id, f"{path.name}: not a file")
    if path.stat().st_size > MAX_ATTESTERS_BYTES:
        raise TrustError(rule_id, f"{path.name}: exceeds {MAX_ATTESTERS_BYTES} bytes")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise TrustError(rule_id, f"{path.name}: cannot read ({type(exc).__name__})") from exc


def load_corpus_attesters(root: Path) -> dict[str, Attester]:
    """Parse the corpus's ``attesters.json`` (discovery list); malformed is UNVERIFIABLE."""
    path = root / "attesters.json"
    return _parse_attesters(_read_bounded(path, RULE_UNVERIFIABLE), RULE_UNVERIFIABLE, "attesters.json")


def parse_attester_flag(text: str) -> Attester:
    """Parse one ``--attester <id>=<certificate_identity>@<oidc_issuer>`` value.

    The identity itself contains ``@`` (``…/attest.yml@refs/heads/main``), so the
    issuer is split off at the LAST ``@``; issuers are bare URLs and carry none.
    """
    ident, sep, rest = text.partition("=")
    identity, sep2, issuer = rest.rpartition("@")
    if not sep or not sep2:
        raise TrustError(RULE_TRUST, f"--attester {text!r}: expected <id>=<certificate_identity>@<oidc_issuer>")
    return _attester_from_item(
        {"id": ident, "certificate_identity": identity, "oidc_issuer": issuer}, RULE_TRUST, "--attester"
    )


def load_consumer_pin(flags: list[str], file: Path | None) -> dict[str, Attester]:
    """Build the consumer trust root from ``--attester`` values and/or ``--attesters-file``.

    Empty → :class:`TrustError` telling the user how to pin: consensus without a
    consumer-held trust root is trust delegated wholesale to whoever hosts the corpus.
    """
    pin: dict[str, Attester] = {}
    if file is not None:
        pin = _parse_attesters(_read_bounded(file, RULE_TRUST), RULE_TRUST, file.name)
    for text in flags:
        att = parse_attester_flag(text)
        if att.id in pin:
            raise TrustError(RULE_TRUST, f"duplicate attester id {att.id!r} in consumer pin")
        pin[att.id] = att
    if not pin:
        raise TrustError(RULE_TRUST, f"--against-community requires a consumer trust pin; {_HOW_TO_PIN}")
    return pin


def resolve_trust(corpus: dict[str, Attester], pin: dict[str, Attester]) -> tuple[dict[str, Attester], list[str]]:
    """Intersect the corpus discovery list with the consumer pin.

    Returns ``(trusted, warnings)``: ``trusted`` is every pinned id the corpus
    declares with an IDENTICAL identity/issuer; a corpus id the consumer did not
    pin becomes a warning and is ignored; a pinned id the corpus declares with a
    DIFFERENT identity or issuer is a hard error (someone is lying about who
    ``alice`` is, and it does not matter which side).
    """
    trusted: dict[str, Attester] = {}
    warnings: list[str] = []
    for att_id, declared in sorted(corpus.items()):
        pinned = pin.get(att_id)
        if pinned is None:
            warnings.append(f"attester {att_id!r} is declared by the corpus but not in your trust pin; ignored")
            continue
        if pinned != declared:
            raise TrustError(
                RULE_TRUST,
                f"attester {att_id!r}: corpus declares a different identity/issuer than your trust pin",
            )
        trusted[att_id] = pinned
    return trusted, warnings
