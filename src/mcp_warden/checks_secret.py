"""Secret-leakage checks (MCP-SECRET) — ``WRD-SEC-*`` (CHECKS.md §4.2).

Deterministic regex + entropy heuristics over the declared surface's string
fields. Snippets are ALWAYS redacted (CHECKS.md §8.2).
"""

from __future__ import annotations

import math
import re
from collections import Counter

from .models import Finding
from .redact import redact_secret

# --- Vendor patterns (CHECKS.md §4.2; case-sensitive unless noted) -----------

_VENDOR_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("WRD-SEC-OPENAI", "critical", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    # GitHub: ghp_ (36) plus gho_/ghu_/ghs_/ghr_ OAuth/app tokens.
    ("WRD-SEC-GITHUB", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("WRD-SEC-AWS-AKID", "critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("WRD-SEC-SLACK", "critical", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "WRD-SEC-PRIVKEY",
        "critical",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    (
        "WRD-SEC-JWT",
        "high",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
]

#: Entropy candidate token pattern (CHECKS.md §4.2).
_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{20,}")

#: Splitter for the entropy pass: whitespace + chars outside the candidate set.
_ENTROPY_SPLIT = re.compile(r"[^A-Za-z0-9+/_=.-]+")

ENTROPY_THRESHOLD = 4.0
ENTROPY_MIN_LEN = 24
ALNUM_DOMINANCE = 0.80


def shannon_entropy(token: str) -> float:
    """Compute Shannon entropy (bits/char) over a token's character distribution.

    ``H = -Σ p_i log2 p_i``.

    Args:
        token: The candidate string.

    Returns:
        Entropy in bits per character; ``0.0`` for an empty string.
    """
    if not token:
        return 0.0
    counts = Counter(token)
    n = len(token)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _alnum_ratio(token: str) -> float:
    """Fraction of characters in ``[A-Za-z0-9]``."""
    if not token:
        return 0.0
    alnum = sum(1 for ch in token if ch.isalnum() and ch.isascii())
    return alnum / len(token)


def scan_field(value: str, target: str) -> list[Finding]:
    """Scan one string field for secret patterns; return redacted findings.

    Applies the vendor patterns first, then the entropy heuristic de-duped
    against any token already matched by a vendor rule.

    Args:
        value: The string field content to scan.
        target: The finding target, e.g. ``"tools/<name>"`` or ``"launch/command"``.

    Returns:
        A list of :class:`Finding` with redacted snippets. May be empty.
    """
    if not value:
        return []

    findings: list[Finding] = []
    matched_spans: set[str] = set()

    # 1) Explicit vendor patterns.
    for rule_id, severity, pattern in _VENDOR_PATTERNS:
        for m in pattern.finditer(value):
            raw = m.group(0)
            matched_spans.add(raw)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    target=target,
                    message=f"{rule_id}: possible secret in field",
                    snippet=redact_secret(raw),
                )
            )

    # 2) Entropy heuristic, de-duped against vendor matches.
    for token in _ENTROPY_SPLIT.split(value):
        if len(token) < ENTROPY_MIN_LEN:
            continue
        if not _ENTROPY_TOKEN.fullmatch(token):
            continue
        if any(token in span or span in token for span in matched_spans):
            continue  # already covered by a vendor rule
        if _alnum_ratio(token) < ALNUM_DOMINANCE:
            continue
        if shannon_entropy(token) >= ENTROPY_THRESHOLD:
            findings.append(
                Finding(
                    rule_id="WRD-SEC-ENTROPY",
                    severity="high",
                    target=target,
                    message="WRD-SEC-ENTROPY: high-entropy token (possible secret)",
                    snippet=redact_secret(token),
                )
            )
            matched_spans.add(token)

    return findings
