"""Deterministic result-inspection primitives (RESULT_INSPECTION.md §3.1, §4.1).

ANSI/control codepoint scanning (parser-free) and injection-phrase normalization
+ exact-substring matching (no broad regex). The exfil-domain + URL primitives
live in ``res_net.py`` and are re-exported here so callers have one import point.
"""

from __future__ import annotations

import re

# Re-export the exfil/URL primitives + seed lists (single import point).
from .res_net import (  # noqa: F401
    SEED_EXFIL_DENYLIST,
    SEED_EXFIL_PATH_QUALIFIED,
    SSRF_NETWORKS,
    extract_urls,
    host_matches_domain,
    match_exfil,
    match_ip_literals,
)

# --- WRD-RES-ANSI: codepoint allowlist (RESULT_INSPECTION.md §3.1) ------------

#: The three whitespace C0 codepoints that ARE allowed (TAB, LF, CR).
_ALLOWED_C0 = frozenset({0x09, 0x0A, 0x0D})

#: Unicode line/paragraph separators treated as control (disallowed in strict).
_LINE_PARA_SEP = frozenset({0x2028, 0x2029})


def _is_disallowed_strict(cp: int) -> bool:
    """Return True if ``cp`` is disallowed under the strict allowlist (``text``).

    Strict: C0 controls except TAB/LF/CR, DEL (U+007F), C1 (U+0080-U+009F), and
    U+2028/U+2029 are disallowed. ESC (U+001B) is in the C0 range — that is what
    makes an ANSI grammar unnecessary.

    Args:
        cp: A Unicode scalar value (``ord(ch)``).

    Returns:
        True if the codepoint is a violation under the strict charset.
    """
    if cp in _ALLOWED_C0:
        return False
    if cp <= 0x1F:
        return True
    if cp == 0x7F:
        return True
    if 0x80 <= cp <= 0x9F:
        return True
    if cp in _LINE_PARA_SEP:
        return True
    return False


def _is_disallowed_extended(cp: int) -> bool:
    """Return True if disallowed under ``expected_output_charset: "extended"``.

    ``extended`` additionally allows C1 and U+2028/U+2029, but still forbids
    ESC/C0 (except TAB/LF/CR) and DEL (RESULT_INSPECTION.md §11.2).

    Args:
        cp: A Unicode scalar value.

    Returns:
        True if the codepoint is a violation under the extended charset.
    """
    if cp in _ALLOWED_C0:
        return False
    if cp <= 0x1F:
        return True
    if cp == 0x7F:
        return True
    return False


def _ansi_predicate(charset: str):
    """Return the disallowed-codepoint predicate for a charset (None if disabled)."""
    if charset == "binary-ok":
        return None
    return _is_disallowed_extended if charset == "extended" else _is_disallowed_strict


def find_ansi_codepoints(text: str, charset: str) -> list[int]:
    """Return indices of disallowed codepoints in ``text`` for a charset (§3.1).

    Parser-free. ``"binary-ok"`` disables the check (returns ``[]``).

    Args:
        text: The inspected result text.
        charset: ``"text"`` (strict), ``"extended"``, or ``"binary-ok"``.

    Returns:
        Indices whose codepoint is disallowed (empty if none).
    """
    predicate = _ansi_predicate(charset)
    if predicate is None:
        return []
    return [i for i, ch in enumerate(text) if predicate(ord(ch))]


def strip_ansi(text: str, charset: str) -> str:
    """Strip all disallowed codepoints from ``text`` (the ANSI redact-on-block op).

    Args:
        text: The inspected result text.
        charset: The effective ``expected_output_charset``.

    Returns:
        ``text`` with every disallowed codepoint removed, order preserved.
    """
    predicate = _ansi_predicate(charset)
    if predicate is None:
        return text
    return "".join(ch for ch in text if not predicate(ord(ch)))


# --- WRD-RES-INJECT-PHRASE (RESULT_INSPECTION.md §4.1) ------------------------

#: Seed injection-phrase denylist (RESULT_INSPECTION.md §4.1). Narrow + curated.
SEED_INJECT_PHRASES: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "disregard all previous instructions",
    "ignore the above instructions",
    "forget previous instructions",
    "forget all prior instructions",
    "you are now",
    "from now on you are",
    "new instructions:",
    "system prompt:",
    "override your instructions",
    "disregard your system prompt",
    "do not tell the user",
    "do not mention this to the user",
    "without telling the user",
    "reveal your system prompt",
    "print your system prompt",
    "exfiltrate",
    "send the following to",
)

#: Run of ASCII whitespace + the Unicode separators (collapsed to one space).
_WS_RUN = re.compile(r"[\t\n\r   ]+")


def normalize_phrase_text(text: str) -> str:
    """Lowercase + collapse whitespace for injection-phrase matching (§4.1).

    Args:
        text: Raw result text.

    Returns:
        Lowercased text with any run of ASCII/Unicode-separator whitespace
        collapsed to a single space. No stemming, no fuzzy matching.
    """
    return _WS_RUN.sub(" ", text.casefold())


def match_inject_phrases(text: str, phrases: tuple[str, ...] | list[str]) -> list[str]:
    """Return the curated phrases that appear as normalized substrings (§4.1).

    Exact substring match against normalized text; broad regex is forbidden.

    Args:
        text: Raw result text.
        phrases: The merged (seed + org) exact-phrase denylist.

    Returns:
        A sorted, de-duplicated list of matched phrases.
    """
    norm = normalize_phrase_text(text)
    return sorted({p for p in phrases if normalize_phrase_text(p) in norm})
