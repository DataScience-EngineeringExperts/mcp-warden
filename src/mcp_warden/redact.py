"""Secret redaction — used everywhere a secret snippet could appear.

Non-negotiable (CHECKS.md §8.2): secret snippets are ALWAYS redacted as
``first4 + "…" + "(len=N)"``. Never the raw match, anywhere (lock, SARIF, JSONL,
stdout).
"""

from __future__ import annotations

#: The ellipsis character used in redactions (single U+2026, not "...").
ELLIPSIS = "…"


def redact_secret(raw: str) -> str:
    """Redact a secret value to ``first4 + "…" + "(len=N)"``.

    Args:
        raw: The raw matched secret string.

    Returns:
        A redacted snippet that reveals at most the first 4 characters and the
        total length, e.g. ``"sk-1…(len=51)"``. For matches shorter than 4
        characters the prefix is whatever exists.

    Examples:
        >>> redact_secret("sk-abcdefghij1234567890")
        'sk-a…(len=22)'
    """
    n = len(raw)
    prefix = raw[:4]
    return f"{prefix}{ELLIPSIS}(len={n})"
