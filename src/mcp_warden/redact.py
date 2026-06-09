"""Secret redaction — used everywhere a secret snippet could appear.

Non-negotiable (CHECKS.md §8.2): secret snippets are ALWAYS redacted as
``prefix + "…" + "(<length-tag>)"`` where ``prefix = raw[:min(4, n//2)]`` and the
length tag is exact for ``n>=4`` and bucketed to ``len<=3`` for ``n<=3``. Never
the raw match in full, anywhere (lock, SARIF, JSONL, stdout, on-wire echo).
"""

from __future__ import annotations

#: The ellipsis character used in redactions (single U+2026, not "...").
ELLIPSIS = "…"


def redact_secret(raw: str) -> str:
    """Redact a secret value to ``prefix + "…" + "(<length-tag>)"``.

    The revealed prefix is ``raw[:min(4, n//2)]`` — never more than half the
    secret (``min(4, n//2)``), so a short secret is **never** fully disclosed.
    The exact length is preserved for ``n>=4`` (a drift/audit signal), but for
    ``n<=3`` the length is bucketed to ``len<=3`` because an exact length there
    would narrow a brute-force search to a handful of candidates. For ``n>=8``
    the behavior is unchanged from prior versions (``sk-a…(len=23)`` etc.).

    Codepoint (not grapheme) semantics: slicing and length operate on Python
    ``str`` codepoints. Non-``str`` input is defensively coerced via ``str()``
    rather than raised, because one call site (the on-wire secret-echo block in
    ``wire_block._redact_secrets_in_text``) runs inside the guard proxy's
    server->client pump, which is NOT wrapped to swallow a redaction ``TypeError``;
    a raise there would crash the guard session. Coercion keeps redaction total.

    Args:
        raw: The raw matched secret string (coerced to ``str`` if not already).

    Returns:
        A redacted snippet that reveals at most ``min(4, n//2)`` leading
        codepoints plus a length tag.

    Examples:
        >>> redact_secret("sk-abcdefghij1234567890")
        'sk-a…(len=23)'
        >>> redact_secret("sk-1")
        'sk…(len=4)'
        >>> redact_secret("ab")
        'a…(len<=3)'
    """
    if not isinstance(raw, str):
        raw = str(raw)
    n = len(raw)
    k = min(4, n // 2)  # revealed prefix is ALWAYS <= floor(n/2)
    length_tag = "len<=3" if n <= 3 else f"len={n}"  # bucket only n<=3; exact for n>=4
    return f"{raw[:k]}{ELLIPSIS}({length_tag})"
