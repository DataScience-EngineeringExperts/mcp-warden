"""Property-based fuzzing of the secret redactor (issue #17, binding #4).

The security property is a LEAK-BOUND: ``redact_secret`` reveals at most the first
4 characters + the length. Properties assert the FORMAT STRUCTURE (not exact
equality — the ``…`` / ``(len=`` literals can collide with secret content and
make an equality oracle false-fail) and the leak-bound (the post-prefix tail of
the secret never appears as a contiguous run in the output).

Per the adversarial review: ``redact_secret`` takes ``str``; ``len`` counts
codepoints. The short-secret (``len <= 4``) full-disclosure is a KNOWN contract
edge case tracked in issue #38 — this suite asserts the CURRENT contract and does
NOT modify ``redact.py``.
"""

from __future__ import annotations

from hypothesis import example, given
from hypothesis import strategies as st

from mcp_warden.redact import ELLIPSIS, redact_secret


@given(raw=st.text(max_size=200))
@example(raw="")  # len 0
@example(raw="a")  # len 1
@example(raw="ab")  # len 2
@example(raw="abc")  # len 3
@example(raw="abcd")  # len 4 — issue #38 boundary (whole value still revealed)
@example(raw="abcde")  # len 5 — first true redaction
@example(raw="sk-abcdefghij1234567890")  # realistic long secret
@example(raw="key…with(len= literals")  # collision chars in the secret body
@example(raw="日本語パスワード鍵")  # multi-byte unicode, len counts codepoints
@example(raw="ab😀cd😀ef")  # astral (surrogate-pair) codepoints
def test_redact_format_structure(raw: str) -> None:
    """Output has the documented ``first4 + ELLIPSIS + (len=N)`` STRUCTURE.

    Asserted structurally (startswith / contains / endswith), never by exact
    equality, so a secret that itself contains ``…`` or ``(len=`` cannot
    false-fail. N is the CODEPOINT length (``len(str)``), consistent with the
    ANSI detector which also iterates codepoints.
    """
    out = redact_secret(raw)
    prefix = raw[:4]
    assert out.startswith(prefix)
    assert ELLIPSIS in out
    assert out.endswith(f"(len={len(raw)})")
    # The exact shape is reconstructable from the three documented parts.
    assert out == f"{prefix}{ELLIPSIS}(len={len(raw)})"


@given(raw=st.text(max_size=200))
@example(raw="abcd")  # #38: len<=4 reveals everything — prefix == raw
@example(raw="abcde")  # the false-fail trap: 1-char tail "e" collides with "(len="
@example(raw="passw0rd-secret-value-1234567890")
@example(raw="…(len=5)abcdef")  # secret literally contains the suffix shape
def test_redact_leak_bound(raw: str) -> None:
    """The ONLY secret-derived region of the output is the <=4-char prefix.

    The output is exactly ``prefix + template`` where ``template = ELLIPSIS +
    f"(len={N})"`` is a pure function of ``len(raw)`` and carries NO content from
    ``raw`` beyond its length. So everything past the prefix is reconstructable
    WITHOUT knowing the secret body — i.e. at most the first 4 characters leak.

    This is the false-fail-proof statement of the leak-bound: a naive
    ``raw[4:] not in output`` check is wrong because a 1-char tail like ``"e"``
    legitimately appears inside the fixed ``(len=N)`` template (that ``"e"`` is
    NOT a leak). We instead assert the template region is content-independent.

    For ``len(raw) <= 4`` the prefix IS the whole secret — the issue #38
    short-secret full-disclosure edge case, asserted here as the CURRENT contract
    (NOT fixed; see redact.py docstring / #38).
    """
    out = redact_secret(raw)
    prefix = raw[:4]
    template = f"{ELLIPSIS}(len={len(raw)})"
    # The output is prefix + a template that depends ONLY on len(raw).
    assert out == prefix + template
    # The template region carries no secret content: recompute it from length
    # alone and confirm it matches the output's tail byte-for-byte.
    after_prefix = out[len(prefix) :]
    assert after_prefix == template
    # Therefore total revealed plaintext == prefix, i.e. <= 4 codepoints.
    assert len(prefix) <= 4


@given(raw=st.text(min_size=5, max_size=200))
def test_redact_reveals_at_most_four_codepoints(raw: str) -> None:
    """For a genuinely-long secret (len>4), at most 4 leading codepoints appear.

    The portion of the output before the ELLIPSIS is exactly the first 4
    codepoints of the secret — never more.
    """
    out = redact_secret(raw)
    before_ellipsis = out.split(ELLIPSIS, 1)[0]
    assert before_ellipsis == raw[:4]
    assert len(before_ellipsis) <= 4


@given(raw=st.text(max_size=64))
def test_redact_is_deterministic(raw: str) -> None:
    """Redaction is a pure function — identical input, identical output."""
    assert redact_secret(raw) == redact_secret(raw)


def test_short_secret_full_disclosure_is_current_contract_issue_38() -> None:
    """Pin the issue #38 edge case explicitly: len<=4 reveals the WHOLE value.

    This is the documented-but-flawed contract. We assert it AS-IS so a future
    fix (the #38 decision) is a deliberate, test-visible change — NOT a silent
    drift. Do not "fix" this in this PR.
    """
    for raw in ("", "a", "ab", "abc", "abcd"):
        out = redact_secret(raw)
        # The entire raw value is recoverable as the prefix (the disclosure).
        assert out.startswith(raw)
        assert out == f"{raw}{ELLIPSIS}(len={len(raw)})"
