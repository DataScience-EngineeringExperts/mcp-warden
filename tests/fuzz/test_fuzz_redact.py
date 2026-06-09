"""Property-based fuzzing of the secret redactor (issue #17, binding #4; #38 floor).

The security property is a LEAK-BOUND: ``redact_secret`` reveals at most the
``min(4, n//2)``-char prefix + a length tag. Properties assert the FORMAT
STRUCTURE (not exact equality against the secret — the ``…`` / ``(len`` literals
can collide with secret content and make an equality oracle false-fail) and the
leak-bound (the post-prefix tail of the secret never appears as a contiguous run
in the output; the template region is recomputable from length alone).

Per the adversarial review: ``redact_secret`` takes ``str``; ``len`` counts
codepoints. The issue #38 short-secret disclosure FLOOR is now FIXED: the revealed
prefix is ``raw[:min(4, n//2)]`` (never more than half the secret), and the length
is bucketed to ``len<=3`` for ``n<=3`` (exact for ``n>=4``). This suite asserts
that NEW contract.
"""

from __future__ import annotations

from hypothesis import example, given
from hypothesis import strategies as st

from mcp_warden.redact import ELLIPSIS, redact_secret


def _expected_prefix(raw: str) -> str:
    """The revealed prefix under the #38 floor: ``raw[:min(4, n//2)]``."""
    return raw[: min(4, len(raw) // 2)]


def _expected_template(raw: str) -> str:
    """The content-independent tail: ``ELLIPSIS + (len-tag)``, a pure fn of len."""
    n = len(raw)
    length_tag = "len<=3" if n <= 3 else f"len={n}"
    return f"{ELLIPSIS}({length_tag})"


@given(raw=st.text(max_size=200))
@example(raw="")  # len 0
@example(raw="a")  # len 1
@example(raw="ab")  # len 2
@example(raw="abc")  # len 3
@example(raw="abcd")  # len 4 — issue #38 boundary (now floored to 2-char prefix)
@example(raw="abcde")  # len 5 — first true redaction
@example(raw="sk-abcdefghij1234567890")  # realistic long secret
@example(raw="key…with(len literals")  # collision chars in the secret body
@example(raw="日本語パスワード鍵")  # multi-byte unicode, len counts codepoints
@example(raw="ab😀cd😀ef")  # astral (surrogate-pair) codepoints
def test_redact_format_structure(raw: str) -> None:
    """Output has the documented ``prefix + ELLIPSIS + (len-tag)`` STRUCTURE.

    Asserted structurally (startswith / contains / endswith), never by exact
    equality, so a secret that itself contains ``…`` or ``(len`` cannot
    false-fail. ``prefix = raw[:min(4, n//2)]`` and N is the CODEPOINT length
    (``len(str)``), consistent with the ANSI detector which also iterates
    codepoints.
    """
    out = redact_secret(raw)
    prefix = _expected_prefix(raw)
    template = _expected_template(raw)
    assert out.startswith(prefix)
    assert ELLIPSIS in out
    assert out.endswith(template)
    # The exact shape is reconstructable from the documented parts.
    assert out == f"{prefix}{template}"


@given(raw=st.text(max_size=200))
@example(raw="abcd")  # #38: len 4 -> prefix is raw[:2], NOT the whole value
@example(raw="abcde")  # the false-fail trap: tail collides with the (len template
@example(raw="passw0rd-secret-value-1234567890")
@example(raw="…(len=5)abcdef")  # secret literally contains the suffix shape
def test_redact_leak_bound(raw: str) -> None:
    """The ONLY secret-derived region of the output is the floored prefix.

    The output is exactly ``prefix + template`` where ``prefix = raw[:min(4,
    n//2)]`` and ``template = ELLIPSIS + f"({tag})"`` is a pure function of
    ``len(raw)`` and carries NO content from ``raw`` beyond its length. So
    everything past the prefix is reconstructable WITHOUT knowing the secret body
    — i.e. at most ``min(4, n//2)`` characters leak, never more than half.

    This is the false-fail-proof statement of the leak-bound: a naive
    ``raw[k:] not in output`` check is wrong because a short tail can legitimately
    appear inside the fixed ``(len...)`` template. We instead assert the template
    region is content-independent (recomputable from length alone).
    """
    out = redact_secret(raw)
    prefix = _expected_prefix(raw)
    template = _expected_template(raw)
    # The output is prefix + a template that depends ONLY on len(raw).
    assert out == prefix + template
    # The template region carries no secret content: recompute it from length
    # alone and confirm it matches the output's tail byte-for-byte.
    after_prefix = out[len(prefix) :]
    assert after_prefix == template
    # Therefore total revealed plaintext == prefix, never more than half the
    # secret and never more than 4 codepoints.
    assert len(prefix) <= len(raw) // 2
    assert len(prefix) <= 4


@given(raw=st.text(min_size=5, max_size=200))
def test_redact_reveals_at_most_four_codepoints(raw: str) -> None:
    """For a genuinely-long secret (len>=5), the prefix is ``raw[:min(4, n//2)]``.

    The portion of the output before the ELLIPSIS is exactly the floored prefix
    — for n in 5..7 that is 2..3 codepoints, for n>=8 it is 4 — never more than 4
    and never more than half the secret.
    """
    out = redact_secret(raw)
    before_ellipsis = out.split(ELLIPSIS, 1)[0]
    assert before_ellipsis == raw[: min(4, len(raw) // 2)]
    assert len(before_ellipsis) <= 4
    assert len(before_ellipsis) <= len(raw) // 2


@given(raw=st.text(max_size=64))
def test_redact_is_deterministic(raw: str) -> None:
    """Redaction is a pure function — identical input, identical output."""
    assert redact_secret(raw) == redact_secret(raw)


def test_short_secret_floor_issue_38_fixed() -> None:
    """Pin the issue #38 FIX: short secrets are NOT fully disclosed.

    For len<=4 the revealed prefix is floored to ``raw[:min(4, n//2)]`` (at most
    half the secret), and for len<=3 the length is bucketed to ``len<=3`` instead
    of an exact count. This is the deliberate, test-visible #38 change.
    """
    # len 0..3: prefix is empty (0//2=0, 1//2=0, 2//2=1, 3//2=1), length bucketed.
    assert redact_secret("") == f"{ELLIPSIS}(len<=3)"
    assert redact_secret("a") == f"{ELLIPSIS}(len<=3)"  # 1//2 = 0 revealed chars
    assert redact_secret("ab") == f"a{ELLIPSIS}(len<=3)"  # 2//2 = 1 char
    assert redact_secret("abc") == f"a{ELLIPSIS}(len<=3)"  # 3//2 = 1 char
    # len 4: exact length, prefix floored to raw[:2] (4//2 = 2), NOT the whole value.
    assert redact_secret("abcd") == f"ab{ELLIPSIS}(len=4)"

    for raw in ("", "a", "ab", "abc", "abcd"):
        out = redact_secret(raw)
        n = len(raw)
        # At most min(4, n//2) chars revealed — the whole value is NOT recoverable
        # whenever the secret is non-trivial (and never more than half).
        revealed = out.split(ELLIPSIS, 1)[0]
        assert revealed == raw[: min(4, n // 2)]
        assert len(revealed) <= n // 2
        # For n<=3 the exact length is bucketed, so the length is not disclosed.
        if n <= 3:
            assert out.endswith("(len<=3)")
        else:
            assert out.endswith(f"(len={n})")
        # The whole secret is never recoverable from the output for n>=2
        # (n=0 trivially empty; n=1 reveals nothing).
        if n >= 2:
            assert not out.startswith(raw)
