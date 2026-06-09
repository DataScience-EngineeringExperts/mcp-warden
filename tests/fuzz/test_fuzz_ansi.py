"""Property-based fuzzing of the ANSI/control codepoint scanner+stripper.

Issue #17, binding fixes #2 (construction-based, NOT a same-charset round-trip
tautology) and #6 (liveness: a KNOWN-disallowed codepoint IS detected). The
security property is COMPLETENESS: ``strip_ansi`` must leave NO disallowed
codepoint behind, and ``inspect_ansi`` must raise a finding IFF one is present —
never a silent pass-through, never a false strip of allowed text.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mcp_warden import res_catalog, res_rules
from mcp_warden.redact import redact_secret
from mcp_warden.result_inspection import InspectionPolicy

# The charsets are NAMED constants in the spec; use the names, never a hardcoded
# disallowed set. "binary-ok" disables the check entirely (out of scope here).
ANSI_CHARSETS = ("text", "extended")

# --- known-disallowed codepoint pools, per the spec ---------------------------
# strict ("text"): C0 except TAB/LF/CR, DEL, C1, U+2028/U+2029.
# extended: C1 and U+2028/U+2029 are ALLOWED; ESC/C0(except WS)/DEL still bad.

_ALLOWED_C0 = {0x09, 0x0A, 0x0D}
_C0_BAD = [cp for cp in range(0x00, 0x20) if cp not in _ALLOWED_C0]  # incl. ESC 0x1B
_DEL = [0x7F]
_C1 = list(range(0x80, 0xA0))
_LINE_PARA = [0x2028, 0x2029]

# Codepoints that are disallowed under BOTH charsets (safe to splice for either).
DISALLOWED_BOTH = _C0_BAD + _DEL
# Codepoints disallowed under strict but ALLOWED under extended.
STRICT_ONLY = _C1 + _LINE_PARA


def disallowed_for(charset: str) -> list[int]:
    return DISALLOWED_BOTH + (STRICT_ONLY if charset == "text" else [])


def allowed_for(charset: str) -> list[int]:
    """A pool of codepoints guaranteed ALLOWED under ``charset`` (no false strip)."""
    pool = [0x09, 0x0A, 0x0D, 0x20, ord("a"), ord("Z"), ord("0"), 0x2603, 0x1F600]
    if charset == "extended":
        pool = pool + STRICT_ONLY  # C1 + U+2028/29 are fine under extended
    return pool


# --- LIVENESS (#6): a KNOWN-disallowed codepoint spliced in IS detected --------


@st.composite
def text_with_known_bad(draw, charset: str):
    """A string of allowed chars with >=1 KNOWN-disallowed codepoint spliced in.

    Returns ``(text, bad_positions)`` so the test can assert detection is exact.
    """
    allowed = allowed_for(charset)
    base = draw(st.lists(st.sampled_from(allowed), max_size=20))
    bad = draw(st.lists(st.sampled_from(disallowed_for(charset)), min_size=1, max_size=6))
    chars = [chr(cp) for cp in base]
    # Splice each bad codepoint at a random insertion point.
    for cp in bad:
        pos = draw(st.integers(min_value=0, max_value=len(chars)))
        chars.insert(pos, chr(cp))
    return "".join(chars)


@given(charset=st.sampled_from(ANSI_CHARSETS), data=st.data())
def test_known_bad_is_detected_and_stripped(charset: str, data) -> None:
    """find_ansi_codepoints reports >=1 hit; strip removes ALL of them."""
    text = data.draw(text_with_known_bad(charset))
    bad = res_rules.find_ansi_codepoints(text, charset)
    assert bad, "a spliced known-disallowed codepoint must be detected (liveness)"
    out = res_rules.strip_ansi(text, charset)
    # Completeness: NO disallowed codepoint may survive the strip.
    assert res_rules.find_ansi_codepoints(out, charset) == []


@pytest.mark.parametrize("charset", ANSI_CHARSETS)
@pytest.mark.parametrize(
    "text",
    [
        "ok\x1bmore\x07end",  # ESC + BEL spliced into allowed text
        "\x1b[31mred\x1b[0m",  # a literal ANSI SGR colour sequence
        "tab\tok\x00nul",  # NUL is disallowed, TAB is allowed
        "del\x7fhere",  # DEL
    ],
)
def test_known_bad_literals_detected(charset: str, text: str) -> None:
    """Frozen literal known-malicious strings: detected AND fully stripped.

    A plain (non-hypothesis) liveness regression so these exact vectors persist
    even outside the fuzz run (binding #6 + #5 freeze policy).
    """
    assert res_rules.find_ansi_codepoints(text, charset), "known-bad must be detected"
    out = res_rules.strip_ansi(text, charset)
    assert res_rules.find_ansi_codepoints(out, charset) == []


# --- SOUNDNESS: allowed-only text is NEVER flagged or stripped -----------------


@given(charset=st.sampled_from(ANSI_CHARSETS), data=st.data())
def test_allowed_only_no_false_strip(charset: str, data) -> None:
    """A string of ONLY allowed codepoints: no finding, strip is identity."""
    allowed = allowed_for(charset)
    text = "".join(chr(cp) for cp in data.draw(st.lists(st.sampled_from(allowed), max_size=40)))
    assert res_rules.find_ansi_codepoints(text, charset) == []
    assert res_rules.strip_ansi(text, charset) == text


# --- strip is total + idempotent on arbitrary text ----------------------------


@given(text=st.text(max_size=80), charset=st.sampled_from(ANSI_CHARSETS))
def test_strip_is_complete_and_idempotent(text: str, charset: str) -> None:
    """Over ARBITRARY text: strip leaves no residue and is idempotent."""
    once = res_rules.strip_ansi(text, charset)
    assert res_rules.find_ansi_codepoints(once, charset) == []
    assert res_rules.strip_ansi(once, charset) == once


# --- inspect_ansi: a finding IFF a disallowed codepoint is present -------------


def _policy(charset: str) -> InspectionPolicy:
    return InspectionPolicy(expected_output_charset=charset)


@given(text=st.text(max_size=80), charset=st.sampled_from(ANSI_CHARSETS))
def test_inspect_ansi_finding_iff_disallowed(text: str, charset: str) -> None:
    """inspect_ansi yields a finding exactly when find_ansi_codepoints is non-empty."""
    has_bad = bool(res_rules.find_ansi_codepoints(text, charset))
    findings = res_catalog.inspect_ansi(text, tool="t", idx=0, policy=_policy(charset))
    assert bool(findings) == has_bad
    if findings:
        assert findings[0].rule_id == "WRD-RES-ANSI"
        assert findings[0].tier == res_catalog.TIER_BLOCK


# --- COMPOSITION (#2): strip∘redact vs redact∘strip on ANSI-bearing secrets ----


@st.composite
def ansi_bearing_secret(draw):
    """A secret-like token with ANSI/control codes spliced in (charset 'text')."""
    body = draw(st.text(alphabet="abcdefABCDEF0123456789-_", min_size=1, max_size=40))
    chars = list("sk-" + body)
    for cp in draw(st.lists(st.sampled_from(DISALLOWED_BOTH), min_size=1, max_size=4)):
        chars.insert(draw(st.integers(min_value=0, max_value=len(chars))), chr(cp))
    return "".join(chars)


@given(secret=ansi_bearing_secret())
def test_strip_redact_composition_same_security_outcome(secret: str) -> None:
    """strip∘redact and redact∘strip both leave NO ANSI residue (order-independent).

    The composition security outcome the brief asks for is order-independence of
    the ANSI completeness guarantee: whichever order the pipeline applies (strip
    then redact, or redact then strip), the final text contains no disallowed
    codepoint. The redaction's leak-bound itself is NOT re-asserted here — its
    ``…(len=N)`` length encoding inherently embeds digits that collide with a
    secret's tail characters, which makes a substring leak-oracle a false-fail
    (a too-clever oracle, the binding-#4 lesson). The rigorous, correctly-framed
    leak-bound over arbitrary ``str`` lives in test_fuzz_redact.py.
    """
    cs = "text"
    stripped = res_rules.strip_ansi(secret, cs)
    strip_then_redact = redact_secret(stripped)
    redact_then_strip = res_rules.strip_ansi(redact_secret(secret), cs)

    assert res_rules.find_ansi_codepoints(strip_then_redact, cs) == []
    assert res_rules.find_ansi_codepoints(redact_then_strip, cs) == []

    # The revealed prefix is bounded the same way regardless of order: redaction
    # always keeps at most the first 4 codepoints of whatever it redacted.
    assert strip_then_redact.startswith(stripped[:4])
    assert redact_then_strip.startswith(res_rules.strip_ansi(secret[:4], cs))
