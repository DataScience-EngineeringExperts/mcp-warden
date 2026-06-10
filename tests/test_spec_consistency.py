"""Spec/impl drift guard for docs/SPEC.md (Issue #44).

``docs/SPEC.md`` is the vendor-neutral "MCP Lock Format v1" specification. Its
normative digest/canonicalization constants MUST match what ``hashing.py``
actually implements, or third parties implementing from the spec will produce
locks this codebase rejects (or vice versa).

These tests parse the constants *out of the spec text* and compare them to the
live implementation, so a future edit that drifts either side fails CI. They
deliberately do not re-test hashing correctness (``test_hashing.py`` owns that);
they assert the *spec* and the *implementation* tell the same story.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcp_warden.hashing import (
    SHA256_PREFIX,
    hash_arguments,
    hash_description,
    hash_input_schema,
)

SPEC_MD = Path(__file__).parent.parent / "docs" / "SPEC.md"
SCHEMA_MD = Path(__file__).parent.parent / "docs" / "WARDEN_LOCK_SCHEMA.md"


def _spec_text() -> str:
    return SPEC_MD.read_text(encoding="utf-8")


# --- digest prefix + encoding ------------------------------------------------


def test_spec_digest_prefix_matches_implementation() -> None:
    """The spec's quoted ``sha256:`` prefix must equal ``SHA256_PREFIX``."""
    text = _spec_text()
    # The spec quotes the literal prefix as `sha256:` (without the trailing
    # angle/quote of the worked digests). Require the bare prefix to appear and
    # to equal the implementation constant.
    assert SHA256_PREFIX == "sha256:"
    assert f"`{SHA256_PREFIX}`" in text or f'"{SHA256_PREFIX}"' in text or f'"{SHA256_PREFIX} ' in text


def test_spec_states_implementation_prefix_construction() -> None:
    """The spec's hash construction string must name the impl's exact prefix."""
    text = _spec_text()
    # Spec §5: '"sha256:" + lowercase_hex(SHA256(canon(value)))'
    construction = re.search(
        r'"(sha256:)"\s*\+\s*lowercase_hex\(SHA256\(canon\(value\)\)\)', text
    )
    assert construction is not None, "SPEC.md §5 digest construction string missing/changed"
    assert construction.group(1) == SHA256_PREFIX


def test_spec_hex_length_matches_sha256() -> None:
    """The spec claims 64 hex chars; SHA-256 hexdigest is exactly 64 chars."""
    text = _spec_text()
    assert re.search(r"\b64\b\s+(?:lowercase\s+)?hex", text, re.IGNORECASE), (
        "SPEC.md must state the digest is 64 lowercase hex characters"
    )
    # Cross-check against a live digest from the implementation.
    live = hash_description("anything")
    assert live.startswith(SHA256_PREFIX)
    assert len(live) == len(SHA256_PREFIX) + 64


def test_spec_names_sha256_and_jcs() -> None:
    """The two algorithm anchors must be named verbatim in the spec."""
    text = _spec_text()
    assert "SHA-256" in text, "SPEC.md must name SHA-256 as the hash algorithm"
    assert "RFC 8785" in text, "SPEC.md must cite RFC 8785 (JCS) for canonicalization"
    assert "JCS" in text, "SPEC.md must name JCS"


# --- field-absence rules ------------------------------------------------------


def test_spec_absence_rules_match_implementation() -> None:
    """Spec §5.1 absence rules must match what the field-hash functions do.

    description absent/null -> hash "";  inputSchema -> hash {};  arguments -> [].
    We assert both that the spec *says* this and that the implementation *does*
    it, so the two cannot drift apart.
    """
    text = _spec_text()

    # Spec wording (normative) — empty string / empty object / empty array, each
    # tied to its field-hash name within the same §5.1 bullet (bounded window so
    # a real edit that breaks the pairing fails, but markdown wrapping does not).
    def _paired(field: str, empty_phrase: str) -> bool:
        idx = text.find(f"`{field}`")
        if idx == -1:
            return False
        window = text[idx : idx + 400]
        return empty_phrase in window

    assert _paired("description_hash", '**empty string** `""`')
    assert _paired("input_schema_hash", "**empty object** `{}`")
    assert _paired("arguments_hash", "**empty array** `[]`")

    # Implementation behaviour — null collapses to the documented empties.
    assert hash_description(None) == hash_description("")
    assert hash_input_schema(None) == hash_input_schema({})
    assert hash_arguments(None) == hash_arguments([])


# --- overall_digest exclusions ------------------------------------------------


def test_spec_overall_digest_exclusions() -> None:
    """Spec §8.1 must exclude exactly findings, pin, warden_version.

    This mirrors WARDEN_LOCK_SCHEMA.md §6.1/§10.2 — the reproducibility-critical
    exclusion set. If the spec ever drops one, the digest stops being stable.
    """
    text = _spec_text()
    for excluded in ("findings", "pin", "warden_version"):
        assert re.search(
            rf"exclude[^.]*`{excluded}`|`{excluded}`[^.]*exclud", text, re.IGNORECASE
        ), f"SPEC.md §8.1 must state `{excluded}` is excluded from overall_digest"


# --- cross-link integrity -----------------------------------------------------


def test_schema_doc_points_at_spec() -> None:
    """WARDEN_LOCK_SCHEMA.md §1 must point at SPEC.md as the format source."""
    schema_text = SCHEMA_MD.read_text(encoding="utf-8")
    assert "SPEC.md" in schema_text, "WARDEN_LOCK_SCHEMA.md §1 must reference docs/SPEC.md"
    # Normalize markdown line-wrapping (and blockquote markers) before matching
    # the required §1 pointer phrase.
    flat = re.sub(r"\s+", " ", schema_text.replace(">", " "))
    assert "mcp-warden implementation of it" in flat


def test_spec_under_line_cap() -> None:
    """SPEC.md must stay under the 500-line core-doc cap (Issue #44)."""
    lines = SPEC_MD.read_text(encoding="utf-8").splitlines()
    assert len(lines) < 500, f"SPEC.md is {len(lines)} lines; must be < 500"
