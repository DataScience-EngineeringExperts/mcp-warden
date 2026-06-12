"""Per-rule catalog helpers + text extraction (RESULT_INSPECTION.md §1, §3-§5).

Split from ``result_inspection.py`` to keep each module focused and under the LOC
budget. Holds the content-block text extractor (§1.1) and the individual rule
evaluators. ``result_inspection.inspect_result`` orchestrates these.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from . import res_rules
from .checks_secret import scan_field

if TYPE_CHECKING:  # avoid a circular import at runtime
    from .result_inspection import InspectionPolicy, ResultFinding

TIER_BLOCK = "block"
TIER_MONITOR = "monitor"
TIER_NOTE = "note"

#: Content-block types not decoded in v0.2 (=> WRD-RES-UNINSPECTABLE note).
_BINARY_TYPES = frozenset({"image", "audio", "blob"})


def _RF(**kwargs: Any) -> "ResultFinding":
    """Construct a ResultFinding (imported lazily to avoid a circular import)."""
    from .result_inspection import ResultFinding

    return ResultFinding(**kwargs)


def extract_blocks(result: dict[str, Any]) -> tuple[list[tuple[int, str]], list[int]]:
    """Extract ``(index, text)`` inspectable blocks + uninspectable indices (§1.1).

    ``text`` -> the text; ``resource`` with embedded text -> that text;
    ``resource`` with a ``uri`` -> the uri; ``image``/``audio``/``blob``/base64
    -> uninspectable; unknown -> uninspectable.

    Args:
        result: The JSON-RPC ``result`` object.

    Returns:
        ``(inspectable, uninspectable_indices)``.
    """
    content = result.get("content")
    inspectable: list[tuple[int, str]] = []
    uninspectable: list[int] = []
    if not isinstance(content, list):
        return inspectable, uninspectable
    for i, block in enumerate(content):
        if not isinstance(block, dict):
            uninspectable.append(i)
            continue
        btype = block.get("type")
        if btype == "text" and isinstance(block.get("text"), str):
            inspectable.append((i, block["text"]))
        elif btype == "resource":
            res = block.get("resource")
            if isinstance(res, dict) and isinstance(res.get("text"), str):
                inspectable.append((i, res["text"]))
            elif isinstance(res, dict) and isinstance(res.get("uri"), str):
                inspectable.append((i, res["uri"]))
            else:
                uninspectable.append(i)
        elif btype in _BINARY_TYPES or "data" in block:
            uninspectable.append(i)
        else:
            uninspectable.append(i)
    return inspectable, uninspectable


def inspect_ansi(text: str, tool: str, idx: int, policy: "InspectionPolicy") -> list["ResultFinding"]:
    """WRD-RES-ANSI (§3.1): any disallowed codepoint, parser-free."""
    bad = res_rules.find_ansi_codepoints(text, policy.expected_output_charset)
    if not bad:
        return []
    sample = ", ".join(f"U+{ord(text[i]):04X}" for i in bad[:5])
    return [
        _RF(
            rule_id="WRD-RES-ANSI",
            severity="high",
            tier=TIER_BLOCK,
            message=f"tools/{tool}: {len(bad)} disallowed control codepoint(s) ({sample})",
            block_index=idx,
        )
    ]


def inspect_secret_echo(text: str, tool: str, idx: int, policy: "InspectionPolicy") -> list["ResultFinding"]:
    """WRD-RES-SECRET-ECHO (§3.2): reuse scan_field; redact; per-tool demote."""
    out: list["ResultFinding"] = []
    demoted = not policy.secret_echo_applies
    for f in scan_field(text, f"tools/{tool}"):
        out.append(
            _RF(
                rule_id="WRD-RES-SECRET-ECHO",
                severity=f.severity,
                tier=TIER_NOTE if demoted else TIER_BLOCK,
                message=(
                    f"tools/{tool}: secret pattern {f.rule_id} echoed in result"
                    + (" (demoted to note by lock)" if demoted else "")
                ),
                snippet=f.snippet,
                block_index=idx,
                sub_rule=f.rule_id,
            )
        )
    return out


def inspect_exfil(text: str, tool: str, idx: int, denylist: tuple[str, ...] | list[str]) -> list["ResultFinding"]:
    """WRD-RES-EXFIL-DOMAIN (§3.3): exact host/subdomain denylist match."""
    hits = res_rules.match_exfil(text, denylist, res_rules.SEED_EXFIL_PATH_QUALIFIED)
    if not hits:
        return []
    return [
        _RF(
            rule_id="WRD-RES-EXFIL-DOMAIN",
            severity="high",
            tier=TIER_BLOCK,
            message=f"tools/{tool}: result references exfil/callback domain(s): {', '.join(hits)}",
            block_index=idx,
        )
    ]


def inspect_exfil_ip_literal(text: str, tool: str, idx: int) -> list["ResultFinding"]:
    """WRD-RES-EXFIL-IP-LITERAL (DR3): raw IP literal in a deny range (SSRF_NETWORKS)."""
    hits = res_rules.match_ip_literals(text, res_rules.SSRF_NETWORKS)
    if not hits:
        return []
    return [
        _RF(
            rule_id="WRD-RES-EXFIL-IP-LITERAL",
            severity="high",
            tier=TIER_BLOCK,
            message=f"tools/{tool}: result references private/loopback/metadata IP literal(s): "
            + ", ".join(f"{ip} ({label})" for ip, label in hits),
            block_index=idx,
        )
    ]


def inspect_url_note(
    text: str,
    tool: str,
    idx: int,
    policy: "InspectionPolicy",
    denylist: tuple[str, ...] | list[str],
) -> list["ResultFinding"]:
    """WRD-RES-URL (§5.1): note non-denylist URLs unless may_return_urls=true."""
    if policy.may_return_urls:
        return []
    urls = res_rules.extract_urls(text)
    if not urls:
        return []
    non_deny = [
        full for host, _path, full in urls if not any(res_rules.host_matches_domain(host, d) for d in denylist)
    ]
    if not non_deny:
        return []
    return [
        _RF(
            rule_id="WRD-RES-URL",
            severity="low",
            tier=TIER_NOTE,
            message=f"tools/{tool}: result contains {len(non_deny)} non-denylisted URL(s)",
            block_index=idx,
        )
    ]


def inspect_inject(text: str, tool: str, idx: int, phrases: tuple[str, ...] | list[str]) -> list["ResultFinding"]:
    """WRD-RES-INJECT-PHRASE (§4.1): narrow exact-phrase, MONITOR tier."""
    hits = res_rules.match_inject_phrases(text, phrases)
    if not hits:
        return []
    return [
        _RF(
            rule_id="WRD-RES-INJECT-PHRASE",
            severity="medium",
            tier=TIER_MONITOR,
            message=f"tools/{tool}: result matched curated injection phrase(s): {', '.join(hits)}",
            block_index=idx,
        )
    ]


def uninspectable_note(tool: str, idx: int) -> "ResultFinding":
    """WRD-RES-UNINSPECTABLE (§5.2): a content block could not be inspected."""
    return _RF(
        rule_id="WRD-RES-UNINSPECTABLE",
        severity="low",
        tier=TIER_NOTE,
        message=f"tools/{tool}: content block {idx} not decoded (binary/unknown)",
        block_index=idx,
    )
