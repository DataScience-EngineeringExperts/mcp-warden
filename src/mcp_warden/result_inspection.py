"""Shared result-inspection catalog (RESULT_INSPECTION.md) — ONE source of truth.

This is the single public entrypoint of the ``WRD-RES-*`` catalog, imported by
BOTH runners (``guard`` live proxy and ``inspect`` offline analyzer). A rule that
fires here fires identically in both — non-negotiable #1.

Tier partition (fixed, §2):
  * BLOCK-deterministic: ``WRD-RES-ANSI``, ``WRD-RES-SECRET-ECHO``,
    ``WRD-RES-EXFIL-DOMAIN``, ``WRD-RES-EXFIL-IP-LITERAL``.
  * MONITOR-fuzzy: ``WRD-RES-INJECT-PHRASE`` (narrow curated exact-phrase).
  * Notes (never block): ``WRD-RES-URL``, ``WRD-RES-UNINSPECTABLE``,
    ``WRD-RES-FRAME-ERROR``, ``WRD-RES-LOCK-INVALID``.

The per-rule evaluators + text extraction live in ``res_catalog.py``; this module
owns the public types (``ResultFinding``, ``InspectionPolicy``), the lock loader,
and the orchestration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from . import res_catalog
from .models import WardenLock

logger = logging.getLogger("mcp_warden.result_inspection")

TIER_BLOCK = "block"
TIER_MONITOR = "monitor"
TIER_NOTE = "note"

BLOCK_RULES = frozenset(
    {"WRD-RES-ANSI", "WRD-RES-SECRET-ECHO", "WRD-RES-EXFIL-DOMAIN", "WRD-RES-EXFIL-IP-LITERAL"}
)

#: Severity -> SARIF level (CHECKS.md §2), mirrored for WRD-RES-*.
_SEVERITY_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

_VALID_CHARSETS = frozenset({"text", "extended", "binary-ok"})


def severity_to_level(severity: str) -> str:
    """Map a severity to a SARIF level (defaults to ``warning``)."""
    return _SEVERITY_LEVEL.get(severity, "warning")


@dataclass(frozen=True)
class ResultFinding:
    """One WRD-RES-* finding on a tool result (or a robustness note).

    Attributes:
        rule_id: The ``WRD-RES-*`` id (the SARIF ruleId verbatim).
        severity: ``critical|high|medium|low``.
        tier: ``block|monitor|note``.
        message: Human-readable, secret-free description.
        snippet: Redacted evidence (empty for notes that carry none).
        block_index: The content-block index the finding points at (or ``-1``).
        sub_rule: The underlying id (e.g. the ``WRD-SEC-*`` for a secret echo).
        action: Set by the runner: ``passed|shadowed|blocked|modified|reported``.
        direction: ``s2c|c2s`` (set by the runner).
        rpc_id: The JSON-RPC id of the frame (set by the runner).
        tool: The tool name (set by the runner).
    """

    rule_id: str
    severity: str
    tier: str
    message: str
    snippet: str = ""
    block_index: int = -1
    sub_rule: str = ""
    action: str = "passed"
    direction: str = "s2c"
    rpc_id: Any = None
    tool: str = ""

    @property
    def level(self) -> str:
        """SARIF level for this finding's severity."""
        return severity_to_level(self.severity)

    def blocks(self) -> bool:
        """Whether this finding's tier is allowed to block at all."""
        return self.tier == TIER_BLOCK


@dataclass
class InspectionPolicy:
    """Effective per-tool inspection policy (WARDEN_LOCK_SCHEMA.md §11).

    Fail-safe defaults (absent => maximum protection): strict charset, URL notes
    on, secret-echo BLOCK-tier.

    Attributes:
        expected_output_charset: ``text|extended|binary-ok``.
        may_return_urls: When True, suppress the ``WRD-RES-URL`` note.
        secret_echo_applies: When False, demote ``WRD-RES-SECRET-ECHO`` to a note.
        lock_notes: Any ``WRD-RES-LOCK-INVALID`` notes raised while reading.
    """

    expected_output_charset: str = "text"
    may_return_urls: bool = False
    secret_echo_applies: bool = True
    lock_notes: list[ResultFinding] = field(default_factory=list)


def _lock_invalid(message: str) -> ResultFinding:
    """Build a low ``WRD-RES-LOCK-INVALID`` note."""
    return ResultFinding(rule_id="WRD-RES-LOCK-INVALID", severity="low", tier=TIER_NOTE, message=message)


def policy_for_tool(lock: WardenLock | None, tool_name: str) -> InspectionPolicy:
    """Resolve the effective :class:`InspectionPolicy` for a tool from a lock.

    Absent lock, absent tool, or absent ``inspection`` block yield fail-safe
    defaults. Invalid values fall back to fail-safe + a ``WRD-RES-LOCK-INVALID``
    note (§11.3).

    Args:
        lock: The loaded ``warden.lock`` (or ``None``).
        tool_name: The tool the result belongs to.

    Returns:
        The effective :class:`InspectionPolicy`.
    """
    pol = InspectionPolicy()
    if lock is None:
        return pol
    entry = next((t for t in lock.tools if t.name == tool_name), None)
    if entry is None:
        return pol
    insp = getattr(entry, "inspection", None)
    if insp is None:
        return pol
    if not isinstance(insp, dict):
        pol.lock_notes.append(_lock_invalid(f"tools/{tool_name}: inspection is not an object"))
        return pol

    charset = insp.get("expected_output_charset", "text")
    if charset in _VALID_CHARSETS:
        pol.expected_output_charset = charset
    else:
        pol.lock_notes.append(
            _lock_invalid(f"tools/{tool_name}: invalid expected_output_charset {charset!r}; using 'text'")
        )

    mru = insp.get("may_return_urls", False)
    if isinstance(mru, bool):
        pol.may_return_urls = mru
    else:
        pol.lock_notes.append(_lock_invalid(f"tools/{tool_name}: may_return_urls must be bool; using false"))

    sea = insp.get("secret_echo_applies", True)
    if isinstance(sea, bool):
        pol.secret_echo_applies = sea
    else:
        pol.lock_notes.append(_lock_invalid(f"tools/{tool_name}: secret_echo_applies must be bool; using true"))
    return pol


def inspect_result(
    result: dict[str, Any],
    tool: str,
    policy: InspectionPolicy,
    *,
    exfil_denylist: tuple[str, ...] | list[str],
    inject_phrases: tuple[str, ...] | list[str],
) -> list[ResultFinding]:
    """Run the full ``WRD-RES-*`` catalog over one ``tools/call`` result.

    The ONE code path shared by ``guard`` and ``inspect``. Pure: no IO, no
    blocking decision (the runner decides blocking from findings + flags).

    Args:
        result: The JSON-RPC ``result`` object (parsed).
        tool: The tool name (for messages + per-tool precision).
        policy: The effective per-tool :class:`InspectionPolicy`.
        exfil_denylist: Merged seed+org bare-host exfil denylist.
        inject_phrases: Merged seed+org exact injection phrases.

    Returns:
        The list of :class:`ResultFinding`, in deterministic order. Findings carry
        no ``direction``/``rpc_id``/``action`` (the runner stamps those).
    """
    findings: list[ResultFinding] = list(policy.lock_notes)
    inspectable, uninspectable = res_catalog.extract_blocks(result)

    for idx in uninspectable:
        findings.append(res_catalog.uninspectable_note(tool, idx))

    for idx, text in inspectable:
        findings.extend(res_catalog.inspect_ansi(text, tool, idx, policy))
        findings.extend(res_catalog.inspect_secret_echo(text, tool, idx, policy))
        findings.extend(res_catalog.inspect_exfil(text, tool, idx, exfil_denylist))
        findings.extend(res_catalog.inspect_exfil_ip_literal(text, tool, idx))
        findings.extend(res_catalog.inspect_url_note(text, tool, idx, policy, exfil_denylist))
        findings.extend(res_catalog.inspect_inject(text, tool, idx, inject_phrases))

    return findings
