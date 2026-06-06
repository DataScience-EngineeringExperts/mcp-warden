"""On-the-wire block synthesis (GUARD_PROXY.md §7) — the normative wire behavior.

When ``guard`` blocks, the client MUST receive a well-formed JSON-RPC frame so
its session never hangs. Two block shapes:

  * **error-response** (§7.1/§7.2b/§7.3): a JSON-RPC error for the frame ``id``,
    reserved code ``-32001``, ``data.warden: true`` + ``stage`` + ``rule``.
  * **redacted-content** (§7.2a): a modified ``result`` with the offending content
    neutralized in place and ``_meta.warden.modified: true``.

Per-category default mapping (§7.2, normative):
  WRD-RES-ANSI        -> redacted-content (strip control chars)
  WRD-RES-EXFIL-DOMAIN-> error-replacement
  WRD-RES-SECRET-ECHO -> error-replacement, OR redacted-content if --redact-secret-echo
  WRD-RES-INJECT-PHRASE -> error-replacement (only if opted in; MONITOR otherwise)

Every secret in a ``reason`` is redacted (§7.4) — handled upstream: the finding
``snippet`` is already redacted by ``checks_secret``/``redact``.
"""

from __future__ import annotations

import logging
from typing import Any

from . import res_rules
from .result_inspection import InspectionPolicy, ResultFinding

logger = logging.getLogger("mcp_warden.wire_block")

#: mcp-warden reserved JSON-RPC error code (§7.4).
WARDEN_ERROR_CODE = -32001

MODE_ERROR = "error"
MODE_REDACT = "redact"


def block_mode_for(rule_id: str, *, redact_secret_echo: bool) -> str:
    """Return the default block sub-mode for a rule (§7.2 normative mapping).

    Args:
        rule_id: The ``WRD-RES-*`` id.
        redact_secret_echo: Whether ``--redact-secret-echo`` is set.

    Returns:
        ``MODE_REDACT`` or ``MODE_ERROR``.
    """
    if rule_id == "WRD-RES-ANSI":
        return MODE_REDACT
    if rule_id == "WRD-RES-SECRET-ECHO":
        return MODE_REDACT if redact_secret_echo else MODE_ERROR
    return MODE_ERROR  # EXFIL-DOMAIN, INJECT-PHRASE (opt-in), list-changed


def error_response(
    rpc_id: Any,
    *,
    stage: str,
    rule: str,
    tool: str,
    reason: str,
    message: str | None = None,
) -> dict[str, Any]:
    """Build a warden JSON-RPC error response (§7.1/§7.2b/§7.3).

    Args:
        rpc_id: The id of the blocked request/response.
        stage: ``request|response|list_changed``.
        rule: The deny code (``WRD-RES-*`` or ``POL-*``).
        tool: The tool name (or ``""``).
        reason: A secret-free, redacted explanation.
        message: Optional top-level message; a default is derived from ``stage``.

    Returns:
        A complete JSON-RPC error object.
    """
    default_msg = {
        "request": "mcp-warden: tools/call blocked by argument policy",
        "response": "mcp-warden: tools/call result blocked by inspection",
        "list_changed": "mcp-warden: tool surface diverged from warden.lock",
    }.get(stage, "mcp-warden: blocked")
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": WARDEN_ERROR_CODE,
            "message": message or default_msg,
            "data": {
                "warden": True,
                "stage": stage,
                "rule": rule,
                "tool": tool,
                "reason": reason,
            },
        },
    }


def redacted_result(
    rpc_id: Any,
    original_result: dict[str, Any],
    findings: list[ResultFinding],
    policy: InspectionPolicy,
    *,
    redact_secret_echo: bool,
) -> dict[str, Any]:
    """Build a modified ``result`` frame with offending content neutralized (§7.2a).

    ANSI: strip disallowed codepoints from text blocks. Secret-echo (only when
    ``redact_secret_echo``): replace each matched secret with its redaction. The
    result shape is preserved; ``_meta.warden.modified`` records the change.

    Args:
        rpc_id: The response id.
        original_result: The server's original ``result`` object.
        findings: The findings driving the redaction (already filtered to the
            rules being redacted).
        policy: The effective per-tool policy (for the ANSI charset).
        redact_secret_echo: Whether secret echoes are redacted in place.

    Returns:
        A new JSON-RPC response object carrying the modified result.
    """
    import copy

    result = copy.deepcopy(original_result)
    content = result.get("content")
    rules_applied: list[str] = []

    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            text = _block_text(block)
            if text is None:
                continue
            new_text = text
            if any(f.rule_id == "WRD-RES-ANSI" for f in findings):
                stripped = res_rules.strip_ansi(new_text, policy.expected_output_charset)
                if stripped != new_text:
                    new_text = stripped
                    if "WRD-RES-ANSI" not in rules_applied:
                        rules_applied.append("WRD-RES-ANSI")
            if redact_secret_echo and any(f.rule_id == "WRD-RES-SECRET-ECHO" for f in findings):
                redacted = _redact_secrets_in_text(new_text)
                if redacted != new_text:
                    new_text = redacted
                    if "WRD-RES-SECRET-ECHO" not in rules_applied:
                        rules_applied.append("WRD-RES-SECRET-ECHO")
            _set_block_text(block, new_text)

    meta = result.get("_meta")
    if not isinstance(meta, dict):
        meta = {}
    meta["warden"] = {"modified": True, "rules": rules_applied or sorted({f.rule_id for f in findings})}
    result["_meta"] = meta
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _block_text(block: dict[str, Any]) -> str | None:
    """Return the inspectable text of a content block, or None."""
    if block.get("type") == "text" and isinstance(block.get("text"), str):
        return block["text"]
    if block.get("type") == "resource":
        res = block.get("resource")
        if isinstance(res, dict) and isinstance(res.get("text"), str):
            return res["text"]
    return None


def _set_block_text(block: dict[str, Any], text: str) -> None:
    """Write text back into a content block in the same shape it was read."""
    if block.get("type") == "text":
        block["text"] = text
    elif block.get("type") == "resource" and isinstance(block.get("resource"), dict):
        block["resource"]["text"] = text


def _redact_secrets_in_text(text: str) -> str:
    """Replace each matched secret substring with its redaction (in place).

    Reuses the same ``WRD-SEC-*`` vendor patterns as ``checks_secret`` so the
    redaction targets exactly what the detector matched.
    """
    from .checks_secret import _VENDOR_PATTERNS  # reuse the one pattern source
    from .redact import redact_secret

    out = text
    for _rule_id, _sev, pattern in _VENDOR_PATTERNS:
        out = pattern.sub(lambda m: redact_secret(m.group(0)), out)
    return out
