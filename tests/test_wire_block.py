"""Unit tests for on-the-wire block synthesis (GUARD_PROXY.md §7)."""

from __future__ import annotations

from mcp_warden import wire_block
from mcp_warden.result_inspection import InspectionPolicy, ResultFinding

FAKE_GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def test_error_response_shape():
    err = wire_block.error_response(
        7, stage="response", rule="WRD-RES-EXFIL-DOMAIN", tool="exfil_tool", reason="hit ngrok.io"
    )
    assert err["jsonrpc"] == "2.0"
    assert err["id"] == 7
    e = err["error"]
    assert e["code"] == wire_block.WARDEN_ERROR_CODE == -32001
    assert e["data"]["warden"] is True
    assert e["data"]["stage"] == "response"
    assert e["data"]["rule"] == "WRD-RES-EXFIL-DOMAIN"
    assert e["data"]["tool"] == "exfil_tool"


def test_error_response_redacts_secret_in_reason():
    # The reason a caller passes for a secret echo must already be redacted; this
    # asserts the wire object never surfaces a raw secret if callers redact (they do).
    redacted = "ghp_…(len=40)"
    err = wire_block.error_response(1, stage="response", rule="WRD-RES-SECRET-ECHO", tool="t", reason=redacted)
    assert FAKE_GH not in str(err)
    assert "ghp_…(len=40)" in err["error"]["data"]["reason"]


def test_block_mode_mapping():
    assert wire_block.block_mode_for("WRD-RES-ANSI", redact_secret_echo=False) == wire_block.MODE_REDACT
    assert wire_block.block_mode_for("WRD-RES-EXFIL-DOMAIN", redact_secret_echo=False) == wire_block.MODE_ERROR
    assert wire_block.block_mode_for("WRD-RES-SECRET-ECHO", redact_secret_echo=False) == wire_block.MODE_ERROR
    assert wire_block.block_mode_for("WRD-RES-SECRET-ECHO", redact_secret_echo=True) == wire_block.MODE_REDACT


def test_redacted_result_strips_ansi_and_marks_modified():
    original = {"content": [{"type": "text", "text": "\x1b[2Jhello\x07 world"}], "isError": False}
    finding = ResultFinding(rule_id="WRD-RES-ANSI", severity="high", tier="block", message="m", block_index=0)
    out = wire_block.redacted_result(5, original, [finding], InspectionPolicy(), redact_secret_echo=False)
    assert out["id"] == 5
    result = out["result"]
    assert result["_meta"]["warden"]["modified"] is True
    assert "WRD-RES-ANSI" in result["_meta"]["warden"]["rules"]
    text = result["content"][0]["text"]
    assert "\x1b" not in text and "\x07" not in text
    assert text == "[2Jhello world"  # rest of content intact


def test_redacted_result_redacts_secret_in_place():
    original = {"content": [{"type": "text", "text": f"token={FAKE_GH} end"}], "isError": False}
    finding = ResultFinding(rule_id="WRD-RES-SECRET-ECHO", severity="critical", tier="block", message="m", block_index=0)
    out = wire_block.redacted_result(9, original, [finding], InspectionPolicy(), redact_secret_echo=True)
    text = out["result"]["content"][0]["text"]
    assert FAKE_GH not in text
    assert "ghp_" in text and "(len=40)" in text
    assert "WRD-RES-SECRET-ECHO" in out["result"]["_meta"]["warden"]["rules"]
