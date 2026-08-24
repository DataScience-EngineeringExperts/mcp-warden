"""Static MCP auth-posture audit tests (WRD-AUTH-*) — DSE-1258.

Covers the pure ``audit_config``/``audit_server`` helpers (each rule, and the
clean paths that must NOT flag) plus the ``auth audit`` CLI (exit codes,
JSON/SARIF, fail-closed on malformed config).
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from mcp_warden.auth_audit import AuthAuditError, audit_config, audit_server
from mcp_warden.cli import app

runner = CliRunner()


def _rules(findings):
    return {f.rule_id for f in findings}


def test_remote_http_without_auth_flags_noauth_and_plaintext():
    findings = audit_server("remote", {"url": "http://mcp.example.com/sse"})
    rules = _rules(findings)
    assert "WRD-AUTH-NOAUTH" in rules
    assert "WRD-AUTH-PLAINTEXT-HTTP" in rules


def test_https_with_auth_header_is_clean():
    server = {"url": "https://mcp.example.com/sse", "headers": {"Authorization": "${MCP_TOKEN}"}}
    assert audit_server("ok", server) == []


def test_localhost_without_auth_is_not_flagged():
    # A stdio-style local server reachable only on loopback is not an exposure.
    assert audit_server("local", {"url": "http://127.0.0.1:8080/mcp"}) == []


def test_literal_token_in_headers_flagged_high():
    server = {"url": "https://mcp.example.com", "headers": {"Authorization": "Bearer sk-abcdefghijklmnopqrstuvwx"}}
    findings = audit_server("lit", server)
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(findings)
    # The credential literal must be redacted in every snippet.
    assert all("sk-abcdefghijklmnopqrstuvwx" not in f.snippet for f in findings)


def test_env_secret_reference_is_clean_literal_is_not():
    ref = {"url": "https://x.example.com", "env": {"API_TOKEN": "${API_TOKEN}"}}
    assert audit_server("ref", ref) == []
    lit = {"url": "https://x.example.com", "env": {"API_TOKEN": "ghp_" + "a" * 36}}
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(audit_server("lit", lit))


def test_stdio_local_command_server_no_findings():
    # No url + no remote transport => a local stdio server, nothing to flag.
    assert audit_server("fs", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}) == []


def test_audit_config_iterates_all_servers_sorted():
    doc = {
        "mcpServers": {
            "a": {"url": "http://a.example.com/sse"},
            "b": {"url": "https://b.example.com", "headers": {"Authorization": "${T}"}},
        }
    }
    findings = audit_config(doc)
    assert all(f.target.startswith("mcpServers/") for f in findings)
    assert findings == sorted(findings, key=lambda f: (f.target, f.rule_id, f.snippet))


def test_audit_config_ignores_non_object_shapes():
    assert audit_config({"mcpServers": "nope"}) == []
    assert audit_config({}) == []


def test_cli_audit_clean_exit_zero(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"ok": {"url": "https://x.example.com", "headers": {"Authorization": "${T}"}}}}))
    result = runner.invoke(app, ["auth", "audit", str(cfg)])
    assert result.exit_code == 0, result.output


def test_cli_audit_findings_exit_one(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"bad": {"url": "http://x.example.com/sse"}}}))
    result = runner.invoke(app, ["auth", "audit", str(cfg)])
    assert result.exit_code == 1, result.output


def test_cli_audit_json_output(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"bad": {"url": "http://x.example.com/sse"}}}))
    result = runner.invoke(app, ["auth", "audit", str(cfg), "--json"])
    assert result.exit_code == 1
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert any("WRD-AUTH-" in line for line in lines)


def test_cli_audit_malformed_config_exit_two(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{ not json")
    result = runner.invoke(app, ["auth", "audit", str(cfg)])
    assert result.exit_code == 2


def test_bearer_prefixed_reference_is_not_a_literal():
    # `Bearer ${TOKEN}` is the single most common CORRECT shape for an
    # Authorization header. Flagging it as a committed credential is the
    # false positive that gets the whole gate switched off. Found by
    # dogfooding against a real config.
    for good in ("Bearer ${GMAIL_TOKEN}", "bearer $GMAIL_TOKEN", "Token {{ secret }}", "${T}"):
        server = {"url": "https://x.example.com", "headers": {"Authorization": good}}
        assert audit_server("ok", server) == [], f"false positive on {good!r}"


def test_literal_next_to_a_reference_is_still_flagged():
    # The permissive path must not become a bypass: a real literal sitting
    # beside a reference is still a committed credential.
    server = {"url": "https://x.example.com", "headers": {"Authorization": "Bearer sk-abcdefghijklmnopqrst ${T}"}}
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(audit_server("mixed", server))


def test_json_output_is_one_line_per_finding(tmp_path):
    # `--json` is a machine contract. rich wraps at 80 cols even when piped,
    # which silently produced invalid JSONL; every emitted line must parse.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "bad": {
                        "url": "http://averyveryverylonghostname.example.com/sse/path/that/is/long",
                        "headers": {"Authorization": "Bearer sk-abcdefghijklmnopqrstuvwxyz012345"},
                    }
                }
            }
        )
    )
    result = runner.invoke(app, ["auth", "audit", str(cfg), "--json"])
    assert result.exit_code == 1
    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
    assert lines, "expected JSONL output"
    for ln in lines:
        json.loads(ln)  # raises if rich wrapped the line


def test_url_userinfo_credential_flagged_and_never_echoed():
    # A credential in the URL authority must be flagged AND stripped from every
    # snippet — the audit must not widen exposure of what it reports.
    server = {"url": "https://svcuser:s3cr3t-token@mcp.example.com/sse"}
    findings = audit_server("userinfo", server)
    assert "WRD-AUTH-URL-CREDENTIAL" in _rules(findings)
    assert all("s3cr3t-token" not in f.snippet for f in findings)
    assert all("s3cr3t-token" not in f.message for f in findings)


def test_userinfo_host_parsing_does_not_confuse_locality():
    # '@' in the authority must not make host detection read the userinfo as host.
    from mcp_warden.auth_audit import _host_of, _safe_url

    assert _host_of("https://user:pw@real.example.com/x") == "real.example.com"
    assert _safe_url("https://user:pw@real.example.com/x") == "https://real.example.com"
    assert _safe_url("real.example.com") == "real.example.com"


def test_non_dict_headers_and_non_string_values_are_ignored():
    # Malformed shapes must be skipped, never crash the audit.
    from mcp_warden.auth_audit import _scan_mapping_for_literals

    assert _scan_mapping_for_literals("not-a-dict", "t") == []  # type: ignore[arg-type]
    assert _scan_mapping_for_literals({"token": 12345, "empty": ""}, "t") == []


def test_short_credential_literal_is_fully_masked():
    server = {"url": "https://x.example.com", "headers": {"Authorization": "abc"}}
    findings = audit_server("short", server)
    assert any(f.snippet == "***" for f in findings)


def test_unreadable_config_path_raises(tmp_path):
    import pytest

    from mcp_warden.auth_audit import audit_path

    with pytest.raises(AuthAuditError):
        audit_path(tmp_path / "does-not-exist.json")


def test_transport_only_remote_without_url_flags_noauth():
    # A streamable-http server declared by transport type, no url, no auth.
    findings = audit_server("ws", {"type": "streamable-http"})
    assert "WRD-AUTH-NOAUTH" in _rules(findings)


def test_cli_audit_sarif_output(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"bad": {"url": "http://x.example.com/sse"}}}))
    sarif = tmp_path / "out.sarif"
    result = runner.invoke(app, ["auth", "audit", str(cfg), "--sarif", str(sarif)])
    assert result.exit_code == 1
    doc = json.loads(sarif.read_text())
    assert doc["runs"][0]["results"], "SARIF must carry the findings"


def test_audit_path_raises_on_non_object(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text("[1, 2, 3]")
    import pytest

    from mcp_warden.auth_audit import audit_path

    with pytest.raises(AuthAuditError):
        audit_path(cfg)
