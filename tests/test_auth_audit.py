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


def test_reference_forms_found_in_a_real_public_corpus():
    # Every shape here appeared in a 463-config public scan and was WRONGLY
    # reported as a committed credential. Each names where a secret lives; none
    # carries one.
    for good in (
        "${GITHUB_TOKEN:-}",            # shell default-expansion
        "${API_KEY:?required}",         # shell error-if-unset
        "op://Private/GitHub/token",    # 1Password reference URI
        "vault://secret/data/app#key",  # Vault reference URI
        "%USERPROFILE_TOKEN%",          # Windows env expansion
        "~/.config/app/keys.json",      # path to a credential file
        "/Users/me/.secrets/token",     # absolute path
    ):
        server = {"url": "https://x.example.com", "headers": {"Authorization": good}}
        assert audit_server("ok", server) == [], f"false positive on {good!r}"


def test_placeholders_are_low_severity_not_committed_credentials():
    # 74% of TOKEN-IN-CONFIG hits in the public corpus were template fill-me-ins.
    # They are a real (low) finding, but calling them committed credentials is
    # false and is the noise that gets a gate switched off.
    for ph in ("YOUR KEY GOES HERE", "<your-api-key>", "xxx", "changeme", "basic", "your_github_token", "api-key"):
        server = {"url": "https://x.example.com", "headers": {"Authorization": ph}}
        rules = _rules(audit_server("ph", server))
        assert "WRD-AUTH-PLACEHOLDER-SECRET" in rules, f"{ph!r} should be a placeholder"
        assert "WRD-AUTH-TOKEN-IN-CONFIG" not in rules, f"{ph!r} wrongly called a credential"


def test_a_real_opaque_credential_is_still_high_severity():
    # The placeholder path must not become a bypass for real secrets.
    server = {"url": "https://x.example.com", "headers": {"Authorization": "aB3xK9mQ7pL2wR5tY8vN4jH6"}}
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(audit_server("real", server))


def test_short_real_secret_shapes_are_not_downgraded_to_placeholder():
    # The short-bare-word rule must not swallow a short REAL secret: a digit or any
    # punctuation beyond -/_ takes the value out of the "scheme word" class.
    for real in ("hunter2!", "p@ss-w0rd", "Xk9#mQ2p", "a1b2c3d4e5", "t0ken", "p@ssword"):
        server = {"url": "https://x.example.com", "headers": {"Authorization": real}}
        rules = _rules(audit_server("real", server))
        assert "WRD-AUTH-TOKEN-IN-CONFIG" in rules, f"{real!r} wrongly downgraded"
        assert "WRD-AUTH-PLACEHOLDER-SECRET" not in rules


def test_placeholder_words_match_whole_tokens_not_substrings():
    # `here` must not match inside `adherence`, `fill` not inside `fillmore`.
    for real in ("adherenceTokenValue", "fillmoreStreetPass", "nonesuchCredential", "exampledotcomPass"):
        server = {"url": "https://x.example.com", "headers": {"Authorization": real}}
        rules = _rules(audit_server("sub", server))
        assert "WRD-AUTH-TOKEN-IN-CONFIG" in rules, f"{real!r} wrongly downgraded"
    # ...while the same words as WHOLE tokens are placeholders.
    for ph in ("goes-here", "fill-me-in", "my-api-key", "change_me", "Bearer <token>", "sk-..."):
        server = {"url": "https://x.example.com", "headers": {"Authorization": ph}}
        rules = _rules(audit_server("ph", server))
        assert "WRD-AUTH-PLACEHOLDER-SECRET" in rules, f"{ph!r} should be a placeholder"


def test_vendor_shaped_secret_is_never_downgraded_even_if_it_contains_placeholder_words():
    # A real ghp_ token that happens to spell `example` is still a committed
    # credential: the vendor scan is the guard, the placeholder heuristic cannot
    # be used to hide a secret.
    ghp = "ghp_" + "example" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O"
    assert len(ghp) == 4 + 36
    server = {"url": "https://x.example.com", "headers": {"Authorization": ghp}}
    rules = _rules(audit_server("ghp", server))
    assert "WRD-SEC-GITHUB" in rules
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in rules
    assert "WRD-AUTH-PLACEHOLDER-SECRET" not in rules


def test_angle_slot_beside_a_real_literal_is_still_a_credential():
    server = {"url": "https://x.example.com", "headers": {"Authorization": "Bearer <token> aB3xK9mQ7pL2wR5t"}}
    rules = _rules(audit_server("mixed", server))
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in rules
    assert "WRD-AUTH-PLACEHOLDER-SECRET" not in rules


def test_base64_blob_starting_with_slash_is_not_a_credential_path():
    # `/9j/4AAQ…` is a literal (one directory segment), not a path to a key file.
    for blob in ("/9j/4AAQSkZJRgABAQAAAQABAAD", "/abc+def=="):
        server = {"url": "https://x.example.com", "headers": {"Authorization": blob}}
        assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(audit_server("b64", server)), blob
    # ...while a real credential-file path (>= 2 directories) is a reference.
    server = {"url": "https://x.example.com", "headers": {"Authorization": "/etc/app/secrets/token"}}
    assert audit_server("path", server) == []


def test_placeholder_finding_is_redacted_like_every_other_snippet():
    server = {"url": "https://x.example.com", "headers": {"Authorization": "YOUR-KEY-GOES-HERE"}}
    (f,) = [x for x in audit_server("ph", server) if x.rule_id == "WRD-AUTH-PLACEHOLDER-SECRET"]
    assert f.severity == "low"
    assert "YOUR-KEY-GOES-HERE" not in f.snippet and "…" in f.snippet


# Sub-threshold literals: NOT caught by the vendor patterns or the entropy guard
# (24 chars at >= 4.0 bits/char), so every assertion below exercises the
# placeholder/reference logic itself and fails on the pre-fix code.
LIT = "9f8e7d6c5b4a"                    # 12-char lowercase hex
LIT24 = "9f8e7d6c5b4a3e2d1c0b9a8f"      # 24-char lowercase hex, H ~ 3.92 bits/char
# Entropy-path control: 24 mixed-case alnum, H >= 4.0 — caught by checks_secret.
REAL = "aB3xK9mQ7pL2wR5tY8vN4jH6"


def _auth(value):
    return _rules(audit_server("s", {"url": "https://x.example.com", "headers": {"Authorization": value}}))


def _is_high(value):
    rules = _auth(value)
    return "WRD-AUTH-TOKEN-IN-CONFIG" in rules and "WRD-AUTH-PLACEHOLDER-SECRET" not in rules


def _is_low(value):
    return "WRD-AUTH-PLACEHOLDER-SECRET" in _auth(value)


def test_f1_shell_default_is_a_literal_unless_empty_reference_or_placeholder():
    # CSO F1/N1/N2: `${VAR:-D}` substitutes D — a secret hidden as the default is a
    # credential, at any nesting depth, and `:=` is an assignment form too.
    assert _is_high("${TOKEN:-" + LIT + "}")
    assert _is_high("${TOKEN-" + LIT + "}")
    assert _is_high("${TOKEN:+" + LIT + "}")
    assert _is_high("${TOKEN:=hunter2!}")
    assert _is_high("${T:-${U:-hunter2!}}")
    assert _is_high("${T:-${U:-" + LIT + "}}")
    assert _is_high("Bearer ${TOKEN:-hunter2!}")
    for ref in ("${TOKEN:-}", "${TOKEN:-${OTHER}}", "${TOKEN:-$OTHER}", "${TOKEN:?required}",
                "${TOKEN?required}", "${T:-${U:-}}", "${T:-${U:-changeme}}"):
        assert not _auth(ref), ref
    assert not _auth("${TOKEN:-changeme}")  # placeholder default -> still a reference


def test_f2_placeholder_needs_every_token_to_be_filler_and_has_a_hard_floor():
    # CSO F2: one placeholder word does not launder the rest of the value.
    assert _is_high("example-" + LIT)             # strong token + a real one
    assert _is_high("your-key-" + LIT)
    assert _is_high("placeholder" + LIT)
    assert _is_high("YOUR KEY GOES HERE 12345 " + LIT)
    # CSO N5: the floor applies only when a non-filler token is present — an all-
    # filler value stays a placeholder however long or digit-laden it is.
    assert _is_low("your-api-key-goes-here-12345")
    assert _is_low("YOUR_API_KEY_1234567890")
    assert _is_low("your-github-token")
    assert _is_low("YOUR KEY GOES HERE")


def test_f3_only_a_closed_set_of_scheme_words_may_sit_beside_a_reference():
    # CSO F3: a short alphabetic SECRET beside a reference is a literal.
    assert _is_high("correcthorse ${TOKEN}")
    assert _is_high("hunter ${TOKEN}")
    assert _is_high("correcthorse <token>")
    for scheme in ("Bearer", "Token", "Basic", "ApiKey", "Negotiate", "Digest", "bearer"):
        assert not _auth(scheme + " ${TOKEN}"), scheme
        assert _is_low(scheme + " <token>"), scheme


def test_f4_short_bare_words_are_placeholders_only_from_a_closed_allowlist():
    # CSO F4/N4: the downgrade is an allowlist of scheme/type slots. Everything else
    # — default and dictionary passwords included — is a working secret.
    for cred in ("changeit", "raspberry", "postgres", "grafana", "elastic", "letmein", "guest",
                 "toor", "admin", "password", "root", "secret", "test", "qwerty", "welcome",
                 "dragon", "iloveyou", "hunter", "monkey"):
        assert _is_high(cred), cred
    for slot in ("basic", "Bearer", "token", "apikey", "api-key", "api_key", "digest", "negotiate", "oauth", "none"):
        assert _is_low(slot), slot
    assert _is_low("changeme")  # strong placeholder token, not the allowlist


def test_f5_locators_need_two_segments_and_no_token_shaped_segment():
    # CSO F5/N3: a URI/path that CARRIES the secret is not a locator. Token-shaped
    # is case-blind: 20+ alphanumerics, or 16+ at >= 3.5 bits/char.
    for lit in ("op://" + LIT, "vault://" + LIT, "~/" + LIT, "/etc/" + LIT24, "./" + LIT, "C:\\" + LIT,
                "op://a/" + LIT24, "~/.config/" + LIT24, "/a/b/" + LIT24, "C:\\Users\\" + LIT24,
                "~/.config/GHSAT0AAAAAABCDEFGHIJ", "/9j/4AAQSkZJRgABAQAAAQABAAD", "/abc+def=="):
        assert _is_high(lit), lit
    for loc in ("op://Private/GitHub/token", "vault://secret/data/app#key", "~/.config/app/keys.json",
                "/etc/app/secrets/token", "./secrets/token.txt", "../keys/app.json", "C:\\Users\\me\\keys.json",
                "~/.config/gcloud/application_default_credentials.json"):
        assert not _auth(loc), loc


def test_f6_ellipsis_is_anchored():
    # CSO F6: `...` marks a placeholder only as the whole value or the tail of a
    # stub / all-filler value — never a substring, never behind a real token.
    assert _is_low("sk-...")
    assert _is_low("your-key...")
    assert _is_low("...")
    assert _is_high("abc..." + LIT)
    assert _is_high(LIT24 + "...")
    assert _is_high(LIT + "...x")


def test_negative_twin_every_benign_prefix_plus_a_real_token_is_still_high():
    # For each shape the audit deliberately excuses, the same shape carrying a
    # sub-threshold literal must still be a committed credential.
    for prefix, suffix in (
        ("Bearer ", ""), ("Token ", ""), ("Basic ", ""), ("ApiKey ", ""), ("Negotiate ", ""), ("Digest ", ""),
        ("${TOKEN:-", "}"), ("${T:-${U:-", "}}"), ("<token> ", ""), ("op://Private/GitHub/", ""),
        ("~/.config/app/", ""), ("your-key-", ""), ("changeme-", ""), ("example/", ""), ("", "..."),
        ("<your-api-key>", ""),
    ):
        value = prefix + LIT24 + suffix
        assert _is_high(value), value
    # Entropy-path control: the same shapes with a >= 4.0 bits/char token are caught
    # by checks_secret before the placeholder logic runs.
    assert _is_high("op://Private/GitHub/" + REAL)
    assert "WRD-SEC-ENTROPY" in _auth("your-key-" + REAL)


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
    # House redactor: at most floor(n/2) leading chars, never a suffix, bucketed length.
    assert any(f.snippet == "a…(len<=3)" for f in findings)
    assert all("abc" not in f.snippet for f in findings)


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
