"""Policy lint + single-sample eval tests (POLICY_MODEL.md)."""

from __future__ import annotations

import textwrap

import pytest

from mcp_warden.policy_eval import evaluate_call, overall_denied
from mcp_warden.policy_model import infer_shapes_from_arguments, load_policy


def _write(tmp_path, text):
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


# --- lint --------------------------------------------------------------------


def test_lint_valid_policy(tmp_path):
    p = _write(
        tmp_path,
        """
        version: 1
        defaults:
          shell_exec:
            allow: false
        tools:
          call_api:
            http_request:
              allow_hosts:
                - api.example.com
        """,
    )
    _, messages = load_policy(p)
    assert not [m for m in messages if m.level == "error"]


def test_lint_unknown_top_key_is_error(tmp_path):
    p = _write(tmp_path, "version: 1\nbogus: true\n")
    _, messages = load_policy(p)
    assert any(m.code == "POL-LINT-UNKNOWN-KEY" and m.level == "error" for m in messages)


def test_lint_unknown_constraint_is_error(tmp_path):
    p = _write(
        tmp_path,
        """
        version: 1
        tools:
          t:
            shell_exec:
              allow: true
              nonsense: 1
        """,
    )
    _, messages = load_policy(p)
    assert any(m.code == "POL-LINT-UNKNOWN-KEY" and m.level == "error" for m in messages)


def test_lint_wrong_version_is_error(tmp_path):
    p = _write(tmp_path, "version: 2\n")
    _, messages = load_policy(p)
    assert any(m.code == "POL-LINT-VERSION" and m.level == "error" for m in messages)


def test_lint_empty_allow_paths_warns(tmp_path):
    p = _write(
        tmp_path,
        """
        version: 1
        tools:
          w:
            filesystem_write:
              allow_paths: []
        """,
    )
    _, messages = load_policy(p)
    assert any(m.code == "POL-LINT-DENY-ALL" and m.level == "warning" for m in messages)


# --- eval: shell-exec --------------------------------------------------------


def test_eval_shell_deny_by_default(tmp_path):
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "run_command", {"command": "ls -la"}, ["shell_exec"])
    assert overall_denied(verdicts)
    assert verdicts[0].constraint == "POL-SHELL-DENY"


def test_eval_shell_metachar_denied_even_if_allowed(tmp_path):
    p = _write(
        tmp_path,
        """
        version: 1
        tools:
          run_command:
            shell_exec:
              allow: true
              allow_commands: [ls]
        """,
    )
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "run_command", {"command": "ls; rm -rf /"}, ["shell_exec"])
    assert overall_denied(verdicts)
    assert any(v.constraint == "POL-SHELL-METACHAR" for v in verdicts)


def test_eval_shell_allowlisted_command(tmp_path):
    p = _write(
        tmp_path,
        """
        version: 1
        tools:
          run_command:
            shell_exec:
              allow: true
              allow_commands: [ls, cat]
        """,
    )
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "run_command", {"command": "ls -la"}, ["shell_exec"])
    assert not overall_denied(verdicts)


# --- eval: http SSRF ---------------------------------------------------------


def test_eval_http_ssrf_metadata_denied(tmp_path):
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    verdicts = evaluate_call(
        policy, "call_api", {"url": "http://169.254.169.254/latest/meta-data/"}, ["http_request"]
    )
    assert overall_denied(verdicts)
    assert verdicts[0].constraint == "deny_private"
    assert "169.254.0.0/16" in verdicts[0].reason


def test_eval_http_rfc1918_denied(tmp_path):
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    for ip in ("10.0.0.5", "192.168.1.1", "172.16.0.1", "127.0.0.1"):
        verdicts = evaluate_call(policy, "call_api", {"url": f"http://{ip}/"}, ["http_request"])
        assert overall_denied(verdicts), ip


def test_eval_http_dns_name_not_resolved(tmp_path):
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "call_api", {"url": "https://api.example.com/v1"}, ["http_request"])
    assert not overall_denied(verdicts)
    assert any(v.constraint == "POL-HTTP-DNS-UNRESOLVED" for v in verdicts)


# --- eval: http SSRF — IPv6 literals (DR5 / #11 audit coverage) ----------------


def test_eval_http_ssrf_ipv6_loopback_bracketed_denied(tmp_path):
    # http://[::1]:8080/x — bracketed IPv6 loopback, with a port.
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "call_api", {"url": "http://[::1]:8080/x"}, ["http_request"])
    assert overall_denied(verdicts)
    assert verdicts[0].constraint == "deny_private"
    assert "IPv6 loopback" in verdicts[0].reason


def test_eval_http_ssrf_ipv6_ula_denied(tmp_path):
    # http://[fc00::1]/x — IPv6 unique-local (fc00::/7).
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "call_api", {"url": "http://[fc00::1]/x"}, ["http_request"])
    assert overall_denied(verdicts)
    assert verdicts[0].constraint == "deny_private"
    assert "IPv6 ULA" in verdicts[0].reason


def test_eval_http_ssrf_ipv6_link_local_scoped_denied(tmp_path):
    # Scoped IPv6 link-local. The bracketed-URL form percent-encodes the zone-id
    # (%25), and the bare host form passes the zone-id through; BOTH must deny.
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    for url in ("http://[fe80::1%25eth0]/x", "fe80::1%eth0"):
        verdicts = evaluate_call(policy, "call_api", {"url": url}, ["http_request"])
        assert overall_denied(verdicts), url
        assert verdicts[0].constraint == "deny_private", url
        assert "IPv6 link-local" in verdicts[0].reason, url


def test_eval_http_ssrf_ipv6_loopback_bare_url_denied(tmp_path):
    # http://[::1]/x — bare-ish bracketed loopback, no port.
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "call_api", {"url": "http://[::1]/x"}, ["http_request"])
    assert overall_denied(verdicts)
    assert verdicts[0].constraint == "deny_private"


def test_eval_http_allow_hosts(tmp_path):
    p = _write(
        tmp_path,
        """
        version: 1
        tools:
          call_api:
            http_request:
              allow_hosts: [api.example.com]
        """,
    )
    policy, _ = load_policy(p)
    ok = evaluate_call(policy, "call_api", {"url": "https://api.example.com/v1"}, ["http_request"])
    assert not overall_denied(ok)
    bad = evaluate_call(policy, "call_api", {"url": "https://evil.example/v1"}, ["http_request"])
    assert overall_denied(bad)


# --- eval: sql ---------------------------------------------------------------


def test_eval_sql_readonly_default_denies_delete(tmp_path):
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "run", {"query": "DELETE FROM users"}, ["sql_query"])
    assert overall_denied(verdicts)


def test_eval_sql_select_allowed(tmp_path):
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "run", {"query": "SELECT * FROM users"}, ["sql_query"])
    assert not overall_denied(verdicts)


def test_eval_sql_stacked_denied(tmp_path):
    p = _write(tmp_path, "version: 1\n")
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "run", {"query": "SELECT 1; DROP TABLE users"}, ["sql_query"])
    assert overall_denied(verdicts)
    assert any(v.constraint == "POL-SQL-STACKED" for v in verdicts)


# --- eval: filesystem-write --------------------------------------------------


def test_eval_fs_deny_all_empty_allow(tmp_path):
    p = _write(
        tmp_path,
        """
        version: 1
        tools:
          w:
            filesystem_write:
              allow_paths: []
        """,
    )
    policy, _ = load_policy(p)
    verdicts = evaluate_call(policy, "w", {"path": "/srv/app/x"}, ["filesystem_write"])
    assert overall_denied(verdicts)


def test_eval_fs_deny_overrides_allow(tmp_path):
    p = _write(
        tmp_path,
        """
        version: 1
        tools:
          w:
            filesystem_write:
              allow_paths: ["/srv/app/**"]
              deny_paths: ["/srv/app/secrets/**"]
        """,
    )
    policy, _ = load_policy(p)
    allowed = evaluate_call(policy, "w", {"path": "/srv/app/cache/x"}, ["filesystem_write"])
    assert not overall_denied(allowed)
    denied = evaluate_call(policy, "w", {"path": "/srv/app/secrets/key"}, ["filesystem_write"])
    assert overall_denied(denied)


# --- shape inference ---------------------------------------------------------


def test_infer_shapes_from_arguments():
    assert infer_shapes_from_arguments({"url": "x"}) == ["http_request"]
    assert infer_shapes_from_arguments({"command": "x"}) == ["shell_exec"]


def test_invalid_policy_raises(tmp_path):
    from mcp_warden.policy_model import PolicyError

    p = tmp_path / "p.yaml"
    p.write_text("just a string", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(p)
