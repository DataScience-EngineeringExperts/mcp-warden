"""``mcp-warden doctor`` CLI tests — DSE-1516.

Exit-code contract, the no-config path, redaction across stdout / JSONL /
SARIF, the static-by-default guarantee (a spawn, socket, or DNS attempt on the
default path fails the test), the ``--pin`` opt-in contract, and Windows path
shapes via injected ``APPDATA``.
"""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_warden.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
GHP = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"  # fake, 36 chars


def _fake_home(tmp_path: Path) -> Path:
    """A macOS-shaped home with three clients configured, one credential planted."""
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                                          "env": {"GITHUB_TOKEN": GHP}}}})
    )
    desktop = home / "Library" / "Application Support" / "Claude"
    desktop.mkdir(parents=True)
    (desktop / "claude_desktop_config.json").write_text(
        json.dumps({"mcpServers": {"remote": {"url": "http://mcp.example.com/sse"}}})
    )
    (home / ".claude.json").write_text(
        json.dumps({"projects": {"/repo": {"mcpServers": {"ok": {"url": "https://h.example.com", "headers": {"Authorization": "Bearer ${T}"}}}}}})
    )
    return home


def _run(*args, home=None, platform="darwin"):
    extra = ["--home", str(home)] if home else []
    return runner.invoke(app, ["doctor", "--platform", platform, *extra, *args])


def test_no_configs_is_exit_zero_with_explicit_message(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = _run(home=tmp_path / "empty")
    assert r.exit_code == 0 and "no MCP configs found" in r.output


def test_report_exit_one_and_every_credential_redacted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = _fake_home(tmp_path)
    r = _run(home=home)
    assert r.exit_code == 1
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in r.output and "WRD-AUTH-PLAINTEXT-HTTP" in r.output
    assert "WRD-SUP-NPX-UNPINNED" in r.output and "WRD-DOCTOR-NO-LOCK" in r.output
    assert "Next steps" in r.output and "mcp-warden pin" in r.output
    assert GHP not in r.output


def test_json_and_sarif_are_valid_and_redacted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = _fake_home(tmp_path)
    sarif = tmp_path / "d.sarif"
    r = _run("--json", "--sarif", str(sarif), home=home)
    assert r.exit_code == 1
    records = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
    assert records and all(rec["kind"] == "finding" for rec in records)
    assert GHP not in r.stdout
    doc = json.loads(sarif.read_text())
    assert doc["runs"][0]["results"] and GHP not in sarif.read_text()


def test_malformed_explicit_config_exit_two(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    r = _run("--no-discover", "--config", str(bad), home=tmp_path / "empty")
    assert r.exit_code == 2


def test_default_path_never_spawns_connects_or_resolves(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = _fake_home(tmp_path)

    def boom(*_a, **_k):
        raise AssertionError("doctor default path must be static")

    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    r = _run(home=home)
    assert r.exit_code == 1 and "Posture findings" in r.output
    assert not isinstance(r.exception, AssertionError)


def test_pin_refuses_non_interactive_without_yes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = _fake_home(tmp_path)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("spawned"))
    r = _run("--pin", home=home)  # CliRunner stdin is not a TTY
    assert r.exit_code == 2 and "--yes" in r.output
    assert not list(tmp_path.glob("*.warden.lock"))


def test_pin_yes_writes_unapproved_lock_for_a_real_server(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps({"mcpServers": {"clean": {"command": sys.executable, "args": [str(FIXTURES / "clean_server.py")]}}})
    )
    r = _run("--no-discover", "--config", str(cfg), "--pin", "--yes", home=tmp_path / "empty")
    lock = tmp_path / "clean.warden.lock"
    assert lock.exists(), r.output
    doc = json.loads(lock.read_text())
    assert doc["pin"]["approved"] is False and "pinned" in r.output
    # Now that the lock exists the same server is covered on the next run.
    again = _run("--no-discover", "--config", str(cfg), home=tmp_path / "empty")
    assert "WRD-DOCTOR-NO-LOCK" not in again.output


def test_pin_capture_failure_is_exit_two_not_silent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"dead": {"command": sys.executable, "args": ["-c", "raise SystemExit(3)"]}}}))
    r = _run("--no-discover", "--config", str(cfg), "--pin", "--yes", "--timeout", "5", home=tmp_path / "empty")
    assert r.exit_code == 2 and "pin failed" in r.output


def test_windows_shape_discovered_via_injected_appdata(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    appdata = tmp_path / "AppData" / "Roaming"
    (appdata / "Claude").mkdir(parents=True)
    (appdata / "Claude" / "claude_desktop_config.json").write_text(
        json.dumps({"mcpServers": {"win": {"url": "http://mcp.example.com"}}})
    )
    monkeypatch.setenv("APPDATA", str(appdata))
    r = _run(home=tmp_path / "home", platform="win32")
    assert r.exit_code == 1 and "win" in r.output and "WRD-AUTH-PLAINTEXT-HTTP" in r.output


def test_symlinked_discovered_config_warns_and_is_skipped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"mcpServers": {"planted": {"url": "http://x.example.com"}}}))
    (home / ".cursor" / "mcp.json").symlink_to(outside)
    r = _run(home=home, platform="linux")
    assert r.exit_code == 0 and "symlink" in r.output and "planted" not in r.output
