"""``doctor`` engine tests — DSE-1516.

Covers discovery as a function of (platform, home, cwd, env), the fail-closed
loaders for every supported config shape, the symlink-escape guard, bounded
lock discovery + coverage matching, per-server composition of the existing
engines, and the redacted ``pin`` funnel. CLI behaviour lives in
``test_doctor_cli.py``; the CSO-review hardening lives in
``test_doctor_security.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_warden.doctor import (
    DoctorError,
    coverage,
    find_locks,
    lock_covers,
    pin_command,
    run_doctor,
    scan_server,
)
from mcp_warden.doctor_discovery import (
    FMT_CLAUDE_JSON,
    FMT_CODEX_TOML,
    FMT_JSON,
    FMT_JSONC,
    ConfigSource,
    discover,
    load_config,
    project_config_paths,
    strip_jsonc,
    well_known_config_paths,
)
from mcp_warden.lockfile import read_lock

FIXTURE_LOCK = Path(__file__).parent / "fixtures" / "clean.warden.lock"
GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # 36 chars, fake


def _warns() -> tuple[list[str], callable]:
    out: list[str] = []
    return out, out.append


def _rules(findings):
    return {f.rule_id for f in findings}


# --- discovery -------------------------------------------------------------


def test_well_known_paths_per_platform(tmp_path):
    home = tmp_path
    mac = {p.name for _, p, _ in well_known_config_paths("darwin", home, {})}
    assert {"claude_desktop_config.json", "mcp.json", ".claude.json", "config.toml", "mcp_config.json"} <= mac
    linux = [p for _, p, _ in well_known_config_paths("linux", home, {})]
    assert home / ".config" / "Claude" / "claude_desktop_config.json" in linux
    win = [p for _, p, _ in well_known_config_paths("win32", home, {"APPDATA": r"C:\Users\x\AppData\Roaming"})]
    assert any(str(p).endswith("claude_desktop_config.json") and "AppData" in str(p) for p in win)
    # No APPDATA -> the two AppData-rooted entries are simply absent, never guessed.
    assert len(well_known_config_paths("win32", home, {})) == 4
    # VS Code entries are JSONC: comments and trailing commas are legal there.
    assert [f for c, _, f in well_known_config_paths("linux", home, {}) if c == "VS Code"] == [FMT_JSONC]


def test_project_walk_stops_at_home_or_git_boundary(tmp_path):
    home = tmp_path / "home"
    cwd = home / "a" / "b"
    cwd.mkdir(parents=True)
    paths = [p for _, p, _, _ in project_config_paths(cwd, home)]
    assert cwd / ".mcp.json" in paths and home / ".mcp.json" in paths
    assert home.parent / ".mcp.json" not in paths
    # A .git boundary below home stops the walk there.
    (home / "a" / ".git").mkdir()
    paths = [p for _, p, _, _ in project_config_paths(cwd, home)]
    assert home / "a" / ".mcp.json" in paths and home / ".mcp.json" not in paths


def test_project_walk_outside_home_without_git_is_cwd_only(tmp_path):
    outside = tmp_path / "x" / "y"
    outside.mkdir(parents=True)
    paths = [p for _, p, _, _ in project_config_paths(outside, tmp_path / "unrelated")]
    assert paths and all(p.parent in (outside, outside / ".cursor", outside / ".vscode") for p in paths)
    (tmp_path / "x" / ".git").mkdir()
    paths = [p for _, p, _, _ in project_config_paths(outside, tmp_path / "unrelated")]
    assert tmp_path / "x" / ".mcp.json" in paths and tmp_path / ".mcp.json" not in paths


# --- loaders -------------------------------------------------------------------


def test_load_json_accepts_mcpservers_and_vscode_servers_key(tmp_path):
    a = tmp_path / "a.json"
    a.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["x"]}}}))
    b = tmp_path / "b.json"
    b.write_text(json.dumps({"servers": {"vs": {"url": "https://h.example.com"}}}))
    assert list(load_config("c", a, FMT_JSON, "a")[0].servers) == ["fs"]
    assert list(load_config("c", b, FMT_JSON, "b")[0].servers) == ["vs"]
    empty = tmp_path / "e.json"
    empty.write_text("{}")
    assert load_config("c", empty, FMT_JSON, "e") == []


def test_jsonc_comments_and_trailing_commas_parse_for_vscode(tmp_path):
    body = '{\n  // user comment\n  "servers": { /* block */ "vs": {"url": "https://h.example.com",},},\n}\n'
    p = tmp_path / "mcp.json"
    p.write_text(body)
    assert list(load_config("VS Code", p, FMT_JSONC, "x")[0].servers) == ["vs"]
    # Comment markers inside strings are preserved verbatim.
    assert json.loads(strip_jsonc('{"a": "http://x//y", "b": "/* keep */",}')) == {"a": "http://x//y", "b": "/* keep */"}
    with pytest.raises(DoctorError):
        load_config("c", p, FMT_JSON, "strict")  # plain JSON still rejects JSONC


def test_load_claude_json_yields_top_level_and_per_project(tmp_path):
    doc = {
        "mcpServers": {"global": {"command": "x"}},
        "projects": {"/repo": {"mcpServers": {"local": {"command": "y"}}}, "/bare": {}},
    }
    p = tmp_path / ".claude.json"
    p.write_text(json.dumps(doc))
    srcs = load_config("Claude Code", p, FMT_CLAUDE_JSON, "~/.claude.json")
    assert [(s.label, list(s.servers)) for s in srcs] == [
        ("~/.claude.json", ["global"]),
        ("~/.claude.json#projects[/repo]", ["local"]),
    ]


def test_load_codex_toml(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('[mcp_servers.gh]\ncommand = "npx"\nargs = ["-y", "@x/y"]\n')
    srcs = load_config("Codex", p, FMT_CODEX_TOML, "~/.codex/config.toml")
    assert srcs[0].servers["gh"]["args"] == ["-y", "@x/y"]


@pytest.mark.parametrize(
    "body,fmt", [("{not json", FMT_JSON), ("[]", FMT_JSON), ('{"mcpServers": 3}', FMT_JSON), ("a = [", FMT_CODEX_TOML)]
)
def test_malformed_config_fails_closed(tmp_path, body, fmt):
    p = tmp_path / ("config.toml" if fmt == FMT_CODEX_TOML else "x.json")
    p.write_text(body)
    with pytest.raises(DoctorError):
        load_config("c", p, fmt, "x")


# --- symlink guard --------------------------------------------------------------


def test_discover_skips_symlinked_config_and_never_reads_its_target(tmp_path):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"mcpServers": {"planted": {"url": "http://evil.example.com"}}}))
    (home / ".cursor" / "mcp.json").symlink_to(outside)
    warnings, warn = _warns()
    found = discover("linux", home, home, {}, warn)
    assert found.sources == [] and found.skipped == 1
    assert any("symlink" in w for w in warnings)


def test_discover_skips_symlinked_directory_component(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / "mcp.json").write_text(json.dumps({"mcpServers": {"planted": {"command": "x"}}}))
    (home / ".cursor").symlink_to(real, target_is_directory=True)
    warnings, warn = _warns()
    found = discover("linux", home, home, {}, warn)
    assert found.sources == [] and warnings and found.skipped == 1


# --- lock coverage -------------------------------------------------------------


def test_find_locks_is_bounded_and_skips_dependency_dirs(tmp_path):
    (tmp_path / "warden.lock").write_bytes(FIXTURE_LOCK.read_bytes())
    deep = tmp_path / "a" / "b" / "c" / "d" / "e"
    deep.mkdir(parents=True)
    (deep / "deep.warden.lock").write_bytes(FIXTURE_LOCK.read_bytes())
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "warden.lock").write_bytes(FIXTURE_LOCK.read_bytes())
    (tmp_path / "broken.warden.lock").write_text("{")
    warnings, warn = _warns()
    found = {p.relative_to(tmp_path).as_posix() for p, _ in find_locks(tmp_path, warn)}
    assert found == {"warden.lock"}
    assert any("broken.warden.lock" in w for w in warnings)


def test_lock_covers_matches_exact_launch_only():
    lock = read_lock(FIXTURE_LOCK)
    assert lock_covers(lock, {"command": lock.server.command, "args": list(lock.server.args)})
    assert not lock_covers(lock, {"command": lock.server.command, "args": [*lock.server.args, "--x"]})
    assert not lock_covers(lock, {"url": "https://h.example.com/mcp"})


def test_coverage_distinguishes_approved_from_unapproved():
    lock = read_lock(FIXTURE_LOCK)
    server = {"command": lock.server.command, "args": list(lock.server.args)}
    unapproved = lock.model_copy(update={"pin": lock.pin.model_copy(update={"approved": False})})
    assert coverage(server, [(FIXTURE_LOCK, lock)]) == "approved"
    assert coverage(server, [(FIXTURE_LOCK, unapproved)]) == "unapproved"
    assert coverage(server, [(FIXTURE_LOCK, unapproved), (FIXTURE_LOCK, lock)]) == "approved"
    assert coverage({"url": "https://none.example.com"}, [(FIXTURE_LOCK, lock)]) is None


# --- composition ---------------------------------------------------------------


def _src(servers) -> ConfigSource:
    return ConfigSource("t", Path("/x"), "~/x.json", servers)


def test_scan_server_composes_auth_supply_and_lock_coverage():
    server = {"url": "http://mcp.example.com", "command": "npx", "args": ["-y", "@x/unpinned"]}
    r = scan_server(_src({"s": server}), "s", server, [])
    rules = _rules(r.findings)
    assert {"WRD-AUTH-NOAUTH", "WRD-AUTH-PLAINTEXT-HTTP", "WRD-SUP-NPX-UNPINNED", "WRD-DOCTOR-NO-LOCK"} <= rules
    assert all(f.target == "~/x.json#s" for f in r.findings)


def test_covered_server_has_no_lock_finding():
    lock = read_lock(FIXTURE_LOCK)
    server = {"command": lock.server.command, "args": list(lock.server.args)}
    r = scan_server(_src({"s": server}), "s", server, [(FIXTURE_LOCK, lock)])
    assert r.covered and not ({"WRD-DOCTOR-NO-LOCK", "WRD-DOCTOR-LOCK-UNAPPROVED"} & _rules(r.findings))


def test_run_doctor_explicit_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"a": {"command": "node", "args": ["s.js"]}}}))
    report = run_doctor(
        platform="linux", home=tmp_path / "nohome", cwd=tmp_path, env={}, explicit=[cfg],
        do_discover=False, warn=lambda _m: None,
    )
    assert [r.name for r in report.reports] == ["a"] and report.searched == 0
    assert _rules(report.findings) == {"WRD-DOCTOR-NO-LOCK"}
    assert report.sources[0].explicit


# --- the funnel -----------------------------------------------------------------


def test_pin_command_masks_secret_shaped_args_and_url_credentials():
    stdio = pin_command("My Server", {"command": "node", "args": ["s.js", "--token", GHP, "a b"]})
    assert GHP not in stdio and "<REDACTED>" in stdio and "'a b'" in stdio
    assert stdio.startswith("mcp-warden pin node s.js --token <REDACTED>")
    assert stdio.endswith("--lock my-server.warden.lock")
    # Entropy alone never masks: a scoped package spec is what the user must copy.
    pkg = pin_command("gh", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]})
    assert "@modelcontextprotocol/server-github" in pkg and "REDACTED" not in pkg
    # An auth-shaped flag masks its value, unless the value is a secret reference.
    high = "qZ8vB2nM4kL7pX1cR9tW5yA3sD6fG0hJ"
    flagged = pin_command("x", {"command": "s", "args": ["--api-key", high, "--api-key", "${KEY}", "TOKEN=" + high]})
    assert high not in flagged and flagged.count("<REDACTED>") == 2 and "${KEY}" in flagged
    url = pin_command("r", {"url": "https://u:tok@h.example.com/mcp"})
    assert "tok" not in url and "REDACTED" in url
    assert pin_command("r", {"url": "https://h.example.com/mcp"}).startswith("mcp-warden pin --url https://h.example.com/mcp")
