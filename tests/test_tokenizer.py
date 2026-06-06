"""Tokenizer + capability-derivation tests (CHECKS.md §3, WARDEN_LOCK_SCHEMA.md §5.4)."""

from __future__ import annotations

from mcp_warden.tokenizer import derive_capabilities, has_token, tokenize


def test_tokenize_camel_snake_kebab_dot():
    assert tokenize("runShellCommand") == ["run", "shell", "command"]
    assert tokenize("fs.write_file") == ["fs", "write", "file"]
    assert tokenize("read-file") == ["read", "file"]
    assert tokenize("HTTPServer") == ["http", "server"]


def test_segment_exact_not_substring():
    # "shelter" must not match "shell" (CHECKS.md §3 / §8.4).
    assert not has_token("shelter", frozenset({"shell"}))
    assert has_token("run_shell", frozenset({"shell"}))


def test_shell_exec_from_name_token():
    assert "shell-exec" in derive_capabilities("run_command", {"properties": {"command": {}}})
    assert "shell-exec" in derive_capabilities("exec_thing", {})


def test_shell_exec_from_command_property():
    assert "shell-exec" in derive_capabilities("do_thing", {"properties": {"command": {"type": "string"}}})


def test_fs_read_requires_name_token_and_path_prop():
    assert "fs-read" in derive_capabilities("read_file", {"properties": {"path": {}}})
    # read name token but no path-like property -> no fs-read
    assert "fs-read" not in derive_capabilities("read_value", {"properties": {"key": {}}})


def test_fs_write_name_token_plus_path():
    caps = derive_capabilities("write_file", {"properties": {"path": {}, "content": {}}})
    assert "fs-write" in caps


def test_fs_write_path_plus_content_signal():
    caps = derive_capabilities("store", {"properties": {"target": {}, "data": {}}})
    assert "fs-write" in caps


def test_http_from_url_property():
    assert "http-request" in derive_capabilities("call_api", {"properties": {"url": {}}})


def test_sql_from_query_property():
    assert "sql-query" in derive_capabilities("run_report", {"properties": {"query": {}}})


def test_capabilities_sorted_and_deduped():
    caps = derive_capabilities("fetch_and_read", {"properties": {"url": {}, "path": {}}})
    assert caps == sorted(caps)
    assert len(caps) == len(set(caps))


def test_clean_read_file_only_fs_read():
    assert derive_capabilities("read_file", {"properties": {"path": {"type": "string"}}}) == ["fs-read"]
