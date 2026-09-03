"""CLI tests for ``check --against-community`` (DSE-1515, phase 1).

The MATCH/MISMATCH/SPLIT/NOVEL runs spawn the real clean fixture server over
stdio (like ``test_e2e_pin_check``); signature verification goes through the
fake boundary from ``test_corpus``.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_warden.cli import app
from mcp_warden.corpus import (
    RULE_MISMATCH,
    RULE_NOVEL,
    RULE_SPLIT,
    RULE_UNREACHABLE,
    RULE_UNRESOLVED,
)

from .test_corpus import CORPUS, FIXTURES, install_fake_verify

runner = CliRunner()
# The committed lock was pinned from the repo root as `python tests/fixtures/clean_server.py`
# and its command_digest binds that exact argv, so run from the repo root with the
# same relative path and make `python` resolve to THIS interpreter (which has the
# mcp SDK) — exactly the way CI's integrity-gate job does.
REPO_ROOT = FIXTURES.parent.parent
CLEAN_SERVER = "tests/fixtures/clean_server.py"
CLEAN_LOCK = "tests/fixtures/clean.warden.lock"
PY = "python"


@pytest.fixture(autouse=True)
def _python_on_path_from_repo_root(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""))


def _check(*extra: str, json_out: bool = False, sarif: Path | None = None):
    argv = ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK, "--against-community", "--corpus", str(CORPUS), *extra]
    if json_out:
        argv.append("--json")
    if sarif is not None:
        argv += ["--sarif", str(sarif)]
    return runner.invoke(app, argv)


def _jsonl_rules(stdout: str) -> list[str]:
    """Consensus rule ids in the JSONL stream (static WRD-CAP-*/WRD-SEC-* findings are expected too)."""
    rules = [json.loads(line).get("rule_id", "") for line in stdout.splitlines() if line.strip()]
    return [r for r in rules if r.startswith("WRD-CONSENSUS-")]


def test_requires_corpus_flag():
    r = runner.invoke(app, ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK, "--against-community"])
    assert r.exit_code == 2 and "--corpus" in r.output


def test_unpinned_launch_fails_before_spawn(monkeypatch):
    install_fake_verify(monkeypatch)
    # `npx foo` is unpinned; `npx` need not even exist — preflight runs before capture.
    r = runner.invoke(app, ["check", "npx", "definitely-not-a-real-package", "--lock", CLEAN_LOCK,
                            "--against-community", "--corpus", str(CORPUS)])
    assert r.exit_code == 2 and RULE_UNRESOLVED in r.output


def test_default_check_unchanged_without_flag():
    r = runner.invoke(app, ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK])
    assert r.exit_code == 0 and "no drift" in r.output and "consensus" not in r.output


def test_match_exits_zero_and_says_so(monkeypatch):
    install_fake_verify(monkeypatch)
    r = _check("--coordinate", "npm:@example/clean@1.0.0")
    assert r.exit_code == 0, r.output
    assert "2 attester(s) observed the same surface" in r.output
    assert "consensus attests observation, not safety" in r.output


def test_mismatch_blocks_with_sarif_and_jsonl(monkeypatch, tmp_path):
    install_fake_verify(monkeypatch)
    r = _check("--coordinate", "npm:@example/other@1.0.0")
    assert r.exit_code == 1 and RULE_MISMATCH in r.output and "no drift" in r.output

    sarif = tmp_path / "c.sarif"
    r = _check("--coordinate", "npm:@example/other@1.0.0", json_out=True, sarif=sarif)
    assert r.exit_code == 1
    assert _jsonl_rules(r.stdout) == [RULE_MISMATCH]
    doc = json.loads(sarif.read_text())
    results = [x for x in doc["runs"][0]["results"] if x["ruleId"].startswith("WRD-CONSENSUS-")]
    assert [x["ruleId"] for x in results] == [RULE_MISMATCH] and results[0]["level"] == "error"
    assert results[0]["properties"]["target"] == "corpus/npm:@example/other@1.0.0"
    assert RULE_MISMATCH in [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]


def test_split_blocks(monkeypatch):
    install_fake_verify(monkeypatch)
    r = _check("--coordinate", "npm:@example/split@1.0.0", json_out=True)
    assert r.exit_code == 1 and _jsonl_rules(r.stdout) == [RULE_SPLIT]


def test_novel_is_reported_but_does_not_block(monkeypatch):
    install_fake_verify(monkeypatch)
    r = _check("--coordinate", "npm:@example/unknown@1.0.0", json_out=True)
    assert r.exit_code == 0 and _jsonl_rules(r.stdout) == [RULE_NOVEL]


def test_unreachable_corpus_is_exit_two(monkeypatch, tmp_path):
    install_fake_verify(monkeypatch)
    r = runner.invoke(app, ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK, "--against-community",
                            "--corpus", str(tmp_path / "missing"), "--coordinate", "npm:@example/clean@1.0.0"])
    assert r.exit_code == 2 and RULE_UNREACHABLE in r.output


def test_url_corpus_requires_ref(monkeypatch):
    install_fake_verify(monkeypatch)
    r = runner.invoke(app, ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK, "--against-community",
                            "--corpus", "https://example.invalid/corpus.git", "--coordinate", "npm:@example/clean@1.0.0"])
    assert r.exit_code == 2 and "--corpus-ref" in r.output
