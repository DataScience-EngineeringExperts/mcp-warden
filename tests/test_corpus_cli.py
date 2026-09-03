"""CLI tests for ``check --against-community`` (DSE-1515, phase 1).

The MATCH/MISMATCH/SPLIT/NOVEL runs spawn the real clean fixture server over
stdio (like ``test_e2e_pin_check``); signature verification goes through the
fake boundary from ``test_corpus``. Every run pins the consumer trust root with
``--attesters-file`` (CSO C3) — the corpus's own list is never the trust root.
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
    RULE_INSUFFICIENT,
    RULE_MISMATCH,
    RULE_NOVEL,
    RULE_SPLIT,
    RULE_UNREACHABLE,
    RULE_UNRESOLVED,
    RULE_UNVERIFIABLE,
)
from mcp_warden.corpus_trust import RULE_TRUST

from .test_corpus import ATTESTERS, CORPUS, FIXTURES, install_fake_verify

runner = CliRunner()
# The committed lock was pinned from the repo root as `python tests/fixtures/clean_server.py`
# and its command_digest binds that exact argv, so run from the repo root with the
# same relative path and make `python` resolve to THIS interpreter (which has the
# mcp SDK) — exactly the way CI's integrity-gate job does.
REPO_ROOT = FIXTURES.parent.parent
CLEAN_SERVER = "tests/fixtures/clean_server.py"
CLEAN_LOCK = "tests/fixtures/clean.warden.lock"
PY = "python"
ALICE = "alice=https://github.com/example/attester-alice/.github/workflows/attest.yml@refs/heads/main@https://token.actions.githubusercontent.com"
BOB = "bob=https://github.com/example/attester-bob/.github/workflows/attest.yml@refs/heads/main@https://token.actions.githubusercontent.com"


@pytest.fixture(autouse=True)
def _python_on_path_from_repo_root(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""))


def _check(*extra: str, json_out: bool = False, sarif: Path | None = None, pin: tuple[str, ...] = ("--attester", ALICE, "--attester", BOB)):
    argv = ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK, "--against-community", "--corpus", str(CORPUS), *pin, *extra]
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
    r = runner.invoke(app, ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK, "--against-community", "--attester", ALICE])
    assert r.exit_code == 2 and "--corpus" in r.output


def test_requires_consumer_trust_pin():
    # CSO C3: no pin -> exit 2 with instructions, before any spawn or fetch.
    r = _check(pin=())
    assert r.exit_code == 2 and RULE_TRUST in r.output and "--attester" in r.output


@pytest.mark.parametrize(
    "flags",
    [["--corpus", "x"], ["--corpus-ref", "0" * 40], ["--coordinate", "npm:a@1.0.0"], ["--attester", "a=b@c"],
     ["--attesters-file", "x"], ["--min-attesters", "1"]],
)
def test_community_options_without_the_flag_are_an_error(flags):
    # CSO L1: a typo'd invocation must not exit 0 having compared nothing.
    r = runner.invoke(app, ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK, *flags])
    assert r.exit_code == 2 and "--against-community" in r.output


def test_verify_with_against_community_is_rejected_not_skipped():
    # CSO re-verify N1: --verify returns before capture, so consensus was silently
    # skipped and a CI job that added --verify passed having compared nothing.
    r = runner.invoke(app, ["check", "--lock", CLEAN_LOCK, "--verify",
                            "--certificate-identity", "x", "--certificate-oidc-issuer", "y",
                            "--against-community", "--corpus", str(CORPUS), "--attester", ALICE])
    assert r.exit_code == 2 and "mutually exclusive" in r.output


def test_unpinned_launch_fails_before_spawn(monkeypatch):
    install_fake_verify(monkeypatch)
    # `npx foo` is unpinned; `npx` need not even exist — preflight runs before capture.
    r = runner.invoke(app, ["check", "npx", "definitely-not-a-real-package", "--lock", CLEAN_LOCK,
                            "--against-community", "--corpus", str(CORPUS), "--attester", ALICE])
    assert r.exit_code == 2 and RULE_UNRESOLVED in r.output


def test_trailing_newline_in_argv_is_unresolved_not_novel(monkeypatch):
    # Untested path 3 / CSO M1.
    install_fake_verify(monkeypatch)
    r = runner.invoke(app, ["check", "npx", "pkg@1.0.0\n", "--lock", CLEAN_LOCK,
                            "--against-community", "--corpus", str(CORPUS), "--attester", ALICE])
    assert r.exit_code == 2 and RULE_UNRESOLVED in r.output and RULE_NOVEL not in r.output


def test_default_check_unchanged_without_flag():
    r = runner.invoke(app, ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK])
    assert r.exit_code == 0 and "no drift" in r.output and "consensus" not in r.output


def test_match_exits_zero_and_says_so(monkeypatch):
    install_fake_verify(monkeypatch)
    r = _check("--coordinate", "npm:@example/clean@1.0.0")
    assert r.exit_code == 0, r.output
    assert "2 trusted attester(s) observed the same surface" in r.output
    assert "consensus attests observation, not safety" in r.output
    assert "carol" in r.output and "not in your trust pin" in r.output


def test_attesters_file_pin_works_and_divergent_pin_is_rejected(monkeypatch, tmp_path):
    install_fake_verify(monkeypatch)
    r = _check("--coordinate", "npm:@example/clean@1.0.0", pin=("--attesters-file", str(ATTESTERS)))
    assert r.exit_code == 0, r.output
    rows = json.loads(ATTESTERS.read_text())
    rows[0]["certificate_identity"] = "https://github.com/attacker/attest.yml@refs/heads/main"
    f = tmp_path / "pin.json"
    f.write_text(json.dumps(rows))
    r = _check("--coordinate", "npm:@example/clean@1.0.0", pin=("--attesters-file", str(f)))
    assert r.exit_code == 2 and RULE_TRUST in r.output


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


def test_insufficient_attesters_and_min_attesters_flag(monkeypatch):
    install_fake_verify(monkeypatch)
    r = _check("--coordinate", "npm:@example/solo@1.0.0", json_out=True)
    assert r.exit_code == 0 and _jsonl_rules(r.stdout) == [RULE_INSUFFICIENT]
    r = _check("--coordinate", "npm:@example/solo@1.0.0", "--min-attesters", "1", json_out=True)
    assert r.exit_code == 0 and _jsonl_rules(r.stdout) == []


def test_unverifiable_corpus_is_exit_two_without_traceback(monkeypatch):
    install_fake_verify(monkeypatch)
    r = _check("--coordinate", "npm:@example/corrupt@1.0.0")
    assert r.exit_code == 2 and RULE_UNVERIFIABLE in r.output and "Traceback" not in r.output


def test_unreachable_corpus_is_exit_two(monkeypatch, tmp_path):
    install_fake_verify(monkeypatch)
    r = runner.invoke(app, ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK, "--against-community",
                            "--corpus", str(tmp_path / "missing"), "--coordinate", "npm:@example/clean@1.0.0",
                            "--attester", ALICE])
    assert r.exit_code == 2 and RULE_UNREACHABLE in r.output


def test_url_corpus_requires_ref(monkeypatch):
    install_fake_verify(monkeypatch)
    r = runner.invoke(app, ["check", PY, CLEAN_SERVER, "--lock", CLEAN_LOCK, "--against-community",
                            "--corpus", "https://example.invalid/corpus.git", "--coordinate", "npm:@example/clean@1.0.0",
                            "--attester", ALICE])
    assert r.exit_code == 2 and "--corpus-ref" in r.output


def test_pin_coordinate_requires_sign_and_is_validated(tmp_path):
    r = runner.invoke(app, ["pin", PY, CLEAN_SERVER, "--lock", str(tmp_path / "x.lock"), "--coordinate", "npm:a@1.0.0"])
    assert r.exit_code == 2 and "--sign" in r.output
    r = runner.invoke(app, ["pin", PY, CLEAN_SERVER, "--lock", str(tmp_path / "x.lock"), "--sign", "--coordinate", "npm:a@latest"])
    assert r.exit_code == 2 and "pinned-version" in r.output
