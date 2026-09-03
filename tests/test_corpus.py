"""Engine tests for the community lock corpus (DSE-1515, phase 1).

Signature verification goes through the SAME boundary the sigstore unit tests
use — ``mcp_warden.corpus.bundle_from_json`` / ``verify_statement`` are
monkeypatched to a local fake — so no network, OIDC, or TUF traffic occurs.
The fixture sidecars under ``tests/fixtures/corpus`` are ``{"over": <statement>}``
documents that ONLY the fake accepts; real sigstore rejects them (fail closed).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from mcp_warden import corpus, signing
from mcp_warden.corpus import (
    RULE_MISMATCH,
    RULE_NOVEL,
    RULE_SPLIT,
    RULE_UNREACHABLE,
    RULE_UNVERIFIABLE,
    CorpusError,
    consensus,
    fetch_corpus,
    load_attesters,
    run_consensus,
    verified_digests,
)
from mcp_warden.corpus_coordinate import Coordinate, parse_explicit, resolve_coordinate
from mcp_warden.lockfile import lock_is_self_consistent, read_lock, surface_digest
from mcp_warden.signing import build_statement

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = FIXTURES / "corpus"
CLEAN_LOCK = read_lock(FIXTURES / "clean.warden.lock")
CLEAN_DIGEST = surface_digest(CLEAN_LOCK)
OTHER_DIGEST = surface_digest(read_lock(CORPUS / "locks/npm/@example__other/1.0.0/alice.lock"))

CLEAN = Coordinate("npm", "@example/clean", "1.0.0")
OTHER = Coordinate("npm", "@example/other", "1.0.0")
SPLIT = Coordinate("npm", "@example/split", "1.0.0")
UNKNOWN = Coordinate("npm", "@example/unknown", "1.0.0")


def install_fake_verify(monkeypatch, calls: list | None = None):
    """Wire the sigstore boundary to a local fake that checks the statement + identity."""
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(corpus, "bundle_from_json", json.loads)
    attesters = {a.id: a for a in load_attesters(CORPUS).values()}

    def _verify(statement: bytes, bundle, identity: str, issuer: str) -> None:
        if calls is not None:
            calls.append((identity, issuer))
        declared = {(a.certificate_identity, a.oidc_issuer) for a in attesters.values()}
        if (identity, issuer) not in declared:
            raise RuntimeError("identity/issuer not declared")
        if not isinstance(bundle, dict) or bundle.get("over") != statement.decode():
            raise RuntimeError("Bundle message digest mismatch")

    monkeypatch.setattr(corpus, "verify_statement", _verify)


# --- coordinates --------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("npm:@example/clean@1.0.0", "npm:@example/clean@1.0.0"),
        ("npm:left-pad@1.3.0", "npm:left-pad@1.3.0"),
        ("pypi:MCP_Server.Foo@0.4.1", "pypi:mcp-server-foo@0.4.1"),
        ("npm:@example/clean@latest", None),
        ("npm:@example/clean@^1.0.0", None),
        ("npm:../../etc@1.0.0", None),
        ("npm:@a/b/c@1.0.0", None),
        ("cargo:foo@1.0.0", None),
        ("garbage", None),
    ],
)
def test_parse_explicit(text, expected):
    got = parse_explicit(text)
    assert (str(got) if got else None) == expected


@pytest.mark.parametrize(
    "command,args,expected",
    [
        ("npx", ["-y", "@modelcontextprotocol/server-github@2025.4.8"], "npm:@modelcontextprotocol/server-github@2025.4.8"),
        ("npx", ["--yes", "left-pad@1.3.0", "--port", "3000"], "npm:left-pad@1.3.0"),
        ("npx", ["-p", "@scope/pkg@1.2.3", "some-bin"], "npm:@scope/pkg@1.2.3"),
        ("/usr/local/bin/npx", ["pkg@0.0.1"], "npm:pkg@0.0.1"),
        ("npx", ["-y", "@modelcontextprotocol/server-github"], None),  # unpinned
        ("npx", ["pkg@latest"], None),
        ("npx", ["./local/server.js"], None),
        ("uvx", ["mcp-server-git==0.6.2"], "pypi:mcp-server-git@0.6.2"),
        ("uvx", ["--from", "Mcp_Server_Fetch[extra]==1.0.0", "mcp-server-fetch"], "pypi:mcp-server-fetch@1.0.0"),
        ("uvx", ["mcp-server-git"], None),
        ("pipx", ["run", "--spec", "foo==2.0", "foo"], "pypi:foo@2.0"),
        ("pipx", ["run", "foo==2.0"], "pypi:foo@2.0"),
        ("pipx", ["install", "foo==2.0"], None),
        ("node", ["./build/index.js"], None),
        ("", [], None),  # --url with no --coordinate
    ],
)
def test_resolve_coordinate_from_argv(command, args, expected):
    got = resolve_coordinate(command, args)
    assert (str(got) if got else None) == expected


def test_explicit_coordinate_overrides_argv():
    got = resolve_coordinate("node", ["./x.js"], explicit="npm:@example/clean@1.0.0")
    assert got == CLEAN and got.path_segment == "@example__clean"
    assert str(got.relative_dir()) == "locks/npm/@example__clean/1.0.0"


# --- verification (fail closed) ----------------------------------------------


def test_verified_digests_match_and_identity_plumbing(monkeypatch):
    calls: list = []
    install_fake_verify(monkeypatch, calls)
    got = verified_digests(CORPUS, CLEAN, load_attesters(CORPUS))
    assert got == {"alice": CLEAN_DIGEST, "bob": CLEAN_DIGEST}
    assert {c[0].split("/")[4] for c in calls} == {"attester-alice", "attester-bob"}


@pytest.mark.parametrize("name", ["@example/nosig", "@example/corrupt", "@example/wrongsig", "@example/stranger"])
def test_bad_entries_reject_the_whole_coordinate(monkeypatch, name):
    install_fake_verify(monkeypatch)
    with pytest.raises(CorpusError) as ei:
        verified_digests(CORPUS, Coordinate("npm", name, "1.0.0"), load_attesters(CORPUS))
    assert ei.value.rule_id == RULE_UNVERIFIABLE


def test_sigstore_unavailable_is_unverifiable(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", False)
    with pytest.raises(CorpusError) as ei:
        run_consensus(CLEAN_DIGEST, CLEAN, str(CORPUS), None)
    assert ei.value.rule_id == RULE_UNVERIFIABLE


def test_attesters_json_malformed(tmp_path):
    (tmp_path / "attesters.json").write_text('{"not": "a list"}')
    with pytest.raises(CorpusError) as ei:
        load_attesters(tmp_path)
    assert ei.value.rule_id == RULE_UNVERIFIABLE
    (tmp_path / "attesters.json").write_text('[{"id": "../x", "certificate_identity": "i", "oidc_issuer": "o"}]')
    with pytest.raises(CorpusError):
        load_attesters(tmp_path)


# --- verdicts -----------------------------------------------------------------


def _rules(result):
    return [f.rule_id for f in result.findings]


def test_match_is_silent():
    r = consensus(CLEAN_DIGEST, CLEAN, {"alice": CLEAN_DIGEST, "bob": CLEAN_DIGEST})
    assert r.findings == [] and r.matched == ["alice", "bob"] and not r.blocking


def test_mismatch_is_high_and_blocking():
    r = consensus(CLEAN_DIGEST, OTHER, {"alice": OTHER_DIGEST, "bob": OTHER_DIGEST})
    assert _rules(r) == [RULE_MISMATCH] and r.blocking
    f = r.findings[0]
    assert f.severity == "high" and f.target == "corpus/npm:@example/other@1.0.0"
    assert f.message.endswith("consensus attests observation, not safety")


def test_split_is_reported_even_when_observed_matches_one():
    r = consensus(CLEAN_DIGEST, SPLIT, {"alice": CLEAN_DIGEST, "bob": OTHER_DIGEST})
    assert _rules(r) == [RULE_SPLIT] and r.blocking and r.matched == ["alice"]


def test_split_and_mismatch_together():
    r = consensus("sha256:" + "f" * 64, SPLIT, {"alice": CLEAN_DIGEST, "bob": OTHER_DIGEST})
    assert _rules(r) == [RULE_SPLIT, RULE_MISMATCH]


def test_novel_is_low_and_not_blocking():
    r = consensus(CLEAN_DIGEST, UNKNOWN, {})
    assert _rules(r) == [RULE_NOVEL] and r.findings[0].severity == "low" and not r.blocking


def test_run_consensus_end_to_end_over_fixture_corpus(monkeypatch):
    install_fake_verify(monkeypatch)
    assert run_consensus(CLEAN_DIGEST, CLEAN, str(CORPUS), None).findings == []
    assert _rules(run_consensus(CLEAN_DIGEST, OTHER, str(CORPUS), None)) == [RULE_MISMATCH]
    assert _rules(run_consensus(CLEAN_DIGEST, SPLIT, str(CORPUS), None)) == [RULE_SPLIT]
    assert _rules(run_consensus(CLEAN_DIGEST, UNKNOWN, str(CORPUS), None)) == [RULE_NOVEL]


# --- corpus sources -----------------------------------------------------------


def _git(*args, cwd=None):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def corpus_repo(tmp_path):
    """A bare git repo holding the fixture corpus; returns (file:// url, head sha)."""
    work = tmp_path / "work"
    subprocess.run(["cp", "-r", str(CORPUS), str(work)], check=True)
    _git("init", "-q", "-b", "main", cwd=work)
    _git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A", cwd=work)
    _git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "corpus", cwd=work)
    bare = tmp_path / "corpus.git"
    _git("clone", "-q", "--bare", str(work), str(bare))
    sha = subprocess.run(["git", "-C", str(work), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    return bare.as_uri(), sha


def test_fetch_local_path_and_ref_checks(tmp_path):
    with fetch_corpus(str(CORPUS), None) as root:
        assert (root / "attesters.json").is_file()
    with pytest.raises(CorpusError) as ei:
        with fetch_corpus(str(tmp_path / "nope"), None):
            pass
    assert ei.value.rule_id == RULE_UNREACHABLE
    with pytest.raises(CorpusError):
        with fetch_corpus(str(CORPUS), "notasha"):
            pass


def test_fetch_url_clones_at_exact_ref_and_cleans_up(corpus_repo, monkeypatch):
    url, sha = corpus_repo
    install_fake_verify(monkeypatch)
    with fetch_corpus(url, sha) as root:
        assert (root / "attesters.json").is_file()
        kept = root
    assert not kept.exists()
    assert run_consensus(CLEAN_DIGEST, CLEAN, url, sha).findings == []


def test_fetch_url_requires_ref_and_rejects_wrong_ref(corpus_repo):
    url, _sha = corpus_repo
    with pytest.raises(CorpusError) as ei:
        with fetch_corpus(url, None):
            pass
    assert ei.value.rule_id == RULE_UNREACHABLE
    with pytest.raises(CorpusError) as ei:
        with fetch_corpus(url, "0" * 40):
            pass
    assert ei.value.rule_id == RULE_UNREACHABLE


def test_fetch_unreachable_url(tmp_path):
    with pytest.raises(CorpusError) as ei:
        with fetch_corpus((tmp_path / "missing.git").as_uri(), "0" * 40):
            pass
    assert ei.value.rule_id == RULE_UNREACHABLE


def test_fixture_sidecars_are_not_real_bundles():
    # The fixture corpus must never pass REAL verification: its sidecars are fakes.
    sc = CORPUS / "locks/npm/@example__clean/1.0.0/alice.lock.sigstore"
    doc = json.loads(sc.read_text())
    assert doc["over"] == build_statement(CLEAN_LOCK.overall_digest).decode()
    assert "mediaType" not in doc  # a real sigstore bundle carries mediaType


def test_surface_digest_is_launch_independent_and_signature_covers_it():
    # overall_digest binds server.command_digest; surface_digest deliberately does not.
    other = CLEAN_LOCK.model_copy(update={"server": CLEAN_LOCK.server.model_copy(update={"command": "npx", "command_digest": "sha256:" + "1" * 64})})
    assert surface_digest(other) == CLEAN_DIGEST
    assert CLEAN_DIGEST != CLEAN_LOCK.overall_digest
    assert lock_is_self_consistent(CLEAN_LOCK)


def test_tampered_entries_under_a_valid_signature_are_rejected(monkeypatch, tmp_path):
    # Keep the signed overall_digest but swap a tool entry: the consistency check must catch it.
    install_fake_verify(monkeypatch)
    src = CORPUS / "locks/npm/@example__clean/1.0.0"
    dst = tmp_path / "locks/npm/@example__clean/1.0.0"
    dst.mkdir(parents=True)
    shutil.copy(CORPUS / "attesters.json", tmp_path / "attesters.json")
    shutil.copy(src / "alice.lock.sigstore", dst / "alice.lock.sigstore")
    doc = json.loads((src / "alice.lock").read_text())
    doc["tools"] = doc["tools"][:1]
    (dst / "alice.lock").write_text(json.dumps(doc))
    with pytest.raises(CorpusError) as ei:
        verified_digests(tmp_path, CLEAN, load_attesters(tmp_path))
    assert ei.value.rule_id == RULE_UNVERIFIABLE and "reproduce" in str(ei.value)
