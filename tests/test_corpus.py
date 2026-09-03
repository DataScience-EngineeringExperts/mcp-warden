"""Engine tests for the community lock corpus (DSE-1515, phase 1).

Signature verification goes through the SAME boundary the sigstore unit tests
use — ``mcp_warden.corpus_verify.bundle_from_json`` / ``verify_statement`` /
``make_verifier`` are monkeypatched to a local fake — so no network, OIDC, or
TUF traffic occurs. The fixture sidecars under ``tests/fixtures/corpus`` are
``{"over": <v2 statement>}`` documents that ONLY the fake accepts; real sigstore
rejects them (fail closed).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from mcp_warden import SCHEMA_VERSION, corpus, corpus_verify, signing
from mcp_warden.corpus import (
    RULE_INSUFFICIENT,
    RULE_MISMATCH,
    RULE_NOVEL,
    RULE_SCHEMA_MISMATCH,
    RULE_SPLIT,
    RULE_UNREACHABLE,
    RULE_UNVERIFIABLE,
    CorpusError,
    consensus,
    fetch_corpus,
    run_consensus,
    verified_digests,
)
from mcp_warden.corpus_coordinate import Coordinate, parse_explicit, resolve_coordinate
from mcp_warden.corpus_trust import (
    RULE_TRUST,
    TrustError,
    load_consumer_pin,
    load_corpus_attesters,
    parse_attester_flag,
    resolve_trust,
)
from mcp_warden.lockfile import lock_is_self_consistent, read_lock, surface_digest
from mcp_warden.signing import STATEMENT_TYPE, STATEMENT_TYPE_V2, build_statement

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = FIXTURES / "corpus"
ATTESTERS = CORPUS / "attesters.json"
CLEAN_LOCK = read_lock(FIXTURES / "clean.warden.lock")
CLEAN_DIGEST = surface_digest(CLEAN_LOCK)
OTHER_DIGEST = surface_digest(read_lock(CORPUS / "locks/npm/@example__other/1.0.0/alice.lock"))

CLEAN = Coordinate("npm", "@example/clean", "1.0.0")
OTHER = Coordinate("npm", "@example/other", "1.0.0")
SPLIT = Coordinate("npm", "@example/split", "1.0.0")
SOLO = Coordinate("npm", "@example/solo", "1.0.0")
UNPINNED = Coordinate("npm", "@example/unpinned", "1.0.0")
UNKNOWN = Coordinate("npm", "@example/unknown", "1.0.0")


def consumer_pin() -> dict:
    """The consumer trust root the tests use: alice + bob (NOT carol)."""
    all_ids = load_corpus_attesters(CORPUS)
    return {k: v for k, v in all_ids.items() if k in ("alice", "bob")}


def install_fake_verify(monkeypatch, calls: list | None = None):
    """Wire the sigstore boundary to a local fake that checks the statement + identity."""
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(corpus_verify, "bundle_from_json", json.loads)
    monkeypatch.setattr(corpus_verify, "make_verifier", lambda: "fake-verifier")
    declared = {(a.certificate_identity, a.oidc_issuer) for a in load_corpus_attesters(CORPUS).values()}

    def _verify(statement: bytes, bundle, identity: str, issuer: str, *, verifier=None) -> None:
        assert verifier == "fake-verifier", "verifier must be built once and passed through"
        if calls is not None:
            calls.append((identity, issuer))
        if (identity, issuer) not in declared:
            raise RuntimeError("identity/issuer not declared")
        if not isinstance(bundle, dict) or bundle.get("over") != statement.decode():
            raise RuntimeError("Bundle message digest mismatch")

    monkeypatch.setattr(corpus_verify, "verify_statement", _verify)


def run(observed, coord, source=str(CORPUS), ref=None, pin=None, min_attesters=2):
    return run_consensus(observed, coord, source, ref, consumer_pin() if pin is None else pin, min_attesters)


def _rules(result):
    return [f.rule_id for f in result.findings]


# --- statements (CSO C2) ------------------------------------------------------


def test_v1_statement_bytes_unchanged_and_v2_binds_coordinate():
    d = "sha256:" + "a" * 64
    v1 = build_statement(d)
    assert v1 == b'{"_type":"mcp-warden-lock-digest/v1","digest":"' + d.encode() + b'"}'
    assert json.loads(v1)["_type"] == STATEMENT_TYPE
    v2 = build_statement(d, "npm:@example/clean@1.0.0")
    assert json.loads(v2) == {"_type": STATEMENT_TYPE_V2, "coordinate": "npm:@example/clean@1.0.0", "digest": d}
    assert v2 != build_statement(d, "npm:@example/other@1.0.0")


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
        ("npm:@example/clean@1.0.0\n", None),  # CSO M1: whitespace never resolves
        (" npm:@example/clean@1.0.0", None),
        ("npm:@exam\x1bple/clean@1.0.0", None),
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
        ("npx", ["-y", "pkg@1.0.0\n"], None),  # CSO M1 / test 3: trailing newline is UNRESOLVED, not NOVEL
        ("npx", ["-y", "pkg\t@1.0.0"], None),
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


# --- trust (CSO C3) -----------------------------------------------------------


def test_attester_flag_parses_identity_containing_at():
    a = parse_attester_flag("alice=https://github.com/x/.github/workflows/a.yml@refs/heads/main@https://issuer")
    assert a.id == "alice" and a.certificate_identity.endswith("@refs/heads/main") and a.oidc_issuer == "https://issuer"
    for bad in ("alice", "alice=nope", "=x@y", "a b=x@y"):
        with pytest.raises(TrustError) as ei:
            parse_attester_flag(bad)
        assert ei.value.rule_id == RULE_TRUST


def test_consumer_pin_required_and_deduplicated(tmp_path):
    with pytest.raises(TrustError) as ei:
        load_consumer_pin([], None)
    assert ei.value.rule_id == RULE_TRUST and "--attester" in str(ei.value)
    pin = load_consumer_pin([], ATTESTERS)
    assert set(pin) == {"alice", "bob", "carol"}
    flag = "alice=https://other@https://issuer"
    with pytest.raises(TrustError):
        load_consumer_pin([flag], ATTESTERS)  # duplicate id across file + flag
    with pytest.raises(TrustError):
        load_consumer_pin([flag, flag], None)  # duplicate id across flags


def test_duplicate_id_in_corpus_attesters_is_rejected(tmp_path):
    # Untested path 5: a second `alice` row must not silently substitute her identity.
    rows = json.loads(ATTESTERS.read_text())
    rows.append(dict(rows[0], certificate_identity="https://attacker"))
    (tmp_path / "attesters.json").write_text(json.dumps(rows))
    with pytest.raises(TrustError) as ei:
        load_corpus_attesters(tmp_path)
    assert ei.value.rule_id == RULE_UNVERIFIABLE and "duplicate" in str(ei.value)


def test_resolve_trust_ignores_unpinned_and_rejects_divergent():
    declared = load_corpus_attesters(CORPUS)
    trusted, warnings = resolve_trust(declared, consumer_pin())
    assert set(trusted) == {"alice", "bob"} and len(warnings) == 1 and "carol" in warnings[0]
    divergent = dict(consumer_pin())
    divergent["alice"] = type(divergent["alice"])("alice", "https://attacker", divergent["alice"].oidc_issuer)
    with pytest.raises(TrustError) as ei:
        resolve_trust(declared, divergent)
    assert ei.value.rule_id == RULE_TRUST


def test_hostile_corpus_cannot_declare_its_own_trust_root(monkeypatch, tmp_path):
    # Untested path 6: a corpus whose attesters.json names attacker identities under
    # the SAME ids must be rejected by the consumer pin; a corpus naming only ids the
    # consumer never pinned yields NOVEL, never a verified match.
    install_fake_verify(monkeypatch)
    hostile = tmp_path / "corpus"
    shutil.copytree(CORPUS, hostile)
    rows = json.loads(ATTESTERS.read_text())
    for r in rows:
        r["certificate_identity"] = "https://github.com/attacker/.github/workflows/attest.yml@refs/heads/main"
    (hostile / "attesters.json").write_text(json.dumps(rows))
    with pytest.raises(CorpusError) as ei:
        run(CLEAN_DIGEST, CLEAN, str(hostile))
    assert ei.value.rule_id == RULE_TRUST
    # Only-strangers corpus: entries exist under carol's name but she is not pinned.
    assert _rules(run(CLEAN_DIGEST, UNPINNED)) == [RULE_NOVEL]


# --- verification (fail closed) ----------------------------------------------


def test_verified_digests_match_and_identity_plumbing(monkeypatch):
    calls: list = []
    install_fake_verify(monkeypatch, calls)
    got = verified_digests(CORPUS, CLEAN, consumer_pin())
    assert got == {"alice": CLEAN_DIGEST, "bob": CLEAN_DIGEST}
    assert len(calls) == 2 and all(i.startswith("https://github.com/example/attester-") for i, _ in calls)


def test_relocated_sidecar_is_rejected(monkeypatch, tmp_path):
    # Untested path 1 / CSO C2: alice's GENUINE signature for @example/clean copied
    # under @example/other must fail — the v2 statement binds the directory coordinate.
    install_fake_verify(monkeypatch)
    root = tmp_path / "corpus"
    shutil.copytree(CORPUS, root)
    src = root / "locks/npm/@example__clean/1.0.0"
    dst = root / "locks/npm/@example__other/1.0.0"
    shutil.copy(src / "alice.lock", dst / "alice.lock")
    shutil.copy(src / "alice.lock.sigstore", dst / "alice.lock.sigstore")
    with pytest.raises(CorpusError) as ei:
        verified_digests(root, OTHER, consumer_pin())
    assert ei.value.rule_id == RULE_UNVERIFIABLE and "signature did not verify" in str(ei.value)


@pytest.mark.parametrize("name", ["@example/nosig", "@example/corrupt", "@example/wrongsig", "@example/stranger"])
def test_bad_entries_reject_the_whole_coordinate(monkeypatch, name):
    install_fake_verify(monkeypatch)
    with pytest.raises(CorpusError) as ei:
        verified_digests(CORPUS, Coordinate("npm", name, "1.0.0"), consumer_pin())
    assert ei.value.rule_id == RULE_UNVERIFIABLE


def test_sigstore_unavailable_is_unverifiable(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", False)
    with pytest.raises(CorpusError) as ei:
        run(CLEAN_DIGEST, CLEAN)
    assert ei.value.rule_id == RULE_UNVERIFIABLE


def test_attesters_json_malformed(tmp_path):
    (tmp_path / "attesters.json").write_text('{"not": "a list"}')
    with pytest.raises(TrustError) as ei:
        load_corpus_attesters(tmp_path)
    assert ei.value.rule_id == RULE_UNVERIFIABLE
    (tmp_path / "attesters.json").write_text('[{"id": "../x", "certificate_identity": "i", "oidc_issuer": "o"}]')
    with pytest.raises(TrustError):
        load_corpus_attesters(tmp_path)


def test_hostile_corpus_shapes_are_unverifiable_not_tracebacks(monkeypatch, tmp_path):
    # Untested path 4 / CSO M2: a DIRECTORY named alice.lock and deeply nested JSON.
    install_fake_verify(monkeypatch)
    root = tmp_path / "corpus"
    shutil.copytree(CORPUS, root)
    d = root / "locks/npm/@example__clean/1.0.0"
    shutil.rmtree(d)
    (d / "alice.lock").mkdir(parents=True)
    with pytest.raises(CorpusError) as ei:
        run(CLEAN_DIGEST, CLEAN, str(root))
    assert ei.value.rule_id == RULE_UNVERIFIABLE
    (root / "attesters.json").write_text("[" * 5000 + "]" * 5000)
    with pytest.raises(CorpusError) as ei:
        run(CLEAN_DIGEST, CLEAN, str(root))
    assert ei.value.rule_id == RULE_UNVERIFIABLE and "Traceback" not in str(ei.value)


def test_size_caps(monkeypatch, tmp_path):
    # CSO M3: oversized lock / sidecar / attesters.json and too many entries all fail closed.
    install_fake_verify(monkeypatch)
    root = tmp_path / "corpus"
    shutil.copytree(CORPUS, root)
    d = root / "locks/npm/@example__clean/1.0.0"
    for target, cap in (
        (d / "alice.lock", corpus_verify.MAX_LOCK_BYTES),
        (d / "alice.lock.sigstore", corpus_verify.MAX_SIDECAR_BYTES),
    ):
        original = target.read_bytes()
        with target.open("ab") as fh:
            fh.truncate(cap + 1)
        with pytest.raises(CorpusError) as ei:
            verified_digests(root, CLEAN, consumer_pin())
        assert ei.value.rule_id == RULE_UNVERIFIABLE and "exceeds" in str(ei.value)
        target.write_bytes(original)
    for i in range(corpus_verify.MAX_ENTRIES_PER_COORDINATE):
        shutil.copy(d / "alice.lock", d / f"x{i}.lock")
    with pytest.raises(CorpusError) as ei:
        verified_digests(root, CLEAN, consumer_pin())
    assert "more than" in str(ei.value)
    big = root / "attesters.json"
    with big.open("ab") as fh:
        fh.truncate(256 * 1024 + 1)
    with pytest.raises(TrustError) as ei:
        load_corpus_attesters(root)
    assert "exceeds" in str(ei.value)


def test_symlinked_locks_dir_escaping_the_corpus_is_rejected(monkeypatch, tmp_path):
    # Untested path 7 / CSO L3.
    install_fake_verify(monkeypatch)
    outside = tmp_path / "outside"
    shutil.copytree(CORPUS / "locks", outside)
    root = tmp_path / "corpus"
    root.mkdir()
    shutil.copy(ATTESTERS, root / "attesters.json")
    os.symlink(outside, root / "locks")
    with pytest.raises(CorpusError) as ei:
        verified_digests(root, CLEAN, consumer_pin())
    assert ei.value.rule_id == RULE_UNVERIFIABLE and "escapes" in str(ei.value)


def test_schema_version_mismatch_is_distinct(monkeypatch, tmp_path):
    # Untested path 8 / CSO L2: an older-schema corpus lock gets its own rule + message.
    install_fake_verify(monkeypatch)
    root = tmp_path / "corpus"
    shutil.copytree(CORPUS, root)
    p = root / "locks/npm/@example__clean/1.0.0/alice.lock"
    doc = json.loads(p.read_text())
    doc["schema_version"] = SCHEMA_VERSION - 1
    p.write_text(json.dumps(doc))
    with pytest.raises(CorpusError) as ei:
        verified_digests(root, CLEAN, consumer_pin())
    assert ei.value.rule_id == RULE_SCHEMA_MISMATCH and "schema_version" in str(ei.value)


def test_pydantic_error_text_is_reduced_to_field_paths(monkeypatch, tmp_path):
    install_fake_verify(monkeypatch)
    root = tmp_path / "corpus"
    shutil.copytree(CORPUS, root)
    p = root / "locks/npm/@example__clean/1.0.0/alice.lock"
    doc = json.loads(p.read_text())
    doc["overall_digest"] = "SECRET-LOOKING-VALUE-THAT-MUST-NOT-ECHO"
    del doc["tools"]
    p.write_text(json.dumps(doc))
    with pytest.raises(CorpusError) as ei:
        verified_digests(root, CLEAN, consumer_pin())
    assert "SECRET-LOOKING" not in str(ei.value) and "tools" in str(ei.value)


# --- verdicts -----------------------------------------------------------------


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


def test_insufficient_attesters_is_low_and_not_blocking():
    r = consensus(CLEAN_DIGEST, SOLO, {"alice": CLEAN_DIGEST}, min_attesters=2)
    assert _rules(r) == [RULE_INSUFFICIENT] and not r.blocking and r.matched == ["alice"]
    assert consensus(CLEAN_DIGEST, SOLO, {"alice": CLEAN_DIGEST}, min_attesters=1).findings == []


def test_run_consensus_end_to_end_over_fixture_corpus(monkeypatch):
    install_fake_verify(monkeypatch)
    ok = run(CLEAN_DIGEST, CLEAN)
    assert ok.findings == [] and any("carol" in w for w in ok.warnings)
    assert _rules(run(CLEAN_DIGEST, OTHER)) == [RULE_MISMATCH]
    assert _rules(run(CLEAN_DIGEST, SPLIT)) == [RULE_SPLIT]
    assert _rules(run(CLEAN_DIGEST, UNKNOWN)) == [RULE_NOVEL]
    assert _rules(run(CLEAN_DIGEST, SOLO)) == [RULE_INSUFFICIENT]
    assert run(CLEAN_DIGEST, SOLO, min_attesters=1).findings == []


# --- corpus sources (CSO C1) --------------------------------------------------


def _git(*args, cwd=None):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def corpus_repo(tmp_path):
    """A bare git repo holding the fixture corpus; returns (path, head sha)."""
    work = tmp_path / "work"
    shutil.copytree(CORPUS, work)
    _git("init", "-q", "-b", "main", cwd=work)
    _git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A", cwd=work)
    _git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "corpus", cwd=work)
    bare = tmp_path / "corpus.git"
    _git("clone", "-q", "--bare", str(work), str(bare))
    sha = subprocess.run(["git", "-C", str(work), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    return bare, sha


def _allow_file_transport(monkeypatch):
    """Tests only: let the REAL clone path run against a local bare repo.

    Production allows https/ssh only; this widens both the URL allowlist and the
    git protocol policy to `file` so the clone mechanics (hardening flags, `--`,
    exact-ref checkout, temp-dir cleanup) are exercised without a network.
    """
    monkeypatch.setattr(corpus, "_URL_PREFIXES", (*corpus._URL_PREFIXES, "file://"))
    monkeypatch.setattr(corpus, "_GIT_CONFIG", [*corpus._GIT_CONFIG, "-c", "protocol.file.allow=always"])


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


@pytest.mark.parametrize(
    "source",
    [
        "ext::sh -c 'touch /tmp/pwned' https://x",
        "--upload-pack=touch /tmp/pwned",
        "-c",
        "file:///tmp/corpus.git",
        "git://example.invalid/corpus.git",
        "host:path/corpus.git",  # scp-style shorthand is not on the allowlist
    ],
)
def test_unsafe_sources_never_reach_git(monkeypatch, source):
    # Untested path 2 / CSO C1.
    def _boom(*a, **k):
        raise AssertionError("subprocess must not run for a rejected source")

    monkeypatch.setattr(subprocess, "run", _boom)
    with pytest.raises(CorpusError) as ei:
        with fetch_corpus(source, "0" * 40):
            pass
    assert ei.value.rule_id == RULE_UNREACHABLE


def test_git_argv_is_hardened_and_source_is_last(monkeypatch, tmp_path):
    seen: list[list[str]] = []

    def _fake_run(argv, **kw):
        seen.append(argv)
        assert "shell" not in kw
        assert kw["env"]["GIT_TERMINAL_PROMPT"] == "0" and set(kw["env"]) <= {*corpus._GIT_ENV_KEYS, "GIT_TERMINAL_PROMPT"}
        if argv[-2:-1] and "clone" in argv:
            Path(argv[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(argv, 0, stdout="0" * 40 + "\n", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with fetch_corpus("https://example.invalid/corpus.git", "0" * 40):
        pass
    clone = seen[0]
    assert clone[:1] == ["git"] and clone[1:1 + len(corpus._GIT_CONFIG)] == corpus._GIT_CONFIG
    assert "protocol.allow=never" in clone and "core.hooksPath=/dev/null" in clone
    assert clone[-3] == "--" and clone[-2] == "https://example.invalid/corpus.git"
    assert all(a[0] == "git" and a[1:1 + len(corpus._GIT_CONFIG)] == corpus._GIT_CONFIG for a in seen)


def test_fetch_url_clones_at_exact_ref_and_cleans_up(corpus_repo, monkeypatch):
    bare, sha = corpus_repo
    _allow_file_transport(monkeypatch)
    install_fake_verify(monkeypatch)
    with fetch_corpus(bare.as_uri(), sha) as root:
        assert (root / "attesters.json").is_file()
        kept = root
    assert not kept.exists()
    assert run(CLEAN_DIGEST, CLEAN, bare.as_uri(), sha).findings == []


def test_fetch_url_requires_ref_and_rejects_wrong_ref(corpus_repo, monkeypatch):
    bare, _sha = corpus_repo
    _allow_file_transport(monkeypatch)
    with pytest.raises(CorpusError) as ei:
        with fetch_corpus(bare.as_uri(), None):
            pass
    assert ei.value.rule_id == RULE_UNREACHABLE
    with pytest.raises(CorpusError) as ei:
        with fetch_corpus(bare.as_uri(), "0" * 40):
            pass
    assert ei.value.rule_id == RULE_UNREACHABLE


def test_fetch_unreachable_url(monkeypatch, tmp_path):
    _allow_file_transport(monkeypatch)
    with pytest.raises(CorpusError) as ei:
        with fetch_corpus((tmp_path / "missing.git").as_uri(), "0" * 40):
            pass
    assert ei.value.rule_id == RULE_UNREACHABLE


# --- digests ------------------------------------------------------------------


def test_fixture_sidecars_are_not_real_bundles():
    # The fixture corpus must never pass REAL verification: its sidecars are fakes.
    sc = CORPUS / "locks/npm/@example__clean/1.0.0/alice.lock.sigstore"
    doc = json.loads(sc.read_text())
    assert doc["over"] == build_statement(CLEAN_LOCK.overall_digest, "npm:@example/clean@1.0.0").decode()
    assert "mediaType" not in doc  # a real sigstore bundle carries mediaType


def test_surface_digest_is_launch_independent_and_signature_covers_it():
    other = CLEAN_LOCK.model_copy(update={"server": CLEAN_LOCK.server.model_copy(update={"command": "npx", "command_digest": "sha256:" + "1" * 64})})
    assert surface_digest(other) == CLEAN_DIGEST
    assert CLEAN_DIGEST != CLEAN_LOCK.overall_digest
    assert lock_is_self_consistent(CLEAN_LOCK)


def test_tampered_entries_under_a_valid_signature_are_rejected(monkeypatch, tmp_path):
    install_fake_verify(monkeypatch)
    src = CORPUS / "locks/npm/@example__clean/1.0.0"
    dst = tmp_path / "locks/npm/@example__clean/1.0.0"
    dst.mkdir(parents=True)
    shutil.copy(ATTESTERS, tmp_path / "attesters.json")
    shutil.copy(src / "alice.lock.sigstore", dst / "alice.lock.sigstore")
    doc = json.loads((src / "alice.lock").read_text())
    doc["tools"] = doc["tools"][:1]
    (dst / "alice.lock").write_text(json.dumps(doc))
    with pytest.raises(CorpusError) as ei:
        verified_digests(tmp_path, CLEAN, consumer_pin())
    assert ei.value.rule_id == RULE_UNVERIFIABLE and "reproduce" in str(ei.value)
