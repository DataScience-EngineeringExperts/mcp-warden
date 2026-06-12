"""Tests for #16 Sigstore keyless signing + verification of ``warden.lock``.

These tests do NOT hit the live Sigstore/Fulcio/Rekor network. They:

  * assert the deterministic statement round-trips byte-identically;
  * exercise the graceful-degrade path (extra absent) -> non-zero exit;
  * exercise the verify WIRING with a MOCKED verifier, including the full
    fail-closed matrix (every failure mode -> non-zero exit; none reach exit 0);
  * assert ``pin --sign`` leaves ``overall_digest`` byte-identical and that the
    out-of-digest pointer attestation is ignored by verify (forged pointer
    changes nothing).

The single LIVE crypto round-trip is the CI ``sigstore-e2e`` job; the committed
offline fixture (test at the bottom) SKIPS until a real bundle is dropped in.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_warden import cli_sign, signing
from mcp_warden.cli import app
from mcp_warden.cli_sign import SIDECAR_NAME, SIGNED_PROVENANCE_VERSION, _sidecar_name_for
from mcp_warden.lockfile import build_lock, read_lock, write_lock
from mcp_warden.models import CapturedSurface, CapturedTool
from mcp_warden.signing import build_statement

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = str(FIXTURES / "clean_server.py")


def _surface() -> CapturedSurface:
    return CapturedSurface(
        command="node",
        args=["./build/index.js"],
        protocol_version="2025-06-18",
        tools=[
            CapturedTool(name="read_file", description="Read a file", input_schema={"properties": {"path": {}}}),
        ],
    )


def _write_unsigned_lock(tmp_path: Path) -> tuple[Path, str]:
    lock = build_lock(_surface(), [])
    lock_path = tmp_path / "warden.lock"
    write_lock(lock, lock_path)
    return lock_path, lock.overall_digest


# --- statement determinism ---------------------------------------------------


def test_statement_roundtrip_byte_identical():
    """Sign-side and verify-side both recompute from the same digest -> identical."""
    digest = "sha256:" + "a" * 64
    sign_side = build_statement(digest)
    verify_side = build_statement(digest)
    assert sign_side == verify_side
    # And it is the exact canonical form we expect (domain separator + digest).
    assert sign_side == b'{"_type":"mcp-warden-lock-digest/v1","digest":"sha256:' + b"a" * 64 + b'"}'


def test_statement_is_key_order_independent():
    """Canonical JSON (sort_keys) makes the bytes independent of build order."""
    digest = "sha256:" + "b" * 64
    # Two semantically-identical dicts built in different key orders must produce
    # the SAME statement bytes; build_statement owns the canonicalization.
    a = build_statement(digest)
    b = build_statement(digest)
    assert a == b
    # Decode and confirm the keys are sorted (_type before digest).
    parsed = json.loads(a)
    assert list(parsed.keys()) == ["_type", "digest"]


def test_statement_differs_for_different_digest():
    assert build_statement("sha256:" + "a" * 64) != build_statement("sha256:" + "c" * 64)


# --- graceful degrade (extra absent) -----------------------------------------


def test_pin_sign_without_extra_exits_nonzero(tmp_path, monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", False)
    result = runner.invoke(
        app,
        ["pin", "python", CLEAN, "--lock", str(tmp_path / "warden.lock"), "--sign"],
    )
    assert result.exit_code != 0
    assert "mcp-warden[sigstore]" in result.output


def test_check_verify_without_extra_exits_nonzero(tmp_path, monkeypatch):
    lock_path, _ = _write_unsigned_lock(tmp_path)
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", False)
    result = runner.invoke(
        app,
        [
            "check",
            "--lock",
            str(lock_path),
            "--verify",
            "--certificate-identity",
            "id@x.invalid",
            "--certificate-oidc-issuer",
            "https://issuer.invalid",
        ],
    )
    assert result.exit_code != 0
    assert "mcp-warden[sigstore]" in result.output


def test_check_verify_requires_identity_and_issuer(tmp_path):
    lock_path, _ = _write_unsigned_lock(tmp_path)
    result = runner.invoke(app, ["check", "--lock", str(lock_path), "--verify"])
    assert result.exit_code != 0
    assert "certificate-identity" in result.output


# --- verify WIRING with a mocked verifier ------------------------------------


def _stub_sigstore_available(monkeypatch):
    """Force the signing module to believe sigstore is installed for wiring tests."""
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)


def _install_fake_verify(monkeypatch, behavior):
    """Patch cli_sign.verify_statement with a callable implementing `behavior`.

    `behavior(statement, bundle, identity, issuer)` either returns None (pass) or
    raises. We also stub bundle loading so no real bundle parsing happens.
    """
    monkeypatch.setattr(cli_sign, "verify_statement", behavior)
    monkeypatch.setattr(cli_sign, "bundle_from_json", lambda text: {"fake": "bundle"})
    _stub_sigstore_available(monkeypatch)


def _verify_cmd(lock_path: Path, identity="id@x.invalid", issuer="https://issuer.invalid", offline=None):
    args = [
        "check",
        "--lock",
        str(lock_path),
        "--verify",
        "--certificate-identity",
        identity,
        "--certificate-oidc-issuer",
        issuer,
    ]
    if offline is not None:
        args += ["--offline-bundle", str(offline)]
    return runner.invoke(app, args)


def _make_signed_lock_with_sidecar(tmp_path: Path, bundle_text: str = '{"fake":"bundle"}') -> Path:
    lock_path, _ = _write_unsigned_lock(tmp_path)
    (tmp_path / SIDECAR_NAME).write_text(bundle_text, encoding="utf-8")
    return lock_path


def test_verify_success_path_exits_zero(tmp_path, monkeypatch):
    lock_path = _make_signed_lock_with_sidecar(tmp_path)

    def ok(statement, bundle, identity, issuer):
        return None  # sigstore semantics: None on success

    _install_fake_verify(monkeypatch, ok)
    result = _verify_cmd(lock_path)
    assert result.exit_code == 0, result.output
    assert "OK" in result.output
    # Fix 2: the success message attests to the TOOL SURFACE and says findings/
    # pins/provenance are NOT covered, so it can't be read as findings integrity.
    assert "tool surface signature verified for" in result.output
    assert "findings, pins, and provenance metadata are NOT covered" in result.output


def test_verify_fails_closed_on_verification_error(tmp_path, monkeypatch):
    lock_path = _make_signed_lock_with_sidecar(tmp_path)

    def boom(statement, bundle, identity, issuer):
        raise signing.VerificationError("signature invalid")

    _install_fake_verify(monkeypatch, boom)
    result = _verify_cmd(lock_path)
    assert result.exit_code != 0


def test_verify_fails_closed_on_generic_exception_tuf_network(tmp_path, monkeypatch):
    lock_path = _make_signed_lock_with_sidecar(tmp_path)

    def boom(statement, bundle, identity, issuer):
        raise RuntimeError("TUF metadata refresh failed / network down")

    _install_fake_verify(monkeypatch, boom)
    result = _verify_cmd(lock_path)
    assert result.exit_code != 0


def test_verify_fails_closed_on_attribute_type_error(tmp_path, monkeypatch):
    """A wrong API call surfacing as AttributeError/TypeError must NOT pass."""
    lock_path = _make_signed_lock_with_sidecar(tmp_path)

    def boom(statement, bundle, identity, issuer):
        raise AttributeError("'Verifier' object has no attribute 'verify'")

    _install_fake_verify(monkeypatch, boom)
    result = _verify_cmd(lock_path)
    assert result.exit_code != 0


def test_verify_fails_closed_on_missing_sidecar(tmp_path, monkeypatch):
    lock_path, _ = _write_unsigned_lock(tmp_path)  # NO sidecar written

    def ok(statement, bundle, identity, issuer):
        return None  # would pass — but we must never reach verify

    _install_fake_verify(monkeypatch, ok)
    result = _verify_cmd(lock_path)
    assert result.exit_code != 0
    assert "not found" in result.output.lower()


def test_verify_empty_overall_digest_exits_2_before_statement(tmp_path, monkeypatch):
    """Nit A: a lock with no overall_digest -> exit 2 with a clear message, BEFORE
    any statement is built or verify is reached."""
    lock_path = _make_signed_lock_with_sidecar(tmp_path)
    # Blank the overall_digest on disk (valid str field, just empty).
    raw = json.loads(lock_path.read_text(encoding="utf-8"))
    raw["overall_digest"] = ""
    lock_path.write_text(json.dumps(raw), encoding="utf-8")

    def must_not_run(statement, bundle, identity, issuer):
        raise AssertionError("verify_statement must never be reached for an empty digest")

    _install_fake_verify(monkeypatch, must_not_run)
    result = _verify_cmd(lock_path)
    assert result.exit_code == 2, result.output
    assert "no overall_digest" in result.output.lower()


def test_verify_fails_closed_on_identity_mismatch(tmp_path, monkeypatch):
    lock_path = _make_signed_lock_with_sidecar(tmp_path)

    def reject_wrong_identity(statement, bundle, identity, issuer):
        # Real sigstore raises VerificationError when the cert SAN != expected id.
        if identity != "expected@x.invalid":
            raise signing.VerificationError("certificate identity does not match")

    _install_fake_verify(monkeypatch, reject_wrong_identity)
    result = _verify_cmd(lock_path, identity="attacker@x.invalid")
    assert result.exit_code != 0


def test_verify_fails_closed_on_malformed_bundle_json(tmp_path, monkeypatch):
    lock_path = _make_signed_lock_with_sidecar(tmp_path, bundle_text="{not valid json")
    _stub_sigstore_available(monkeypatch)

    # Real bundle_from_json raises on malformed JSON; emulate that.
    def raising_loader(text):
        raise ValueError("malformed bundle JSON")

    monkeypatch.setattr(cli_sign, "bundle_from_json", raising_loader)

    def ok(statement, bundle, identity, issuer):
        return None  # must never be reached

    monkeypatch.setattr(cli_sign, "verify_statement", ok)
    result = _verify_cmd(lock_path)
    assert result.exit_code != 0


def test_verify_fails_closed_on_statement_digest_mismatch(tmp_path, monkeypatch):
    """If the recomputed statement doesn't match what was signed, verify raises."""
    lock_path = _make_signed_lock_with_sidecar(tmp_path)
    lock_doc = read_lock(lock_path)
    signed_over = build_statement("sha256:" + "f" * 64)  # a DIFFERENT digest

    def reject_mismatch(statement, bundle, identity, issuer):
        # Real sigstore re-hashes `statement` and compares to the signed digest.
        if statement != signed_over:
            raise signing.VerificationError("digest of input does not match signature")

    _install_fake_verify(monkeypatch, reject_mismatch)
    # The CLI recomputes from lock_doc.overall_digest, which != the "signed_over"
    # digest above -> mismatch -> must fail closed.
    assert build_statement(lock_doc.overall_digest) != signed_over
    result = _verify_cmd(lock_path)
    assert result.exit_code != 0


def test_no_failure_mode_reaches_exit_zero(tmp_path, monkeypatch):
    """Aggregate guard: every modeled failure mode is strictly non-zero."""
    lock_path = _make_signed_lock_with_sidecar(tmp_path)
    failures = [
        signing.VerificationError("bad sig"),
        RuntimeError("network"),
        AttributeError("api drift"),
        TypeError("api drift"),
    ]
    for exc in failures:
        def boom(statement, bundle, identity, issuer, _exc=exc):
            raise _exc

        _install_fake_verify(monkeypatch, boom)
        result = _verify_cmd(lock_path)
        assert result.exit_code != 0, f"{type(exc).__name__} unexpectedly passed"


# --- pin --sign integrity (signature is OUT of overall_digest) ---------------


def _install_fake_signer(monkeypatch, bundle_json='{"fake":"signed-bundle"}'):
    """Patch cli_sign.sign_statement + bundle_to_json so pin --sign needs no network."""
    _stub_sigstore_available(monkeypatch)
    monkeypatch.setattr(cli_sign, "sign_statement", lambda statement, token: {"stmt": statement})
    monkeypatch.setattr(cli_sign, "bundle_to_json", lambda bundle: bundle_json)


def test_pin_sign_leaves_overall_digest_unchanged(tmp_path, monkeypatch):
    """A signed pin's overall_digest == an unsigned pin of the same surface."""
    # Unsigned reference pin (no --sign).
    unsigned_lock = tmp_path / "unsigned.lock"
    r1 = runner.invoke(app, ["pin", "python", CLEAN, "--lock", str(unsigned_lock)])
    assert r1.exit_code == 0, r1.output
    unsigned_digest = read_lock(unsigned_lock).overall_digest

    # Signed pin of the same server (use the default lock name so the expected
    # sidecar name is the canonical default "warden.lock.sigstore").
    _install_fake_signer(monkeypatch)
    signed_lock = tmp_path / "warden.lock"
    r2 = runner.invoke(app, ["pin", "python", CLEAN, "--lock", str(signed_lock), "--sign"])
    assert r2.exit_code == 0, r2.output
    signed = read_lock(signed_lock)

    # Signature is out-of-digest: the digest must be byte-identical.
    assert signed.overall_digest == unsigned_digest

    # The sidecar was written next to the lock with the DERIVED name.
    expected_sidecar = tmp_path / _sidecar_name_for(signed_lock)
    assert expected_sidecar.exists()
    assert expected_sidecar.read_text() == '{"fake":"signed-bundle"}'
    # When the lock is named "warden.lock" the derived name == the canonical default.
    assert expected_sidecar.name == SIDECAR_NAME

    # The out-of-digest pointer attestation is present + bumped provenance_version.
    pointers = [a for a in signed.pin.attestations if a.method == "sigstore-keyless"]
    assert len(pointers) == 1
    assert pointers[0].signature_bundle == _sidecar_name_for(signed_lock)
    assert pointers[0].bound_digest == signed.overall_digest
    assert signed.pin.provenance_version == SIGNED_PROVENANCE_VERSION


def test_pin_sign_failclosed_leaves_no_partial_sidecar(tmp_path, monkeypatch):
    """A signing error exits non-zero and does not leave a half-written sidecar."""
    _stub_sigstore_available(monkeypatch)

    def boom(statement, token):
        raise signing.SigningError("no ambient OIDC credential available")

    monkeypatch.setattr(cli_sign, "sign_statement", boom)
    lock_path = tmp_path / "warden.lock"
    result = runner.invoke(app, ["pin", "python", CLEAN, "--lock", str(lock_path), "--sign"])
    assert result.exit_code != 0
    # No sidecar (and no .tmp) left behind.
    assert not (tmp_path / SIDECAR_NAME).exists()
    assert not (tmp_path / (SIDECAR_NAME + ".tmp")).exists()


def test_pin_sign_sidecar_promotion_failure_leaves_neither(tmp_path, monkeypatch):
    """Fix 3 invariant: if the FINAL temp-sidecar -> fixed-sidecar promotion fails
    AFTER the pointer-bearing lock is written, restore the unsigned lock and leave
    NEITHER a .sigstore NOR a .tmp behind (BOTH-or-NEITHER)."""
    _install_fake_signer(monkeypatch)

    # Force the final os.replace (temp sidecar -> fixed name) to fail, but only
    # when the destination is our fixed sidecar (so write_lock's own I/O is intact).
    real_replace = os.replace

    def failing_replace(src, dst, *a, **k):
        if str(dst).endswith(SIDECAR_NAME):
            raise OSError("simulated sidecar promotion failure")
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(cli_sign.os, "replace", failing_replace)

    lock_path = tmp_path / "warden.lock"
    result = runner.invoke(app, ["pin", "python", CLEAN, "--lock", str(lock_path), "--sign"])
    assert result.exit_code != 0, result.output
    # Neither the sidecar nor the temp file remains.
    assert not (tmp_path / SIDECAR_NAME).exists()
    assert not (tmp_path / (SIDECAR_NAME + ".tmp")).exists()
    # The lock on disk was restored to its UNSIGNED form (no signer pointer,
    # provenance_version not bumped) so it never claims a signature it can't back.
    restored = read_lock(lock_path)
    signers = [a for a in restored.pin.attestations if a.method == "sigstore-keyless"]
    assert signers == []
    assert restored.pin.provenance_version != SIGNED_PROVENANCE_VERSION


# --- pointer is IGNORED by verify (forged pointer changes nothing) -----------


def test_verify_ignores_forged_pointer_uses_fixed_sidecar(tmp_path, monkeypatch):
    """A lock whose pointer names an attacker path / forged digest still verifies
    only against the FIXED sidecar + recomputed statement."""
    lock_path = _make_signed_lock_with_sidecar(tmp_path)
    lock_doc = read_lock(lock_path)

    # Forge the pointer: point signature_bundle at an attacker-controlled file and
    # forge bound_digest. Write a malicious "bundle" at that attacker path that, if
    # ever read, would be honored by the fake verifier.
    attacker_bundle = tmp_path / "attacker.sigstore"
    attacker_bundle.write_text('{"attacker":"bundle"}', encoding="utf-8")
    from mcp_warden.provenance import make_sigstore_pointer_attestation

    forged = make_sigstore_pointer_attestation(
        bound_digest="sha256:" + "0" * 64,  # forged
        signature_bundle=str(attacker_bundle),  # attacker absolute path
        actor="attacker",
        now="2026-06-09T00:00:00Z",
    )
    lock_doc.pin.attestations = [*lock_doc.pin.attestations, forged]
    lock_doc.pin.provenance_version = SIGNED_PROVENANCE_VERSION
    write_lock(lock_doc, lock_path)

    seen = {}

    def record(statement, bundle, identity, issuer):
        seen["statement"] = statement
        seen["bundle"] = bundle
        return None

    _stub_sigstore_available(monkeypatch)
    monkeypatch.setattr(cli_sign, "verify_statement", record)
    # bundle_from_json returns a tagged object so we can prove WHICH file was read.
    monkeypatch.setattr(cli_sign, "bundle_from_json", lambda text: {"loaded_text": text})

    result = _verify_cmd(lock_path)
    assert result.exit_code == 0, result.output
    # Proof 1: the statement verified is recomputed from the REAL overall_digest,
    # NOT the forged bound_digest in the pointer.
    assert seen["statement"] == build_statement(lock_doc.overall_digest)
    assert seen["statement"] != build_statement("sha256:" + "0" * 64)
    # Proof 2: the bundle loaded is the FIXED sidecar content, not the attacker file.
    assert seen["bundle"]["loaded_text"] == '{"fake":"bundle"}'
    assert seen["bundle"]["loaded_text"] != '{"attacker":"bundle"}'


# --- offline-bundle override -------------------------------------------------


def test_verify_offline_bundle_override(tmp_path, monkeypatch):
    """--offline-bundle reads the explicit path instead of the fixed sidecar."""
    lock_path, _ = _write_unsigned_lock(tmp_path)  # no fixed sidecar
    explicit = tmp_path / "elsewhere" / "my.sigstore"
    explicit.parent.mkdir()
    explicit.write_text('{"explicit":"bundle"}', encoding="utf-8")

    seen = {}

    def record(statement, bundle, identity, issuer):
        seen["bundle"] = bundle
        return None

    _stub_sigstore_available(monkeypatch)
    monkeypatch.setattr(cli_sign, "verify_statement", record)
    monkeypatch.setattr(cli_sign, "bundle_from_json", lambda text: {"loaded_text": text})

    result = _verify_cmd(lock_path, offline=explicit)
    assert result.exit_code == 0, result.output
    assert seen["bundle"]["loaded_text"] == '{"explicit":"bundle"}'


# --- sign_statement explicit-token fail-closed -------------------------------


def test_sign_statement_empty_token_fails_closed():
    """An explicit-but-empty token raises (never falls back to ambient)."""
    if not signing._SIGSTORE_AVAILABLE:
        pytest.skip("sigstore extra not installed")
    with pytest.raises(signing.SigningError):
        signing.sign_statement(build_statement("sha256:" + "a" * 64), "   ")


def test_sign_statement_invalid_token_fails_closed():
    """An explicit malformed token raises SigningError, not ambient fallback."""
    if not signing._SIGSTORE_AVAILABLE:
        pytest.skip("sigstore extra not installed")
    with pytest.raises(signing.SigningError):
        signing.sign_statement(build_statement("sha256:" + "a" * 64), "not-a-jwt")


# --- sidecar name derivation (root-cause regression tests for #16 fix) --------


def test_sidecar_name_default_lock():
    """Default lock name produces the canonical default sidecar name."""
    assert _sidecar_name_for(Path("warden.lock")) == "warden.lock.sigstore"
    assert _sidecar_name_for(Path("/some/dir/warden.lock")) == "warden.lock.sigstore"


def test_sidecar_name_non_default_lock():
    """Non-default lock name (e.g. e2e.warden.lock) derives the correct sidecar name.

    Root-cause regression: the old _sidecar_path_for used a fixed constant
    'warden.lock.sigstore' regardless of the lock filename, so a pin with
    --lock e2e.warden.lock wrote the sidecar as 'warden.lock.sigstore' instead of
    'e2e.warden.lock.sigstore'. The CI workflow then ran `test -f e2e.warden.lock.sigstore`
    and failed, producing a silent exit-1 (the pin table was already printed before
    the test ran, so no error message appeared in the log).
    """
    assert _sidecar_name_for(Path("e2e.warden.lock")) == "e2e.warden.lock.sigstore"
    assert _sidecar_name_for(Path("/work/e2e.warden.lock")) == "e2e.warden.lock.sigstore"


def test_pin_sign_sidecar_colocated_with_non_default_lock(tmp_path, monkeypatch):
    """pin --sign with a non-default --lock name writes the sidecar next to that lock.

    Regression test: before the fix, pin --lock e2e.warden.lock --sign wrote the
    sidecar as 'warden.lock.sigstore' (fixed constant), not 'e2e.warden.lock.sigstore'.
    """
    _install_fake_signer(monkeypatch)
    e2e_lock = tmp_path / "e2e.warden.lock"
    result = runner.invoke(app, ["pin", "python", CLEAN, "--lock", str(e2e_lock), "--sign"])
    assert result.exit_code == 0, result.output
    # The sidecar MUST be next to the lock with the DERIVED name.
    assert (tmp_path / "e2e.warden.lock.sigstore").exists(), (
        "sidecar 'e2e.warden.lock.sigstore' not found; was it written as 'warden.lock.sigstore'?"
    )
    # The OLD wrong path must NOT exist.
    assert not (tmp_path / "warden.lock.sigstore").exists(), (
        "old fixed-constant sidecar 'warden.lock.sigstore' was created instead of the correct name"
    )
    # Pointer attestation in the lock should also carry the derived name.
    signed = read_lock(e2e_lock)
    pointers = [a for a in signed.pin.attestations if a.method == "sigstore-keyless"]
    assert len(pointers) == 1
    assert pointers[0].signature_bundle == "e2e.warden.lock.sigstore"


# --- signing failure is LOUD (error on stderr, non-zero exit) -------------------


def test_sign_failure_is_loud(tmp_path, monkeypatch):
    """A sign failure MUST print a structured error to stderr AND exit non-zero.

    The root-cause incident showed a silent exit-1: the pin table was printed to
    stdout but no error appeared in the CI log. This test asserts that ANY
    signing failure always emits '[red]signing failed:[/red]' to stderr before
    the non-zero exit, so the operator knows WHY it failed.
    """
    _stub_sigstore_available(monkeypatch)

    def noisy_boom(statement, token):
        raise signing.SigningError("no ambient OIDC credential available; id-token permission missing")

    monkeypatch.setattr(cli_sign, "sign_statement", noisy_boom)
    lock_path = tmp_path / "warden.lock"
    result = runner.invoke(
        app,
        ["pin", "python", CLEAN, "--lock", str(lock_path), "--sign"],
        catch_exceptions=False,
    )
    assert result.exit_code != 0, "a signing failure must exit non-zero"
    # The error marker must appear somewhere in the combined output so the
    # operator can see WHY it failed.
    combined = result.output
    assert "signing failed" in combined.lower(), (
        f"signing failure was silent — no 'signing failed' in output:\n{combined!r}"
    )


# --- committed offline fixture (SKIPS until a real bundle is dropped in) ------


SIGNED_FIXTURE_DIR = FIXTURES / "signed"
SIGNED_FIXTURE_BUNDLE = SIGNED_FIXTURE_DIR / "warden.lock.sigstore"
SIGNED_FIXTURE_LOCK = SIGNED_FIXTURE_DIR / "warden.lock"
#: The fixture's signer identity is pinned to the DEDICATED, contractually-stable
#: workflow path. NEVER rename .github/workflows/sigstore-fixture.yml or this
#: identity breaks (see docs/SIGNING.md).
FIXTURE_IDENTITY = (
    "https://github.com/ernestprovo23/mcp-warden/"
    ".github/workflows/sigstore-fixture.yml@refs/heads/main"
)
FIXTURE_ISSUER = "https://token.actions.githubusercontent.com"


def test_offline_fixture_verifies_when_present():
    """Verify the committed fixture OFFLINE against its pinned identity.

    SKIPS cleanly until a real bundle is dropped in from the first
    sigstore-fixture.yml run's artifact (see docs/SIGNING.md refresh steps).
    """
    if not signing._SIGSTORE_AVAILABLE:
        pytest.skip("sigstore extra not installed")
    if not SIGNED_FIXTURE_BUNDLE.exists() or not SIGNED_FIXTURE_LOCK.exists():
        pytest.skip("committed signed fixture not present yet (run sigstore-fixture.yml)")

    lock_doc = read_lock(SIGNED_FIXTURE_LOCK)
    statement = build_statement(lock_doc.overall_digest)
    bundle = signing.bundle_from_json(SIGNED_FIXTURE_BUNDLE.read_text(encoding="utf-8"))
    # No exception == pass; any failure raises and fails the test.
    signing.verify_statement(
        statement, bundle, identity=FIXTURE_IDENTITY, issuer=FIXTURE_ISSUER
    )
