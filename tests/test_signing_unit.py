"""Unit tests for the sigstore trust-root wiring in :mod:`mcp_warden.signing`.

The sibling ``test_signing.py`` exercises the CLI-level wiring by mocking the
``sign_statement`` / ``verify_statement`` seams from *cli_sign*. This module goes
one layer deeper: it drives the *internal* sign/verify code paths inside
``signing.py`` itself by monkeypatching the pinned sigstore boundary symbols
(``_ClientTrustConfig``, ``_SigningContext``, ``_Verifier``, ``_policy``,
``_IdentityToken``, ``_detect_credential``, ``_Bundle``).

NO real network, OIDC, TUF, or Fulcio/Rekor traffic occurs — every sigstore
object is a local fake. This covers the sign path, the verify path,
certificate-identity/issuer plumbing, and the fail-closed error branches that the
CLI-level tests cannot reach (they stub the functions out entirely).
"""

from __future__ import annotations

import warnings

import pytest

from mcp_warden import signing
from mcp_warden.signing import (
    SigningError,
    build_statement,
    bundle_from_json,
    bundle_to_json,
    sign_statement,
    verify_statement,
)

_DIGEST = "sha256:" + "a" * 64


# --- fakes for the sigstore boundary -----------------------------------------


class _FakeSigner:
    """Context-manager signer whose ``sign_artifact`` returns a sentinel bundle."""

    def __init__(self, recorder: dict):
        self._recorder = recorder

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def sign_artifact(self, statement_bytes: bytes):
        self._recorder["signed_bytes"] = statement_bytes
        return {"bundle": "signed", "over": statement_bytes}


def _install_fake_sign_boundary(monkeypatch, recorder: dict):
    """Wire every sigstore sign-side symbol to a local fake (no network)."""
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)

    class _FakeTrustConfig:
        @staticmethod
        def production():
            return "trust-config-sentinel"

    class _FakeCtx:
        def signer(self, identity):
            recorder["identity"] = identity
            return _FakeSigner(recorder)

    def _from_trust_config(trust_config):
        recorder["trust_config"] = trust_config
        return _FakeCtx()

    def _identity_token(raw):
        recorder["raw_token"] = raw
        return f"identity({raw})"

    monkeypatch.setattr(signing, "_ClientTrustConfig", _FakeTrustConfig)
    monkeypatch.setattr(
        signing, "_SigningContext", type("SC", (), {"from_trust_config": staticmethod(_from_trust_config)})
    )
    monkeypatch.setattr(signing, "_IdentityToken", _identity_token)


# --- _sigstore_version_tuple -------------------------------------------------


def test_version_tuple_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", False)
    assert signing._sigstore_version_tuple() is None


def test_version_tuple_parses_installed_version():
    if not signing._SIGSTORE_AVAILABLE:
        pytest.skip("sigstore extra not installed")
    ver = signing._sigstore_version_tuple()
    assert ver is not None
    assert len(ver) == 3
    assert all(isinstance(n, int) for n in ver)


def test_version_tuple_pads_short_version(monkeypatch):
    if not signing._SIGSTORE_AVAILABLE:
        pytest.skip("sigstore extra not installed")
    import sigstore

    monkeypatch.setattr(sigstore, "__version__", "4", raising=False)
    assert signing._sigstore_version_tuple() == (4, 0, 0)


def test_version_tuple_returns_none_on_unparseable(monkeypatch):
    if not signing._SIGSTORE_AVAILABLE:
        pytest.skip("sigstore extra not installed")
    import sigstore

    monkeypatch.setattr(sigstore, "__version__", "not.a.version", raising=False)
    assert signing._sigstore_version_tuple() is None


# --- _warn_if_unpinned_version ----------------------------------------------


def test_warn_noop_when_version_none(monkeypatch):
    monkeypatch.setattr(signing, "_sigstore_version_tuple", lambda: None)
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning would raise
        signing._warn_if_unpinned_version()  # must NOT warn


def test_warn_noop_when_version_in_window(monkeypatch):
    monkeypatch.setattr(signing, "_sigstore_version_tuple", lambda: (4, 3, 0))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        signing._warn_if_unpinned_version()  # in-window -> silent


def test_warn_below_window(monkeypatch):
    monkeypatch.setattr(signing, "_sigstore_version_tuple", lambda: (4, 2, 9))
    with pytest.warns(RuntimeWarning, match="Crypto-API drift"):
        signing._warn_if_unpinned_version()


def test_warn_above_window(monkeypatch):
    monkeypatch.setattr(signing, "_sigstore_version_tuple", lambda: (5, 0, 0))
    with pytest.warns(RuntimeWarning, match="Crypto-API drift"):
        signing._warn_if_unpinned_version()


# --- sign_statement: unavailable + identity resolution -----------------------


def test_sign_unavailable_raises(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", False)
    with pytest.raises(SigningError, match="mcp-warden\\[sigstore\\]"):
        sign_statement(build_statement(_DIGEST), None)


def test_sign_ambient_no_credential_raises(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(signing, "_warn_if_unpinned_version", lambda: None)
    monkeypatch.setattr(signing, "_detect_credential", lambda: None)
    with pytest.raises(SigningError, match="no ambient OIDC credential"):
        sign_statement(build_statement(_DIGEST), None)


def test_sign_ambient_empty_string_credential_raises(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(signing, "_warn_if_unpinned_version", lambda: None)
    monkeypatch.setattr(signing, "_detect_credential", lambda: "")
    with pytest.raises(SigningError, match="no ambient OIDC credential"):
        sign_statement(build_statement(_DIGEST), None)


def test_sign_explicit_empty_token_raises(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(signing, "_warn_if_unpinned_version", lambda: None)
    with pytest.raises(SigningError, match="empty"):
        sign_statement(build_statement(_DIGEST), "   ")


def test_sign_invalid_token_raises(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(signing, "_warn_if_unpinned_version", lambda: None)

    def _bad_identity(raw):
        raise ValueError("malformed JWT")

    monkeypatch.setattr(signing, "_IdentityToken", _bad_identity)
    with pytest.raises(SigningError, match="identity token is invalid"):
        sign_statement(build_statement(_DIGEST), "not-a-jwt")


# --- sign_statement: success paths -------------------------------------------


def test_sign_explicit_token_success(monkeypatch):
    recorder: dict = {}
    monkeypatch.setattr(signing, "_warn_if_unpinned_version", lambda: None)
    _install_fake_sign_boundary(monkeypatch, recorder)

    statement = build_statement(_DIGEST)
    bundle = sign_statement(statement, "my-explicit-token")

    assert bundle == {"bundle": "signed", "over": statement}
    # The explicit token was passed straight through to IdentityToken.
    assert recorder["raw_token"] == "my-explicit-token"
    assert recorder["signed_bytes"] == statement
    assert recorder["trust_config"] == "trust-config-sentinel"


def test_sign_ambient_token_success(monkeypatch):
    recorder: dict = {}
    monkeypatch.setattr(signing, "_warn_if_unpinned_version", lambda: None)
    monkeypatch.setattr(signing, "_detect_credential", lambda: "ambient-token")
    _install_fake_sign_boundary(monkeypatch, recorder)

    statement = build_statement(_DIGEST)
    bundle = sign_statement(statement, None)

    assert bundle == {"bundle": "signed", "over": statement}
    assert recorder["raw_token"] == "ambient-token"


def test_sign_signing_operation_failure_wrapped(monkeypatch):
    """A failure inside the sigstore signer is wrapped as SigningError (fail closed)."""
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(signing, "_warn_if_unpinned_version", lambda: None)
    monkeypatch.setattr(signing, "_IdentityToken", lambda raw: "identity")

    class _BoomTrustConfig:
        @staticmethod
        def production():
            raise RuntimeError("fulcio unreachable")

    monkeypatch.setattr(signing, "_ClientTrustConfig", _BoomTrustConfig)
    with pytest.raises(SigningError, match="sigstore signing failed"):
        sign_statement(build_statement(_DIGEST), "token")


def test_sign_signer_sign_artifact_failure_wrapped(monkeypatch):
    """An exception raised inside sign_artifact is caught and re-raised closed."""
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(signing, "_warn_if_unpinned_version", lambda: None)
    monkeypatch.setattr(signing, "_IdentityToken", lambda raw: "identity")

    class _FailSigner:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def sign_artifact(self, _b):
            raise RuntimeError("rekor rejected the entry")

    class _Ctx:
        def signer(self, identity):
            return _FailSigner()

    monkeypatch.setattr(
        signing, "_ClientTrustConfig", type("TC", (), {"production": staticmethod(lambda: "cfg")})
    )
    monkeypatch.setattr(
        signing, "_SigningContext", type("SC", (), {"from_trust_config": staticmethod(lambda cfg: _Ctx())})
    )
    with pytest.raises(SigningError, match="sigstore signing failed"):
        sign_statement(build_statement(_DIGEST), "token")


# --- verify_statement --------------------------------------------------------


def _install_fake_verify_boundary(monkeypatch, recorder: dict, *, verify_impl=None):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(signing, "_warn_if_unpinned_version", lambda: None)

    class _FakeVerifier:
        @staticmethod
        def production():
            return _FakeVerifier()

        def verify_artifact(self, statement_bytes, bundle, policy):
            recorder["statement"] = statement_bytes
            recorder["bundle"] = bundle
            recorder["policy"] = policy
            if verify_impl is not None:
                verify_impl(statement_bytes, bundle, policy)

    def _identity(identity, issuer):
        recorder["identity"] = identity
        recorder["issuer"] = issuer
        return ("policy", identity, issuer)

    monkeypatch.setattr(signing, "_Verifier", _FakeVerifier)
    monkeypatch.setattr(signing, "_policy", type("P", (), {"Identity": staticmethod(_identity)}))


def test_verify_unavailable_raises(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="mcp-warden\\[sigstore\\]"):
        verify_statement(build_statement(_DIGEST), object(), "id@x", "https://issuer")


def test_verify_success_returns_none_and_plumbs_identity_issuer(monkeypatch):
    recorder: dict = {}
    _install_fake_verify_boundary(monkeypatch, recorder)
    statement = build_statement(_DIGEST)
    result = verify_statement(statement, {"b": 1}, "id@x.invalid", "https://issuer.invalid")
    assert result is None
    # Identity + issuer were threaded into policy.Identity exactly.
    assert recorder["identity"] == "id@x.invalid"
    assert recorder["issuer"] == "https://issuer.invalid"
    assert recorder["statement"] == statement
    assert recorder["bundle"] == {"b": 1}
    assert recorder["policy"] == ("policy", "id@x.invalid", "https://issuer.invalid")


def test_verify_propagates_verification_error(monkeypatch):
    recorder: dict = {}

    def _boom(statement, bundle, policy):
        raise signing.VerificationError("certificate identity does not match")

    _install_fake_verify_boundary(monkeypatch, recorder, verify_impl=_boom)
    with pytest.raises(signing.VerificationError, match="does not match"):
        verify_statement(build_statement(_DIGEST), {}, "wrong@x", "https://issuer")


def test_verify_propagates_generic_error(monkeypatch):
    recorder: dict = {}

    def _boom(statement, bundle, policy):
        raise RuntimeError("TUF metadata refresh failed")

    _install_fake_verify_boundary(monkeypatch, recorder, verify_impl=_boom)
    with pytest.raises(RuntimeError, match="TUF metadata"):
        verify_statement(build_statement(_DIGEST), {}, "id@x", "https://issuer")


# --- bundle_to_json / bundle_from_json ---------------------------------------


def test_bundle_to_json_delegates():
    class _B:
        def to_json(self):
            return '{"round":"trip"}'

    assert bundle_to_json(_B()) == '{"round":"trip"}'


def test_bundle_from_json_unavailable_raises(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="mcp-warden\\[sigstore\\]"):
        bundle_from_json('{"x":1}')


def test_bundle_from_json_delegates(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)
    recorder: dict = {}

    class _FakeBundle:
        @staticmethod
        def from_json(text):
            recorder["text"] = text
            return {"parsed": text}

    monkeypatch.setattr(signing, "_Bundle", _FakeBundle)
    out = bundle_from_json('{"real":"bundle"}')
    assert out == {"parsed": '{"real":"bundle"}'}
    assert recorder["text"] == '{"real":"bundle"}'


def test_bundle_from_json_propagates_parse_error(monkeypatch):
    monkeypatch.setattr(signing, "_SIGSTORE_AVAILABLE", True)

    class _FakeBundle:
        @staticmethod
        def from_json(text):
            raise ValueError("malformed bundle JSON")

    monkeypatch.setattr(signing, "_Bundle", _FakeBundle)
    with pytest.raises(ValueError, match="malformed bundle"):
        bundle_from_json("{not valid json")
