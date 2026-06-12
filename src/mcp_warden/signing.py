"""Sigstore keyless signing + verification of a ``warden.lock`` digest (#16).

This module signs and verifies a tiny, deterministic *statement* that binds ONLY
the lock's ``overall_digest`` (the definition-portion digest), NEVER the whole
lock JSON. Binding the digest (not the file) means out-of-digest mutations —
``warden lock rotate`` (#19), added attestations, new provenance fields — do NOT
invalidate a previously-produced signature: the signed thing is the surface
identity, not the bytes of the file.

Crypto correctness is the entire point of this tool, so the design fails CLOSED
everywhere:

  * The ONLY graceful-degrade path is ``except ImportError`` at import time. If
    the optional ``sigstore`` extra is not installed, ``_SIGSTORE_AVAILABLE`` is
    ``False`` and the CLI refuses to sign/verify (non-zero exit) rather than
    pretending success.
  * :func:`verify_statement` RAISES on any failure (it returns ``None`` on
    success). It never returns a truthy/falsy "result" that a caller could
    mis-read as a pass. Success is defined as "no exception raised".
  * An explicit identity token that is empty/invalid is a hard failure; we never
    silently fall back to ambient OIDC when the operator asked for a specific
    identity.

Verified against the INSTALLED sigstore (4.3.0). Pinned API (see module-level
constants and the guarded import below):

  * Sign:   ``ClientTrustConfig.production()`` -> ``SigningContext.from_trust_config(cfg)``
            -> ``ctx.signer(IdentityToken(raw)) as signer`` -> ``signer.sign_artifact(bytes) -> Bundle``.
            Raw-artifact (hashedrekord) signing, NOT DSSE.
  * Verify: ``Verifier.production()`` -> ``v.verify_artifact(bytes, bundle, policy.Identity(identity=..., issuer=...)) -> None``;
            raises ``sigstore.errors.VerificationError`` on failure.
  * Bundle: ``Bundle.to_json() -> str`` / ``Bundle.from_json(str) -> Bundle``.

NOTE on the conclave brief: it asserted ``Verifier.production`` has NO ``offline``
kwarg in 4.3.0. The INSTALLED 4.3.0 source DOES expose ``production(*, offline:
bool = False)``. Per instruction, the implementation FOLLOWS THE INSTALLED API:
we simply call ``Verifier.production()`` (default ``offline=False``) and never
pass a kwarg that the verify call doesn't accept.
"""

from __future__ import annotations

import json
import warnings

#: The statement ``_type`` domain separator (raw-bytes / hashedrekord signing).
#: Byte-identical at sign time and verify time; changing it is a breaking change.
STATEMENT_TYPE = "mcp-warden-lock-digest/v1"

#: Lower (inclusive) / upper (exclusive) supported sigstore versions. Outside this
#: window we ``warnings.warn`` (not error): the API may have shifted under us and a
#: silent shift on a security verifier is exactly what we must surface loudly.
_MIN_SIGSTORE = (4, 3, 0)
_MAX_SIGSTORE = (5, 0, 0)

try:
    # Pinned, VERIFIED public imports for the installed sigstore (4.3.0).
    from sigstore.errors import VerificationError as _VerificationError
    from sigstore.models import Bundle as _Bundle
    from sigstore.oidc import IdentityToken as _IdentityToken
    from sigstore.oidc import detect_credential as _detect_credential
    from sigstore.sign import ClientTrustConfig as _ClientTrustConfig
    from sigstore.sign import SigningContext as _SigningContext
    from sigstore.verify import Verifier as _Verifier
    from sigstore.verify import policy as _policy

    _SIGSTORE_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via monkeypatch in tests
    # `except ImportError` is the ONLY graceful-degrade path. Everything below is
    # named so the module still imports; the CLI must check _SIGSTORE_AVAILABLE.
    _SIGSTORE_AVAILABLE = False
    _VerificationError = Exception  # type: ignore[assignment,misc]
    _Bundle = object  # type: ignore[assignment,misc]
    _IdentityToken = object  # type: ignore[assignment,misc]
    _detect_credential = None  # type: ignore[assignment]
    _ClientTrustConfig = object  # type: ignore[assignment,misc]
    _SigningContext = object  # type: ignore[assignment,misc]
    _Verifier = object  # type: ignore[assignment,misc]
    _policy = None  # type: ignore[assignment]


#: Re-exported for callers that want to catch the verify failure precisely. When
#: sigstore is absent this is plain ``Exception`` (verify is unreachable anyway —
#: the CLI gates on ``_SIGSTORE_AVAILABLE`` first).
VerificationError = _VerificationError


class SigningError(RuntimeError):
    """Raised on any signing-side failure (fail closed; no partial sidecar)."""


def _sigstore_version_tuple() -> tuple[int, int, int] | None:
    """Parse ``sigstore.__version__`` to a ``(major, minor, patch)`` tuple.

    Returns:
        The parsed tuple, or ``None`` if sigstore is absent or the version string
        cannot be parsed (in which case the caller skips the range warning).
    """
    if not _SIGSTORE_AVAILABLE:
        return None
    try:
        import sigstore

        parts = str(sigstore.__version__).split(".")[:3]
        nums = tuple(int(p) for p in parts)
        # pad to 3 so comparisons are total
        while len(nums) < 3:
            nums = (*nums, 0)
        return (nums[0], nums[1], nums[2])
    except (ImportError, ValueError, AttributeError):
        return None


def _warn_if_unpinned_version() -> None:
    """Emit a (non-fatal) warning if the installed sigstore is outside the window.

    A security verifier silently riding an untested API version is a latent
    fail-open, so we make the operator aware. We do NOT raise: a newer sigstore is
    likely fine and the verify call itself still fails closed on any real problem.
    """
    ver = _sigstore_version_tuple()
    if ver is None:
        return
    if ver < _MIN_SIGSTORE or ver >= _MAX_SIGSTORE:
        warnings.warn(
            f"mcp-warden signing was verified against sigstore "
            f"[{'.'.join(map(str, _MIN_SIGSTORE))}, {'.'.join(map(str, _MAX_SIGSTORE))}); "
            f"installed sigstore is {'.'.join(map(str, ver))}. Crypto-API drift is "
            f"possible — verify behaviour before trusting results.",
            RuntimeWarning,
            stacklevel=2,
        )


def build_statement(overall_digest: str) -> bytes:
    """Build the DETERMINISTIC statement bytes bound to ``overall_digest``.

    The statement is canonical JSON: keys sorted, no whitespace, so it is
    byte-identical at sign time and verify time when both recompute it from the
    same ``overall_digest``. ``_type`` is the domain separator (raw-bytes
    signing). This function is the single source of truth for both sides.

    Args:
        overall_digest: The lock's ``overall_digest`` VERBATIM, i.e. the
            ``"sha256:<64 lowercase hex>"`` form this repo stores (the
            ``sha256:`` prefix is kept — both sign and verify pass it unchanged).

    Returns:
        The UTF-8 canonical-JSON statement bytes.
    """
    statement = {"_type": STATEMENT_TYPE, "digest": overall_digest}
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_statement(statement_bytes: bytes, identity_token: str | None):
    """Sign ``statement_bytes`` with Sigstore keyless signing; return a ``Bundle``.

    Identity resolution (fail closed on an explicit-but-bad token):

      * ``identity_token is None`` -> ambient/CI OIDC via
        :func:`sigstore.oidc.detect_credential`. If no ambient credential is
        available, this raises :class:`SigningError` (never silently no-ops).
      * a non-empty ``identity_token`` -> that exact token. An empty or malformed
        token RAISES :class:`SigningError`; we NEVER fall back to ambient when the
        caller asked for a specific identity.

    Args:
        statement_bytes: The output of :func:`build_statement` (signed verbatim as
            raw artifact bytes / hashedrekord).
        identity_token: An explicit OIDC token, or ``None`` for ambient OIDC.

    Returns:
        A sigstore ``Bundle`` (serialize with ``bundle.to_json()``).

    Raises:
        SigningError: If sigstore is unavailable, no/!invalid identity is
            resolved, or the signing operation fails for any reason. Fails CLOSED.
    """
    if not _SIGSTORE_AVAILABLE:
        raise SigningError("sigstore is not installed; run: pip install 'mcp-warden[sigstore]'")

    _warn_if_unpinned_version()

    # --- resolve identity (fail closed) ------------------------------------
    if identity_token is None:
        raw_token = _detect_credential()  # type: ignore[misc]
        if not raw_token:
            raise SigningError(
                "no ambient OIDC credential available; run inside a CI provider with "
                "id-token permission, or pass --identity-token"
            )
    else:
        # An explicit-but-empty token is a hard error: do NOT fall back to ambient.
        if not identity_token.strip():
            raise SigningError("--identity-token was given but is empty")
        raw_token = identity_token

    try:
        # The OIDC JWT (from detect_credential / passed-in token) is NEVER written
        # to disk or logged — only the resulting Fulcio public certificate ends up
        # embedded in the Bundle. We deliberately do not echo `raw_token` anywhere.
        identity = _IdentityToken(raw_token)  # malformed token -> raises here
    except Exception as exc:  # noqa: BLE001 - any token error is fail-closed
        raise SigningError(f"identity token is invalid: {exc}") from exc

    try:
        trust_config = _ClientTrustConfig.production()
        signing_ctx = _SigningContext.from_trust_config(trust_config)
        with signing_ctx.signer(identity) as signer:
            bundle = signer.sign_artifact(statement_bytes)
    except SigningError:
        raise
    except Exception as exc:  # noqa: BLE001 - any signing failure is fail-closed
        raise SigningError(f"sigstore signing failed: {exc}") from exc

    return bundle


def verify_statement(statement_bytes: bytes, bundle, identity: str, issuer: str) -> None:
    """Verify a Sigstore ``Bundle`` over ``statement_bytes`` for ``identity``/``issuer``.

    On SUCCESS this returns ``None`` (i.e. it simply does not raise). On ANY
    failure it RAISES. Callers MUST treat "no exception" as the only success
    signal and MUST NOT inspect a return value — there is none.

    The underlying ``Verifier.verify_artifact`` re-derives the SHA-256 of
    ``statement_bytes`` and checks the certificate identity/issuer against the
    supplied policy, so a mismatched statement or wrong identity fails closed
    inside sigstore.

    Args:
        statement_bytes: The output of :func:`build_statement`, RECOMPUTED on the
            verify side from the lock's own ``overall_digest`` (never trusted from
            an attacker-controlled pointer field).
        bundle: A sigstore ``Bundle`` (load with ``Bundle.from_json(text)``).
        identity: The expected certificate SAN identity (e.g. the CI workflow ref).
        issuer: The expected OIDC issuer (e.g.
            ``https://token.actions.githubusercontent.com``).

    Raises:
        VerificationError: If signature/identity/issuer verification fails.
        RuntimeError: If sigstore is unavailable (caller should gate first).
        Exception: Any other error (TUF/network/type errors) propagates so the
            CLI fails CLOSED — it catches broadly and exits non-zero.
    """
    if not _SIGSTORE_AVAILABLE:
        raise RuntimeError("sigstore is not installed; run: pip install 'mcp-warden[sigstore]'")

    _warn_if_unpinned_version()

    verifier = _Verifier.production()
    # `policy.Identity` performs EXACT-string equality, not substring/regex:
    # verified against sigstore 4.3.0 verify/policy.py — Identity.verify does
    # `self._identity in all_sans` (set membership over the cert SANs) and
    # OIDCIssuer (via _SingleX509ExtPolicy.verify) does `ext_value != self._value`.
    # So a near-miss identity or issuer fails closed.
    verification_policy = _policy.Identity(identity=identity, issuer=issuer)
    # verify_artifact returns None on success and RAISES on failure. We do NOT
    # capture or test a return value — success == this line did not raise.
    #
    # Evidence the STATEMENT cannot be tampered without failing: sigstore 4.3.0
    # verify/verifier.py::verify_artifact computes `hashed_input = sha256_digest(input_)`,
    # raises VerificationError("Bundle message digest mismatch") if it differs from
    # the bundle's message_digest, and verifies the ECDSA signature OVER that
    # `hashed_input.digest` (then validates the rekord body against it). A mismatched
    # statement (e.g. a tampered overall_digest) therefore fails closed inside sigstore.
    verifier.verify_artifact(statement_bytes, bundle, verification_policy)


def bundle_to_json(bundle) -> str:
    """Serialize a sigstore ``Bundle`` to its canonical JSON string."""
    return bundle.to_json()


def bundle_from_json(text: str):
    """Parse a sigstore ``Bundle`` from JSON text.

    Args:
        text: The bundle JSON (as written to the ``warden.lock.sigstore`` sidecar).

    Returns:
        The parsed ``Bundle``.

    Raises:
        RuntimeError: If sigstore is unavailable.
        Exception: If the JSON is malformed/invalid — propagates so verify fails
            CLOSED.
    """
    if not _SIGSTORE_AVAILABLE:
        raise RuntimeError("sigstore is not installed; run: pip install 'mcp-warden[sigstore]'")
    return _Bundle.from_json(text)
