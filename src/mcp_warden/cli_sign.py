"""CLI helpers for #16 Sigstore signing/verification (``pin --sign`` / ``check --verify``).

Split from ``cli.py`` to keep that module under the LOC budget. These helpers are
invoked by the ``pin`` and ``check`` command bodies and own ALL signing/verify
control flow, including the fail-closed exit semantics.

Fail-closed contract (this is a security gate):

  * Missing optional extra -> exit non-zero with an install message.
  * Signing error -> exit non-zero, NO half-written sidecar (we write the bundle
    to a temp file and atomically replace; on any error the original sidecar — if
    any — is untouched and no partial file remains).
  * Verify: the bundle is loaded from a FIXED path (``<lockdir>/warden.lock.sigstore``
    or an explicit ``--offline-bundle``); the attacker-controlled pointer field in
    the lock is NEVER read for pathing. The statement is RECOMPUTED from the lock's
    own ``overall_digest``. ANY exception from verify -> exit 1. Success (no
    exception) -> print OK + exit 0.
"""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

import typer
from rich.console import Console

from .lockfile import read_lock, write_lock
from .models import WardenLock
from .provenance import make_sigstore_pointer_attestation
from .signing import (
    VerificationError,
    bundle_from_json,
    bundle_to_json,
    build_statement,
    sign_statement,
    verify_statement,
)

#: Default sidecar filename when the lock is named ``warden.lock``. Exported for
#: backward-compatibility and tests. Callers MUST use :func:`_sidecar_name_for`
#: to derive the actual sidecar filename from a (potentially non-default) lock path
#: instead of referencing this constant directly.
SIDECAR_NAME = "warden.lock.sigstore"

#: ``provenance_version`` value stamped on a signed lock (additive bump 1 -> 2,
#: OUTSIDE ``overall_digest``). Signals "this lock carries a #16 signer pointer".
SIGNED_PROVENANCE_VERSION = 2

#: NOTE: ``[sigstore]`` is escaped (``\\[``) so Rich does not interpret the
#: bracket as console markup and silently drop the extra name from the message.
_INSTALL_MSG = r"sigstore extra not installed; run: pip install 'mcp-warden\[sigstore]'"


def _now_rfc3339() -> str:
    """Current UTC time as RFC 3339, second precision."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sidecar_name_for(lock_path: Path) -> str:
    """Derive the sidecar filename from ``lock_path``.

    The sidecar is always ``<lock_filename>.sigstore``, co-located with the lock.
    For example::

        warden.lock        ->  warden.lock.sigstore
        e2e.warden.lock    ->  e2e.warden.lock.sigstore
        /tmp/a.lock        ->  a.lock.sigstore  (in /tmp/)

    Using a fixed constant (SIDECAR_NAME = "warden.lock.sigstore") regardless of
    the lock's filename was the root-cause bug: when ``--lock e2e.warden.lock`` is
    passed, the sidecar was written to ``warden.lock.sigstore`` but callers (and
    the CI workflow) looked for ``e2e.warden.lock.sigstore``.
    """
    return Path(lock_path).name + ".sigstore"


def _sidecar_path_for(lock_path: Path) -> Path:
    """The FIXED sidecar path next to ``lock_path`` (never an attacker pointer)."""
    return Path(os.path.dirname(os.path.abspath(lock_path))) / _sidecar_name_for(lock_path)


def sign_after_pin(
    lock_doc: WardenLock,
    lock_path: Path,
    identity_token: str | None,
    err_console: Console,
) -> WardenLock:
    """Sign a freshly-pinned lock's ``overall_digest`` and write the bundle sidecar.

    Steps (all fail closed): build the deterministic statement from
    ``lock_doc.overall_digest``; Sigstore-sign it; write the bundle JSON to the
    FIXED sidecar atomically; append an out-of-digest pointer attestation; bump
    ``provenance_version`` 1 -> 2. The signature, bundle, and pointer are all
    OUTSIDE ``overall_digest`` — this function does NOT recompute or mutate the
    digest.

    Args:
        lock_doc: The just-built lock (already written unsigned by the caller).
        lock_path: Where the lock lives (the sidecar goes alongside it).
        identity_token: Explicit OIDC token, or ``None`` for ambient/CI OIDC.
        err_console: stderr console for fail-closed messages.

    Returns:
        A NEW :class:`WardenLock` with the pointer attestation + bumped
        provenance_version. ``overall_digest`` is byte-identical to ``lock_doc``.

    Raises:
        typer.Exit: code 2 on the sigstore-absent path; code 1 on any signing
            failure (no partial sidecar left behind).
    """
    # Import lazily so the absent-extra branch can be tested by monkeypatching the
    # flag without sigstore installed.
    from . import signing

    if not signing._SIGSTORE_AVAILABLE:
        err_console.print(f"[red]error:[/red] {_INSTALL_MSG}")
        raise typer.Exit(code=2)

    statement = build_statement(lock_doc.overall_digest)
    try:
        bundle = sign_statement(statement, identity_token)
        bundle_json = bundle_to_json(bundle)
    except Exception as exc:  # noqa: BLE001 - signing fails CLOSED
        err_console.print(f"[red]signing failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Build the signed lock (deep copy: never mutate the caller's object).
    # Appends the OUT-OF-DIGEST pointer attestation + bumps provenance_version;
    # overall_digest is left byte-identical (provenance is excluded from the digest).
    signed = lock_doc.model_copy(deep=True)
    actor = os.environ.get("WARDEN_ACTOR") or "sigstore-keyless"
    # Use the DERIVED sidecar name (from lock_path.name), not the constant, so
    # non-default lock names (e.g. e2e.warden.lock) get the correct pointer.
    sidecar_name = _sidecar_name_for(lock_path)
    pointer = make_sigstore_pointer_attestation(
        bound_digest=signed.overall_digest,
        signature_bundle=sidecar_name,
        actor=actor,
        now=_now_rfc3339(),
    )
    signed.pin.attestations = [*signed.pin.attestations, pointer]
    signed.pin.provenance_version = SIGNED_PROVENANCE_VERSION

    # INVARIANT: the on-disk state is ALWAYS consistent — either BOTH the
    # pointer-bearing lock AND its sidecar are present, or NEITHER (no lock that
    # claims a signature without the sidecar, and no orphan sidecar/.tmp).
    #
    # Order that maintains it (Fix 3): (1) stage the bundle to a TEMP sidecar;
    # (2) write the pointer-bearing lock — if this raises we still have NO pointer
    # promoted to the fixed sidecar name and we delete the temp sidecar, so the
    # caller's already-written unsigned lock + empty sidecar slot = NEITHER;
    # (3) os.replace the temp sidecar into its fixed name. If that final promotion
    # raises (the only failure that could leave a pointer-bearing lock without a
    # sidecar), we re-write the UNSIGNED lock to restore BOTH-or-NEITHER and drop
    # the temp file. Every error path therefore exits with no orphan .sigstore or
    # .tmp and no pointer-bearing lock lacking its bundle.
    sidecar = _sidecar_path_for(lock_path)
    tmp = sidecar.with_name(sidecar.name + ".tmp")

    def _cleanup_tmp() -> None:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass

    try:
        tmp.write_text(bundle_json, encoding="utf-8")
    except OSError as exc:
        _cleanup_tmp()
        err_console.print(f"[red]signing failed:[/red] could not write bundle sidecar: {exc}")
        raise typer.Exit(code=1) from exc

    try:
        write_lock(signed, lock_path)
    except OSError as exc:
        # The pointer-bearing lock did not land; drop the staged sidecar so no
        # orphan .tmp remains. The unsigned lock the caller already wrote stays.
        _cleanup_tmp()
        err_console.print(f"[red]signing failed:[/red] could not re-write signed lock: {exc}")
        raise typer.Exit(code=1) from exc

    try:
        os.replace(tmp, sidecar)
    except OSError as exc:
        # Final promotion failed: the lock now has a pointer but the sidecar is
        # absent. Re-write the unsigned lock to restore the BOTH-or-NEITHER
        # invariant, then clean up the temp sidecar.
        _cleanup_tmp()
        try:
            write_lock(lock_doc, lock_path)
        except OSError:
            pass
        err_console.print(f"[red]signing failed:[/red] could not place bundle sidecar: {exc}")
        raise typer.Exit(code=1) from exc

    return signed


def verify_lock_signature(
    lock_path: Path,
    certificate_identity: str | None,
    certificate_oidc_issuer: str | None,
    offline_bundle: Path | None,
    console: Console,
    err_console: Console,
) -> None:
    """Verify a lock's Sigstore signature; exit 0 on pass, non-zero on ANY failure.

    Security-critical control flow:

      * ``--certificate-identity`` and ``--certificate-oidc-issuer`` are both
        REQUIRED; either missing -> exit 2 (we never verify against an empty
        identity/issuer).
      * If the optional extra is absent -> exit 2 + install message (NOT skip).
      * Load the lock; recompute the statement from ITS OWN ``overall_digest``.
      * Load the bundle from the FIXED sidecar path (or ``--offline-bundle``).
        The lock's pointer ``signature_bundle`` is NEVER consulted for pathing.
        Missing sidecar -> exit 1 ("bundle not found"), NOT skip.
      * Call :func:`verify_statement`. Success is the no-exception path ONLY.
        ``VerificationError`` -> exit 1; ANY other exception (TUF/network/
        AttributeError/TypeError/malformed-bundle) -> exit 1. Nothing here can
        reach exit 0 except a clean verify.

    Args:
        lock_path: Path to the lock to verify.
        certificate_identity: Expected certificate SAN identity.
        certificate_oidc_issuer: Expected OIDC issuer.
        offline_bundle: Optional explicit bundle path (else the fixed sidecar).
        console: stdout console.
        err_console: stderr console.

    Raises:
        typer.Exit: code 2 (extra absent / lock unreadable), code 1 (any verify
            failure or missing/malformed bundle), code 0 only on a clean verify.
    """
    from . import signing

    if not certificate_identity or not certificate_oidc_issuer:
        err_console.print(
            "[red]error:[/red] --verify requires --certificate-identity and --certificate-oidc-issuer"
        )
        raise typer.Exit(code=2)

    if not signing._SIGSTORE_AVAILABLE:
        err_console.print(f"[red]error:[/red] {_INSTALL_MSG}")
        raise typer.Exit(code=2)

    try:
        lock_doc = read_lock(lock_path)
    except (FileNotFoundError, ValueError) as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    # Nit A: a lock with no overall_digest can never be verified. Reject it with a
    # clear message and exit 2 BEFORE building a statement (cleaner than a
    # downstream VerificationError from an empty-digest statement).
    if not lock_doc.overall_digest:
        err_console.print("[red]error:[/red] lock has no overall_digest; cannot verify")
        raise typer.Exit(code=2)

    # Recompute the statement from the lock's OWN overall_digest. We deliberately
    # ignore the pointer attestation's bound_digest (attacker-controlled).
    statement = build_statement(lock_doc.overall_digest)

    bundle_path = Path(offline_bundle) if offline_bundle is not None else _sidecar_path_for(lock_path)
    if not bundle_path.exists():
        err_console.print(
            f"[red]error:[/red] signature bundle not found at {bundle_path}; "
            f"this lock is unsigned or the sidecar is missing"
        )
        raise typer.Exit(code=1)

    try:
        bundle_text = bundle_path.read_text(encoding="utf-8")
        bundle = bundle_from_json(bundle_text)  # malformed JSON -> raises -> fail closed
    except Exception as exc:  # noqa: BLE001 - malformed bundle fails CLOSED
        err_console.print(f"[red]verification failed:[/red] could not load bundle: {exc}")
        raise typer.Exit(code=1) from exc

    try:
        # Returns None on success, RAISES on failure. We test NO return value.
        verify_statement(
            statement,
            bundle,
            identity=certificate_identity,
            issuer=certificate_oidc_issuer,
        )
    except VerificationError as exc:
        err_console.print(f"[red]verification failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # noqa: BLE001 - TUF/network/type errors ALL fail closed
        err_console.print(f"[red]verification failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # ONLY reachable when verify_statement did not raise. The signature binds the
    # TOOL SURFACE (overall_digest), NOT findings/pins/provenance — the success
    # message says so explicitly so it can never be read as findings integrity.
    console.print(f"[green]OK[/green] tool surface signature verified for {certificate_identity}")
    console.print(f"  issuer: {certificate_oidc_issuer}")
    console.print(f"  overall_digest: {lock_doc.overall_digest}")
    console.print(f"  bundle: {bundle_path}")
    console.print("  note: findings, pins, and provenance metadata are NOT covered by this signature")
