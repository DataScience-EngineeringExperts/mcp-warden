"""Structured provenance construction + rotation (WARDEN_LOCK_SCHEMA.md §8.x, #19).

All provenance lives inside the ``pin`` block, which is **excluded** from
``overall_digest`` (§6.1). Therefore nothing here can change a lock's
``overall_digest`` — populating a pinner, appending an attestation, or rotating
provenance leaves the definition portion byte-stable. These helpers are pure (no
file I/O) so they are unit-testable; the CLI does read/verify/write around
:func:`rotate_provenance`.
"""

from __future__ import annotations

import os

from . import PROVENANCE_VERSION, __version__
from .models import ATTESTATION_NOTE_MAX_LEN, Attestation, Pinner, WardenLock


class ProvenanceError(ValueError):
    """Raised when a provenance field violates a §8.x constraint (fail closed)."""


def _validate_note(note: str | None) -> str | None:
    """Enforce the ``Attestation.note`` length cap (fail closed).

    Args:
        note: Caller-supplied note, or ``None``.

    Returns:
        The note unchanged (``None`` stays ``None``).

    Raises:
        ProvenanceError: If ``note`` exceeds :data:`ATTESTATION_NOTE_MAX_LEN`.
    """
    if note is not None and len(note) > ATTESTATION_NOTE_MAX_LEN:
        raise ProvenanceError(
            f"attestation note exceeds {ATTESTATION_NOTE_MAX_LEN} chars "
            f"(got {len(note)}); notes are public tamper-evident text — keep them short"
        )
    return note


def make_pinner(actor: str | None = None) -> Pinner:
    """Build the :class:`Pinner` for the running warden (§8.x).

    Args:
        actor: Human/CI principal; falls back to ``WARDEN_ACTOR`` env, else
            ``None``. Self-asserted, non-authoritative (CRIT-3).

    Returns:
        A populated :class:`Pinner` (``tool_version`` = current ``__version__``,
        ``environment`` best-effort from ``WARDEN_ENV`` env or ``None``).
    """
    resolved_actor = actor or os.environ.get("WARDEN_ACTOR")
    environment = os.environ.get("WARDEN_ENV")  # best-effort, non-authoritative
    return Pinner(
        tool="mcp-warden",
        tool_version=__version__,
        actor=resolved_actor,
        environment=environment if environment else None,
    )


def make_approver_attestation(approver: str, bound_digest: str, *, now: str, note: str | None = None) -> Attestation:
    """Build the mirrored approver :class:`Attestation` (§8.x; B2 consistency rule).

    The scalar ``approved*`` fields stay canonical; this is the forward-compatible
    projection of the approver into the attester set.

    Args:
        approver: Approver identity (mirrors the scalar ``pin.approver``).
        bound_digest: The ``overall_digest`` this attestation binds to, VERBATIM
            with its ``sha256:`` prefix (B4).
        now: RFC 3339 UTC timestamp.
        note: Optional public note (length-capped, fail closed).

    Returns:
        The approver :class:`Attestation` (``role="approver"``, ``method="manual"``).

    Raises:
        ProvenanceError: If ``note`` exceeds the length cap.
    """
    return Attestation(
        actor=approver,
        role="approver",
        method="manual",
        created_at=now,
        bound_digest=bound_digest,
        note=_validate_note(note),
    )


def make_sigstore_pointer_attestation(
    bound_digest: str, signature_bundle: str, *, actor: str, now: str
) -> Attestation:
    """Build the #16 out-of-digest Sigstore pointer :class:`Attestation`.

    This is an INFORMATIONAL pointer appended to ``pin.attestations`` after a
    ``pin --sign``: it records that a Sigstore signature over the lock's
    ``overall_digest`` exists, and names the sidecar file holding the bundle. It
    is NOT a trust anchor — ``check --verify`` ignores this attestation entirely
    and re-derives everything from the lock's own ``overall_digest`` plus the
    bundle at a FIXED sidecar path. The ``bound_digest`` here is convenience
    metadata, NOT a security check (an attacker can forge it; verify never reads
    it). Stored OUTSIDE ``overall_digest`` like all provenance.

    Args:
        bound_digest: The lock's ``overall_digest`` VERBATIM (with ``sha256:``).
        signature_bundle: RELATIVE sidecar filename (e.g. ``"warden.lock.sigstore"``).
        actor: Self-asserted principal recorded on the attestation.
        now: RFC 3339 UTC timestamp.

    Returns:
        The pointer :class:`Attestation` (``role="signer"``, ``method="sigstore-keyless"``).
    """
    return Attestation(
        actor=actor,
        role="signer",
        method="sigstore-keyless",
        created_at=now,
        bound_digest=bound_digest,
        signature_bundle=signature_bundle,
    )


def rotate_provenance(
    lock: WardenLock,
    *,
    approver: str | None,
    actor: str | None,
    note: str | None,
    now: str,
) -> WardenLock:
    """Re-attest an existing lock's provenance WITHOUT re-capturing the surface.

    Mutates ONLY out-of-digest provenance: appends one attestation, stamps
    ``rotated_at``, bumps ``rotation_count``, refreshes ``pinner``, and (when an
    ``approver`` is given) re-binds the canonical scalar approval to the lock's
    *unchanged* ``overall_digest``. It never re-captures, never recomputes entry
    digests, and never touches ``overall_digest``: the returned lock's
    ``overall_digest`` is byte-identical to the input's (§8.x; B3).

    The CLI wrapper (:mod:`mcp_warden.cli_lock`) is responsible for the integrity
    gate (recompute-from-entries) BEFORE calling this; this helper assumes the
    lock is already verified consistent.

    **Append-only attestation log (contract).** ``pin.attestations`` is an
    append-only audit log: each rotation appends one entry and NEVER dedups or
    rewrites prior ones. Rotating an already-approved lock with ``--approver``
    therefore appends a SECOND ``role="approver"`` attestation — this is intended.
    The scalar ``approved*`` fields remain the single canonical approval record;
    the **most-recent** ``role="approver"`` attestation (``attestations[-1]`` after
    an approver rotation) binds the CURRENT ``overall_digest``. Do not add dedup.

    Args:
        lock: The verified baseline lock to re-attest.
        approver: When given, the attestation is ``role="approver"`` and the
            canonical scalar approval is (re)set; when ``None`` the attestation is
            ``role="pinner"`` and approval state is left untouched.
        actor: Human/CI principal for the refreshed pinner (or ``WARDEN_ACTOR``).
        note: Optional public note (length-capped, fail closed).
        now: RFC 3339 UTC timestamp for this rotation.

    Returns:
        A NEW :class:`WardenLock` (deep copy) with mutated provenance and an
        UNCHANGED ``overall_digest``.

    Raises:
        ProvenanceError: If ``note`` exceeds the length cap.
    """
    _validate_note(note)
    new_lock = lock.model_copy(deep=True)
    pin = new_lock.pin

    role = "approver" if approver else "pinner"
    attester = approver or actor or os.environ.get("WARDEN_ACTOR") or "unknown"
    attestation = Attestation(
        actor=attester,
        role=role,
        method="manual",
        created_at=now,
        # B4: bind to the UNCHANGED overall_digest, verbatim (with sha256: prefix).
        bound_digest=lock.overall_digest,
        note=note,
    )
    pin.attestations = [*pin.attestations, attestation]
    pin.rotated_at = now
    pin.rotation_count += 1
    pin.provenance_version = PROVENANCE_VERSION
    pin.pinner = make_pinner(actor)

    if approver:
        # Re-bind the canonical scalar approval to the (unchanged) surface.
        pin.approved = True
        pin.approver = approver
        pin.approved_at = now
        pin.approved_digest = lock.overall_digest

    return new_lock
