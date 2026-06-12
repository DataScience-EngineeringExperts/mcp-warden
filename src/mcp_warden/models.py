"""Pydantic models for the captured surface and the ``warden.lock`` baseline.

Split from the lockfile writer/reader (lockfile.py) and drift engine (drift.py)
to keep each module focused and under the LOC budget.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --- Raw captured surface (pre-hashing) --------------------------------------


class CapturedTool(BaseModel):
    """A tool definition as returned by ``tools/list`` (raw, pre-hash).

    ``input_schema`` is typed ``Any`` (not ``dict``) so a server returning a
    malformed/non-object schema is captured verbatim and surfaced as a
    ``WRD-SCHEMA-MALFORMED`` finding (CHECKS.md §5.5) rather than rejected.
    """

    name: str
    description: str | None = None
    input_schema: Any | None = None


class CapturedResource(BaseModel):
    """A resource definition as returned by ``resources/list`` (raw, pre-hash)."""

    uri: str
    name: str | None = None
    description: str | None = None
    mime_type: str | None = None


class CapturedPrompt(BaseModel):
    """A prompt definition as returned by ``prompts/list`` (raw, pre-hash)."""

    name: str
    description: str | None = None
    arguments: list[dict[str, Any]] | None = None


class CapturedSurface(BaseModel):
    """The full captured declared surface of an MCP server over stdio."""

    command: str
    args: list[str] = Field(default_factory=list)
    protocol_version: str
    tools: list[CapturedTool] = Field(default_factory=list)
    resources: list[CapturedResource] = Field(default_factory=list)
    prompts: list[CapturedPrompt] = Field(default_factory=list)


# --- normalized schema skeleton (structural diff input) ----------------------


class PropFacts(BaseModel):
    """Security-relevant facts about one property path in a tool input schema.

    A skeleton stores one :class:`PropFacts` per dotted property path. Only
    security-relevant structure is kept; cosmetic keys (description, title,
    examples, default) are dropped at extraction time so semantically equal
    schemas produce byte-identical skeletons (WARDEN_LOCK_SCHEMA.md §6.2).

    Attributes:
        type: The JSON Schema ``type`` normalized to a sorted tuple, or ``None``
            when the schema declares no type.
        required: Whether this property is listed in its parent's ``required``.
        enum: The sorted, canonicalized enum values, or ``None`` when absent.
        constraints: The retained constraint keys (``maxLength``, ``minLength``,
            ``minimum``, ``maximum``, ``pattern``, ``format``,
            ``additionalProperties``) plus the opaque-leaf markers ``$ref`` and
            ``_truncated``. Sorted for determinism.
    """

    type: tuple[str, ...] | None = None
    required: bool = False
    enum: list[Any] | None = None
    constraints: dict[str, Any] = Field(default_factory=dict)


class SchemaSkeleton(BaseModel):
    """A deterministic structural extraction of a tool input schema.

    Maps each dotted property path to its :class:`PropFacts`. The skeleton is a
    pure function of the input schema and is serialized into the lock so that
    ``check`` can classify *what* changed between baseline and current surfaces.

    Attributes:
        props: Path -> facts mapping. Insertion order is deterministic (sorted
            by path at build time).
    """

    props: dict[str, PropFacts] = Field(default_factory=dict)


# --- warden.lock entry models (hashed) ---------------------------------------


class Finding(BaseModel):
    """A static-check finding (CHECKS.md / WARDEN_LOCK_SCHEMA.md §7)."""

    rule_id: str
    severity: str  # critical|high|medium|low
    target: str  # e.g. "tools/run_command" or "launch/command"
    message: str
    snippet: str  # secrets MUST be redacted


class ServerIdentity(BaseModel):
    """Server identity block (WARDEN_LOCK_SCHEMA.md §4)."""

    command: str
    args: list[str]
    command_digest: str


class ToolEntry(BaseModel):
    """Hashed tool entry, sorted by name (WARDEN_LOCK_SCHEMA.md §5.1, §11).

    The optional ``inspection`` block (§11) is additive: when ``None`` it is
    excluded from both the serialized lock and the canonicalized entry body, so
    a tool with no inspection policy hashes BYTE-IDENTICALLY to a v0.1 entry
    (existing locks need no re-pin — see §11.4).

    ``schema_skeleton`` (SCHEMA_VERSION 2) holds the normalized structural
    skeleton used for granular schema-diff classification. It defaults to
    ``None`` so v1 locks (no skeleton) still validate on read; ``check`` falls
    back to the legacy ``schema-modified`` drift when a baseline lacks it.
    """

    name: str
    description_hash: str
    input_schema_hash: str
    capabilities: list[str]
    inspection: dict[str, Any] | None = None
    schema_skeleton: SchemaSkeleton | None = None
    entry_digest: str


class ResourceEntry(BaseModel):
    """Hashed resource entry, sorted by uri (WARDEN_LOCK_SCHEMA.md §5.2)."""

    uri: str
    name: str | None
    description_hash: str
    mime_type: str | None
    entry_digest: str


class PromptEntry(BaseModel):
    """Hashed prompt entry, sorted by name (WARDEN_LOCK_SCHEMA.md §5.2)."""

    name: str
    description_hash: str
    arguments_hash: str
    entry_digest: str


#: Hard cap on ``Attestation.note`` length (#19 folded nice-to-have). Notes are
#: public, tamper-evident free text destined for #16's signed payload; an
#: unbounded note is a denial-of-service / bloat surface, so build/rotate reject
#: anything longer (fail closed).
ATTESTATION_NOTE_MAX_LEN = 1000


class Pinner(BaseModel):
    """Who/what produced a pin (WARDEN_LOCK_SCHEMA.md §8.x, #19).

    Stored inside the ``pin`` block, OUTSIDE ``overall_digest`` (additive, never
    re-hashes the definition portion). ``extra="ignore"`` (B1) lets a #19-era
    reader tolerate future #16/#23 fields without raising.

    Attributes:
        tool: The tool that produced the pin (always ``"mcp-warden"`` today).
        tool_version: The warden version at pin time. Defaults to ``"unknown"``
            (B5) so construction never fails when ``__version__`` is unavailable
            (test fixtures, editable/partial builds, programmatic #16/#23 use).
        actor: Optional human/CI principal (``--actor`` or ``WARDEN_ACTOR`` env).
            **Self-asserted and non-authoritative** (CRIT-3) — not a trust anchor;
            authenticated identity is #16's job.
        environment: Best-effort ``"ci"``/``"local"``/``None``. Self-asserted,
            non-authoritative (CRIT-3).
    """

    model_config = ConfigDict(extra="ignore")

    tool: str = "mcp-warden"
    tool_version: str = "unknown"
    actor: str | None = None
    environment: str | None = None


class Attestation(BaseModel):
    """One entry in the attester APPEND-ONLY log (WARDEN_LOCK_SCHEMA.md §8.x, #19).

    ``pin.attestations`` is an append-only audit log: a fresh ``build_lock(approve)``
    holds one mirrored approver attestation, but every ``lock rotate`` APPENDS one
    more entry and never dedups — so rotating an already-approved lock yields TWO
    ``role="approver"`` attestations (intended). The scalar ``approved*`` fields stay
    the single canonical approval; the MOST-RECENT ``role="approver"`` attestation
    binds the current ``overall_digest``. The list also lets #16 (cosign) and #23
    (multi-attester) extend it without another schema break. Stored OUTSIDE
    ``overall_digest``. ``extra="ignore"`` (B1) tolerates future signature fields
    added by #16.

    Attributes:
        actor: Who attests (identity string). Self-asserted (CRIT-3).
        role: ``"approver"`` | ``"pinner"`` | future roles.
        method: ``"manual"`` for human approvals; ``"sigstore-keyless"`` for the
            #16 out-of-digest pointer attestation that records a Sigstore
            signature over the lock's ``overall_digest``.
        created_at: RFC 3339 UTC timestamp of the attestation.
        bound_digest: The ``overall_digest`` this attestation binds to,
            **VERBATIM** — i.e. ``sha256:<64 lowercase hex>`` WITH the
            ``sha256:`` prefix this repo stores (B4). Do NOT strip the prefix on
            disk; #16 may strip it for Rekor/in-toto subjects at signing time.
        note: Optional public, tamper-evident free text destined for #16's
            signed payload. Capped at :data:`ATTESTATION_NOTE_MAX_LEN` chars;
            build/rotate reject longer (fail closed). Never holds secrets.
    """

    model_config = ConfigDict(extra="ignore")

    actor: str
    role: str = "approver"
    method: str = "manual"
    created_at: str
    bound_digest: str
    note: str | None = None
    #: #16: for a ``method="sigstore-keyless"`` pointer attestation, the RELATIVE
    #: sidecar filename (e.g. ``"warden.lock.sigstore"``) where the signature
    #: bundle lives. This pointer is INFORMATIONAL ONLY and is **never** trusted by
    #: ``check --verify`` (which loads the bundle from a FIXED path next to the
    #: lock); an attacker editing it changes nothing about verification. Out of
    #: ``overall_digest`` like the rest of the ``pin`` block.
    signature_bundle: str | None = None

    @field_validator("note")
    @classmethod
    def _cap_note(cls, value: str | None) -> str | None:
        """Enforce the note length cap at the TYPE boundary (fail closed).

        Belt-and-suspenders for the helper-only ``provenance._validate_note``: a
        direct ``Attestation(...)`` constructor (future #16/#23 paths) cannot bypass
        the cap. Raises pydantic ``ValidationError`` when ``note`` exceeds
        :data:`ATTESTATION_NOTE_MAX_LEN`. The CLI keeps ``_validate_note`` ahead of
        construction so the operator still sees the clean ``ProvenanceError`` message.
        """
        if value is not None and len(value) > ATTESTATION_NOTE_MAX_LEN:
            raise ValueError(
                f"attestation note exceeds {ATTESTATION_NOTE_MAX_LEN} chars (got {len(value)})"
            )
        return value


class PinMetadata(BaseModel):
    """Pin metadata + optional approver attestation (WARDEN_LOCK_SCHEMA.md §8).

    The scalar ``approved``/``approver``/``approved_at``/``approved_digest``
    fields remain the **canonical** approval record (``drift.py`` reads them).
    The #19 additive provenance fields below are all OUTSIDE ``overall_digest``
    and degrade gracefully on pre-#19 locks (optional with defaults). The
    ``attestations`` list is the forward-compatible superset; the scalars are
    the legacy projection of the approver attestation. ``extra="ignore"`` (B1)
    keeps pre-#19 locks and future #16/#23 fields readable without error.
    """

    model_config = ConfigDict(extra="ignore")

    created_at: str
    warden_version: str
    mcp_protocol_version: str
    approved: bool = False
    approver: str | None = None
    approved_at: str | None = None
    approved_digest: str | None = None
    # --- #19 additive structured provenance (all OUTSIDE overall_digest) ---
    provenance_version: int = 1
    pinner: Pinner | None = None
    attestations: list[Attestation] = Field(default_factory=list)
    rotated_at: str | None = None
    rotation_count: int = 0


class WardenLock(BaseModel):
    """Top-level ``warden.lock`` document (WARDEN_LOCK_SCHEMA.md §2)."""

    schema_version: int
    warden_version: str
    server: ServerIdentity
    tools: list[ToolEntry]
    resources: list[ResourceEntry]
    prompts: list[PromptEntry]
    findings: list[Finding]
    overall_digest: str
    pin: PinMetadata
