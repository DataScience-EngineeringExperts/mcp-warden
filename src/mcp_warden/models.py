"""Pydantic models for the captured surface and the ``warden.lock`` baseline.

Split from the lockfile writer/reader (lockfile.py) and drift engine (drift.py)
to keep each module focused and under the LOC budget.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

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


class PinMetadata(BaseModel):
    """Pin metadata + optional approver attestation (WARDEN_LOCK_SCHEMA.md §8)."""

    created_at: str
    warden_version: str
    mcp_protocol_version: str
    approved: bool = False
    approver: str | None = None
    approved_at: str | None = None
    approved_digest: str | None = None


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
