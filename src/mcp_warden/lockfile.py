"""``warden.lock`` builder + reader/writer (WARDEN_LOCK_SCHEMA.md).

Builds a :class:`WardenLock` from a captured surface (hashing, sorting, entry
digests, overall digest), and reads/writes the pretty-printed JSON file.

Reproducibility (§10): all hashing uses :mod:`mcp_warden.hashing` (RFC 8785 +
SHA-256). The pretty-printed file is for humans; hashing never uses its bytes.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION, __version__
from .hashing import (
    hash_arguments,
    hash_description,
    hash_input_schema,
    hash_value,
)
from .models import (
    CapturedSurface,
    Finding,
    PinMetadata,
    PromptEntry,
    ResourceEntry,
    ServerIdentity,
    ToolEntry,
    WardenLock,
)
from .schema_diff import extract_skeleton
from .tokenizer import derive_capabilities

logger = logging.getLogger("mcp_warden.lockfile")

DEFAULT_LOCK_NAME = "warden.lock"


def _now_rfc3339() -> str:
    """Current UTC time as RFC 3339, second precision (e.g. ``2026-06-06T14:22:05Z``)."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _server_identity(surface: CapturedSurface) -> ServerIdentity:
    """Build the server identity block + ``command_digest`` (§4.1)."""
    command_digest = hash_value({"command": surface.command, "args": surface.args})
    return ServerIdentity(command=surface.command, args=list(surface.args), command_digest=command_digest)


#: The three valid expected_output_charset literals (WARDEN_LOCK_SCHEMA.md §11.2).
_VALID_CHARSETS = ("text", "extended", "binary-ok")


class LockValidationError(ValueError):
    """Raised at pin time when a §11 inspection declaration is invalid (fail closed)."""


def _validate_inspection(name: str, inspection: dict[str, Any] | None) -> None:
    """Validate a §11 inspection block at pin time; raise on invalid (§11.3).

    Args:
        name: The tool name (for the error message).
        inspection: The inspection object, or ``None``.

    Raises:
        LockValidationError: If a value violates §11.2 (fail closed — no lock
            is written).
    """
    if inspection is None:
        return
    if not isinstance(inspection, dict):
        raise LockValidationError(f"tool '{name}': inspection must be an object")
    charset = inspection.get("expected_output_charset", "text")
    if charset not in _VALID_CHARSETS:
        raise LockValidationError(
            f"tool '{name}': expected_output_charset must be one of {_VALID_CHARSETS}, got {charset!r}"
        )
    for key in ("may_return_urls", "secret_echo_applies"):
        if key in inspection and not isinstance(inspection[key], bool):
            raise LockValidationError(f"tool '{name}': {key} must be a JSON boolean")


def _tool_entry(tool: Any, inspection: dict[str, Any] | None = None) -> ToolEntry:
    """Build a hashed tool entry (§5.1/§5.3, §11) from a captured tool.

    Args:
        tool: A captured tool (``name``/``description``/``input_schema``).
        inspection: Optional §11 inspection block. When ``None`` it is excluded
            from the hashed body, so the digest is byte-identical to v0.1.

    Returns:
        The hashed :class:`ToolEntry`.
    """
    schema = tool.input_schema if isinstance(tool.input_schema, dict) else None
    # The structural skeleton (#15) is derived from the *raw* input_schema so a
    # malformed/non-dict schema still yields a (possibly empty) skeleton without
    # raising (schema_diff invariant e).
    skeleton = extract_skeleton(tool.input_schema)
    body: dict[str, Any] = {
        "name": tool.name,
        "description_hash": hash_description(tool.description),
        "input_schema_hash": hash_input_schema(schema),
        "capabilities": derive_capabilities(tool.name, schema),
    }
    if inspection is not None:
        _validate_inspection(tool.name, inspection)
        body["inspection"] = inspection
    # Include the serialized skeleton in the hashed body so a tampered stored
    # skeleton changes entry_digest (R2). v2 entry_digest formula change is a
    # deliberate, versioned contract change vs v1.
    body["schema_skeleton"] = skeleton.model_dump(mode="json")
    entry_digest = hash_value(body)
    # entry_digest already accounts for the skeleton; reuse the rest of body.
    entry_fields = {k: v for k, v in body.items() if k != "schema_skeleton"}
    return ToolEntry(**entry_fields, schema_skeleton=skeleton, entry_digest=entry_digest)


def _resource_entry(res: Any) -> ResourceEntry:
    """Build a hashed resource entry (§5.2/§5.3) from a captured resource."""
    body = {
        "uri": res.uri,
        "name": res.name,
        "description_hash": hash_description(res.description),
        "mime_type": res.mime_type,
    }
    entry_digest = hash_value(body)
    return ResourceEntry(**body, entry_digest=entry_digest)


def _prompt_entry(prompt: Any) -> PromptEntry:
    """Build a hashed prompt entry (§5.2/§5.3) from a captured prompt."""
    body = {
        "name": prompt.name,
        "description_hash": hash_description(prompt.description),
        "arguments_hash": hash_arguments(prompt.arguments),
    }
    entry_digest = hash_value(body)
    return PromptEntry(**body, entry_digest=entry_digest)


def compute_overall_digest(
    server: ServerIdentity,
    tools: list[ToolEntry],
    resources: list[ResourceEntry],
    prompts: list[PromptEntry],
) -> str:
    """Compute ``overall_digest`` per §6.1.

    Excludes ``findings``, ``pin``, and ``warden_version`` (§6.1/§10.2). Entry
    digests are listed in the (already-sorted) entry order.

    Args:
        server: The server identity block.
        tools: Sorted tool entries.
        resources: Sorted resource entries.
        prompts: Sorted prompt entries.

    Returns:
        The ``sha256:`` overall digest.
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "server": {"command_digest": server.command_digest},
        "tools": [t.entry_digest for t in tools],
        "resources": [r.entry_digest for r in resources],
        "prompts": [p.entry_digest for p in prompts],
    }
    return hash_value(payload)


def build_lock(
    surface: CapturedSurface,
    findings: list[Finding],
    *,
    approve: bool = False,
    approver: str | None = None,
) -> WardenLock:
    """Build a complete :class:`WardenLock` from a captured surface + findings.

    Sorting (§10.5): tools by ``name``, resources by ``uri``, prompts by ``name``
    BEFORE hashing the overall digest.

    Args:
        surface: The captured declared surface.
        findings: Static-check findings to embed (§7).
        approve: When True, record the ``--approve`` attestation (§8).
        approver: The approver identity string (required-ish when ``approve``).

    Returns:
        A fully-populated, internally-consistent :class:`WardenLock`.
    """
    server = _server_identity(surface)

    tools = sorted((_tool_entry(t) for t in surface.tools), key=lambda e: e.name)
    resources = sorted((_resource_entry(r) for r in surface.resources), key=lambda e: e.uri)
    prompts = sorted((_prompt_entry(p) for p in surface.prompts), key=lambda e: e.name)

    overall_digest = compute_overall_digest(server, tools, resources, prompts)

    now = _now_rfc3339()
    pin = PinMetadata(
        created_at=now,
        warden_version=__version__,
        mcp_protocol_version=surface.protocol_version,
        approved=approve,
        approver=approver if approve else None,
        approved_at=now if approve else None,
        approved_digest=overall_digest if approve else None,
    )

    return WardenLock(
        schema_version=SCHEMA_VERSION,
        warden_version=__version__,
        server=server,
        tools=tools,
        resources=resources,
        prompts=prompts,
        findings=list(findings),
        overall_digest=overall_digest,
        pin=pin,
    )


def lock_to_pretty_json(lock: WardenLock) -> str:
    """Serialize a lock to pretty-printed JSON (§1): 2-space indent, one trailing newline.

    Args:
        lock: The lock document.

    Returns:
        The UTF-8 JSON text (ending in exactly one ``\\n``).
    """
    data = lock.model_dump(mode="json")
    # §11.4: a tool with no inspection policy must serialize EXACTLY as in v0.1
    # (the key is simply absent). Only drop the key when it is None — present
    # inspection blocks are kept and are part of the digest.
    for tool in data.get("tools", []):
        if tool.get("inspection") is None:
            tool.pop("inspection", None)
    text = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)
    return text + "\n"


def write_lock(lock: WardenLock, path: str | Path) -> None:
    """Write a lock to disk as pretty-printed JSON.

    Args:
        lock: The lock document.
        path: Destination file path.

    Raises:
        OSError: If the file cannot be written.
    """
    p = Path(path)
    try:
        p.write_text(lock_to_pretty_json(lock), encoding="utf-8")
    except OSError as exc:
        logger.error("failed to write lock to %s: %s", p, exc)
        raise
    logger.info("wrote lock to %s (overall_digest=%s)", p, lock.overall_digest)


def read_lock(path: str | Path) -> WardenLock:
    """Read and validate a lock from disk.

    Args:
        path: Source file path.

    Returns:
        The validated :class:`WardenLock`.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not valid JSON or fails schema validation.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"lock file not found: {p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"lock file {p} is not valid JSON: {exc}") from exc
    try:
        return WardenLock.model_validate(raw)
    except Exception as exc:
        raise ValueError(f"lock file {p} failed schema validation: {exc}") from exc
