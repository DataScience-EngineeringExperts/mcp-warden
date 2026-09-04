"""Canonicalization + hashing — THE reproducibility contract.

Implements ``canon()`` and ``hash()`` exactly per ``docs/WARDEN_LOCK_SCHEMA.md``
§3 so that ``pin`` and ``check`` agree byte-for-byte.

Non-negotiables (WARDEN_LOCK_SCHEMA.md §10):
  1. ``canon()`` is RFC 8785 (JCS). SHA-256. ``"sha256:" + lowercase_hex``.
  6. Absent/null ``description`` -> hash ``""``; absent/null ``inputSchema`` -> hash ``{}``.

We delegate canonicalization to the vetted ``rfc8785`` library (JCS) rather than
hand-rolling number formatting, as the spec recommends.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import rfc8785

from mcp_warden.content_models import DigestDomain

logger = logging.getLogger("mcp_warden.hashing")

#: Public prefix for every digest emitted by mcp-warden.
SHA256_PREFIX = "sha256:"

#: Normative nesting bound for LOCK/SURFACE canonicalization (docs/SPEC.md §4): the
#: document root is depth 0 and every enclosing array/object adds one; an element at
#: depth > MAX_CANON_DEPTH MUST be refused, never hashed. ``@mcp-warden/lock`` enforces
#: the same constant. Distinct from ``content_models.MAX_JSON_DEPTH`` (16), which bounds
#: the content-envelope profile. Without an explicit check the reference silently
#: accepted 513–~990 levels (up to the interpreter's recursion limit) while the
#: TypeScript verifier refused them — two conforming implementations disagreeing on one
#: document (DSE-1527).
MAX_CANON_DEPTH = 512


class DepthError(ValueError):
    """A JSON value nests deeper than :data:`MAX_CANON_DEPTH` (fail closed)."""


def check_depth(value: Any, *, where: str = "value") -> None:
    """Raise :class:`DepthError` if ``value`` nests deeper than :data:`MAX_CANON_DEPTH`.

    Iterative (explicit stack) so the check itself can never trip the interpreter's
    recursion limit on the very input it exists to refuse. Leaves count: a scalar at
    depth 513 is as much a violation as a container there.
    """
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_CANON_DEPTH:
            raise DepthError(f"{where}: nesting deeper than {MAX_CANON_DEPTH} levels")
        if isinstance(node, dict):
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, (list, tuple)):
            stack.extend((child, depth + 1) for child in node)


def hash_bytes(payload: bytes, *, domain: DigestDomain) -> str:
    """Hash exact bytes under a closed content-envelope digest domain."""
    if type(payload) is not bytes or type(domain) is not DigestDomain:
        raise TypeError("payload and domain must be exact typed values")
    digest = hashlib.sha256(domain.value.encode("ascii") + b"\x00" + payload).hexdigest()
    return SHA256_PREFIX + digest


def canon(value: Any) -> bytes:
    """Return the RFC 8785 (JCS) canonical byte serialization of ``value``.

    Args:
        value: Any JSON-compatible Python value (dict, list, str, int, float,
            bool, None). Object keys are sorted by UTF-16 code units (RFC 8785
            §3.2.3 — NOT by code point; the two differ for astral characters),
            arrays preserve order, no insignificant whitespace, JCS number formatting.

    Returns:
        The canonical UTF-8 byte string.

    Raises:
        DepthError: If ``value`` nests deeper than :data:`MAX_CANON_DEPTH` (SPEC.md §4);
            a ``ValueError`` subclass, raised before any serialization is attempted.
        ValueError: If ``value`` is not JSON-serializable under JCS.
    """
    check_depth(value)
    try:
        return rfc8785.dumps(value)
    except Exception as exc:  # rfc8785 raises a variety of types on bad input
        logger.error("canonicalization failed for value of type %s: %s", type(value).__name__, exc)
        raise ValueError(f"value is not JCS-canonicalizable: {exc}") from exc


def hash_value(value: Any) -> str:
    """Compute ``"sha256:" + hex(SHA256(canon(value)))``.

    Args:
        value: Any JSON-compatible value to hash via its canonical form.

    Returns:
        A string of the form ``"sha256:<64 lowercase hex chars>"``.
    """
    digest = hashlib.sha256(canon(value)).hexdigest()
    return SHA256_PREFIX + digest


def hash_description(description: str | None) -> str:
    """Hash a description string, treating ``None`` and ``""`` identically.

    Per §3.3: absent/null description hashes the empty string ``""``.

    Args:
        description: The tool/resource/prompt description, or ``None``.

    Returns:
        The ``sha256:`` digest of the description (or of ``""`` if null/empty).
    """
    return hash_value(description if description is not None else "")


def hash_input_schema(input_schema: dict[str, Any] | None) -> str:
    """Hash an inputSchema object, treating ``None`` as the empty object ``{}``.

    Per §3.3: absent/null inputSchema hashes ``{}``. The *entire* schema object
    is hashed (type, properties, required, enum, nested schemas, ...).

    Args:
        input_schema: The full JSON Schema object, or ``None``.

    Returns:
        The ``sha256:`` digest of the schema (or of ``{}`` if null).
    """
    return hash_value(input_schema if input_schema is not None else {})


def hash_arguments(arguments: list[Any] | None) -> str:
    """Hash a prompt ``arguments`` array, treating ``None`` as ``[]``.

    Per §5.2: ``arguments_hash = hash(arguments_array_or_[])``.

    Args:
        arguments: The prompt arguments list, or ``None``.

    Returns:
        The ``sha256:`` digest of the arguments array (or of ``[]`` if null).
    """
    return hash_value(arguments if arguments is not None else [])
