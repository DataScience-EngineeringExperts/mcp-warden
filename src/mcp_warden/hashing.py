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
            bool, None). Object keys are sorted by Unicode code point, arrays
            preserve order, no insignificant whitespace, JCS number formatting.

    Returns:
        The canonical UTF-8 byte string.

    Raises:
        ValueError: If ``value`` is not JSON-serializable under JCS.
    """
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
