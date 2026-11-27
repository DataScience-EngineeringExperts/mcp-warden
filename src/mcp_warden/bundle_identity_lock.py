"""Project declared capability commitments from a v4 lock."""

from __future__ import annotations

import hashlib

import rfc8785

from mcp_warden.bundle_identity import (
    MAX_CAPABILITIES,
    CapabilityIdentityV1,
    IdentityError,
    _ordered_capabilities,
)
from mcp_warden.decision_models import DecisionDigestDomain, digest_decision_bytes
from mcp_warden.hashing import check_depth
from mcp_warden.models import ToolEntry, WardenLock

MAX_CAPABILITY_IDENTIFIER_BYTES = 8192


def capabilities_from_v4_lock(lock: WardenLock) -> tuple[CapabilityIdentityV1, ...]:
    """Project v4 entry-body digests from a v4 lock into evidence commitments."""
    result = []
    try:
        if (
            type(lock) is not WardenLock
            or lock.schema_version != 4
            or len(lock.tools) + len(lock.resources) + len(lock.prompts) > MAX_CAPABILITIES
        ):
            raise ValueError
        for kind, entries in (
            ("tool", lock.tools),
            ("resource", lock.resources),
            ("prompt", lock.prompts),
        ):
            for entry in entries:
                identifier = entry.uri if kind == "resource" else entry.name
                if (
                    type(identifier) is not str
                    or not 0 < len(identifier) <= MAX_CAPABILITY_IDENTIFIER_BYTES
                ):
                    raise ValueError
                if len(identifier.encode("utf-8")) > MAX_CAPABILITY_IDENTIFIER_BYTES:
                    raise ValueError
                fields = entry.model_dump(mode="json", exclude={"entry_digest"})
                if type(entry) is ToolEntry:
                    if any(
                        fields[key] is None
                        for key in ("schema_skeleton", "annotations_hash", "output_schema_hash")
                    ):
                        raise ValueError
                    if fields["inspection"] is None:
                        del fields["inspection"]
                check_depth(fields)
                body_digest = "sha256:" + hashlib.sha256(rfc8785.dumps(fields)).hexdigest()
                if body_digest != entry.entry_digest:
                    raise ValueError
                result.append(
                    CapabilityIdentityV1(
                        kind=kind,
                        identifier_digest=digest_decision_bytes(
                            rfc8785.dumps([kind, identifier]),
                            domain=DecisionDigestDomain.CAPABILITY_IDENTIFIER,
                        ),
                        entry_digest=body_digest,
                    )
                )
        return _ordered_capabilities(tuple(result))
    except (AttributeError, KeyError, RecursionError, TypeError, ValueError):
        pass
    raise IdentityError("IDENTITY-LOCK-MALFORMED")
