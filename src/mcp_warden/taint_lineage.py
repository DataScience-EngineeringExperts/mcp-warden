"""Bounded, digest-only ancestry for untrusted content."""

from __future__ import annotations

from dataclasses import dataclass

from .content_envelope import to_public_dict, verify_lineage
from .content_models import MAX_PARENTS, ContentEnvelopeError, ContentEnvelopeV1

MAX_LINEAGE_ENVELOPES = 128
MAX_LINEAGE_EDGES = 256
MAX_LINEAGE_DEPTH = 16


@dataclass(frozen=True, slots=True)
class ContentLineageV1:
    """Additional data parents and their transitive ancestors supplied by an adapter."""

    parents: tuple[ContentEnvelopeV1, ...]
    ancestors: tuple[ContentEnvelopeV1, ...] = ()

    def __post_init__(self) -> None:
        if (type(self.parents) is not tuple or not self.parents
                or type(self.ancestors) is not tuple):
            raise ContentEnvelopeError("ENV-LINEAGE-INVALID")
        # Leave space for the capture, its ancestry link and the normalized envelope.
        if (len(self.parents) >= MAX_PARENTS
                or len(self.parents) + len(self.ancestors) > MAX_LINEAGE_ENVELOPES - 3):
            raise ContentEnvelopeError("ENV-OVER-CAP")
        if any(type(node) is not ContentEnvelopeV1 for node in self.parents + self.ancestors):
            raise ContentEnvelopeError("ENV-LINEAGE-INVALID")


def verify_lineage_graph(
    envelope: ContentEnvelopeV1,
    ancestors: tuple[ContentEnvelopeV1, ...],
    *,
    add_child: bool = False,
) -> None:
    """Check exact transitive closure, digest bindings, and monotonic taint on every edge."""
    if type(ancestors) is not tuple:
        raise ContentEnvelopeError("ENV-LINEAGE-INVALID")
    reserved = int(add_child)
    if len(ancestors) + 1 + reserved > MAX_LINEAGE_ENVELOPES:
        raise ContentEnvelopeError("ENV-OVER-CAP")

    by_digest: dict[str, ContentEnvelopeV1] = {}
    edges = reserved
    for node in (envelope, *ancestors):
        to_public_dict(node)
        if node.envelope_digest in by_digest:
            raise ContentEnvelopeError("ENV-LINEAGE-INVALID")
        by_digest[node.envelope_digest] = node
        edges += len(node.parents)
        if edges > MAX_LINEAGE_EDGES:
            raise ContentEnvelopeError("ENV-OVER-CAP")

    active: set[str] = set()
    heights: dict[str, int] = {}

    def visit(node: ContentEnvelopeV1, depth: int) -> int:
        key = node.envelope_digest
        if depth > MAX_LINEAGE_DEPTH:
            raise ContentEnvelopeError("ENV-OVER-CAP")
        if key in active:
            raise ContentEnvelopeError("ENV-LINEAGE-INVALID")
        if key in heights:
            height = heights[key]
        else:
            active.add(key)
            try:
                parents = tuple(by_digest[ref.envelope_digest] for ref in node.parents)
            except KeyError:
                raise ContentEnvelopeError("ENV-LINEAGE-INVALID") from None
            verify_lineage(node, parents=parents)
            height = 1 + max((visit(parent, depth + 1) for parent in parents), default=0)
            heights[key] = height
            active.remove(key)
        if depth + height - 1 > MAX_LINEAGE_DEPTH:
            raise ContentEnvelopeError("ENV-OVER-CAP")
        return height

    visit(envelope, 1 + reserved)
    if heights.keys() != by_digest.keys():
        raise ContentEnvelopeError("ENV-LINEAGE-INVALID")
