"""Additional v4 tool commitments: hints never grant authority."""

from __future__ import annotations

from .hashing import hash_value
from .models import ToolEntry
from .schema_diff import diff_skeletons

NULL_HASH = hash_value(None)


def metadata_changes(b: ToolEntry, c: ToolEntry) -> list[tuple[str, str, str, str | None]]:
    """Return (class, severity, message, safe detail) without raw annotation values.

    Legacy entries have no commitments to these fields. Their review boundary is
    the schema migration and unchanged unapproved-change finding, not fictional
    differences against a historical null value.
    """
    items = []
    if b.annotations_hash is not None and b.annotations_hash != c.annotations_hash:
        items.append(("tool-annotations-modified", "high", "annotations changed (server declarations, not authority)", None))
    if b.output_schema_hash is None or b.output_schema_hash == c.output_schema_hash:
        return items
    if b.output_schema_hash == NULL_HASH:
        items.append(("schema-out-added", "high", "outputSchema added", None))
    elif c.output_schema_hash == NULL_HASH:
        items.append(("schema-out-removed", "high", "outputSchema removed", None))
    elif b.output_schema_skeleton is None or c.output_schema_skeleton is None:
        items.append(("schema-out-modified", "high", "outputSchema changed", None))
    else:
        changes = diff_skeletons(b.output_schema_skeleton, c.output_schema_skeleton)
        if not changes:
            items.append(("schema-out-cosmetic-modified", "low", "outputSchema changed cosmetically (no structural change)", None))
        for change in changes:
            cls = change.change_class.replace("schema-", "schema-out-", 1)
            items.append((cls, change.severity, f"outputSchema {cls} at '{change.path}'", change.detail))
    return items
