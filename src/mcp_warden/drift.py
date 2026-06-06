"""Drift/diff engine (WARDEN_LOCK_SCHEMA.md §6.2).

Compares a freshly-built lock (from ``check``) against the stored baseline and
produces a list of :class:`DriftItem`. Any non-empty drift set means a non-zero
``check`` exit (§10.7). Severity drives reporting/SARIF level only.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import (
    PromptEntry,
    ResourceEntry,
    ToolEntry,
    WardenLock,
)


@dataclass(frozen=True)
class DriftItem:
    """One detected drift between baseline and current surface.

    Attributes:
        drift_class: Stable identifier, e.g. ``"server-identity"``, ``"tool-added"``.
        severity: ``critical|high|medium|low``.
        target: Entry the drift applies to, e.g. ``"tools/<name>"``.
        message: Human-readable description.
    """

    drift_class: str
    severity: str
    target: str
    message: str


def _index_by(entries: list, key: str) -> dict[str, object]:
    """Index a list of entries by an attribute value."""
    return {getattr(e, key): e for e in entries}


def _diff_tools(baseline: list[ToolEntry], current: list[ToolEntry]) -> list[DriftItem]:
    """Diff tool entries across all tool drift classes (§6.2)."""
    items: list[DriftItem] = []
    base = _index_by(baseline, "name")
    cur = _index_by(current, "name")

    for name in sorted(set(cur) - set(base)):
        items.append(DriftItem("tool-added", "high", f"tools/{name}", f"Tool '{name}' added since pin"))
    for name in sorted(set(base) - set(cur)):
        items.append(DriftItem("tool-removed", "medium", f"tools/{name}", f"Tool '{name}' removed since pin"))

    for name in sorted(set(base) & set(cur)):
        b: ToolEntry = base[name]  # type: ignore[assignment]
        c: ToolEntry = cur[name]  # type: ignore[assignment]
        target = f"tools/{name}"

        schema_changed = b.input_schema_hash != c.input_schema_hash
        if schema_changed:
            items.append(DriftItem("schema-modified", "high", target, f"Tool '{name}' inputSchema changed"))

        added_caps = sorted(set(c.capabilities) - set(b.capabilities))
        removed_caps = sorted(set(b.capabilities) - set(c.capabilities))
        for cap in added_caps:
            items.append(DriftItem("capability-added", "high", target, f"Tool '{name}' gained capability '{cap}'"))
        for cap in removed_caps:
            items.append(
                DriftItem("capability-removed", "medium", target, f"Tool '{name}' lost capability '{cap}'")
            )

        # §11.4: a changed/added/removed inspection policy is medium-severity drift.
        if b.inspection != c.inspection:
            items.append(
                DriftItem(
                    "inspection-policy-modified",
                    "medium",
                    target,
                    f"Tool '{name}' inspection policy changed (security-relevant relaxation/tightening)",
                )
            )

        # Description-only drift: only when schema + caps are unchanged (§6.2).
        if (
            b.description_hash != c.description_hash
            and not schema_changed
            and not added_caps
            and not removed_caps
        ):
            items.append(
                DriftItem("description-modified", "low", target, f"Tool '{name}' description changed")
            )

    return items


def _diff_resources(baseline: list[ResourceEntry], current: list[ResourceEntry]) -> list[DriftItem]:
    """Diff resource entries (added=medium, removed=low, modified=low) (§6.2)."""
    items: list[DriftItem] = []
    base = _index_by(baseline, "uri")
    cur = _index_by(current, "uri")

    for uri in sorted(set(cur) - set(base)):
        items.append(DriftItem("resource-added", "medium", f"resources/{uri}", f"Resource '{uri}' added"))
    for uri in sorted(set(base) - set(cur)):
        items.append(DriftItem("resource-removed", "low", f"resources/{uri}", f"Resource '{uri}' removed"))
    for uri in sorted(set(base) & set(cur)):
        b: ResourceEntry = base[uri]  # type: ignore[assignment]
        c: ResourceEntry = cur[uri]  # type: ignore[assignment]
        if b.entry_digest != c.entry_digest:
            items.append(
                DriftItem("resource-modified", "low", f"resources/{uri}", f"Resource '{uri}' modified")
            )
    return items


def _diff_prompts(baseline: list[PromptEntry], current: list[PromptEntry]) -> list[DriftItem]:
    """Diff prompt entries (added=medium, removed=low, modified=low) (§6.2)."""
    items: list[DriftItem] = []
    base = _index_by(baseline, "name")
    cur = _index_by(current, "name")

    for name in sorted(set(cur) - set(base)):
        items.append(DriftItem("prompt-added", "medium", f"prompts/{name}", f"Prompt '{name}' added"))
    for name in sorted(set(base) - set(cur)):
        items.append(DriftItem("prompt-removed", "low", f"prompts/{name}", f"Prompt '{name}' removed"))
    for name in sorted(set(base) & set(cur)):
        b: PromptEntry = base[name]  # type: ignore[assignment]
        c: PromptEntry = cur[name]  # type: ignore[assignment]
        if b.entry_digest != c.entry_digest:
            items.append(DriftItem("prompt-modified", "low", f"prompts/{name}", f"Prompt '{name}' modified"))
    return items


def compute_drift(baseline: WardenLock, current: WardenLock) -> list[DriftItem]:
    """Compute the full drift set between a baseline lock and a current lock.

    Fast path: if ``overall_digest`` matches, there is provably no drift (§6.2).

    Args:
        baseline: The stored ``warden.lock`` baseline.
        current: A freshly-built lock from the current surface.

    Returns:
        A list of :class:`DriftItem` (empty if no drift). Any non-empty result
        means ``check`` must exit non-zero.
    """
    if baseline.overall_digest == current.overall_digest:
        return []

    items: list[DriftItem] = []

    # Server-identity drift (critical) — highest severity.
    if baseline.server.command_digest != current.server.command_digest:
        items.append(
            DriftItem(
                "server-identity",
                "critical",
                "launch/command",
                "Server launch command/args changed since pin (you are pinning a different launch)",
            )
        )

    items.extend(_diff_tools(baseline.tools, current.tools))
    items.extend(_diff_resources(baseline.resources, current.resources))
    items.extend(_diff_prompts(baseline.prompts, current.prompts))

    # Unapproved-change finding (§8): approved baseline whose attested digest no
    # longer matches the recomputed surface.
    if baseline.pin.approved and baseline.pin.approved_digest not in (None, current.overall_digest):
        items.append(
            DriftItem(
                "unapproved-change",
                "high",
                "pin/approved_digest",
                "Surface changed since approval; approved_digest no longer matches the current surface",
            )
        )

    items.sort(key=lambda d: (d.target, d.drift_class))
    return items
