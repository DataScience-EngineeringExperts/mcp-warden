"""Policy schema + loader + lint (POLICY_MODEL.md §3, §4.1).

Fail-closed: unknown keys at any level are a lint error (§6.7). Defaults are
fail-closed (§6.2). Lint cross-checks against an optional lock.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import WardenLock
from .tokenizer import derive_capabilities

logger = logging.getLogger("mcp_warden.policy")

POLICY_VERSION = 1

#: The four shapes (snake_case in YAML) -> backing capability flag.
SHAPE_TO_FLAG = {
    "filesystem_write": "fs-write",
    "shell_exec": "shell-exec",
    "http_request": "http-request",
    "sql_query": "sql-query",
}

#: Allowed constraint keys per shape (POLICY_MODEL.md §2). Unknown -> lint error.
SHAPE_CONSTRAINTS: dict[str, set[str]] = {
    "filesystem_write": {"allow_paths", "deny_paths", "path_arg"},
    "shell_exec": {"allow", "allow_commands", "command_arg"},
    "http_request": {"allow_hosts", "deny_cidrs", "deny_private", "url_arg"},
    "sql_query": {"deny_statements", "allow_readonly_only", "query_arg"},
}

#: Fail-closed defaults (POLICY_MODEL.md §6.2).
SHAPE_DEFAULTS: dict[str, dict[str, Any]] = {
    "filesystem_write": {},
    "shell_exec": {"allow": False},
    "http_request": {"deny_private": True},
    "sql_query": {"allow_readonly_only": True},
}

DEFAULT_SQL_DENY = ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT", "REVOKE", "UPDATE"]


@dataclass
class LintMessage:
    """A single lint diagnostic.

    Attributes:
        code: e.g. ``POL-LINT-ORPHAN``, ``POL-LINT-UNKNOWN-KEY``.
        level: ``error|warning|note``.
        message: Human-readable description.
    """

    code: str
    level: str  # error|warning|note
    message: str


@dataclass
class Policy:
    """A loaded, validated policy document.

    Attributes:
        version: Policy schema version (must be 1).
        defaults: Shape-wide defaults keyed by snake_case shape.
        tools: Per-tool overrides: ``{tool_name: {shape: {constraint: value}}}``.
    """

    version: int
    defaults: dict[str, dict[str, Any]] = field(default_factory=dict)
    tools: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)

    def effective(self, tool_name: str, shape: str) -> dict[str, Any]:
        """Return effective constraints for a tool/shape (defaults deep-merged).

        Per-tool override wins over shape defaults; built-in fail-closed defaults
        underlie both (POLICY_MODEL.md §3).

        Args:
            tool_name: Exact tool name.
            shape: snake_case shape key.

        Returns:
            The merged constraint dict.
        """
        merged: dict[str, Any] = dict(SHAPE_DEFAULTS.get(shape, {}))
        merged.update(self.defaults.get(shape, {}))
        merged.update(self.tools.get(tool_name, {}).get(shape, {}))
        return merged


class PolicyError(Exception):
    """Raised when a policy file cannot be parsed into a :class:`Policy`."""


def load_policy(path: str | Path) -> tuple[Policy, list[LintMessage]]:
    """Load + structurally validate a policy file.

    Args:
        path: Path to the YAML policy.

    Returns:
        ``(policy, lint_messages)``. Structural problems are returned as
        ``error``-level :class:`LintMessage` rather than raised, so the caller
        can report them all; a fatal parse failure raises :class:`PolicyError`.

    Raises:
        PolicyError: If the file is missing or not valid YAML/mapping.
    """
    p = Path(path)
    if not p.exists():
        raise PolicyError(f"policy file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy file {p} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"policy file {p} must be a YAML mapping at the top level")

    messages: list[LintMessage] = []
    policy = Policy(version=0)

    # --- version ---
    version = raw.get("version")
    if version != POLICY_VERSION:
        messages.append(
            LintMessage("POL-LINT-VERSION", "error", f"version must be {POLICY_VERSION}, got {version!r}")
        )
    policy.version = version if isinstance(version, int) else 0

    allowed_top = {"version", "defaults", "tools"}
    for key in raw:
        if key not in allowed_top:
            messages.append(
                LintMessage("POL-LINT-UNKNOWN-KEY", "error", f"unknown top-level key '{key}'")
            )

    # --- defaults ---
    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        messages.append(LintMessage("POL-LINT-TYPE", "error", "'defaults' must be a mapping"))
        defaults = {}
    for shape, constraints in defaults.items():
        if shape not in SHAPE_CONSTRAINTS:
            messages.append(LintMessage("POL-LINT-UNKNOWN-KEY", "error", f"unknown shape in defaults: '{shape}'"))
            continue
        _validate_constraints(shape, constraints, f"defaults.{shape}", messages)
        policy.defaults[shape] = constraints if isinstance(constraints, dict) else {}

    # --- tools ---
    tools = raw.get("tools") or {}
    if not isinstance(tools, dict):
        messages.append(LintMessage("POL-LINT-TYPE", "error", "'tools' must be a mapping"))
        tools = {}
    for tool_name, shapes in tools.items():
        if not isinstance(shapes, dict):
            messages.append(LintMessage("POL-LINT-TYPE", "error", f"tools.{tool_name} must be a mapping"))
            continue
        policy.tools[tool_name] = {}
        for shape, constraints in shapes.items():
            if shape not in SHAPE_CONSTRAINTS:
                messages.append(
                    LintMessage("POL-LINT-UNKNOWN-KEY", "error", f"unknown shape '{shape}' on tool '{tool_name}'")
                )
                continue
            _validate_constraints(shape, constraints, f"tools.{tool_name}.{shape}", messages)
            policy.tools[tool_name][shape] = constraints if isinstance(constraints, dict) else {}

    return policy, messages


def _validate_constraints(shape: str, constraints: Any, where: str, messages: list[LintMessage]) -> None:
    """Validate a constraint block for a shape; append lint messages in place."""
    if not isinstance(constraints, dict):
        messages.append(LintMessage("POL-LINT-TYPE", "error", f"{where} must be a mapping"))
        return
    allowed = SHAPE_CONSTRAINTS[shape]
    for key in constraints:
        if key not in allowed:
            messages.append(
                LintMessage("POL-LINT-UNKNOWN-KEY", "error", f"unknown constraint '{key}' in {where}")
            )

    # Internal consistency: empty allow_paths on a constrained fs-write = deny-all warn.
    if shape == "filesystem_write":
        allow_paths = constraints.get("allow_paths")
        deny_paths = constraints.get("deny_paths") or []
        if allow_paths is not None and len(allow_paths) == 0:
            messages.append(
                LintMessage("POL-LINT-DENY-ALL", "warning", f"{where}.allow_paths is empty (deny-all)")
            )
        if isinstance(allow_paths, list) and isinstance(deny_paths, list):
            overlap = set(allow_paths) & set(deny_paths)
            for path in sorted(overlap):
                messages.append(
                    LintMessage(
                        "POL-LINT-CONFLICT",
                        "warning",
                        f"{where}: '{path}' appears in both allow_paths and deny_paths (deny wins)",
                    )
                )


def lint_against_lock(policy: Policy, lock: WardenLock) -> list[LintMessage]:
    """Cross-check policy tool entries against a lock (POLICY_MODEL.md §4.1.3).

    Flags orphan tool rules (tool not in lock) and shape mismatches (tool exists
    but lacks the declared shape's capability).

    Args:
        policy: The loaded policy.
        lock: The baseline lock to cross-check against.

    Returns:
        Warning-level lint messages (POL-LINT-ORPHAN / POL-LINT-SHAPE-MISMATCH).
    """
    messages: list[LintMessage] = []
    # Recompute capabilities is unnecessary — the lock stores them.
    lock_caps = {t.name: set(t.capabilities) for t in lock.tools}
    for tool_name, shapes in policy.tools.items():
        if tool_name not in lock_caps:
            messages.append(
                LintMessage("POL-LINT-ORPHAN", "warning", f"policy targets unknown tool '{tool_name}'")
            )
            continue
        for shape in shapes:
            flag = SHAPE_TO_FLAG.get(shape)
            if flag and flag not in lock_caps[tool_name]:
                messages.append(
                    LintMessage(
                        "POL-LINT-SHAPE-MISMATCH",
                        "warning",
                        f"tool '{tool_name}' does not have capability '{flag}' for shape '{shape}'",
                    )
                )
    return messages


def infer_shapes_from_arguments(arguments: dict[str, Any]) -> list[str]:
    """Infer policy shapes from a sample call's argument names (§4.2.1 fallback).

    Used when no lock is provided to ``policy eval``. Builds a synthetic schema
    whose properties are the argument keys and reuses the shared capability
    derivation, then maps flags back to shape keys.

    Args:
        arguments: The sample call's ``arguments`` object.

    Returns:
        Sorted list of snake_case shape keys.
    """
    synthetic_schema = {"properties": {k: {} for k in arguments}}
    flags = set(derive_capabilities("", synthetic_schema))
    flag_to_shape = {v: k for k, v in SHAPE_TO_FLAG.items()}
    return sorted(flag_to_shape[f] for f in flags if f in flag_to_shape)
