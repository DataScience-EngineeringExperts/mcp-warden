"""Deterministic structural JSON-Schema diffing (mcp-warden #15).

Extracts a normalized :class:`SchemaSkeleton` from a tool input schema and
classifies the difference between two skeletons into security-relevant drift
classes (WARDEN_LOCK_SCHEMA.md §6.2; binding taxonomy in 03_ADVERSARIAL_REVIEW).

Design invariants (tested as contracts):
  a. ``extract_skeleton`` is PURE/order-independent — same (or key-reordered) schema
     → byte-identical skeleton (everything sorted).
  b. Absent ``additionalProperties`` normalized to ``true`` at build (R1).
  c. In-document ``$ref`` is FOLLOWED into its target subschema (R8) so a
     constraint relaxation hidden behind a shared definition classifies
     granularly. A non-resolvable ref (remote / unresolvable / sibling keys /
     non-dict target / budget exhausted) degrades to the legacy OPAQUE LEAF
     (literal target recorded); a cyclic ref degrades to the ``_truncated`` leaf
     — both map to ``schema-modified`` (high). Never under-report.
  d. ``type`` normalized to a sorted tuple (R5).
  e. Extraction NEVER raises on cyclic/malformed/non-dict input — degrades to an
     empty/partial skeleton (R4 recursion guard + MAX_DEPTH).
  f. Diffs emitted PER-FACT (R7): one :class:`SchemaChange` per changed fact.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from typing import Any

from .models import PropFacts, SchemaSkeleton

#: Hard cap on recursion depth; on hit a node is recorded as an opaque leaf (R4).
MAX_DEPTH = 64

#: Per-path unique-$ref budget (R8): cap on the number of in-document refs that
#: may be resolved along a SINGLE walk path. Exceeding it degrades to an opaque
#: leaf (never under-report) and is a belt-and-suspenders bound against an
#: adversarial deeply-chained-ref schema (B4/B5).
MAX_REFS = 256

#: Sentinel: ``$ref`` does not resolve to a follow-able in-document dict subschema
#: → record the existing opaque leaf ``{"$ref": r}`` (maps to schema-modified).
_OPAQUE = object()
#: Sentinel: ``$ref`` re-enters a ref already resolved on the current path (cycle)
#: → record the existing ``{"_truncated": True}`` leaf (maps to schema-modified).
_CYCLE = object()

#: Reserved path for root-level facts (e.g. a root ``additionalProperties`` open).
ROOT_PATH = "$root"

#: Constraint keys retained in the skeleton (cosmetic keys are dropped).
_CONSTRAINT_KEYS = (
    "maxLength",
    "minLength",
    "minimum",
    "maximum",
    "pattern",
    "format",
    "additionalProperties",
)

#: Constraints that, when raised, RELAX the contract (upper bounds / max length).
_RELAX_WHEN_HIGHER = ("maxLength", "maximum")
#: Constraints that, when lowered, RELAX the contract (lower bounds).
_RELAX_WHEN_LOWER = ("minLength", "minimum")
#: Constraints whose REMOVAL relaxes the contract (string/format restrictions).
_RELAX_WHEN_REMOVED = ("pattern", "format")

#: Heuristic markers for a value that may be a secret (redact-guard, design §95).
_SECRET_HINTS = ("secret", "token", "password", "apikey", "api_key", "key", "bearer")


def _normalize_type(raw: Any) -> tuple[str, ...] | None:
    """Normalize a JSON Schema ``type`` to a sorted tuple of strings (R5); else ``None``."""
    if raw is None:
        return None
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, list):
        names = sorted({t for t in raw if isinstance(t, str)})
        return tuple(names) if names else None
    return None


def _enum_key(v: Any) -> str:
    """Deterministic, total ordering/dedup key for an enum value.

    Dict-typed values are keyed by canonical JSON (``sort_keys=True``) so two
    semantically-equal schemas whose dicts differ only by key-insertion order
    produce identical skeletons. Falls back to ``repr`` only for values JSON
    cannot serialize, keeping the key total.
    """
    try:
        return json.dumps(v, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(v)


def _normalize_enum(raw: Any) -> list[Any] | None:
    """Canonicalize an ``enum`` list to a deterministic sorted form (else ``None``)."""
    if not isinstance(raw, list):
        return None
    return sorted(raw, key=lambda v: (type(v).__name__, _enum_key(v)))


def _extract_constraints(schema: dict[str, Any]) -> dict[str, Any]:
    """Extract retained constraint keys, sorted; absent additionalProperties → true (R1)."""
    out: dict[str, Any] = {}
    for key in _CONSTRAINT_KEYS:
        if key in schema:
            out[key] = schema[key]
    # R1: absent additionalProperties ≡ true (permissive default).
    out.setdefault("additionalProperties", True)
    return dict(sorted(out.items()))


def _resolve_in_doc_ref(ref: str, root: Any, ref_path: frozenset[str]) -> Any:
    """Resolve a SAME-DOCUMENT ``$ref`` JSON pointer to its dict subschema (R8).

    Follows ``#/$defs/...``, ``#/definitions/...`` and any same-document RFC 6901
    JSON pointer. Returns the resolved dict subschema, or a sentinel:

      * :data:`_OPAQUE` — not an in-document ref, unresolvable, a non-dict target,
        budget exhausted, or any unexpected error (caller records ``{"$ref": r}``).
      * :data:`_CYCLE` — ``ref`` is already on the current resolution path
        (caller records ``{"_truncated": True}``).

    The function NEVER raises (belt-and-suspenders, invariant e): any unexpected
    exception degrades to :data:`_OPAQUE`.

    Args:
        ref: The raw ``$ref`` string.
        root: The top-level schema document (captured once in extract_skeleton).
        ref_path: The frozenset of ref strings already resolved on THIS path
            (passed by value; never mutated — B5).

    Returns:
        The resolved dict subschema, or :data:`_OPAQUE` / :data:`_CYCLE`.
    """
    try:
        if not isinstance(root, dict):
            return _OPAQUE
        # In-document iff a non-empty same-document fragment. Remote refs
        # (``https://x/y#/z``) and the bare document self-ref (``#``) are opaque.
        if not ref.startswith("#") or ref == "#":
            return _OPAQUE
        # Cycle on the CURRENT path: re-entering an already-resolved ref (B5).
        if ref in ref_path:
            return _CYCLE
        # Budget (B4/B5): bound the per-path ref chain length.
        if len(ref_path) >= MAX_REFS:
            return _OPAQUE

        # B3 — pointer resolution order: percent-decode BEFORE RFC 6901 unescape.
        frag = ref[1:]  # drop the leading '#'
        frag = urllib.parse.unquote(frag)  # percent-decode first
        if frag == "":
            return _OPAQUE  # bare '#' already excluded; defensive.
        segments = frag.split("/")
        # A same-document pointer is ``#/a/b`` → split yields ['', 'a', 'b']; the
        # leading element is the empty string before the first '/'. A ref like
        # ``#foo`` (no leading slash) is NOT a valid JSON pointer → opaque.
        if segments[0] != "":
            return _OPAQUE
        segments = segments[1:]
        # RFC 6901 unescape per segment: ``~1`` → ``/`` THEN ``~0`` → ``~``.
        segments = [seg.replace("~1", "/").replace("~0", "~") for seg in segments]

        cur: Any = root
        for seg in segments:
            if isinstance(cur, dict):
                if seg in cur:
                    cur = cur[seg]
                else:
                    return _OPAQUE
            elif isinstance(cur, list):
                # NO list/dict coercion: only a literal numeric index resolves.
                # RFC 6901 §4: array indices are ASCII digits with no leading
                # zero (except the single "0"); reject "007" (silently → idx 7)
                # and non-ASCII digit codepoints for strict determinism.
                if seg.isascii() and seg.isdigit() and (seg == "0" or not seg.startswith("0")) and int(seg) < len(cur):
                    cur = cur[int(seg)]
                else:
                    return _OPAQUE
            else:
                return _OPAQUE
        # Only dict subschemas resolve; a non-dict target stays opaque.
        if not isinstance(cur, dict):
            return _OPAQUE
        return cur
    except Exception:
        # Belt-and-suspenders: resolution must never propagate (invariant e).
        return _OPAQUE


def _walk(
    schema: Any,
    path: str,
    required: bool,
    props: dict[str, PropFacts],
    visited: set[int],
    depth: int,
    *,
    root: dict | None,
    ref_path: frozenset[str] = frozenset(),
) -> None:
    """Recurse a schema node, recording one :class:`PropFacts` per property path.

    Never raises (invariant e): malformed/non-dict nodes, unresolvable ``$ref``
    and recursion-guard hits degrade to opaque/skipped leaves. ``props`` is
    mutated in place; ``visited`` (id-set) + ``depth`` cap enforce termination (R4).

    In-document ``$ref`` (``#/$defs/...``, ``#/definitions/...``, same-document
    JSON pointers) is FOLLOWED into its target subschema so constraint changes
    hidden behind a shared definition diff GRANULARLY (R8). Resolution is bounded
    by ``ref_path`` (per-path cycle/budget guard, passed BY VALUE — never mutated,
    so a diamond-DAG resolves order-independently, B5/B6) and degrades to the
    existing opaque/cycle leaves on every non-resolution path (never under-report).
    """
    # The root node is recorded under ROOT_PATH so root-level facts (e.g. an
    # ``additionalProperties`` open-world escalation) are diffable. A non-dict
    # ROOT degrades to an empty skeleton (the ``if path:`` guard below).
    node_key = path or ROOT_PATH

    if not isinstance(schema, dict):
        # Malformed / non-object leaf: record a bare fact only for named props.
        if path:
            props[path] = PropFacts(constraints={"additionalProperties": True})
        return

    # R8: in-document $ref resolution. A bare ``$ref`` is FOLLOWED into its
    # target subschema; every non-resolution path degrades to the legacy opaque
    # leaf (``{"$ref": r}``) or cycle leaf (``{"_truncated": True}``), both of
    # which ``_diff_constraints`` maps to schema-modified (high) — never
    # under-report (R4/R8).
    if "$ref" in schema:
        # B2 — siblings: a ``$ref`` accompanied by ANY other key is treated as an
        # opaque leaf (resolving would silently drop the siblings' semantics).
        if len(schema) != 1:
            props[node_key] = PropFacts(required=required, constraints={"$ref": str(schema["$ref"])})
            return
        ref = schema["$ref"]
        if not isinstance(ref, str):
            props[node_key] = PropFacts(required=required, constraints={"$ref": str(ref)})
            return
        resolved = _resolve_in_doc_ref(ref, root, ref_path)
        if resolved is _OPAQUE:
            props[node_key] = PropFacts(required=required, constraints={"$ref": ref})
            return
        if resolved is _CYCLE:
            props[node_key] = PropFacts(required=required, constraints={"_truncated": True})
            return
        # Resolved to a dict subschema: recurse INTO it at the SAME path,
        # recording ``ref`` on the path-local frozenset (passed by value, B5).
        _walk(
            resolved,
            path,
            required,
            props,
            visited,
            depth + 1,
            root=root,
            ref_path=ref_path | {ref},
        )
        return

    # R4: recursion / cycle guard — terminate on depth or re-visit.
    node_id = id(schema)
    if depth > MAX_DEPTH or node_id in visited:
        props[node_key] = PropFacts(required=required, constraints={"_truncated": True})
        return
    visited = visited | {node_id}

    props[node_key] = PropFacts(
        type=_normalize_type(schema.get("type")),
        required=required,
        enum=_normalize_enum(schema.get("enum")),
        constraints=_extract_constraints(schema),
    )

    # Recurse object properties.
    properties = schema.get("properties")
    if isinstance(properties, dict):
        req_raw = schema.get("required")
        req_set = {r for r in req_raw if isinstance(r, str)} if isinstance(req_raw, list) else set()
        for key in sorted(properties, key=str):
            child = properties[key]
            child_path = f"{path}.{key}" if path else key
            _walk(child, child_path, key in req_set, props, visited, depth + 1, root=root, ref_path=ref_path)

    # Recurse array items (single-schema form only; tuple form is treated opaque).
    items = schema.get("items")
    if isinstance(items, dict):
        child_path = f"{path}[]" if path else "[]"
        _walk(items, child_path, False, props, visited, depth + 1, root=root, ref_path=ref_path)


def extract_skeleton(input_schema: Any | None) -> SchemaSkeleton:
    """Extract a normalized, deterministic :class:`SchemaSkeleton` from a schema.

    Pure function: the same schema (and any key-reordered equivalent) yields a
    byte-identical skeleton. Never raises on cyclic/malformed/non-dict input —
    degrades to an empty or partial skeleton (invariant e).

    Args:
        input_schema: The full JSON Schema object, or ``None``/malformed.

    Returns:
        A :class:`SchemaSkeleton` whose ``props`` are sorted by path.
    """
    props: dict[str, PropFacts] = {}
    # R8: capture the top-level document ONCE so in-document ``$ref`` pointers
    # (``#/$defs/...`` etc.) resolve against it. A non-dict root → no resolution
    # target (refs stay opaque), matching pre-R8 behavior for malformed input.
    root = input_schema if isinstance(input_schema, dict) else None
    try:
        _walk(input_schema, "", False, props, set(), 0, root=root, ref_path=frozenset())
    except Exception:
        # Belt-and-suspenders: extraction must never propagate (invariant e).
        pass
    ordered = {p: props[p] for p in sorted(props, key=str)}
    return SchemaSkeleton(props=ordered)


# --- diffing -----------------------------------------------------------------


@dataclass(frozen=True)
class SchemaChange:
    """One classified, security-relevant change between two skeletons (R7).

    Attributes:
        path: The dotted property path the change applies to.
        change_class: The stable drift class, e.g. ``"schema-enum-widened"``.
        severity: ``high|medium|low``.
        detail: A compact, non-secret description, e.g. ``"maxLength 64→4096"``.
    """

    path: str
    change_class: str
    severity: str
    detail: str


def _looks_secret(value: Any) -> bool:
    """Return True when a value/key fragment hints at a secret (redact-guard)."""
    s = str(value).lower()
    return any(h in s for h in _SECRET_HINTS)


def _safe(value: Any, *, limit: int = 40) -> str:
    """Render a constraint value compactly for ``detail``, redacting secret-looking input."""
    if _looks_secret(value):
        return "<redacted>"
    s = repr(value) if not isinstance(value, (str, int, float, bool)) else str(value)
    if len(s) > limit:
        return s[:limit] + "…"
    return s


def _is_unconstrained(f: PropFacts) -> bool:
    """Unconstrained = no enum, no pattern, no maxLength, type string/object/absent (taxonomy)."""
    if f.enum:
        return False
    c = f.constraints
    if c.get("pattern") is not None or c.get("maxLength") is not None:
        return False
    if f.type is None:
        return True
    return set(f.type) <= {"string", "object"}


def _diff_type(path: str, b: PropFacts, c: PropFacts) -> list[SchemaChange]:
    """Classify a type change between two props (R5: superset/subset/disjoint)."""
    bt = set(b.type or ())
    ct = set(c.type or ())
    if bt == ct:
        return []
    detail = f"type {sorted(bt) or 'any'}→{sorted(ct) or 'any'}"
    if not bt or not ct:
        # any→typed is a tightening (narrowed); typed→any is a broadening.
        if not bt and ct:
            return [SchemaChange(path, "schema-type-narrowed", "low", detail)]
        return [SchemaChange(path, "schema-type-broadened", "high", detail)]
    if bt < ct:
        return [SchemaChange(path, "schema-type-broadened", "high", detail)]
    if ct < bt:
        return [SchemaChange(path, "schema-type-narrowed", "low", detail)]
    return [SchemaChange(path, "schema-type-changed", "medium", detail)]


def _diff_enum(path: str, b: PropFacts, c: PropFacts) -> list[SchemaChange]:
    """Classify an enum change between two props (R6)."""
    be, ce = b.enum, c.enum
    if be == ce:
        return []
    if be is not None and ce is None:
        return [SchemaChange(path, "schema-enum-removed", "high", "enum removed")]
    if be is None and ce is not None:
        return [SchemaChange(path, "schema-enum-added", "low", "enum added")]
    bs, cs = set(map(_enum_key, be or [])), set(map(_enum_key, ce or []))
    # Detail uses raw list lengths (accurate even with duplicate enum values);
    # classification below uses the deduped sets (R6 set-membership semantics).
    detail = f"enum {len(be or [])}→{len(ce or [])} values"
    if bs < cs:
        return [SchemaChange(path, "schema-enum-widened", "high", detail)]
    if cs < bs:
        return [SchemaChange(path, "schema-enum-narrowed", "low", detail)]
    # Equal size or disjoint membership change == widening (new values allowed).
    return [SchemaChange(path, "schema-enum-widened", "high", detail)]


_RELAX = "schema-constraint-relaxed"
_TIGHTEN = "schema-constraint-tightened"


def _num(value: Any) -> float | None:
    """Coerce a constraint to a number for comparison, else ``None``."""
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _diff_numeric(path: str, key: str, bv: float | None, cv: float | None, relax_up: bool) -> list[SchemaChange]:
    """Diff one numeric bound. ``relax_up`` = raising the value relaxes it."""
    if bv is None and cv is None:
        return []
    if bv is None:  # added a bound = tighten
        return [SchemaChange(path, _TIGHTEN, "low", f"{key} added {_safe(cv)}")]
    if cv is None:  # removed a bound = relax
        return [SchemaChange(path, _RELAX, "medium", f"{key} removed")]
    if cv == bv:
        return []
    relaxed = (cv > bv) if relax_up else (cv < bv)
    klass, sev = (_RELAX, "medium") if relaxed else (_TIGHTEN, "low")
    return [SchemaChange(path, klass, sev, f"{key} {_safe(bv)}→{_safe(cv)}")]


def _diff_constraints(path: str, b: PropFacts, c: PropFacts) -> list[SchemaChange]:
    """Classify constraint changes between two props (relax=medium, tighten=low).

    Handles ``additionalProperties false→true`` as the high-severity
    open-world escalation ``schema-additional-props-opened`` (R1).
    """
    out: list[SchemaChange] = []
    bc, cc = b.constraints, c.constraints

    # Opaque-leaf markers ($ref / _truncated, R4): any change is a structural
    # change of unknown direction -> per-path schema-modified fallback (high),
    # matching the taxonomy's "skeleton differs, no rule matches" row. Never
    # under-report. The literal target is non-secret (a JSON-pointer / sentinel).
    for marker in ("$ref", "_truncated"):
        bv, cv = bc.get(marker), cc.get(marker)
        if bv != cv:
            out.append(SchemaChange(path, "schema-modified", "high", f"{marker} {_safe(bv)}→{_safe(cv)}"))

    # R1: additionalProperties opening (false → true OR false → schema-object) is a
    # privilege escalation (high). "open" = anything other than the closed-world
    # literal ``false``. Absent normalizes to true (open) at extraction (R1).
    b_ap, c_ap = bc.get("additionalProperties", True), cc.get("additionalProperties", True)
    b_open, c_open = b_ap is not False, c_ap is not False
    if not b_open and c_open:
        out.append(SchemaChange(path, "schema-additional-props-opened", "high", f"additionalProperties {_safe(b_ap)}→{_safe(c_ap)}"))
    elif b_open and not c_open:
        out.append(SchemaChange(path, _TIGHTEN, "low", f"additionalProperties {_safe(b_ap)}→{_safe(c_ap)}"))

    for key in _RELAX_WHEN_HIGHER:
        out.extend(_diff_numeric(path, key, _num(bc.get(key)), _num(cc.get(key)), relax_up=True))
    for key in _RELAX_WHEN_LOWER:
        out.extend(_diff_numeric(path, key, _num(bc.get(key)), _num(cc.get(key)), relax_up=False))

    # pattern/format removed = relax; added/changed = tighten.
    for key in _RELAX_WHEN_REMOVED:
        bv, cv = bc.get(key), cc.get(key)
        if bv == cv:
            continue
        if bv is not None and cv is None:
            out.append(SchemaChange(path, _RELAX, "medium", f"{key} removed"))
        elif bv is None:
            out.append(SchemaChange(path, _TIGHTEN, "low", f"{key} added"))
        else:
            out.append(SchemaChange(path, _TIGHTEN, "low", f"{key} changed"))

    return out


def _classify_added(path: str, f: PropFacts) -> SchemaChange:
    """Classify a newly-added property per the binding taxonomy (R3)."""
    if f.required:
        if _is_unconstrained(f):
            return SchemaChange(path, "schema-required-unconstrained-added", "high", "new required unconstrained")
        return SchemaChange(path, "schema-required-added", "medium", "new required constrained")
    if _is_unconstrained(f):
        return SchemaChange(path, "schema-unconstrained-added", "high", "new optional unconstrained")
    return SchemaChange(path, "schema-property-added", "low", "new optional constrained")


def diff_skeletons(base: SchemaSkeleton, cur: SchemaSkeleton) -> list[SchemaChange]:
    """Diff two skeletons into a sorted, per-fact list of :class:`SchemaChange`.

    Emission is PER-FACT (R7): a property that both broadens its type and is
    relaxed required→optional yields BOTH a ``schema-type-broadened`` and a
    ``schema-constraint-relaxed`` change. Implements the full binding taxonomy
    (03_ADVERSARIAL_REVIEW.md). Deterministic: output is sorted by
    ``(path, change_class)``.

    Args:
        base: The baseline skeleton (from the stored lock).
        cur: The current skeleton (freshly extracted).

    Returns:
        A list of :class:`SchemaChange`; empty when the skeletons are equal.
    """
    out: list[SchemaChange] = []
    bpaths, cpaths = base.props, cur.props

    # Added properties.
    for path in set(cpaths) - set(bpaths):
        out.append(_classify_added(path, cpaths[path]))

    # Removed properties (required-removed=high, optional-removed=medium).
    for path in set(bpaths) - set(cpaths):
        f = bpaths[path]
        if f.required:
            out.append(SchemaChange(path, "schema-required-removed", "high", "required property removed"))
        else:
            out.append(SchemaChange(path, "schema-property-removed", "medium", "optional property removed"))

    # Common properties — emit one change per changed fact.
    for path in set(bpaths) & set(cpaths):
        b, c = bpaths[path], cpaths[path]

        # required → optional is a relaxation (medium). optional → required is a
        # contract addition handled here as required-added severity equivalence.
        if b.required and not c.required:
            out.append(SchemaChange(path, "schema-constraint-relaxed", "medium", "required→optional"))
        elif not b.required and c.required:
            if _is_unconstrained(c):
                out.append(
                    SchemaChange(path, "schema-required-unconstrained-added", "high", "optional→required unconstrained")
                )
            else:
                out.append(SchemaChange(path, "schema-required-added", "medium", "optional→required"))

        out.extend(_diff_type(path, b, c))
        out.extend(_diff_enum(path, b, c))
        out.extend(_diff_constraints(path, b, c))

    out.sort(key=lambda ch: (ch.path, ch.change_class))
    return out
