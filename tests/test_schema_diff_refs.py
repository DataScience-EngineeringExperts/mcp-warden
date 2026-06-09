"""In-document ``$ref`` resolution tests (#29, R8): granular diff through refs.

Covers the binding acceptance bar for #29:
  1. granular classification through a shared ``$ref`` definition,
  2. ``#/definitions/...`` (draft-07) parity with ``#/$defs/...``,
  3-4. self- and mutually-recursive defs terminate without raising,
  5. unresolvable / non-dict / remote / bare-``#`` refs stay OPAQUE (never under-report),
  6. a ``$ref`` with a sibling key stays OPAQUE (B2),
  7. determinism across key-reordering and a diamond DAG (B6),
  8. RFC 6901 (``~1``/``~0``) + percent-decoding (B3),
  9. the per-path ref budget terminates a pathological chain (B4/B5).

All resolution invariants degrade to the legacy opaque/cycle leaf, so a change to
an unresolvable ref string still surfaces as ``schema-modified`` (high).
"""

from __future__ import annotations

from mcp_warden.schema_diff import (
    MAX_REFS,
    diff_skeletons,
    extract_skeleton,
)


def _diff(base_schema, cur_schema):
    return diff_skeletons(extract_skeleton(base_schema), extract_skeleton(cur_schema))


def _classes(changes):
    return {(c.path, c.change_class, c.severity) for c in changes}


# --- 1. granular classification THROUGH a shared $ref -------------------------


def test_constraint_relaxed_through_ref():
    base = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/S"}},
        "$defs": {"S": {"type": "string", "maxLength": 64}},
    }
    cur = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/S"}},
        "$defs": {"S": {"type": "string", "maxLength": 4096}},
    }
    classes = _classes(_diff(base, cur))
    assert ("x", "schema-constraint-relaxed", "medium") in classes
    # The coarse blob-level class must NOT fire — the ref was followed.
    assert not any(cc == "schema-modified" for (_, cc, _) in classes)


# --- 2. #/definitions/... (draft-07) resolves identically ---------------------


def test_definitions_resolves_like_defs():
    base = {
        "type": "object",
        "properties": {"x": {"$ref": "#/definitions/S"}},
        "definitions": {"S": {"type": "string", "maxLength": 64}},
    }
    cur = {
        "type": "object",
        "properties": {"x": {"$ref": "#/definitions/S"}},
        "definitions": {"S": {"type": "string", "maxLength": 4096}},
    }
    classes = _classes(_diff(base, cur))
    assert ("x", "schema-constraint-relaxed", "medium") in classes
    assert not any(cc == "schema-modified" for (_, cc, _) in classes)


# --- 3. self-recursive $defs terminates, recursive position truncated ---------


def test_self_recursive_terminates():
    schema = {
        "type": "object",
        "properties": {"node": {"$ref": "#/$defs/Node"}},
        "$defs": {
            "Node": {
                "type": "object",
                "properties": {"next": {"$ref": "#/$defs/Node"}},
            }
        },
    }
    skel = extract_skeleton(schema)  # must not raise / must terminate
    # The re-entrant position degrades to the cycle leaf (_truncated).
    truncated = [p for p, f in skel.props.items() if f.constraints.get("_truncated") is True]
    assert truncated, "self-recursive ref must produce a _truncated leaf"


# --- 4. mutually-recursive A->B->A terminates --------------------------------


def test_mutually_recursive_terminates():
    schema = {
        "type": "object",
        "properties": {"a": {"$ref": "#/$defs/A"}},
        "$defs": {
            "A": {"type": "object", "properties": {"b": {"$ref": "#/$defs/B"}}},
            "B": {"type": "object", "properties": {"a": {"$ref": "#/$defs/A"}}},
        },
    }
    skel = extract_skeleton(schema)  # must not raise / must terminate
    assert any(f.constraints.get("_truncated") is True for f in skel.props.values())


# --- 5. unresolvable / non-dict / remote / bare-# stay OPAQUE -----------------


def _opaque_paths(skel):
    return {p: f.constraints["$ref"] for p, f in skel.props.items() if "$ref" in f.constraints}


def test_unresolvable_ref_stays_opaque_and_diffs_high():
    base = {"type": "object", "properties": {"x": {"$ref": "#/$defs/Missing"}}, "$defs": {}}
    cur = {"type": "object", "properties": {"x": {"$ref": "#/$defs/Other"}}, "$defs": {}}
    assert _opaque_paths(extract_skeleton(base)) == {"x": "#/$defs/Missing"}
    classes = _classes(_diff(base, cur))
    assert ("x", "schema-modified", "high") in classes


def test_non_dict_target_stays_opaque():
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/S"}},
        "$defs": {"S": "not-a-dict"},
    }
    assert _opaque_paths(extract_skeleton(schema)) == {"x": "#/$defs/S"}


def test_remote_ref_stays_opaque():
    base = {"type": "object", "properties": {"x": {"$ref": "https://x/y#/z"}}}
    cur = {"type": "object", "properties": {"x": {"$ref": "https://x/q#/z"}}}
    assert _opaque_paths(extract_skeleton(base)) == {"x": "https://x/y#/z"}
    assert ("x", "schema-modified", "high") in _classes(_diff(base, cur))


def test_bare_hash_ref_stays_opaque():
    schema = {"type": "object", "properties": {"x": {"$ref": "#"}}}
    assert _opaque_paths(extract_skeleton(schema)) == {"x": "#"}


def test_non_string_ref_stays_opaque():
    schema = {"type": "object", "properties": {"x": {"$ref": 123}}}
    assert _opaque_paths(extract_skeleton(schema)) == {"x": "123"}


# --- 6. $ref with a sibling key stays OPAQUE (B2) -----------------------------


def test_ref_with_sibling_key_stays_opaque():
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/S", "description": "hi"}},
        "$defs": {"S": {"type": "string", "maxLength": 64}},
    }
    skel = extract_skeleton(schema)
    # Resolution suppressed (B2): the leaf records the opaque target, not S's facts.
    assert _opaque_paths(skel) == {"x": "#/$defs/S"}
    assert skel.props["x"].constraints.get("maxLength") is None


# --- 7. determinism: key-reorder + diamond DAG --------------------------------


def test_key_reorder_is_byte_identical():
    a = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/S"}},
        "$defs": {"S": {"type": "string", "maxLength": 64, "minLength": 1}},
    }
    b = {
        "$defs": {"S": {"minLength": 1, "maxLength": 64, "type": "string"}},
        "properties": {"x": {"$ref": "#/$defs/S"}},
        "type": "object",
    }
    assert extract_skeleton(a) == extract_skeleton(b)
    # And stable across repeated runs.
    assert extract_skeleton(a) == extract_skeleton(a)


def test_diamond_dag_is_order_independent():
    # A and B both reference the same shared definition S (diamond DAG).
    a = {
        "type": "object",
        "properties": {
            "a": {"$ref": "#/$defs/A"},
            "b": {"$ref": "#/$defs/B"},
        },
        "$defs": {
            "A": {"type": "object", "properties": {"s": {"$ref": "#/$defs/S"}}},
            "B": {"type": "object", "properties": {"s": {"$ref": "#/$defs/S"}}},
            "S": {"type": "string", "maxLength": 64},
        },
    }
    # Same schema, defs in a different insertion order.
    b = {
        "type": "object",
        "properties": {
            "b": {"$ref": "#/$defs/B"},
            "a": {"$ref": "#/$defs/A"},
        },
        "$defs": {
            "S": {"maxLength": 64, "type": "string"},
            "B": {"type": "object", "properties": {"s": {"$ref": "#/$defs/S"}}},
            "A": {"type": "object", "properties": {"s": {"$ref": "#/$defs/S"}}},
        },
    }
    assert extract_skeleton(a) == extract_skeleton(b)
    # Both shared positions resolved to S's facts (maxLength carried through).
    skel = extract_skeleton(a)
    assert skel.props["a.s"].constraints.get("maxLength") == 64
    assert skel.props["b.s"].constraints.get("maxLength") == 64


# --- 8. RFC 6901 (~1/~0) + percent-decoding (B3) ------------------------------


def test_rfc6901_slash_segment():
    # A $defs key literally containing '/' is referenced via '~1'.
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/a~1b"}},
        "$defs": {"a/b": {"type": "string", "maxLength": 64}},
    }
    skel = extract_skeleton(schema)
    assert skel.props["x"].constraints.get("maxLength") == 64


def test_rfc6901_tilde_segment():
    # A key containing '~' is referenced via '~0'.
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/a~0b"}},
        "$defs": {"a~b": {"type": "string", "maxLength": 64}},
    }
    skel = extract_skeleton(schema)
    assert skel.props["x"].constraints.get("maxLength") == 64


def test_percent_encoded_fragment_resolves_like_decoded():
    # B3 ordering: percent-decode is applied to the WHOLE fragment BEFORE the
    # RFC 6901 '/' split, so '%2F' decodes to a literal path separator and
    # resolves identically to the already-decoded '/' form (NOT to '~1', which
    # escapes a slash INSIDE one segment). Here both forms address the nested
    # path $defs -> a -> b.
    nested_defs = {"$defs": {"a": {"b": {"type": "string", "maxLength": 64}}}}
    pct = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/a%2Fb"}},
        **nested_defs,
    }
    decoded = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/a/b"}},
        **nested_defs,
    }
    assert extract_skeleton(pct) == extract_skeleton(decoded)
    assert extract_skeleton(pct).props["x"].constraints.get("maxLength") == 64


# --- 9. per-path ref budget terminates a pathological chain -------------------


# --- 10. ~1 vs %7E1 encode the SAME key → identical, stable resolution --------


def test_slash_key_resolves_identically_via_tilde1_and_percent_encoded():
    # A $defs key literally containing '/' addressed two ways inside ONE segment:
    #   - RFC 6901 '~1' escape:           #/$defs/a~1b
    #   - percent-encoded '~1' ('%7E1'):  #/$defs/a%7E1b  (decodes to '~1' then unescapes)
    # Both must resolve to the SAME target ('a/b'), byte-identically and stably.
    tilde = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/a~1b"}},
        "$defs": {"a/b": {"type": "string", "maxLength": 64}},
    }
    pct = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/a%7E1b"}},
        "$defs": {"a/b": {"type": "string", "maxLength": 64}},
    }
    skel_tilde = extract_skeleton(tilde)
    skel_pct = extract_skeleton(pct)
    # Same resolved target at the 'x' path (byte-identical PropFacts).
    assert skel_tilde.props["x"] == skel_pct.props["x"]
    assert skel_pct.props["x"].constraints.get("maxLength") == 64
    # Stable across repeated calls.
    assert extract_skeleton(pct) == skel_pct
    assert extract_skeleton(tilde) == skel_tilde


# --- 11. differently-encoded cyclic ref still TERMINATES (id-set backstop) -----


def test_differently_encoded_cyclic_ref_terminates():
    # Node N self-references through a DIFFERENTLY percent-encoded ref string than
    # the one used to reach it: the entry ref is the plain '#/$defs/N~1x', while N
    # re-enters via the percent-encoded '#/$defs/N%7E1x' (both address key 'N/x').
    # The raw-string ref_path cycle guard sees two distinct strings; the visited
    # id-set must still backstop the cycle so extraction terminates and the
    # re-entrant position degrades to the _truncated leaf.
    schema = {
        "type": "object",
        "properties": {"node": {"$ref": "#/$defs/N~1x"}},
        "$defs": {
            "N/x": {
                "type": "object",
                "properties": {"loop": {"$ref": "#/$defs/N%7E1x"}},
            }
        },
    }
    skel = extract_skeleton(schema)  # must not hang / must not raise
    assert any(f.constraints.get("_truncated") is True for f in skel.props.values()), (
        "differently-encoded cyclic ref must degrade to a _truncated leaf"
    )


# --- 12. leading-zero array index stays OPAQUE; '0' and '1' resolve in range ---


def test_leading_zero_array_index_stays_opaque():
    # '#/$defs/arr/007' must NOT silently resolve to index 7 (RFC 6901 §4 forbids
    # leading zeros). A single '0' and an in-range '1' DO resolve.
    base = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/arr/007"}},
        "$defs": {
            "arr": [
                {"type": "string", "maxLength": 1},
                {"type": "string", "maxLength": 2},
                {"type": "string", "maxLength": 3},
                {"type": "string", "maxLength": 4},
                {"type": "string", "maxLength": 5},
                {"type": "string", "maxLength": 6},
                {"type": "string", "maxLength": 7},
                {"type": "string", "maxLength": 8},
            ]
        },
    }
    skel = extract_skeleton(base)
    # Stays OPAQUE: records the literal {"$ref": ...}, does NOT resolve to idx 7.
    assert _opaque_paths(skel) == {"x": "#/$defs/arr/007"}
    assert skel.props["x"].constraints.get("maxLength") is None

    # Single '0' resolves to index 0 (maxLength 1).
    zero = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/arr/0"}},
        "$defs": base["$defs"],
    }
    skel0 = extract_skeleton(zero)
    assert skel0.props["x"].constraints.get("maxLength") == 1
    assert "$ref" not in skel0.props["x"].constraints

    # In-range '1' resolves to index 1 (maxLength 2).
    one = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/arr/1"}},
        "$defs": base["$defs"],
    }
    skel1 = extract_skeleton(one)
    assert skel1.props["x"].constraints.get("maxLength") == 2
    assert "$ref" not in skel1.props["x"].constraints


# --- 9. per-path ref budget terminates a pathological chain -------------------


def test_ref_budget_terminates():
    # Build a linear ref chain longer than MAX_REFS: R0 -> R1 -> ... where each
    # Rk only references R(k+1); the tail is a plain string node.
    depth = MAX_REFS + 50
    defs = {}
    for k in range(depth):
        defs[f"R{k}"] = {"$ref": f"#/$defs/R{k + 1}"}
    defs[f"R{depth}"] = {"type": "string", "maxLength": 64}
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/R0"}},
        "$defs": defs,
    }
    skel = extract_skeleton(schema)  # must not raise / must terminate
    f = skel.props["x"]
    # Budget (or depth) exhausted -> degrades to opaque or truncated leaf.
    assert "$ref" in f.constraints or f.constraints.get("_truncated") is True


# --- 10. genuine pre-#29 OPAQUE-leaf baseline vs v3 resolved current ----------
# Locks the audit's cardinal-sin scenario: a lock pinned by an OLD (pre-#29)
# warden stored an OPAQUE $ref leaf; under v3 the same surface re-extracts to a
# RESOLVED skeleton. If the shared def relaxed, the diff must still fire HIGH
# (the gate blocks) — granularity-loss is acceptable, a silent pass is NOT.


def test_opaque_v2_baseline_vs_resolved_v3_relaxation_blocks_high(monkeypatch):
    import mcp_warden.schema_diff as sd

    base_schema = {
        "type": "object",
        "properties": {"user": {"$ref": "#/$defs/User"}},
        "$defs": {"User": {"type": "object", "properties": {"id": {}, "name": {}}, "required": ["id", "name"]}},
    }
    # RELAXED shared def: 'name' dropped from properties + required.
    cur_schema = {
        "type": "object",
        "properties": {"user": {"$ref": "#/$defs/User"}},
        "$defs": {"User": {"type": "object", "properties": {"id": {}}, "required": ["id"]}},
    }

    # Build a genuine v2 OPAQUE-leaf baseline by forcing the resolver to OPAQUE
    # during baseline extraction only (reproduces a pre-#29 stored skeleton).
    monkeypatch.setattr(sd, "_resolve_in_doc_ref", lambda ref, root, ref_path: sd._OPAQUE)
    v2_baseline = extract_skeleton(base_schema)
    monkeypatch.undo()
    v3_current = extract_skeleton(cur_schema)

    # Sanity: the baseline really held an opaque $ref leaf at 'user'.
    assert v2_baseline.props["user"].constraints.get("$ref") == "#/$defs/User"

    changes = diff_skeletons(v2_baseline, v3_current)
    highs = [c for c in changes if c.severity == "high"]
    # The opaque->resolved transition fires schema-modified (high) at the ref
    # path -> the gate blocks; the relaxation is never an under-report.
    assert highs, f"expected >=1 HIGH (gate must block), got {[ (c.change_class, c.severity) for c in changes]}"
    assert any(c.change_class == "schema-modified" and c.path == "user" for c in highs)
