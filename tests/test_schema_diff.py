"""Structural schema-diff unit tests (#15): taxonomy rows + contract invariants.

Covers every row of the binding taxonomy (03_ADVERSARIAL_REVIEW.md) plus the
determinism / R1 / R4 / malformed / per-fact contract tests.
"""

from __future__ import annotations

from mcp_warden.schema_diff import (
    MAX_DEPTH,
    ROOT_PATH,
    diff_skeletons,
    extract_skeleton,
)


def _diff(base_schema, cur_schema):
    return diff_skeletons(extract_skeleton(base_schema), extract_skeleton(cur_schema))


def _classes(changes):
    return {(c.path, c.change_class, c.severity) for c in changes}


def _obj(props, required=None, **extra):
    s = {"type": "object", "properties": props}
    if required is not None:
        s["required"] = required
    s.update(extra)
    return s


# --- taxonomy rows -----------------------------------------------------------


def test_required_prop_removed_high():
    base = _obj({"a": {"type": "string"}}, required=["a"])
    cur = _obj({})
    assert ("a", "schema-required-removed", "high") in _classes(_diff(base, cur))


def test_optional_prop_removed_medium():
    base = _obj({"a": {"type": "string"}})
    cur = _obj({})
    assert ("a", "schema-property-removed", "medium") in _classes(_diff(base, cur))


def test_new_required_unconstrained_high():
    base = _obj({})
    cur = _obj({"a": {"type": "string"}}, required=["a"])
    assert ("a", "schema-required-unconstrained-added", "high") in _classes(_diff(base, cur))


def test_new_required_constrained_medium():
    base = _obj({})
    cur = _obj({"a": {"type": "string", "maxLength": 8}}, required=["a"])
    assert ("a", "schema-required-added", "medium") in _classes(_diff(base, cur))


def test_new_optional_unconstrained_high():
    base = _obj({})
    cur = _obj({"a": {"type": "string"}})
    assert ("a", "schema-unconstrained-added", "high") in _classes(_diff(base, cur))


def test_new_optional_constrained_low():
    base = _obj({})
    cur = _obj({"a": {"type": "string", "enum": ["x", "y"]}})
    assert ("a", "schema-property-added", "low") in _classes(_diff(base, cur))


def test_type_broadened_high():
    base = _obj({"a": {"type": "string"}})
    cur = _obj({"a": {"type": ["string", "object"]}})
    assert ("a", "schema-type-broadened", "high") in _classes(_diff(base, cur))


def test_type_narrowed_low():
    base = _obj({"a": {"type": ["string", "object"]}})
    cur = _obj({"a": {"type": "string"}})
    assert ("a", "schema-type-narrowed", "low") in _classes(_diff(base, cur))


def test_type_changed_medium():
    base = _obj({"a": {"type": "string"}})
    cur = _obj({"a": {"type": "integer"}})
    assert ("a", "schema-type-changed", "medium") in _classes(_diff(base, cur))


def test_enum_widened_high():
    base = _obj({"a": {"enum": ["x"]}})
    cur = _obj({"a": {"enum": ["x", "y"]}})
    assert ("a", "schema-enum-widened", "high") in _classes(_diff(base, cur))


def test_enum_narrowed_low():
    base = _obj({"a": {"enum": ["x", "y"]}})
    cur = _obj({"a": {"enum": ["x"]}})
    assert ("a", "schema-enum-narrowed", "low") in _classes(_diff(base, cur))


def test_enum_removed_high():
    base = _obj({"a": {"enum": ["x", "y"]}})
    cur = _obj({"a": {}})
    assert ("a", "schema-enum-removed", "high") in _classes(_diff(base, cur))


def test_enum_added_low():
    base = _obj({"a": {}})
    cur = _obj({"a": {"enum": ["x", "y"]}})
    assert ("a", "schema-enum-added", "low") in _classes(_diff(base, cur))


def test_required_to_optional_constraint_relaxed_medium():
    base = _obj({"a": {"type": "string"}}, required=["a"])
    cur = _obj({"a": {"type": "string"}})
    assert ("a", "schema-constraint-relaxed", "medium") in _classes(_diff(base, cur))


def test_constraint_relaxed_maxlength_up_medium():
    base = _obj({"a": {"type": "string", "maxLength": 64}})
    cur = _obj({"a": {"type": "string", "maxLength": 4096}})
    changes = _diff(base, cur)
    relaxed = [c for c in changes if c.change_class == "schema-constraint-relaxed"]
    assert relaxed and relaxed[0].severity == "medium"
    assert relaxed[0].detail == "maxLength 64→4096"


def test_constraint_relaxed_pattern_removed_medium():
    base = _obj({"a": {"type": "string", "pattern": "^x$"}})
    cur = _obj({"a": {"type": "string"}})
    assert ("a", "schema-constraint-relaxed", "medium") in _classes(_diff(base, cur))


def test_constraint_relaxed_minimum_lowered_medium():
    base = _obj({"a": {"type": "integer", "minimum": 10}})
    cur = _obj({"a": {"type": "integer", "minimum": 0}})
    assert ("a", "schema-constraint-relaxed", "medium") in _classes(_diff(base, cur))


def test_additional_props_opened_high():
    base = _obj({}, additionalProperties=False)
    cur = _obj({}, additionalProperties=True)
    assert (ROOT_PATH, "schema-additional-props-opened", "high") in _classes(_diff(base, cur))


def test_additional_props_opened_to_schema_object_high():
    # false -> {"type": "string"} is a real relaxation (closed-world ->
    # typed-extra-props allowed), classified as the open-world escalation (high).
    base = _obj({}, additionalProperties=False)
    cur = _obj({}, additionalProperties={"type": "string"})
    assert (ROOT_PATH, "schema-additional-props-opened", "high") in _classes(_diff(base, cur))


def test_additional_props_schema_object_to_false_tightened_low():
    # The reverse ({"type": "string"} -> false) is a tightening (low).
    base = _obj({}, additionalProperties={"type": "string"})
    cur = _obj({}, additionalProperties=False)
    assert (ROOT_PATH, "schema-constraint-tightened", "low") in _classes(_diff(base, cur))


def test_constraint_tightened_low():
    base = _obj({"a": {"type": "string", "maxLength": 4096}})
    cur = _obj({"a": {"type": "string", "maxLength": 16}})
    assert ("a", "schema-constraint-tightened", "low") in _classes(_diff(base, cur))


def test_skeleton_identical_no_changes():
    s = _obj({"a": {"type": "string", "description": "x"}})
    # Only the cosmetic description differs -> dropped -> empty diff.
    s2 = _obj({"a": {"type": "string", "description": "TOTALLY DIFFERENT"}})
    assert diff_skeletons(extract_skeleton(s), extract_skeleton(s2)) == []


# --- contract / invariant tests ----------------------------------------------


def test_determinism_key_reordered_equivalent():
    a = _obj({"x": {"type": "string", "maxLength": 10}, "y": {"type": "integer"}}, required=["x"])
    b = {
        "properties": {"y": {"type": "integer"}, "x": {"maxLength": 10, "type": "string"}},
        "required": ["x"],
        "type": "object",
    }
    assert extract_skeleton(a) == extract_skeleton(b)


def test_determinism_repeated_extraction_identical():
    s = _obj({"a": {"type": ["object", "string"], "enum": ["b", "a"]}})
    assert extract_skeleton(s) == extract_skeleton(s)


def test_r1_additional_props_absent_equals_explicit_true():
    s1 = _obj({"a": {"type": "string"}})
    s2 = _obj({"a": {"type": "string"}}, additionalProperties=True)
    assert extract_skeleton(s1) == extract_skeleton(s2)
    assert diff_skeletons(extract_skeleton(s1), extract_skeleton(s2)) == []


def test_r4_ref_is_opaque_leaf():
    base = _obj({"a": {"$ref": "#/defs/x"}})
    cur = _obj({"a": {"$ref": "#/defs/y"}})
    skel = extract_skeleton(base)
    assert skel.props["a"].constraints == {"$ref": "#/defs/x"}
    # Two different refs differ deterministically; same ref => no drift.
    assert diff_skeletons(extract_skeleton(base), extract_skeleton(base)) == []
    assert diff_skeletons(skel, extract_skeleton(cur)) != []


def test_r4_cyclic_schema_terminates_no_crash():
    cyc = {"type": "object", "properties": {}}
    cyc["properties"]["self"] = cyc  # self-reference
    skel = extract_skeleton(cyc)  # must terminate, not raise
    assert ROOT_PATH in skel.props


def test_r4_deeply_nested_truncates():
    # Build a chain deeper than MAX_DEPTH; extraction must terminate.
    node: dict = {"type": "object", "properties": {}}
    root = node
    for _ in range(MAX_DEPTH + 10):
        child: dict = {"type": "object", "properties": {}}
        node["properties"]["n"] = child
        node = child
    skel = extract_skeleton(root)
    assert any(f.constraints.get("_truncated") for f in skel.props.values())


def test_malformed_non_dict_does_not_raise():
    for bad in (None, "string", 42, [1, 2, 3], True):
        assert extract_skeleton(bad).props == {}


def test_malformed_nested_property_degrades():
    # A property whose value is not a dict is captured as a bare leaf, no raise.
    skel = extract_skeleton(_obj({"a": "not-a-schema"}))
    assert "a" in skel.props


def test_per_fact_emission_required_and_type():
    # required:true,string -> required:false,[string,null] emits BOTH facts (R7).
    base = _obj({"a": {"type": "string"}}, required=["a"])
    cur = _obj({"a": {"type": ["null", "string"]}})
    classes = {c.change_class for c in _diff(base, cur)}
    assert "schema-constraint-relaxed" in classes  # required -> optional
    assert "schema-type-broadened" in classes  # string -> string|null


def test_array_items_recursed():
    base = _obj({"a": {"type": "array", "items": {"type": "string", "maxLength": 4}}})
    cur = _obj({"a": {"type": "array", "items": {"type": "string", "maxLength": 99}}})
    changes = _diff(base, cur)
    assert any(c.path == "a[]" and c.change_class == "schema-constraint-relaxed" for c in changes)


def test_detail_redacts_secret_looking_values():
    # A constraint carrying a secret-looking literal must not echo the raw value.
    base = _obj({"a": {"type": "string", "pattern": "^api_key-AKIA1234567890$"}})
    cur = _obj({"a": {"type": "string", "pattern": "^token-XYZ$"}})
    changes = _diff(base, cur)
    for c in changes:
        assert "AKIA1234567890" not in (c.detail or "")
