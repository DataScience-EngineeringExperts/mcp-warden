from dataclasses import asdict

import pytest

from mcp_warden.content_models import IngressKindV1, TaintV1
from mcp_warden.correlation import CorrelationEngine

AUTHORITY_CLAIM = "WRD-RES-INJECT-AUTHORITY-IMPERSONATION"
OVERRIDE = "WRD-RES-INJECT-INSTRUCTION-OVERRIDE"
TOOL_COERCION = "WRD-RES-INJECT-TOOL-COERCION"
SELECT_TOOL = "DSE720-SELECT-TOOL"
TOOL_CALL = "DSE720-TOOL-CALL-OBSERVED"


@pytest.mark.parametrize(
    ("attempt", "suffix", "boundary"),
    [
        ("DSE720-GRANT-AUTHORITY", "AUTHORITY-GRANT", "authority"),
        ("DSE720-REQUEST-PRIVILEGE", "PRIVILEGE-REQUEST", "privilege"),
        ("DSE720-ALTER-POLICY", "POLICY-ALTERATION", "policy"),
        (SELECT_TOOL, "TOOL-SELECTION", "tool-selection"),
    ],
)
def test_correlates_four_boundary_attempts(attempt, suffix, boundary):
    engine = CorrelationEngine()

    assert engine.observe(IngressKindV1.BUNDLE_METADATA, injection_rule_ids=(AUTHORITY_CLAIM,)) == ()
    assert engine.observe() == ()
    result, = engine.observe(IngressKindV1.AGENT_MESSAGE, injection_rule_ids=(attempt,))

    assert result.rule_id == f"WRD-RES-CORRELATION-{suffix}"
    assert result.boundary == f"untrusted-content-to-{boundary}"
    assert tuple(signal.ordinal for signal in result.evidence) == (1, 3)
    assert tuple(signal.ingress for signal in result.evidence) == (
        IngressKindV1.BUNDLE_METADATA, IngressKindV1.AGENT_MESSAGE,
    )
    assert tuple(signal.signal_ids for signal in result.evidence) == ((AUTHORITY_CLAIM,), (attempt,))
    assert result.taints == (TaintV1.AUTHORITY_INJECTION, TaintV1.UNTRUSTED)


def test_single_observation_repeated_signal_and_unrelated_call_do_not_correlate():
    engine = CorrelationEngine()
    assert engine.observe(IngressKindV1.TOOL_RESULT, injection_rule_ids=(AUTHORITY_CLAIM,)) == ()
    assert engine.observe(IngressKindV1.TOOL_RESULT, injection_rule_ids=(AUTHORITY_CLAIM,)) == ()
    assert engine.observe(tool_selection=True) == ()

    engine = CorrelationEngine()
    assert engine.observe(
        IngressKindV1.TOOL_RESULT, injection_rule_ids=(AUTHORITY_CLAIM, SELECT_TOOL),
    ) == ()


def test_actual_tool_selection_requires_prior_selection_evidence():
    engine = CorrelationEngine()
    assert engine.observe(tool_selection=True) == ()
    assert engine.observe(IngressKindV1.MCP_PROMPT, injection_rule_ids=(TOOL_COERCION,)) == ()

    result, = engine.observe(tool_selection=True)

    assert result.boundary == "untrusted-content-to-tool-selection"
    assert tuple(item.ordinal for item in result.evidence) == (2, 3)
    assert result.evidence[1].ingress is None
    assert result.evidence[1].signal_ids == (TOOL_CALL,)
    assert result.evidence[1].taints == ()
    assert engine.observe(tool_selection=True) == ()


def test_equivalent_selection_indicators_do_not_supply_distinct_evidence():
    engine = CorrelationEngine()
    assert engine.observe(IngressKindV1.MCP_PROMPT, injection_rule_ids=(TOOL_COERCION,)) == ()
    assert engine.observe(IngressKindV1.AGENT_MESSAGE, injection_rule_ids=(SELECT_TOOL,)) == ()


def test_observed_call_does_not_seed_future_correlation():
    engine = CorrelationEngine()
    assert engine.observe(tool_selection=True) == ()
    assert engine.observe(IngressKindV1.DOCUMENT, injection_rule_ids=(OVERRIDE,)) == ()


def test_verified_taint_correlates_without_raw_content_or_a_catalog_signal():
    engine = CorrelationEngine()
    assert engine.observe(
        IngressKindV1.EMAIL, taints=(TaintV1.AUTHORITY_INJECTION, TaintV1.SECRET),
    ) == ()
    result, = engine.observe(IngressKindV1.MCP_RESOURCE, injection_rule_ids=(OVERRIDE,))

    assert result.boundary == "untrusted-content-to-policy"
    assert result.evidence[0].signal_ids == ()
    assert result.taints == (TaintV1.AUTHORITY_INJECTION, TaintV1.SECRET, TaintV1.UNTRUSTED)


def test_untrusted_label_alone_does_not_establish_an_antecedent():
    engine = CorrelationEngine()
    assert engine.observe(IngressKindV1.WEB, taints=(TaintV1.UNTRUSTED,)) == ()
    assert engine.observe(IngressKindV1.TOOL_RESULT, injection_rule_ids=(SELECT_TOOL,)) == ()


def test_expiry_is_inclusive_and_advanced_by_clean_local_observations():
    live = CorrelationEngine(max_observation_distance=2)
    expired = CorrelationEngine(max_observation_distance=2)
    for engine in (live, expired):
        assert engine.observe(IngressKindV1.DOCUMENT, injection_rule_ids=(AUTHORITY_CLAIM,)) == ()
        assert engine.observe() == ()

    assert len(live.observe(IngressKindV1.AGENT_MESSAGE, injection_rule_ids=(OVERRIDE,))) == 1
    assert expired.observe() == ()
    assert expired.observe(IngressKindV1.AGENT_MESSAGE, injection_rule_ids=(OVERRIDE,)) == ()


def test_sessions_have_independent_history_and_order():
    one, two = CorrelationEngine(), CorrelationEngine()
    assert one.observe(IngressKindV1.DOCUMENT, injection_rule_ids=(AUTHORITY_CLAIM,)) == ()
    assert two.observe(IngressKindV1.AGENT_MESSAGE, injection_rule_ids=(SELECT_TOOL,)) == ()
    result, = one.observe(IngressKindV1.AGENT_MESSAGE, injection_rule_ids=(SELECT_TOOL,))

    assert tuple(item.ordinal for item in result.evidence) == (1, 2)


def test_history_bound_and_replay_are_deterministic():
    def trace():
        engine = CorrelationEngine(max_observation_distance=3)
        findings = []
        for index in range(50):
            signals = (AUTHORITY_CLAIM,) if index % 2 else (OVERRIDE,)
            findings.extend(engine.observe(IngressKindV1.TOOL_RESULT, injection_rule_ids=signals))
            assert len(engine._history) <= 3
        return findings

    assert trace() == trace()


def test_evidence_uses_only_allowlisted_ids_and_ingress():
    engine = CorrelationEngine()
    assert engine.observe(
        IngressKindV1.TOOL_RESULT,
        injection_rule_ids=(AUTHORITY_CLAIM, AUTHORITY_CLAIM, "private fixture", TOOL_CALL),
        taints=("unregistered private fixture",),
    ) == ()
    result, = engine.observe(IngressKindV1.AGENT_MESSAGE, injection_rule_ids=(SELECT_TOOL,))

    assert "private fixture" not in repr(asdict(result))
    assert result.evidence[0].signal_ids == (AUTHORITY_CLAIM,)
    assert result.evidence[0].taints == (TaintV1.AUTHORITY_INJECTION, TaintV1.UNTRUSTED)


def test_signal_collection_is_consumed_under_a_fixed_bound():
    def excess_signals():
        for _ in range(65):
            yield AUTHORITY_CLAIM
        pytest.fail("read beyond the signal input bound")

    engine = CorrelationEngine()
    assert engine.observe(IngressKindV1.TOOL_RESULT, injection_rule_ids=excess_signals()) == ()
    assert engine.observe(IngressKindV1.AGENT_MESSAGE, injection_rule_ids=(SELECT_TOOL,)) == ()


@pytest.mark.parametrize("distance", (-1, 0, True, 257, float("nan")))
def test_invalid_expiry_rejected(distance):
    with pytest.raises(ValueError, match="observation distance"):
        CorrelationEngine(max_observation_distance=distance)


@pytest.mark.parametrize("second", [
    (OVERRIDE, SELECT_TOOL),
    (OVERRIDE, TOOL_COERCION),
    (SELECT_TOOL,),
])
def test_repeated_multicategory_observation_is_not_a_new_crossing(second):
    engine = CorrelationEngine()
    assert engine.observe(IngressKindV1.TOOL_RESULT, injection_rule_ids=(OVERRIDE, SELECT_TOOL)) == ()
    assert engine.observe(IngressKindV1.TOOL_RESULT, injection_rule_ids=second) == ()
