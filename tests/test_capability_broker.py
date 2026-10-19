import pytest

from mcp_warden.capability_broker import project_tools, select_capability
from mcp_warden.capability_models import MAX_CANDIDATES, CapabilityError, CapabilityIntentV1
from mcp_warden.decision_models import DecisionRequestV1
from tests.capability_fixtures import fixture
from tests.test_policy_enforcement import _digest


def test_unique_narrower_signed_interval_selected_independent_of_order():
    intent, candidates, authority, _ = fixture(windows=((100, 300), (150, 250)))
    first = select_capability(intent, candidates=candidates, **authority)
    second = select_capability(intent, candidates=tuple(reversed(candidates)), **authority)
    assert first == second
    assert first.request == candidates[1]
    assert first.scope_schema == "exact-bound-operation-v1"


@pytest.mark.parametrize("windows", [((100, 250), (150, 300)), ((100, 300), (100, 300))])
def test_incomparable_and_equal_minima_prepare_nothing(windows):
    intent, candidates, authority, _ = fixture(windows=windows)
    assert select_capability(intent, candidates=candidates, **authority) is None


@pytest.mark.parametrize("options", [{"grant": False}, {"revoked": True}, {"now": 300}])
def test_unapproved_revoked_expired_candidates_hidden(options):
    intent, candidates, authority, _ = fixture(**options)
    assert select_capability(intent, candidates=candidates, **authority) is None


def test_duplicate_candidates_are_closed_error():
    intent, candidates, authority, _ = fixture()
    with pytest.raises(CapabilityError):
        select_capability(intent, candidates=candidates * 2, **authority)


def test_distinct_registered_operations_are_incomparable_even_with_nested_time():
    intent, candidates, authority, _ = fixture(
        windows=((100, 300), (150, 250)), operation_ids=("document.read", "document.other"),
    )
    assert select_capability(intent, candidates=candidates, **authority) is None
    assert project_tools(intent, candidates=candidates, **authority) == ()


@pytest.mark.parametrize("field", [
    "data_scope_digest", "purpose_digest", "destination_digest", "arguments_digest",
])
def test_changed_scope_or_effect_hides_candidate(field):
    intent, candidates, authority, _ = fixture()
    changed = intent.model_copy(update={field: _digest("changed")})
    assert select_capability(changed, candidates=candidates, **authority) is None


@pytest.mark.parametrize("field", ["user_digest", "agent_digest", "device_digest", "session_digest"])
def test_identity_substitution_hides_candidate(field):
    intent, candidates, authority, _ = fixture()
    identity = intent.identity.model_copy(update={field: _digest("other")})
    changed = intent.model_copy(update={"identity": identity})
    assert select_capability(changed, candidates=candidates, **authority) is None


@pytest.mark.parametrize("field,value", [
    ("operation_id", "unknown.operation"), ("adapter_id", "unknown.adapter"),
    ("adapter_manifest_digest", _digest("other")), ("capability", "disclose"),
])
def test_operation_and_manifest_drift_never_prepare(field, value):
    intent, candidates, authority, _ = fixture()
    request = candidates[0]
    changed = request.model_copy(update={"operation": request.operation.model_copy(update={field: value})})
    assert select_capability(intent, candidates=(changed,), **authority) is None


def test_expiry_equality_and_not_before_use_activated_time():
    for now, expected in ((149, False), (150, True), (249, True), (250, False)):
        intent, candidates, authority, _ = fixture(windows=((150, 250),), now=now)
        assert (select_capability(intent, candidates=candidates, **authority) is not None) is expected


def test_candidate_cap_and_plus_one_and_empty_input():
    intent, candidates, authority, _ = fixture(windows=((100, 300),) * MAX_CANDIDATES)
    assert select_capability(intent, candidates=candidates, **authority) is None
    assert select_capability(intent, candidates=(), **authority) is None
    with pytest.raises(CapabilityError):
        select_capability(intent, candidates=candidates + candidates[:1], **authority)


@pytest.mark.parametrize("candidate", [object(), DecisionRequestV1.model_construct()])
def test_hostile_or_incomplete_candidates_are_closed(candidate):
    intent, _, authority, _ = fixture()
    with pytest.raises(CapabilityError):
        select_capability(intent, candidates=(candidate,), **authority)


def test_unactivated_authority_and_incomplete_intent_fail_closed():
    intent, candidates, authority, _ = fixture()
    for key in ("pdp", "adapter"):
        with pytest.raises(CapabilityError, match="CAP-AUTHORITY-UNAVAILABLE"):
            select_capability(intent, candidates=candidates, **(authority | {key: object()}))
    assert select_capability(intent, candidates=candidates, **(authority | {"runtime": object()})) is None
    with pytest.raises(CapabilityError):
        select_capability(CapabilityIntentV1.model_construct(), candidates=candidates, **authority)
