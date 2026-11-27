import pytest

from mcp_warden.capability_models import CapabilityError, CapabilityIntentV1
from tests.capability_fixtures import fixture


def test_intent_is_strict_immutable_and_roundtrips():
    intent, _, _, _ = fixture()
    assert CapabilityIntentV1.model_validate(intent.model_dump()) == intent
    with pytest.raises(CapabilityError):
        intent.capability = "execute"


@pytest.mark.parametrize("change", [
    {"approved": True}, {"call_limit": 1}, {"arguments_digest": "PLANTED-SECRET"},
    {"capability": "invented"}, {"schema_version": True}, {"identity": object()},
])
def test_malformed_and_unsupported_inputs_are_code_only(change):
    intent, _, _, _ = fixture()
    with pytest.raises(CapabilityError) as caught:
        CapabilityIntentV1(**(intent.model_dump() | change))
    assert str(caught.value) == "CAP-INPUT-MALFORMED"
    assert "PLANTED" not in repr(caught.value)


@pytest.mark.parametrize("route", ["assign", "private", "delete", "json", "strings", "validate"])
def test_all_supported_validation_and_mutation_errors_discard_rejected_values(route):
    intent, _, _, _ = fixture()
    with pytest.raises(CapabilityError) as caught:
        if route == "assign":
            intent.capability = "PLANTED-PRIVATE-SECRET"
        elif route == "private":
            intent._client = object()
        elif route == "delete":
            del intent.capability
        elif route == "json":
            CapabilityIntentV1.model_validate_json('{"PLANTED-PRIVATE-SECRET":"secret"}')
        elif route == "strings":
            CapabilityIntentV1.model_validate_strings({"PLANTED-PRIVATE-SECRET": "secret"})
        else:
            CapabilityIntentV1.model_validate({"PLANTED-PRIVATE-SECRET": "secret"})
    assert str(caught.value) == "CAP-INPUT-MALFORMED"
    assert not hasattr(caught.value, "errors")
    assert not hasattr(caught.value, "json")
    assert caught.value.__context__ is None
