import pytest

from mcp_warden.policy_enforcement import ActivatedAdapterV1
from tests.receipt_fixtures import pep_fixture


def test_positive_trace_records_evidence_before_sink():
    pep, request, runtime, effect, providers = pep_fixture()
    result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert result.invoked
    assert (
        trace.events.index("decision")
        < trace.events.index("evidence")
        < trace.events.index("sink")
        < trace.events.index("output")
    )
    assert result.evidence.mode == "primary-durable"


@pytest.mark.parametrize(
    "failure", ["primary", "fallback", "state", "latch", "signer", "runtime", "effect", "request"]
)
def test_negative_failure_paths_never_reach_effect(monkeypatch, failure):
    pep, request, runtime, effect, providers = pep_fixture()
    calls = []
    monkeypatch.setattr(
        ActivatedAdapterV1, "_handler", lambda self, name: lambda payload: calls.append(payload)
    )
    if failure in {"primary", "state", "latch"}:
        providers[failure].fail = True
    elif failure == "fallback":
        providers["primary"].fail = True
        providers["fallback"].fail = True
    elif failure == "signer":

        def fail(**kwargs):
            raise ValueError("secret signer path")

        monkeypatch.setattr(pep._coordinator.signer, "sign", fail)
    elif failure == "runtime":
        runtime = object()
    elif failure == "effect":
        effect = object()
    else:
        request = object()
    result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert not result.invoked and not calls
    assert "evidence" in trace.events
    assert "secret" not in b"".join(trace.output_channels).decode()


def test_failed_allow_gets_exactly_one_separately_bound_deny_conversion():
    pep, request, runtime, effect, providers = pep_fixture()
    providers["primary"].fail = True
    result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert trace.events.count("evidence") == 2
    assert result.decision.effective_verdict == "deny"
    assert result.decision.converted_from_decision_digest is not None


def test_private_instrumented_trace_contains_actual_signed_evidence():
    pep, request, runtime, effect, providers = pep_fixture()
    result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert providers["primary"].payloads[0] in trace.output_channels
    assert b"signature_hex" in providers["primary"].payloads[0]
    from mcp_warden.policy_enforcement_v2 import serialize_enforcement_result_v2

    assert b"signature_hex" not in serialize_enforcement_result_v2(result)


def test_late_state_failure_records_distinct_deny(monkeypatch):
    pep, request, runtime, effect, providers = pep_fixture()
    original = providers["state"].read

    def late_read():
        if providers["primary"].tail.sequence > 0:
            # The coordinator reads after commit; allow that first read, fail the
            # second read at the pre-sink boundary.
            late_read.count += 1
            if late_read.count >= 2:
                raise ValueError("secret late provider")
        return original()

    late_read.count = 0
    monkeypatch.setattr(providers["state"], "read", late_read)
    result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert not result.invoked
    assert result.decision.effective_verdict == "deny"
    assert result.decision.converted_from_decision_digest is not None
    assert trace.events.count("evidence") == 2


def test_forged_result_rejected_by_code_only_serializer():
    from mcp_warden.policy_enforcement_v2 import serialize_enforcement_result_v2
    from mcp_warden.receipt_kernel import ReceiptError

    pep, request, runtime, effect, providers = pep_fixture()
    result = pep.execute(request, runtime=runtime, effect=effect)
    from dataclasses import replace

    if hasattr(result, "model_copy"):
        forged = result.model_copy(update={"code": "secret result text"})
    else:
        forged = replace(result, code="secret result text")
    with pytest.raises(ReceiptError) as error:
        serialize_enforcement_result_v2(forged)
    assert error.value.__context__ is None
