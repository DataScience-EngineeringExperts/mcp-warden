"""Synthetic PEP integration only; reference profiles never prove platform safety."""

import pytest

from mcp_warden.capability_broker import select_capability
from mcp_warden.capability_models import serialize_prepared_capability
from mcp_warden.client_capability_adapter import prepare_client_call
from mcp_warden.receipt_conformance import run_receipt_conformance
from tests.capability_fixtures import intent_for
from tests.receipt_fixtures import pep_fixture
from tests.test_receipt_conformance import matrix


def test_prepared_request_is_rechecked_and_evidenced_before_synthetic_effect():
    pep, request, runtime, effect, providers = pep_fixture()
    prepared = prepare_client_call(
        request.operation.operation_id, effect.arguments, intent_for(request),
        candidates=(request,), pdp=pep._pdp, adapter=pep._adapter, runtime=runtime,
    )
    assert prepared is not None and prepared.request == request
    assert not providers["primary"].payloads  # Preparation produces no issuance/allow receipt.
    result, trace = pep._execute_instrumented(prepared.request, runtime=runtime, effect=effect)
    assert result.invoked and result.evidence.mode == "primary-durable"
    assert trace.events.index("evidence") < trace.events.index("sink")


@pytest.mark.parametrize("failure", ["primary", "dual", "state", "latch", "signer"])
def test_prepared_data_cannot_bypass_later_evidence_failures(monkeypatch, failure):
    pep, request, runtime, effect, providers = pep_fixture()
    prepared = select_capability(
        intent_for(request), candidates=(request,), pdp=pep._pdp, adapter=pep._adapter,
        runtime=runtime,
    )
    assert prepared is not None
    if failure in {"primary", "dual"}:
        providers["primary"].fail = True
    if failure == "dual":
        providers["fallback"].fail = True
    if failure in {"state", "latch"}:
        providers[failure].fail = True
    if failure == "signer":
        def fail(**kwargs):
            raise ValueError("PLANTED-PRIVATE-SECRET")
        monkeypatch.setattr(pep._coordinator.signer, "sign", fail)
    result, trace = pep._execute_instrumented(prepared.request, runtime=runtime, effect=effect)
    assert not result.invoked and "sink" not in trace.events
    assert b"PLANTED" not in b"".join(trace.output_channels)
    assert b"PLANTED" not in serialize_prepared_capability(prepared)


def test_broker_addition_preserves_nonoptional_receipt_failure_corpus(tmp_path):
    vector = matrix(tmp_path)
    scenario = vector.allow
    assert select_capability(
        intent_for(scenario.request), candidates=(scenario.request,), pdp=scenario.pep._pdp,
        adapter=scenario.pep._adapter, runtime=scenario.runtime,
    ) is not None
    report = run_receipt_conformance((vector,))
    assert report.passed and report.total_cases == 16 and report.fixed_cases == 5
    assert report.platform_status == "unsupported" and report.atk_conformant is False
