"""Independent CSO findings reproduced through the complete PEP boundary."""

import os
import stat

import pytest

from mcp_warden.evidence_reference import InMemoryRecoveryLatchV1
from mcp_warden.evidence_state import RecoveryLatchSnapshotV1
from mcp_warden.policy_enforcement import ActivatedAdapterV1
from mcp_warden.receipt_log import FilePrimaryReceiptStoreV1
from mcp_warden.receipt_verification import primary_payload_validator
from tests.receipt_fixtures import pep_fixture


@pytest.mark.parametrize(
    "fields",
    [
        {"generation": 0, "latched": 0},
        {"generation": 0, "latched": []},
        {"generation": 0, "latched": ""},
        {"generation": False, "latched": False},
    ],
)
@pytest.mark.parametrize("boundary", ["reference", "actual-port"])
def test_forged_latch_never_permits_effect(monkeypatch, fields, boundary):
    pep, request, runtime, effect, p = pep_fixture()
    forged = RecoveryLatchSnapshotV1.model_construct(**fields)
    if boundary == "reference":
        p["latch"]._snapshot = forged
    else:
        monkeypatch.setattr(p["latch"], "read", lambda: forged)
    calls = []
    monkeypatch.setattr(
        ActivatedAdapterV1, "_handler", lambda self, name: lambda payload: calls.append(payload)
    )
    result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert not result.invoked and not calls
    assert result.decision.effective_verdict == "deny"
    assert "evidence" in trace.events


def file_pep(tmp_path):
    pep, request, runtime, effect, p = pep_fixture()
    c = pep._coordinator
    c.primary = FilePrimaryReceiptStoreV1(
        tmp_path / "primary",
        store_identity_digest=p["primary"].store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=c.authorization, verifier=c.verifier, snapshot=p["state"].read
        ),
    )
    return pep, request, runtime, effect, p


def test_first_coordinator_read_create_then_append_syncs_directory(tmp_path, monkeypatch):
    pep, request, runtime, effect, p = file_pep(tmp_path)
    syncs = []
    original = os.fsync

    def capture(fd):
        syncs.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        original(fd)

    monkeypatch.setattr(os, "fsync", capture)
    result = pep.execute(request, runtime=runtime, effect=effect)
    assert result.invoked
    assert "directory" in syncs and "file" in syncs


def test_directory_fsync_failure_prevents_effect(tmp_path, monkeypatch):
    pep, request, runtime, effect, p = file_pep(tmp_path)
    original = os.fsync

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("secret directory fsync path")
        original(fd)

    monkeypatch.setattr(os, "fsync", fail_directory)
    calls = []
    monkeypatch.setattr(
        ActivatedAdapterV1, "_handler", lambda self, name: lambda payload: calls.append(payload)
    )
    result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert not result.invoked and not calls
    assert b"secret" not in b"".join(trace.output_channels)


@pytest.mark.parametrize("transition", ["degraded", "fallback", "both"])
def test_false_fallback_commit_is_latched_and_second_call_cannot_execute(monkeypatch, transition):
    pep, request, runtime, effect, p = pep_fixture()
    original = p["state"].compare_and_advance

    def false_ack(expected, candidate):
        degraded = candidate.mode.value == "evidence-degraded" and candidate.fallback_sequence == 0
        fallback = candidate.fallback_sequence > 0
        if (
            transition == "both"
            or transition == "degraded"
            and degraded
            or transition == "fallback"
            and fallback
        ):
            return candidate
        return original(expected, candidate)

    monkeypatch.setattr(p["state"], "compare_and_advance", false_ack)
    p["primary"].fail = True
    first = pep.execute(request, runtime=runtime, effect=effect)
    if transition == "degraded":
        assert not p["fallback"].payloads
    assert first.evidence.mode != "fallback-durable"
    assert p["latch"].read().latched
    monkeypatch.setattr(p["state"], "compare_and_advance", original)
    p["primary"].fail = False
    calls = []
    monkeypatch.setattr(
        ActivatedAdapterV1, "_handler", lambda self, name: lambda payload: calls.append(payload)
    )
    second = pep.execute(request, runtime=runtime, effect=effect)
    assert not second.invoked and not calls


@pytest.mark.parametrize(
    "fields",
    [
        {"generation": 0, "latched": 0},
        {"generation": 0, "latched": []},
        {"generation": 0, "latched": ""},
        {"generation": False, "latched": False},
    ],
)
def test_malformed_latch_rejected_by_reference_and_pure_boundaries(fields):
    from mcp_warden.evidence_recovery import _CLEAR_SEAL, AuthorizedLatchClearV1
    from mcp_warden.evidence_state import operationally_healthy
    from mcp_warden.receipt_kernel import ReceiptError, receipt_digest
    from mcp_warden.receipt_models import ReceiptEventContextV1
    from mcp_warden.receipt_replay import ReplayVectorV1, current_eligibility

    pep, request, runtime, effect, p = pep_fixture()
    forged = RecoveryLatchSnapshotV1.model_construct(**fields)
    state = p["state"].read()
    assert not operationally_healthy(state, forged)
    with pytest.raises(ReceiptError) as error:
        InMemoryRecoveryLatchV1(snapshot=forged)
    assert error.value.__context__ is None
    p["latch"]._snapshot = forged
    event = receipt_digest(b"clear", "latch")
    receipt = receipt_digest(b"exit", "receipt")
    token = AuthorizedLatchClearV1(1, event, receipt, _CLEAR_SEAL)
    for operation in (
        lambda: p["latch"].read(),
        lambda: p["latch"].set(generation=0, event_digest=event),
        lambda: p["latch"].authenticated_clear(
            generation=1, prior_event_digest=event, exit_receipt_digest=receipt, authorization=token
        ),
    ):
        with pytest.raises(ReceiptError) as error:
            operation()
        assert error.value.__context__ is None
    vector = ReplayVectorV1(
        request=request,
        effect=effect,
        policy=pep._governor.policy,
        runtime=runtime,
        rules=pep._governor.rules,
        signer_authorization=pep._coordinator.authorization,
        snapshot=state,
        store_identity_digest=p["primary"].store_identity_digest,
        signer_identity_digest=pep._coordinator.signer_identity_digest,
        event=ReceiptEventContextV1(kind="allow"),
    )
    assert current_eligibility(vector, snapshot=state, latch=forged) == "recovery-only"


@pytest.mark.parametrize(
    "fields",
    [
        {"generation": 0, "latched": 0},
        {"generation": 0, "latched": []},
        {"generation": 0, "latched": ""},
        {"generation": False, "latched": False},
    ],
)
def test_recovery_actual_port_rejects_malformed_latch_before_append(monkeypatch, fields):
    from mcp_warden.receipt_kernel import ReceiptError
    from tests.test_evidence_recovery import recovery_fixture

    recovery, active, context, p = recovery_fixture()
    before = len(p["primary"].payloads)
    forged = RecoveryLatchSnapshotV1.model_construct(**fields)
    monkeypatch.setattr(p["latch"], "read", lambda: forged)
    with pytest.raises(ReceiptError) as error:
        recovery.exit(active, context)
    assert error.value.__context__ is None
    assert len(p["primary"].payloads) == before


def test_authenticated_clear_rejects_bool_generation_with_closed_error():
    from mcp_warden.evidence_recovery import _CLEAR_SEAL, AuthorizedLatchClearV1
    from mcp_warden.receipt_kernel import ReceiptError, receipt_digest

    latch = InMemoryRecoveryLatchV1()
    event = receipt_digest(b"event", "latch")
    receipt = receipt_digest(b"exit", "receipt")
    latch.set(generation=0, event_digest=event)
    token = AuthorizedLatchClearV1(1, event, receipt, _CLEAR_SEAL)
    with pytest.raises(ReceiptError) as error:
        latch.authenticated_clear(
            generation=True,
            prior_event_digest=event,
            exit_receipt_digest=receipt,
            authorization=token,
        )
    assert error.value.__context__ is None
    assert latch.read().latched


@pytest.mark.parametrize("store", ["primary", "fallback"])
def test_forged_append_ack_requires_actual_log_readback(monkeypatch, store):
    pep, request, runtime, effect, p = pep_fixture()
    log = p[store]
    original = log.append

    def false_ack(value, *, expected_tail):
        old = log.tail
        proof = original(value, expected_tail=expected_tail)
        log.tail = old
        log.payloads.pop()
        return proof

    monkeypatch.setattr(log, "append", false_ack)
    p["primary"].fail = store == "fallback"
    calls = []
    monkeypatch.setattr(
        ActivatedAdapterV1, "_handler", lambda self, name: lambda payload: calls.append(payload)
    )
    result = pep.execute(request, runtime=runtime, effect=effect)
    assert not result.invoked and not calls
    if store == "fallback":
        assert result.evidence.mode != "fallback-durable"
        assert p["latch"].read().latched
    else:
        assert p["state"].read().primary_sequence == 0


@pytest.mark.parametrize("when", ["before-decision", "before-sink"])
def test_unresolved_fallback_tail_prevents_normal_permit(monkeypatch, when):
    from mcp_warden.receipt_kernel import receipt_digest
    from mcp_warden.receipt_log import LogTailV1

    pep, request, runtime, effect, p = pep_fixture()
    wrong = LogTailV1(sequence=1, entry_digest=receipt_digest(b"unresolved", "log-entry"))
    if when == "before-decision":
        p["fallback"].tail = wrong
    else:
        original = p["state"].compare_and_advance

        def mutate_after_commit(expected, candidate):
            result = original(expected, candidate)
            p["fallback"].tail = wrong
            return result

        monkeypatch.setattr(p["state"], "compare_and_advance", mutate_after_commit)
    calls = []
    monkeypatch.setattr(
        ActivatedAdapterV1, "_handler", lambda self, name: lambda payload: calls.append(payload)
    )
    result = pep.execute(request, runtime=runtime, effect=effect)
    assert not result.invoked and not calls
    assert p["latch"].read().latched
