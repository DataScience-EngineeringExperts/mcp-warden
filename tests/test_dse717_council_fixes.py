"""Council-confirmed defensive regressions using deterministic trusted test ports."""

import pytest

from mcp_warden.content_models import TaintV1
from mcp_warden.evidence_floor import FLOOR_KINDS
from mcp_warden.evidence_reference import InMemoryProtectedStateV1
from mcp_warden.policy_decision import (
    compute_request_binding_digest,
    create_capability_lease,
    create_decision_request,
)
from mcp_warden.policy_enforcement import ActivatedAdapterV1
from mcp_warden.receipt_verification import parse_signed_receipt
from tests.receipt_fixtures import pep_fixture
from tests.test_policy_decision import _envelope


@pytest.mark.parametrize("grant,critical", [(True, True), (False, False), (True, False)])
def test_invalid_override_preserves_critical_quarantine_and_rejects_input(
    monkeypatch, grant, critical
):
    pep, request, runtime, effect, p = pep_fixture(grant=grant)
    if critical:
        envelope = _envelope(taints=(TaintV1.CRITICAL,))
        binding = compute_request_binding_digest(
            identity=request.identity,
            operation=request.operation,
            envelope=envelope,
            data_scope_digest=request.data_scope_digest,
            purpose_digest=request.purpose_digest,
        )
        lease = create_capability_lease(
            **(
                request.lease.model_dump(exclude={"schema_version", "lease_digest"})
                | {"request_binding_digest": binding}
            )
        )
        request = create_decision_request(
            identity=request.identity,
            operation=request.operation,
            envelope=envelope,
            data_scope_digest=request.data_scope_digest,
            purpose_digest=request.purpose_digest,
            lease=lease,
        )
    base = pep._pdp.evaluate(request, runtime=runtime)
    assert base.verdict == ("quarantine" if critical else "allow" if grant else "deny")
    selections = []
    monkeypatch.setattr(ActivatedAdapterV1, "_handler", lambda *args: selections.append(args))
    result, trace = pep._execute_instrumented(
        request, runtime=runtime, effect=effect, override=object()
    )
    assert not result.invoked and not selections and "evidence" in trace.events
    assert result.decision.effective_verdict == ("quarantine" if critical else "deny")
    assert result.decision.public_reason == (base.reason if critical else "RULE-OVERRIDE-INVALID")
    assert result.decision.recovery_code == base.recovery
    assert result.evidence.mode == "primary-durable"
    signed = parse_signed_receipt(p["primary"].payloads[0])
    assert signed.receipt.effective_verdict == result.decision.effective_verdict
    assert signed.receipt.public_reason == result.decision.public_reason


@pytest.mark.parametrize("missing", [kind for kind in FLOOR_KINDS if kind != "override"])
def test_v2_missing_mandatory_floor_blocks_before_handler_or_primary_permit(monkeypatch, missing):
    pep, request, runtime, effect, p = pep_fixture()
    state = p["state"].read()
    p["state"] = InMemoryProtectedStateV1(
        state.model_copy(update={"floors": tuple(f for f in state.floors if f.kind != missing)})
    )
    pep._coordinator.protected_state = p["state"]
    selections = []
    monkeypatch.setattr(ActivatedAdapterV1, "_handler", lambda *args: selections.append(args))
    result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
    assert not result.invoked and not selections
    assert "evidence" in trace.events and not p["primary"].payloads
    assert result.decision.effective_verdict == "deny"
    assert result.decision.public_reason == "PEP-RECOVERY-ONLY"
    assert result.evidence.mode in {"recovery-latched", "unavailable"}
    assert p["latch"].read().latched


def _rotate_receipt_authority(c, p):
    """TCB rotation of root, signer key, authorization and protected floors."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from mcp_warden.decision_receipts import signature_frame
    from mcp_warden.evidence_floor import ArtifactFloorV1
    from mcp_warden.evidence_reference import advance_state
    from mcp_warden.receipt_kernel import canonical, receipt_digest
    from mcp_warden.signer_authorization import (
        PinnedGovernanceVerifierV1,
        activate_signer_authorization,
    )
    from tests.receipt_fixtures import TestSigner

    root = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(3, 35)))
    public = key.public_key().public_bytes_raw()
    identity = receipt_digest(public, "trust-root")
    verifier = PinnedGovernanceVerifierV1(
        root_public_key=root.public_key().public_bytes_raw(),
        signer_public_keys=((identity, public),),
    )
    bundle = c.authorization.bundle.model_copy(
        update={
            "generation": 2,
            "valid_from": 20,
            "trust_root_digest": verifier.trust_root_digest,
            "grants": tuple(
                g.model_copy(update={"signer_identity_digest": identity})
                for g in c.authorization.bundle.grants
            ),
        }
    )
    digest = receipt_digest(canonical(bundle), "authorization")
    old = p["state"].read()
    floors = tuple(
        ArtifactFloorV1(
            kind=f.kind,
            generation=2,
            digest=digest if f.kind == "signer-authorization" else verifier.trust_root_digest,
        )
        if f.kind in {"signer-authorization", "trust-root"}
        else f
        for f in old.floors
    )
    advanced = advance_state(old, floors=floors)
    p["state"].compare_and_advance(old, advanced)
    frame = signature_frame(
        payload=canonical(bundle),
        artifact_kind="signer-authorization",
        role="trust-root",
        signer_identity_digest=verifier.trust_root_digest,
        authorization_digest=verifier.trust_root_digest,
    )
    authorization = activate_signer_authorization(
        bundle,
        signature=root.sign(frame),
        verifier=verifier,
        snapshot=advanced,
        now=30,
        trust_root_generation=2,
    )
    return authorization, verifier, TestSigner(key, identity)


def test_historical_pin_reads_after_live_signer_and_root_floor_advance(tmp_path):
    from mcp_warden.receipt_log import FilePrimaryReceiptStoreV1
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    store = FilePrimaryReceiptStoreV1(
        tmp_path / "primary",
        store_identity_digest=p["primary"].store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=c.authorization, verifier=c.verifier, snapshot=p["state"].read
        ),
    )
    c.primary = p["primary"] = store
    assert c.record_decision(context).mode == "primary-durable"
    tail = store.read_tail()
    _rotate_receipt_authority(c, p)
    assert store.read_tail() == tail


def test_signer_rotation_supports_subsequent_append_and_reopen(tmp_path):
    from mcp_warden.evidence_models import create_evidence_context
    from mcp_warden.evidence_state import StateError
    from mcp_warden.receipt_kernel import ReceiptError
    from mcp_warden.receipt_log import FilePrimaryReceiptStoreV1
    from mcp_warden.receipt_verification import (
        primary_payload_validator,
        verify_receipt_chain,
        verify_signed_receipt,
    )
    from mcp_warden.signer_authorization import check_authorization
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    old_auth, old_verifier = c.authorization, c.verifier
    path = tmp_path / "primary"
    old_store = FilePrimaryReceiptStoreV1(
        path,
        store_identity_digest=p["primary"].store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=old_auth, verifier=old_verifier, snapshot=p["state"].read
        ),
    )
    c.primary = p["primary"] = old_store
    assert c.record_decision(context).mode == "primary-durable"
    old_payload = old_store.read_payloads()[0]
    old_tail = old_store.read_tail()
    authorization, verifier, signer = _rotate_receipt_authority(c, p)
    # A retained pin can still read historical evidence after its live retirement.
    assert old_store.read_tail() == old_tail
    with pytest.raises(StateError, match="STATE-FLOOR-ROLLBACK"):
        check_authorization(old_auth, snapshot=p["state"].read(), now=10)
    with pytest.raises(StateError, match="STATE-FLOOR-ROLLBACK"):
        verify_signed_receipt(
            parse_signed_receipt(old_payload),
            authorization=old_auth,
            verifier=old_verifier,
            snapshot=p["state"].read(),
        )
    c.authorization, c.verifier, c.signer = authorization, verifier, signer
    c.signer_identity_digest = signer.identity
    pins = ((old_auth, old_verifier),)

    def reopened():
        return FilePrimaryReceiptStoreV1(
            path,
            store_identity_digest=old_store.store_identity_digest,
            validate_payload=primary_payload_validator(
                authorization=authorization,
                verifier=verifier,
                snapshot=p["state"].read,
                historical_authorities=pins,
            ),
        )

    c.primary = p["primary"] = reopened()
    assert c.primary.read_tail() == old_tail
    new_context = create_evidence_context(
        decision=context.decision,
        effect_digest=context.effect_digest,
        trusted_time=30,
        trusted_time_valid_until=40,
        signer_authorization_digest=authorization.digest,
    )
    result = c.record_decision(new_context)
    assert result.mode == "primary-durable" and result.sequence == 2
    reopened_store = reopened()
    assert reopened_store.read_tail() == c.primary.read_tail()
    payloads = reopened_store.read_payloads()
    assert payloads[0] == old_payload and len(payloads) == 2
    assert (
        parse_signed_receipt(payloads[1]).receipt.signer_authorization_digest
        == authorization.digest
    )
    assert verify_receipt_chain(
        payloads,
        authorization=authorization,
        verifier=verifier,
        snapshot=p["state"].read(),
        store_identity_digest=old_store.store_identity_digest,
        historical_authorities=pins,
    )
    # The new pin alone cannot authorize an older frame; logs never enroll keys.
    unpinned = FilePrimaryReceiptStoreV1(
        path,
        store_identity_digest=old_store.store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=authorization, verifier=verifier, snapshot=p["state"].read
        ),
    )
    with pytest.raises(ReceiptError):
        unpinned.read_tail()


def test_retired_live_signer_cannot_append_permit_after_rotation(tmp_path):
    from mcp_warden.receipt_log import FilePrimaryReceiptStoreV1
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    store = FilePrimaryReceiptStoreV1(
        tmp_path / "primary",
        store_identity_digest=p["primary"].store_identity_digest,
        validate_payload=primary_payload_validator(
            authorization=c.authorization, verifier=c.verifier, snapshot=p["state"].read
        ),
    )
    c.primary = p["primary"] = store
    assert c.record_decision(context).mode == "primary-durable"
    _rotate_receipt_authority(c, p)
    before = store.read_payloads()
    result = c.record_decision(context)
    assert result.mode == "unavailable"
    assert store.read_payloads() == before


@pytest.mark.parametrize("bad_pins", [[], ((object(), object()),), ((),), (object(),)])
def test_historical_authority_registry_rejects_unactivated_or_malformed_pins(bad_pins):
    from mcp_warden.receipt_kernel import ReceiptError
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, _, p = coordinator_fixture()
    with pytest.raises(ReceiptError) as error:
        primary_payload_validator(
            authorization=c.authorization,
            verifier=c.verifier,
            snapshot=p["state"].read,
            historical_authorities=bad_pins,
        )
    assert error.value.__context__ is None
    assert "object" not in str(error.value)


def test_historical_pin_does_not_accept_wrong_root_verifier_or_modified_signature():
    from mcp_warden.receipt_kernel import ReceiptError, canonical, parse_canonical
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    assert c.record_decision(context).mode == "primary-durable"
    old_auth, old_verifier, payload = c.authorization, c.verifier, p["primary"].payloads[0]
    _, new_verifier, _ = _rotate_receipt_authority(c, p)
    wrong = primary_payload_validator(
        authorization=old_auth, verifier=new_verifier, snapshot=p["state"].read
    )
    with pytest.raises(ReceiptError, match="RCT-SIGNATURE-INVALID"):
        wrong(payload)
    validator = primary_payload_validator(
        authorization=old_auth, verifier=old_verifier, snapshot=p["state"].read
    )
    data = parse_canonical(payload)
    data["evidence"]["signature_hex"] = "00" * 64
    with pytest.raises(ReceiptError, match="RCT-SIGNATURE-INVALID"):
        validator(canonical(data))


def test_unknown_governor_exception_is_closed_and_authority_failure_is_not_recovery(monkeypatch):
    from mcp_warden.decision_governor import DecisionGovernorV1
    from mcp_warden.receipt_kernel import ReceiptError

    for error, expected in (
        (ValueError("secret provider path"), "RCT-INTERNAL-ERROR"),
        (ReceiptError("RCT-SIGNER-UNAUTHORIZED"), "RCT-SIGNER-UNAUTHORIZED"),
        (ReceiptError("RCT-RECOVERY-ONLY"), "PEP-RECOVERY-ONLY"),
    ):
        pep, request, runtime, effect, _ = pep_fixture()

        def fail(*args, failure=error, **kwargs):
            raise failure

        monkeypatch.setattr(DecisionGovernorV1, "govern", fail)
        result, trace = pep._execute_instrumented(request, runtime=runtime, effect=effect)
        assert not result.invoked
        assert result.decision.public_reason == expected
        assert b"secret" not in b"".join(trace.output_channels)
        assert "evidence" in trace.events


def test_override_floor_is_optional_without_override_and_legacy_empty_floors_remain_valid():
    from mcp_warden.evidence_reference import advance_state
    from mcp_warden.evidence_state import validate_snapshot
    from tests.receipt_fixtures import authority

    _, _, _, legacy = authority()
    legacy = legacy.model_copy(update={"floors": ()})
    newer = advance_state(legacy)
    validate_snapshot(newer, legacy)
    assert newer.floors == ()
    pep, request, runtime, effect, p = pep_fixture()
    state = p["state"].read()
    without_override = state.model_copy(
        update={"floors": tuple(f for f in state.floors if f.kind != "override")}
    )
    p["state"] = InMemoryProtectedStateV1(without_override)
    pep._coordinator.protected_state = p["state"]
    assert pep.execute(request, runtime=runtime, effect=effect).invoked


def test_override_floor_required_when_context_carries_override():
    from mcp_warden.evidence_models import create_evidence_context
    from mcp_warden.governed_decision import create_governed_decision
    from mcp_warden.receipt_kernel import ZERO_DIGEST
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    state = p["state"].read()
    p["state"] = InMemoryProtectedStateV1(
        state.model_copy(update={"floors": tuple(f for f in state.floors if f.kind != "override")})
    )
    c.protected_state = p["state"]
    values = context.decision.model_dump(exclude={"decision_digest"})
    values.update(public_reason="RULE-OVERRIDE", override_digest=ZERO_DIGEST, override_generation=1)
    from mcp_warden.receipt_models import ReceiptEventContextV1

    event = ReceiptEventContextV1(
        kind="override",
        actor_digest=ZERO_DIGEST,
        scope_digest=ZERO_DIGEST,
        authority_digest=ZERO_DIGEST,
        expires_at=20,
    )
    override_context = create_evidence_context(
        decision=create_governed_decision(**values),
        effect_digest=context.effect_digest,
        trusted_time=10,
        trusted_time_valid_until=20,
        signer_authorization_digest=c.authorization.digest,
        event=event,
    )
    result = c.record_decision(override_context)
    assert result.mode == "unavailable" and not p["primary"].payloads


def test_invalid_override_preserves_signed_rule_strengthening_to_quarantine():
    from mcp_warden.decision_governor import DecisionGovernorV1
    from mcp_warden.decision_models import (
        SignedPolicyCandidateV1,
        SignedRuntimeCandidateV1,
        VerificationAlgorithmV1,
    )
    from mcp_warden.policy_decision import PolicyDecisionPointV1, activate_policy, activate_runtime
    from mcp_warden.policy_enforcement_v2 import PolicyEnforcementPointV2
    from mcp_warden.receipt_kernel import ZERO_DIGEST, canonical, receipt_digest
    from mcp_warden.rule_engine import activate_rule_bundle
    from mcp_warden.rule_models import RuleBundleV1, RuleConditionV1, RuleGroupV1, RuleV1
    from tests.test_policy_enforcement import Verifier, _activated_adapter, _noop_handler

    pep, request, runtime, effect, p = pep_fixture()
    c = pep._coordinator
    bundle = RuleBundleV1(
        generation=2,
        valid_from=0,
        valid_until=1000,
        rules=(
            RuleV1(
                rule_id="quarantine-rule",
                effect="quarantine",
                group=RuleGroupV1(
                    mode="all",
                    conditions=(
                        RuleConditionV1(field="base.verdict", operator="equals", value="allow"),
                    ),
                ),
            ),
        ),
    )
    rule_digest = receipt_digest(canonical(bundle), "rule")
    policy = activate_policy(
        SignedPolicyCandidateV1(
            policy=pep._governor.policy.policy.model_copy(update={"rule_set_digest": rule_digest}),
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=ZERO_DIGEST,
            signature=b"valid-signature",
        ),
        verifier=Verifier(),
    )
    runtime = activate_runtime(
        SignedRuntimeCandidateV1(
            runtime=runtime.runtime.model_copy(
                update={
                    "policy_digest_at_floor": policy.policy_digest,
                    "revocation_digest_at_floor": policy.revocation_digest,
                }
            ),
            algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
            signer_identity=ZERO_DIGEST,
            signature=b"valid-signature",
        ),
        verifier=Verifier(),
    )
    state = p["state"].read()
    updates = {
        "policy": (policy.policy.policy_generation, policy.policy_digest),
        "rule": (bundle.generation, rule_digest),
    }
    from mcp_warden.evidence_floor import ArtifactFloorV1

    floors = tuple(
        ArtifactFloorV1(kind=f.kind, generation=updates[f.kind][0], digest=updates[f.kind][1])
        if f.kind in updates
        else f
        for f in state.floors
    )
    p["state"] = InMemoryProtectedStateV1(state.model_copy(update={"floors": floors}))
    c.protected_state = p["state"]
    rules = activate_rule_bundle(
        bundle,
        evidence=c.signer.sign(
            payload=canonical(bundle),
            artifact_kind="rule",
            role="rule-publisher",
            authorization_digest=c.authorization.digest,
        ),
        authorization=c.authorization,
        verifier=c.verifier,
        snapshot=p["state"].read(),
        now=200,
        policy_rule_digest=rule_digest,
    )
    governor = DecisionGovernorV1(policy=policy, rules=rules, authorization=c.authorization)
    adapter, _, _ = _activated_adapter(policy, _noop_handler)
    pep = PolicyEnforcementPointV2(
        PolicyDecisionPointV1(policy), adapter, governor=governor, coordinator=c
    )
    assert pep._pdp.evaluate(request, runtime=runtime).verdict == "allow"
    result = pep.execute(request, runtime=runtime, effect=effect, override=object())
    assert not result.invoked and result.decision.effective_verdict == "quarantine"
    assert result.decision.public_reason == "RULE-QUARANTINED"
    assert result.evidence.mode == "primary-durable"
    assert (
        parse_signed_receipt(p["primary"].payloads[0]).receipt.public_reason == "RULE-QUARANTINED"
    )


def test_historical_receipt_still_requires_signing_time_validity():
    from mcp_warden.decision_receipts import serialize_signed_receipt, serialize_unsigned_receipt
    from mcp_warden.receipt_kernel import ReceiptError, receipt_digest
    from mcp_warden.receipt_models import SignedReceiptV1
    from mcp_warden.receipt_verification import primary_payload_validator
    from tests.receipt_fixtures import coordinator_fixture

    c, context, p = coordinator_fixture()
    assert c.record_decision(context).mode == "primary-durable"
    record = parse_signed_receipt(p["primary"].payloads[0])
    expired = record.receipt.model_copy(update={"trusted_time": c.authorization.bundle.valid_until})
    payload = serialize_unsigned_receipt(expired)
    evidence = c.signer.sign(
        payload=payload,
        artifact_kind="receipt",
        role="receipt-signer",
        authorization_digest=c.authorization.digest,
    )
    candidate = SignedReceiptV1(
        receipt=expired, evidence=evidence, receipt_digest=receipt_digest(payload, "receipt")
    )
    validator = primary_payload_validator(
        authorization=c.authorization, verifier=c.verifier, snapshot=p["state"].read
    )
    with pytest.raises(ReceiptError, match="RCT-STALE"):
        validator(serialize_signed_receipt(candidate))
