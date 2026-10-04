"""Deterministic property evidence for canonical events and authorized signatures."""

from __future__ import annotations

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from mcp_warden.content_models import TaintV1
from mcp_warden.evidence_models import create_evidence_context
from mcp_warden.receipt_kernel import (
    MAX_CANONICAL_BYTES,
    ReceiptError,
    canonical,
    parse_canonical,
    receipt_digest,
)
from mcp_warden.receipt_models import ReceiptEventContextV1
from mcp_warden.receipt_projection import (
    AGENT_FIELDS,
    HUMAN_FIELDS,
    agent_projection,
    human_projection,
)
from mcp_warden.receipt_verification import parse_signed_receipt
from mcp_warden.rule_engine import PRECEDENCE, evaluate_rules, matches
from mcp_warden.rule_models import RuleConditionV1, RuleGroupV1, RuleV1
from mcp_warden.signer_authorization import verify_authorized_artifact
from tests.receipt_fixtures import authority, coordinator_fixture

DIGEST = "sha256:" + "a" * 64


def _event(kind: str, value: int) -> ReceiptEventContextV1:
    fields: dict[str, object] = {"kind": kind}
    if kind == "override":
        fields.update(
            actor_digest=DIGEST, scope_digest=DIGEST, authority_digest=DIGEST, expires_at=value
        )
    elif kind == "revoke":
        fields.update(
            artifact_kind="rule",
            artifact_digest=DIGEST,
            artifact_generation=value,
            revocation_generation=value,
        )
    elif kind == "expiry":
        fields.update(artifact_kind="rule", artifact_digest=DIGEST, validity_boundary=value)
    elif kind == "recovery-exit":
        fields.update(authority_digest=DIGEST)
    return ReceiptEventContextV1(**fields)


@given(
    st.sampled_from(
        ["allow", "deny", "quarantine", "override", "revoke", "expiry", "recovery-exit"]
    ),
    st.integers(min_value=0, max_value=2**53 - 1),
)
def test_canonical_event_round_trip_is_repeatable(kind: str, value: int) -> None:
    left, right = _event(kind, value), _event(kind, value)
    payload = canonical(left)
    assert payload == canonical(right)
    assert canonical(ReceiptEventContextV1(**parse_canonical(payload))) == payload
    assert receipt_digest(payload, "receipt") != receipt_digest(payload, "rule")


@given(st.binary(max_size=512))
@example(b'{"duplicate":1,"duplicate":2}')
@example(b'{"number":NaN}')
@example(b"[" * 256)
def test_bounded_malformed_json_has_only_closed_errors(payload: bytes) -> None:
    try:
        parsed = parse_canonical(payload)
    except ReceiptError as error:
        assert str(error) in {"RCT-NONCANONICAL", "RCT-OVER-CAP", "RCT-MALFORMED"}
        assert error.__context__ is None
    else:
        assert type(parsed) is dict
        assert canonical(parsed) == payload


@given(st.binary(min_size=1, max_size=256), st.integers(min_value=0, max_value=255))
def test_single_byte_tamper_never_verifies(payload: bytes, position: int) -> None:
    auth, verifier, signer, snapshot = authority()
    evidence = signer.sign(
        payload=payload,
        artifact_kind="receipt",
        role="receipt-signer",
        authorization_digest=auth.digest,
    )
    position %= len(payload)
    tampered = bytearray(payload)
    tampered[position] ^= 1
    with pytest.raises(ReceiptError, match="^RCT-SIGNATURE-INVALID$"):
        verify_authorized_artifact(
            payload=bytes(tampered),
            evidence=evidence,
            authorization=auth,
            artifact_kind="receipt",
            role="receipt-signer",
            verifier=verifier,
            snapshot=snapshot,
            now=10,
        )


@given(
    st.sampled_from(
        [
            ("rule", "rule-publisher"),
            ("override", "override-authorizer"),
            ("recovery", "recovery-administrator"),
        ]
    ),
    st.binary(max_size=128),
)
def test_receipt_signature_cannot_be_reused_for_other_roles(target, payload: bytes) -> None:
    auth, verifier, signer, snapshot = authority()
    evidence = signer.sign(
        payload=payload,
        artifact_kind="receipt",
        role="receipt-signer",
        authorization_digest=auth.digest,
    )
    with pytest.raises(ReceiptError, match="^RCT-SIGNER-UNAUTHORIZED$"):
        verify_authorized_artifact(
            payload=payload,
            evidence=evidence,
            authorization=auth,
            artifact_kind=target[0],
            role=target[1],
            verifier=verifier,
            snapshot=snapshot,
            now=10,
        )


@given(
    st.lists(st.sampled_from(["deny", "quarantine"]), min_size=1, max_size=12),
    st.sampled_from(["allow", "deny", "quarantine"]),
    st.data(),
)
def test_rule_order_is_independent_and_cannot_weaken(effects, base, data):
    condition = RuleConditionV1(
        field="trusted_time", operator="integer-range", minimum=0, maximum=2**53 - 1
    )
    group = RuleGroupV1(mode="all", conditions=(condition,))
    rules = tuple(
        RuleV1(rule_id=f"rule-{i:02}", group=group, effect=e) for i, e in enumerate(effects)
    )
    reordered = tuple(data.draw(st.permutations(rules)))
    fields = {"trusted_time": 10}
    left = evaluate_rules(rules, fields, base_verdict=base)
    right = evaluate_rules(reordered, fields, base_verdict=base)
    assert left == right
    assert PRECEDENCE[left] == max(PRECEDENCE[base], *(PRECEDENCE[e] for e in effects))


@given(
    st.sets(st.sampled_from(tuple(t.value for t in TaintV1))),
    st.sampled_from(tuple(t.value for t in TaintV1)),
)
def test_taint_matching_is_exact_membership(taints, target):
    condition = RuleConditionV1(field="envelope.taints", operator="contains-taint", value=target)
    assert matches(condition, {"envelope.taints": tuple(sorted(taints))}) == (target in taints)
    assert not matches(condition, {"envelope.taints": target})
    assert not matches(condition, {"envelope.taints": list(taints)})


@given(st.sampled_from(["allow", "deny", "quarantine"]), st.integers(min_value=0, max_value=999))
def test_projections_keep_closed_allowlists_for_actual_signed_receipts(verdict, now):
    coordinator, seed, providers = coordinator_fixture(verdict)
    context = create_evidence_context(
        decision=seed.decision,
        effect_digest=seed.effect_digest,
        trusted_time=now,
        trusted_time_valid_until=now + 1,
        signer_authorization_digest=seed.signer_authorization_digest,
    )
    evidence = coordinator.record_decision(context)
    record = parse_signed_receipt(providers["primary"].payloads[0])
    human = human_projection(record, evidence=evidence, verification_status="verified")
    agent = agent_projection(record)
    assert set(human) == HUMAN_FIELDS and set(agent) == AGENT_FIELDS
    assert human["receipt_reference"] == agent["receipt_reference"] == record.receipt_digest
    assert agent["effective_verdict"] == verdict
    forbidden = {
        "signature",
        "signature_hex",
        "arguments",
        "content",
        "matched_rule_ids",
        "thresholds",
    }
    assert not forbidden & (set(human) | set(agent))


@given(st.integers(min_value=MAX_CANONICAL_BYTES - 32, max_value=MAX_CANONICAL_BYTES + 32))
def test_canonical_cap_is_measured_in_serialized_bytes(size):
    expected = b'{"value":"' + b"x" * size + b'"}'
    if len(expected) <= MAX_CANONICAL_BYTES:
        assert canonical({"value": "x" * size}) == expected
    else:
        with pytest.raises(ReceiptError, match="^RCT-OVER-CAP$") as error:
            canonical({"value": "x" * size})
        assert error.value.__context__ is None
