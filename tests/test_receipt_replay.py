from mcp_warden.decision_receipts import serialize_unsigned_receipt
from mcp_warden.governed_decision import serialize_governed_decision
from mcp_warden.receipt_models import ReceiptEventContextV1
from mcp_warden.receipt_replay import ReplayVectorV1, current_eligibility, replay_historical
from mcp_warden.receipt_verification import parse_signed_receipt
from tests.receipt_fixtures import pep_fixture


def test_replay_reconstructs_without_touching_any_provider(monkeypatch):
    pep, request, runtime, effect, p = pep_fixture()
    historical = p["state"].read()
    result = pep.execute(request, runtime=runtime, effect=effect)
    record = parse_signed_receipt(p["primary"].payloads[0])
    vector = ReplayVectorV1(
        request=request,
        effect=effect,
        policy=pep._governor.policy,
        runtime=runtime,
        rules=pep._governor.rules,
        signer_authorization=pep._coordinator.authorization,
        snapshot=historical,
        store_identity_digest=p["primary"].store_identity_digest,
        signer_identity_digest=pep._coordinator.signer_identity_digest,
        event=ReceiptEventContextV1(kind="allow"),
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("provider called by replay")

    for provider in p.values():
        for name in ("read", "read_tail", "append", "compare_and_advance", "set"):
            if hasattr(provider, name):
                monkeypatch.setattr(provider, name, forbidden)
    replay = replay_historical(
        vector,
        expected_decision_bytes=serialize_governed_decision(result.decision),
        expected_receipt_bytes=serialize_unsigned_receipt(record.receipt),
    )
    assert replay.decision_matches and replay.receipt_matches
    # Eligibility is independently assessed against an explicit current snapshot.
    assert current_eligibility(vector, snapshot=historical) == "eligible-foundation"
