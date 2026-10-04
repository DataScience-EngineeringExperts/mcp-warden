from mcp_warden.receipt_projection import (
    AGENT_FIELDS,
    HUMAN_FIELDS,
    agent_projection,
    human_projection,
)
from mcp_warden.receipt_verification import parse_signed_receipt
from tests.receipt_fixtures import coordinator_fixture


def test_closed_projections_are_signature_and_private_detail_free():
    c, x, p = coordinator_fixture()
    evidence = c.record_decision(x)
    receipt = parse_signed_receipt(p["primary"].payloads[0])
    human = human_projection(receipt, evidence=evidence, verification_status="verified")
    agent = agent_projection(receipt)
    assert set(human) == HUMAN_FIELDS
    assert set(agent) == AGENT_FIELDS
    assert agent["reason"] == "authorized"
    assert "signature" not in str(human) and "signature" not in str(agent)
