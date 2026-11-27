import json

import pytest
from typer.testing import CliRunner

from mcp_warden.artifact_payload import ArtifactTrustError
from mcp_warden.capability_review import (
    MAX_REVIEW_BYTES,
    parse_review_evidence,
    project_agent_review,
    project_human_review,
)
from mcp_warden.cli import app


def digest(digit):
    return "sha256:" + digit * 64


def evidence(ref, *, operation="lookup", capability="read", identity="a", environment="test"):
    return {
        "adapter_id": "catalog",
        "operation_id": operation,
        "capability": capability,
        "evidence_digest": digest(ref),
        "binding": {
            "identity_digest": digest(identity),
            "scope": {
                "purpose_id": "inventory",
                "data_scope_id": "internal-fixture",
                "environment_id": environment,
                "scope_digest": digest("b"),
            },
        },
    }


def payload(declared, observed):
    return {"schema_version": 1, "declarations": declared, "observations": observed}


def parse(declared, observed):
    return parse_review_evidence(json.dumps(payload(declared, observed)).encode())


def test_review_keeps_provenance_and_only_exact_pairs_are_pending():
    declaration = evidence("1")
    observation = evidence("2")
    review = project_human_review(
        parse(
            [evidence("3", operation="declared"), declaration],
            [observation, evidence("4", operation="observed", capability="execute")],
        )
    )
    declared, matched, observed = review["rows"]
    assert declared["status"] == observed["status"] == "ineligible"
    assert declared["reasons"] == ["CAP-REVIEW-OBSERVATION-MISSING"]
    assert observed["reasons"] == ["CAP-REVIEW-DECLARATION-MISSING"]
    assert observed["risk"] == "critical"
    assert matched["status"] == "pending-human-review"
    assert matched["reasons"] == ["CAP-REVIEW-HUMAN-REVIEW-REQUIRED"]
    assert matched["declarations"] == [
        {"evidence_digest": digest("1"), "binding": declaration["binding"]}
    ]
    assert matched["observations"] == [
        {"evidence_digest": digest("2"), "binding": observation["binding"]}
    ]


@pytest.mark.parametrize(
    "observation,reason",
    [
        (evidence("2", identity="c"), "CAP-REVIEW-IDENTITY-CONFLICT"),
        (evidence("2", environment="production"), "CAP-REVIEW-SCOPE-CONFLICT"),
        (evidence("1"), "CAP-REVIEW-EVIDENCE-REUSED"),
        (evidence("2") | {"binding": None}, "CAP-REVIEW-OBSERVATION-INCOMPLETE"),
    ],
)
def test_unresolved_evidence_is_visible_and_ineligible(observation, reason):
    review = parse([evidence("1")], [observation])
    row = project_human_review(review)["rows"][0]
    assert row["status"] == "ineligible"
    assert reason in row["reasons"]
    assert row["observations"][0]["binding"] == observation["binding"]
    assert project_agent_review(review)["rows"] == [{"status": "ineligible", "reasons": [reason]}]


def test_conflicting_capability_mappings_keep_both_rows_ineligible():
    rows = project_human_review(parse([evidence("1")], [evidence("2", capability="transform")]))[
        "rows"
    ]
    assert [row["capability"] for row in rows] == ["read", "transform"]
    assert all(row["status"] == "ineligible" for row in rows)
    assert all("CAP-REVIEW-CAPABILITY-CONFLICT" in row["reasons"] for row in rows)


def test_conflicting_repeated_bindings_cannot_select_an_eligible_pair():
    row = project_human_review(
        parse([evidence("1"), evidence("3", identity="c")], [evidence("2")])
    )["rows"][0]
    assert row["status"] == "ineligible"
    assert row["reasons"] == ["CAP-REVIEW-DECLARATION-AMBIGUOUS", "CAP-REVIEW-IDENTITY-CONFLICT"]


def test_distinct_capabilities_cannot_reuse_one_reference():
    result = project_human_review(
        parse(
            [evidence("1"), evidence("1", operation="edit")],
            [evidence("2"), evidence("3", operation="edit")],
        )
    )
    assert [row["reasons"] for row in result["rows"]] == [
        ["CAP-REVIEW-EVIDENCE-REUSED"],
        ["CAP-REVIEW-EVIDENCE-REUSED"],
    ]


def test_projection_is_order_independent_and_ids_bind_the_evidence():
    declaration = evidence("1")
    first = parse([evidence("4"), declaration, declaration], [evidence("2")])
    second = parse([declaration, evidence("4")], [evidence("2")])
    changed = parse([declaration, evidence("4")], [evidence("3")])
    for project in (project_human_review, project_agent_review):
        assert project(first) == project(second)
        assert project(second)["rows"][0]["review_id"] != project(changed)["rows"][0]["review_id"]


@pytest.mark.parametrize(
    "source",
    [
        b'{"schema_version":true,"declarations":[],"observations":[]}',
        b'{"schema_version":1,"schema_version":1,"declarations":[],"observations":[]}',
        b'{"schema_version":1,"declarations":[],"observations":NaN}',
        b'{"schema_version":1,"declarations":[]}',
        b"\xff",
        b"x" * (MAX_REVIEW_BYTES + 1),
    ],
)
def test_unambiguous_bounded_evidence_input(source):
    with pytest.raises(ArtifactTrustError, match="^CAP-REVIEW-INPUT-MALFORMED$"):
        parse_review_evidence(source)


def test_cli_explicit_audience_and_agent_allowlist(tmp_path):
    evidence_file = tmp_path / "evidence.json"
    observation = evidence("2", operation="operator-only-label")
    evidence_file.write_text(
        json.dumps(payload([evidence("1", operation="operator-only-label")], [observation]))
    )
    command = ["trust", "review-capabilities", str(evidence_file)]
    runner = CliRunner()
    assert runner.invoke(app, command).exit_code == 2

    human = runner.invoke(app, [*command, "--audience", "human"])
    agent = runner.invoke(app, [*command, "--audience", "agent"])
    assert human.exit_code == agent.exit_code == 0
    human_row = json.loads(human.stdout)["rows"][0]
    assert human_row["operation_id"] == "operator-only-label"
    assert json.loads(agent.stdout)["rows"] == [
        {
            "capability": "read",
            "review_id": human_row["review_id"],
            "status": "pending-human-review",
            "reasons": ["CAP-REVIEW-HUMAN-REVIEW-REQUIRED"],
        }
    ]
    for hidden in (
        "catalog",
        "operator-only-label",
        "internal-fixture",
        "inventory",
        digest("1"),
        digest("a"),
    ):
        assert hidden not in agent.output


@pytest.mark.parametrize(
    "poisoned",
    [
        evidence("1", operation="[bold]spoof[/bold]\x1b[2J"),
        evidence("1", operation="look\u202eup"),
        evidence("1", operation="lookup\n"),
        evidence("1") | {"raw_detail": "do-not-print-test-marker"},
        evidence("1") | {"approved": True},
    ],
)
def test_cli_rejects_unreviewable_labels_and_unknown_fields_without_echo(tmp_path, poisoned):
    evidence_file = tmp_path / "evidence.json"
    evidence_file.write_text(json.dumps(payload([poisoned], [])))
    result = CliRunner().invoke(
        app, ["trust", "review-capabilities", str(evidence_file), "--audience", "human"]
    )
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.strip() == "CAP-REVIEW-INPUT-MALFORMED"
