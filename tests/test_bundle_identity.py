from __future__ import annotations

import json
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from mcp_warden.artifact_trust import (
    Ed25519ArtifactVerifierV1,
    TrustedArtifactKeyV1,
    artifact_signing_bytes,
    canonical_roots_bytes,
    roots_digest,
)
from mcp_warden.bundle_identity import (
    IdentityComparisonStatus,
    IdentityError,
    IdentityObservationV1,
    canonical_deployment_identity_bytes,
    compare_deployment_identities,
    parse_deployment_identity,
)
from mcp_warden.bundle_identity_lock import capabilities_from_v4_lock
from mcp_warden.cli import app
from mcp_warden.decision_models import ArtifactKindV1
from mcp_warden.lockfile import build_lock
from mcp_warden.models import CapturedPrompt, CapturedResource, CapturedSurface, CapturedTool


def digest(value: int) -> str:
    return f"sha256:{value:064x}"


@pytest.fixture
def document():
    return {
        "schema_version": 1,
        "package": {
            "coordinate": "pypi:example-server@1.2.3",
            "artifact_digest": digest(1),
            "publisher_identity_digest": digest(2),
            "signer_identity_digest": digest(3),
            "provenance_digest": digest(4),
            "dependency_closure_digest": digest(5),
            "sbom_digest": digest(6),
        },
        "server_identity_digest": digest(7),
        "configuration_digest": digest(8),
        "transport": {"kind": "stdio", "binding_digest": digest(9)},
        "capabilities": [
            {"kind": "tool", "identifier_digest": digest(10), "entry_digest": digest(11)},
            {"kind": "resource", "identifier_digest": digest(12), "entry_digest": digest(13)},
        ],
        "policy_binding_digest": digest(14),
        "behavior": {"profile_digest": digest(15), "evidence_digest": digest(16)},
    }


def parse(document):
    return parse_deployment_identity(json.dumps(document).encode())


@pytest.fixture
def attester():
    private = Ed25519PrivateKey.generate()
    kind = ArtifactKindV1.DEPLOYMENT_OBSERVATION
    root = TrustedArtifactKeyV1(private.public_key().public_bytes_raw(), (kind,))
    roots = (root,)
    verifier = Ed25519ArtifactVerifierV1(roots, expected_roots_digest=roots_digest(roots))

    def sign(model):
        payload = canonical_deployment_identity_bytes(model)
        signature = private.sign(artifact_signing_bytes(kind, root.signer_identity, payload))
        return IdentityObservationV1(model, root.signer_identity, signature)

    return sign, verifier, roots


def test_canonical_and_verified_across_ordering(document, attester):
    sign, verifier, _ = attester
    reordered = deepcopy(document)
    reordered["capabilities"].reverse()
    reordered["package"]["coordinate"] = "pypi:Example_Server@1.2.3"
    original = parse(document)
    normalized = parse(dict(reversed(list(reordered.items()))))
    assert canonical_deployment_identity_bytes(original) == canonical_deployment_identity_bytes(
        normalized
    )
    same = compare_deployment_identities(sign(original), sign(normalized), verifier=verifier)
    assert same.status is IdentityComparisonStatus.MATCH
    assert same.reasons == ()
    assert same.baseline == same.current
    assert same.current.package_digest != same.current.deployment_digest


@pytest.mark.parametrize(
    ("path", "value", "reason", "package_changes"),
    [
        (("package", "coordinate"), "pypi:example-server@1.2.4", "coordinate_changed", True),
        (("package", "artifact_digest"), digest(100), "artifact_digest_changed", True),
        (
            ("package", "publisher_identity_digest"),
            digest(100),
            "publisher_identity_digest_changed",
            True,
        ),
        (
            ("package", "signer_identity_digest"),
            digest(100),
            "signer_identity_digest_changed",
            True,
        ),
        (("package", "provenance_digest"), digest(100), "provenance_digest_changed", True),
        (
            ("package", "dependency_closure_digest"),
            digest(100),
            "dependency_closure_digest_changed",
            True,
        ),
        (("package", "sbom_digest"), digest(100), "sbom_digest_changed", True),
        (("server_identity_digest",), digest(100), "server_identity_digest_changed", False),
        (("configuration_digest",), digest(100), "configuration_digest_changed", False),
        (("transport", "kind"), "streamable-http", "transport_changed", False),
        (("transport", "binding_digest"), digest(100), "transport_changed", False),
        (("capabilities", 0, "entry_digest"), digest(100), "capabilities_changed", False),
        (("capabilities", 0, "identifier_digest"), digest(100), "capabilities_changed", False),
        (("policy_binding_digest",), digest(100), "policy_binding_digest_changed", False),
        (("behavior", "profile_digest"), digest(100), "behavior_changed", False),
        (("behavior", "evidence_digest"), digest(100), "behavior_changed", False),
    ],
)
def test_each_identity_dimension_changes(document, attester, path, value, reason, package_changes):
    sign, verifier, _ = attester
    changed = deepcopy(document)
    target = changed
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    result = compare_deployment_identities(
        sign(parse(document)), sign(parse(changed)), verifier=verifier
    )
    assert result.status is IdentityComparisonStatus.DRIFT
    assert result.reasons == (reason,)
    assert result.baseline.deployment_digest != result.current.deployment_digest
    assert (result.baseline.package_digest != result.current.package_digest) is package_changes


def test_missing_unsigned_and_rebound_signature_are_indeterminate(document, attester):
    sign, verifier, _ = attester
    baseline = sign(parse(document))
    partial = deepcopy(document)
    del partial["behavior"]
    partial["configuration_digest"] = digest(100)
    current = parse(partial)
    result = compare_deployment_identities(
        baseline,
        IdentityObservationV1(current, baseline.signer_identity, baseline.signature),
        verifier=verifier,
    )
    assert result.status is IdentityComparisonStatus.INDETERMINATE
    assert result.current is None
    assert result.reasons == (
        "current_unverified",
        "current_behavior_missing",
        "configuration_digest_changed",
    )
    signed_partial = compare_deployment_identities(baseline, sign(current), verifier=verifier)
    assert signed_partial.status is IdentityComparisonStatus.INDETERMINATE
    assert signed_partial.reasons == ("current_behavior_missing", "configuration_digest_changed")
    unsigned = compare_deployment_identities(
        IdentityObservationV1(parse(document)), IdentityObservationV1(parse(document))
    )
    assert unsigned.status is IdentityComparisonStatus.INDETERMINATE
    assert unsigned.reasons == ("baseline_unverified", "current_unverified")


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":true}',
        b'{"schema_version":1.0}',
        b'{"schema_version":2}',
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":1,"package":{"artifact_digest":null,"artifact_digest":null}}',
        b'{"schema_version":1,"package":{"coordinate":"npm:bad/range@^1"}}',
        b'{"schema_version":1,"transport":{"kind":"streamable-http","url":"SYNTHETIC_PRIVATE"}}',
        b'{"schema_version":1,"configuration_digest":NaN}',
        b'{"schema_version":1,"configuration_digest":"SHA256:0000"}',
        b'{"schema_version":1,"capabilities":[null]}',
        b'["SYNTHETIC_PRIVATE"]',
        b" " * (512 * 1024 + 1),
        b"\xff",
    ],
)
def test_malformed_payloads_are_rejected_without_echo(payload):
    with pytest.raises(IdentityError) as failure:
        parse_deployment_identity(payload)
    assert str(failure.value) == "IDENTITY-MALFORMED"


def test_duplicate_capability_is_rejected_even_with_different_entry(document):
    original = document["capabilities"][0]
    document["capabilities"].append({**original, "entry_digest": digest(100)})
    with pytest.raises(IdentityError, match="^IDENTITY-MALFORMED$"):
        parse(document)


def test_cli_compares_attested_remote_observations(document, attester, tmp_path):
    sign, _, roots = attester
    document["transport"]["kind"] = "streamable-http"
    observation = sign(parse(document))
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    signature = tmp_path / "signature"
    roots_file = tmp_path / "roots.json"
    baseline.write_bytes(canonical_deployment_identity_bytes(observation.identity))
    current.write_bytes(baseline.read_bytes())
    signature.write_bytes(observation.signature)
    roots_file.write_bytes(canonical_roots_bytes(roots))
    runner = CliRunner()
    command = ["identity", "compare", str(baseline), str(current)]
    verification = [
        "--roots",
        str(roots_file),
        "--roots-digest",
        roots_digest(roots),
        "--baseline-signer",
        observation.signer_identity,
        "--baseline-signature",
        str(signature),
        "--current-signer",
        observation.signer_identity,
        "--current-signature",
        str(signature),
    ]
    unsigned = runner.invoke(app, command)
    assert unsigned.exit_code == 2
    assert json.loads(unsigned.stdout)["status"] == "indeterminate"
    match = runner.invoke(app, command + verification)
    assert match.exit_code == 0, match.output
    assert json.loads(match.stdout)["status"] == "match"
    document["transport"]["binding_digest"] = digest(120)
    changed = sign(parse(document))
    current.write_bytes(canonical_deployment_identity_bytes(changed.identity))
    current_signature = tmp_path / "current.sig"
    current_signature.write_bytes(changed.signature)
    drift = runner.invoke(app, command + verification[:-1] + [str(current_signature)])
    assert drift.exit_code == 1, drift.output
    assert json.loads(drift.stdout)["reasons"] == ["transport_changed"]
    invalid = runner.invoke(app, command + verification)
    assert invalid.exit_code == 2
    assert json.loads(invalid.stdout)["reasons"] == ["current_unverified", "transport_changed"]

    current.write_text('{"schema_version":1,"endpoint":"SYNTHETIC_PRIVATE"}')
    malformed = runner.invoke(app, command + verification)
    assert malformed.exit_code == 2
    assert "SYNTHETIC_PRIVATE" not in malformed.output
    assert json.loads(malformed.stdout)["reasons"] == ["current_malformed"]


def test_v4_projection_uses_exact_entries_and_ignores_raw_transport():
    tool = CapturedTool(name="echo", input_schema={"type": "object"})
    resource = CapturedResource(uri="fixture://service/item?ref=SYNTHETIC_PRIVATE")
    prompt = CapturedPrompt(name="summarize")
    surface = CapturedSurface(
        command="server",
        protocol_version="2025-03-26",
        tools=[tool],
        resources=[resource],
        prompts=[prompt],
    )
    local = build_lock(surface, [])
    remote = build_lock(
        surface.model_copy(update={"command": "", "url": "https://fixture.invalid/mcp"}), []
    )
    local_entries = capabilities_from_v4_lock(local)
    assert local_entries == capabilities_from_v4_lock(remote)
    assert {entry.entry_digest for entry in local_entries} == {
        local.tools[0].entry_digest,
        local.resources[0].entry_digest,
        local.prompts[0].entry_digest,
    }
    assert "SYNTHETIC_PRIVATE" not in repr(local_entries)
    remote.tools[0].input_schema_hash = digest(800)
    with pytest.raises(IdentityError, match="^IDENTITY-LOCK-MALFORMED$"):
        capabilities_from_v4_lock(remote)


def test_key_for_another_role_cannot_verify_observation(document, attester):
    sign, _, roots = attester
    observation = sign(parse(document))
    wrong_role = (TrustedArtifactKeyV1(roots[0].public_key, (ArtifactKindV1.BUNDLE,)),)
    verifier = Ed25519ArtifactVerifierV1(wrong_role, expected_roots_digest=roots_digest(wrong_role))
    result = compare_deployment_identities(observation, observation, verifier=verifier)
    assert result.status is IdentityComparisonStatus.INDETERMINATE
    assert result.reasons == ("baseline_unverified", "current_unverified")
