from __future__ import annotations

import json
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from mcp_warden.artifact_trust import (
    artifact_signing_bytes,
    canonical_roots_bytes,
    roots_digest,
)
from mcp_warden.cli import app
from mcp_warden.decision_models import ArtifactKindV1
from tests.test_artifact_trust import policy_payload, trust_fixture

runner = CliRunner()


def inputs(tmp_path):
    private, root, _ = trust_fixture()
    candidate = tmp_path / "policy.json"
    candidate.write_bytes(policy_payload())
    roots = tmp_path / "roots.json"
    roots.write_bytes(canonical_roots_bytes((root,)))
    signature = tmp_path / "approval.sig"
    signature.write_bytes(
        private.sign(
            artifact_signing_bytes(
                ArtifactKindV1.POLICY, root.signer_identity, candidate.read_bytes()
            )
        )
    )
    return root, candidate, roots, signature


def verify_args(root, candidate, roots, signature):
    return [
        "trust",
        "verify",
        "policy",
        str(candidate),
        "--roots",
        str(roots),
        "--roots-digest",
        roots_digest((root,)),
        "--signer",
        root.signer_identity,
        "--signature",
        str(signature),
    ]


def test_roots_digest_and_prepare_unsigned_review_artifacts(tmp_path):
    root, candidate, roots, _ = inputs(tmp_path)
    result = runner.invoke(app, ["trust", "roots-digest", str(roots)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["roots_digest"] == roots_digest((root,))
    canonical = tmp_path / "canonical.json"
    frame = tmp_path / "signing.bin"
    # Human review drafts may be pretty-printed, but ambiguous JSON is rejected.
    candidate.write_text(json.dumps(json.loads(candidate.read_bytes()), indent=2))
    result = runner.invoke(
        app,
        [
            "trust",
            "prepare",
            "policy",
            str(candidate),
            "--signer",
            root.signer_identity,
            "--canonical-out",
            str(canonical),
            "--signing-out",
            str(frame),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["status"] == "unsigned-review-artifact"
    assert canonical.read_bytes() == policy_payload()
    assert frame.read_bytes() == artifact_signing_bytes(
        ArtifactKindV1.POLICY, root.signer_identity, canonical.read_bytes()
    )


def test_verify_reports_signature_only_and_needs_independent_pin(tmp_path):
    root, candidate, roots, signature = inputs(tmp_path)
    result = runner.invoke(app, verify_args(root, candidate, roots, signature))
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["status"] == "signature-verified"
    args = verify_args(root, candidate, roots, signature)
    args[args.index("--roots-digest") + 1] = "sha256:" + "0" * 64
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "TRUST-ROOT-PIN-MISMATCH" in result.output


@pytest.mark.parametrize("mutation", ["payload", "signature", "oversize", "duplicate", "unknown"])
def test_cli_tamper_and_secret_safe_failures(tmp_path, mutation):
    root, candidate, roots, signature = inputs(tmp_path)
    planted = "PLANTED-SECRET-DO-NOT-REFLECT"
    if mutation == "payload":
        body = json.loads(candidate.read_bytes())
        body["policy_generation"] += 1
        import rfc8785

        candidate.write_bytes(rfc8785.dumps(body))
    elif mutation == "signature":
        signature.write_bytes(b"x" * 64)
    elif mutation == "oversize":
        signature.write_bytes(planted.encode() * 100)
    elif mutation == "duplicate":
        candidate.write_text('{"schema_version":1,"schema_version":1,"secret":"' + planted + '"}')
    else:
        body = json.loads(candidate.read_bytes())
        body["secret"] = planted
        candidate.write_text(json.dumps(body))
    result = runner.invoke(app, verify_args(root, candidate, roots, signature))
    assert result.exit_code == 2
    assert planted not in result.output
    assert "TRUST-" in result.output


def test_prepare_never_clobbers_input_or_existing_outputs_and_rolls_back(tmp_path):
    root, candidate, _, _ = inputs(tmp_path)
    first = tmp_path / "canonical.json"
    existing = tmp_path / "signing.bin"
    existing.write_bytes(b"preserve")
    original = candidate.read_bytes()
    common = ["trust", "prepare", "policy", str(candidate), "--signer", root.signer_identity]
    result = runner.invoke(
        app, common + ["--canonical-out", str(first), "--signing-out", str(existing)]
    )
    assert result.exit_code == 2
    assert not first.exists()
    assert existing.read_bytes() == b"preserve"
    result = runner.invoke(
        app, common + ["--canonical-out", str(candidate), "--signing-out", str(first)]
    )
    assert result.exit_code == 2
    assert candidate.read_bytes() == original
    assert not first.exists()


def test_missing_file_and_wrong_artifact_type_are_safe(tmp_path):
    root, candidate, roots, signature = inputs(tmp_path)
    candidate.unlink()
    result = runner.invoke(app, verify_args(root, candidate, roots, signature))
    assert result.exit_code == 2
    assert "TRUST-FILE-UNAVAILABLE" in result.output
    result = runner.invoke(app, ["trust", "roots-digest", str(signature)])
    assert result.exit_code == 2


def test_prepare_symlink_loop_is_code_only_and_creates_no_outputs(tmp_path):
    root, candidate, _, _ = inputs(tmp_path)
    loop = tmp_path / "PLANTED-SENSITIVE-PATH"
    loop.symlink_to(loop.name)
    other = tmp_path / "signing.bin"
    args = [
        "trust",
        "prepare",
        "policy",
        str(candidate),
        "--signer",
        root.signer_identity,
        "--canonical-out",
        str(loop),
        "--signing-out",
        str(other),
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert result.output.strip() == "TRUST-OUTPUT-UNAVAILABLE"
    assert not other.exists()
    process = subprocess.run(
        [sys.executable, "-m", "mcp_warden", *args], capture_output=True, text=True, timeout=20
    )
    assert process.returncode == 2
    assert process.stdout == ""
    assert process.stderr.strip() == "TRUST-OUTPUT-UNAVAILABLE"
    assert not other.exists()
