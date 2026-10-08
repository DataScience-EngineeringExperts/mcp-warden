from __future__ import annotations

import json

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_warden.artifact_trust import (
    ArtifactTrustError,
    Ed25519ArtifactVerifierV1,
    TrustedArtifactKeyV1,
    artifact_signing_bytes,
    canonical_roots_bytes,
    parse_roots,
    roots_digest,
)
from mcp_warden.decision_models import ArtifactKindV1, VerificationAlgorithmV1
from mcp_warden.policy_decision import canonical_policy_bytes
from tests.test_policy_decision import _policy_bundle


def trust_fixture(kinds=(ArtifactKindV1.POLICY,)):
    private = Ed25519PrivateKey.generate()
    root = TrustedArtifactKeyV1(private.public_key().public_bytes_raw(), kinds)
    roots = (root,)
    verifier = Ed25519ArtifactVerifierV1(roots, expected_roots_digest=roots_digest(roots))
    return private, root, verifier


def policy_payload():
    return canonical_policy_bytes(_policy_bundle(lease_digest=None))


def check(verifier, root, base_payload, base_signature, **changes):
    args = dict(
        artifact_kind=ArtifactKindV1.POLICY,
        algorithm=VerificationAlgorithmV1.EXTERNAL_V1,
        signer_identity=root.signer_identity,
        payload=base_payload,
        signature=base_signature,
    )
    args.update(changes)
    return verifier.verify(**args)


def test_real_signature_and_exact_frame():
    private, root, verifier = trust_fixture()
    payload = policy_payload()
    frame = artifact_signing_bytes(ArtifactKindV1.POLICY, root.signer_identity, payload)
    assert frame == (
        b"mcp-warden/artifact-signature/v1\x00policy\x00"
        + root.signer_identity.encode("ascii")
        + b"\x00"
        + payload
    )
    assert check(verifier, root, payload, private.sign(frame)) is True


@pytest.mark.parametrize(
    "changes",
    [
        {"artifact_kind": ArtifactKindV1.RUNTIME},
        {"artifact_kind": "policy"},
        {"algorithm": "external-v1"},
        {"signer_identity": "sha256:" + "0" * 64},
        {"signature": b""},
        {"signature": b"x" * 63},
        {"signature": b"x" * 65},
        {"payload": b"null"},
        {"payload": b"{}"},
        {"payload": b"\xff"},
        {"payload": b" " * (512 * 1024 + 1)},
        {"payload": bytearray(b"{}")},
    ],
)
def test_substitution_fails_closed(changes):
    private, root, verifier = trust_fixture()
    payload = policy_payload()
    signature = private.sign(
        artifact_signing_bytes(ArtifactKindV1.POLICY, root.signer_identity, payload)
    )
    assert check(verifier, root, payload, signature, **changes) is False


def test_changed_payload_wrong_key_raw_signature_and_noncanonical_fail():
    private, root, verifier = trust_fixture()
    payload = policy_payload()
    signature = private.sign(
        artifact_signing_bytes(ArtifactKindV1.POLICY, root.signer_identity, payload)
    )
    changed = rfc8785.dumps({**json.loads(payload), "policy_generation": 3})
    assert not check(verifier, root, changed, signature)
    assert not check(verifier, root, payload, Ed25519PrivateKey.generate().sign(payload))
    assert not check(verifier, root, payload, private.sign(payload))
    assert not check(verifier, root, b" " + payload, signature)


def test_role_is_checked_even_for_cryptographically_valid_signature():
    private, root, verifier = trust_fixture((ArtifactKindV1.BUNDLE,))
    payload = policy_payload()
    signature = private.sign(
        artifact_signing_bytes(ArtifactKindV1.POLICY, root.signer_identity, payload)
    )
    assert not check(verifier, root, payload, signature)


def test_roots_pin_covers_roles_and_keys_and_configuration_is_immutable():
    _, root, verifier = trust_fixture()
    changed = (TrustedArtifactKeyV1(root.public_key, (ArtifactKindV1.RUNTIME,)),)
    assert roots_digest(changed) != roots_digest((root,))
    with pytest.raises(ArtifactTrustError, match="TRUST-ROOT-PIN-MISMATCH"):
        Ed25519ArtifactVerifierV1(changed, expected_roots_digest=roots_digest((root,)))
    with pytest.raises(ArtifactTrustError, match="TRUST-IMMUTABLE"):
        verifier._roots = {}
    assert parse_roots(canonical_roots_bytes((root,))) == (root,)


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"null",
        b'{"schema_version":true,"keys":[]}',
        b'{"schema_version":1,"schema_version":1,"keys":[]}',
        b'{"schema_version":1,"keys":[],"private_key":"secret"}',
        b'{"schema_version":1,"keys":[]}',
        b'{"schema_version":NaN,"keys":[]}',
        b"x" * (64 * 1024 + 1),
    ],
)
def test_malformed_roots_are_code_only(raw):
    with pytest.raises(ArtifactTrustError) as exc:
        parse_roots(raw)
    assert str(exc.value) == repr(exc.value) == "TRUST-ROOTS-MALFORMED"
    assert exc.value.__context__ is None


def test_unknown_root_fields_duplicate_roles_and_duplicate_keys_rejected():
    _, root, _ = trust_fixture()
    value = json.loads(canonical_roots_bytes((root,)))
    variants = []
    item = value["keys"][0]
    variants.append({**value, "keys": [{**item, "private_key": "planted-secret"}]})
    variants.append({**value, "keys": [{**item, "artifact_kinds": ["policy", "policy"]}]})
    variants.append({**value, "keys": [item, item]})
    variants.append({**value, "keys": [{**item, "public_key": "0" * 62}]})
    for malformed in variants:
        with pytest.raises(ArtifactTrustError):
            parse_roots(json.dumps(malformed).encode())


def test_optional_dependency_failure_is_explicit(monkeypatch):
    from mcp_warden import artifact_trust

    def unavailable():
        raise ArtifactTrustError("TRUST-CRYPTO-UNAVAILABLE")

    _, root, _ = trust_fixture()
    monkeypatch.setattr(artifact_trust, "_public_key_type", unavailable)
    with pytest.raises(ArtifactTrustError, match="TRUST-CRYPTO-UNAVAILABLE"):
        Ed25519ArtifactVerifierV1((root,), expected_roots_digest=roots_digest((root,)))


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("policy_generation", True),
        ("valid_from", "100"),
        ("grants", {}),
        ("unknown", "PLANTED-SECRET"),
    ],
)
def test_artifact_parser_rejects_coercion_and_unknown_fields(field, value):
    from mcp_warden.artifact_payload import canonical_artifact_payload

    body = {**json.loads(policy_payload()), field: value}
    with pytest.raises(ArtifactTrustError, match="TRUST-ARTIFACT-MALFORMED") as exc:
        canonical_artifact_payload(ArtifactKindV1.POLICY, json.dumps(body).encode())
    assert exc.value.__context__ is None


def test_roots_order_does_not_change_pin_and_duplicate_roles_cannot_expand_authority():
    _, one, _ = trust_fixture()
    _, two, _ = trust_fixture((ArtifactKindV1.RUNTIME,))
    assert roots_digest((one, two)) == roots_digest((two, one))
    with pytest.raises(ArtifactTrustError):
        TrustedArtifactKeyV1(one.public_key, (ArtifactKindV1.POLICY, ArtifactKindV1.POLICY))
