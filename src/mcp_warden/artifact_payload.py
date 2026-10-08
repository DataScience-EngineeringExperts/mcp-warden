"""Bounded, unambiguous parsing of existing governance artifact contracts."""

from __future__ import annotations

import json

from mcp_warden.decision_models import (
    ArtifactKindV1,
    PolicyBundleV1,
    PolicyGrantV1,
    RuntimeSnapshotV1,
)
from mcp_warden.executable_bundle import (
    ExecutableBundleManifestV1,
    canonical_bundle_manifest_bytes,
)
from mcp_warden.policy_decision import canonical_policy_bytes, canonical_runtime_bytes
from mcp_warden.policy_enforcement import (
    AdapterManifestV1,
    ManifestOperationV1,
    canonical_manifest_bytes,
)

MAX_ARTIFACT_BYTES = 512 * 1024


class ArtifactTrustError(Exception):
    """Code-only failure; never retain input or lower-layer exception text."""

    def __repr__(self) -> str:
        return str(self)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _nonfinite(_: str) -> None:
    raise ValueError


def bounded_json(payload: bytes, *, cap: int, code: str) -> object:
    result = None
    invalid = type(payload) is not bytes or len(payload) > cap
    if not invalid:
        try:
            result = json.loads(
                payload.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite
            )
        except Exception:
            invalid = True
    if invalid:
        raise ArtifactTrustError(code) from None
    return result


_ARTIFACTS = {
    ArtifactKindV1.POLICY: (PolicyBundleV1, canonical_policy_bytes),
    ArtifactKindV1.RUNTIME: (RuntimeSnapshotV1, canonical_runtime_bytes),
    ArtifactKindV1.ADAPTER: (AdapterManifestV1, canonical_manifest_bytes),
    ArtifactKindV1.BUNDLE: (ExecutableBundleManifestV1, canonical_bundle_manifest_bytes),
}


def canonical_artifact_payload(kind: ArtifactKindV1, payload: bytes) -> bytes:
    """Validate a review draft using the existing model; return exact canonical bytes."""
    if type(kind) is not ArtifactKindV1:
        raise ArtifactTrustError("TRUST-ARTIFACT-MALFORMED") from None
    parsed = bounded_json(payload, cap=MAX_ARTIFACT_BYTES, code="TRUST-ARTIFACT-MALFORMED")
    if (
        type(parsed) is not dict
        or type(parsed.get("schema_version")) is not int
        or parsed["schema_version"] != 1
    ):
        raise ArtifactTrustError("TRUST-ARTIFACT-MALFORMED") from None
    canonical = None
    try:
        model, serialize = _ARTIFACTS[kind]
        # Existing custom model constructors intentionally reject Python lists
        # for tuple fields. Translate only the declared JSON array fields;
        # all scalar, nested-object and extra-field checks stay strict.
        fields = dict(parsed)
        arrays = {
            ArtifactKindV1.POLICY: ("grants", "revoked_lease_digests"),
            ArtifactKindV1.ADAPTER: ("dependency_digests", "operations"),
            ArtifactKindV1.BUNDLE: ("dependency_digests",),
            ArtifactKindV1.RUNTIME: (),
        }
        for name in arrays[kind]:
            if type(fields[name]) is not list:
                raise ValueError
            fields[name] = tuple(fields[name])
        if kind is ArtifactKindV1.POLICY:
            fields["grants"] = tuple(PolicyGrantV1(**item) for item in fields["grants"])
        if kind is ArtifactKindV1.ADAPTER:
            fields["operations"] = tuple(
                ManifestOperationV1(**item) for item in fields["operations"]
            )
        candidate = model(**fields)
        canonical = serialize(candidate)
    except Exception:
        pass
    if canonical is None:
        raise ArtifactTrustError("TRUST-ARTIFACT-MALFORMED") from None
    return canonical
