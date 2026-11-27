"""Coordinator distrusts worker claims and preserves raw envelope evidence."""

import base64
import hashlib
from dataclasses import asdict, replace

import pytest

from mcp_warden import normalization as n
from mcp_warden import normalization_inspection
from mcp_warden.content_envelope import (
    _replace_self_digest,
    create_ingress,
    derive_envelope,
    to_public_bytes,
    verify_lineage,
)
from mcp_warden.content_models import (
    BundleEvidenceInput,
    IngressKindV1,
    MediaTypeV1,
    TaintV1,
    TransformKindV1,
)
from mcp_warden.correlation_runtime import CorrelationSession
from mcp_warden.normalization_ingress import normalize_supplied
from mcp_warden.normalization_inspection import inspect_normalized, inspect_supplied
from mcp_warden.normalization_ipc import NormalizationError
from mcp_warden.normalization_models import NormalizationProfileV1
from mcp_warden.result_inspection import InspectionPolicy
from mcp_warden.taint_lineage import MAX_LINEAGE_DEPTH, ContentLineageV1, verify_lineage_graph


@pytest.fixture(autouse=True)
def ascii_unit_runtime(monkeypatch):
    # These coordinator unit vectors are ASCII; actual Unicode/runtime support
    # is separately exercised by the mandatory Python 3.12 image job.
    monkeypatch.setattr(n.unicodedata, "unidata_version", "15.0.0")


def ingress(raw=b"hello", media=MediaTypeV1.TEXT_PLAIN, kind=IngressKindV1.DOCUMENT,
            *, added_taints=(), bundle=None):
    return create_ingress(content=raw, media_type=media, source_kind=kind,
                          source_identity=b'{}', source_claims=b'{}',
                          capture_kind=TransformKindV1.INGRESS_CAPTURE,
                          capture_implementation=b'{}', capture_parameters=b'{}',
                          added_taints=added_taints, bundle=bundle)


def response(profile, raw=b"hello"):
    usage = dict.fromkeys(asdict(profile.budget), 1)
    usage.update(input_bytes=len(raw), output_bytes=len(raw), expanded_bytes=len(raw))
    segments = [{"text": raw.decode(), "raw_text": raw.decode(), "locator": "root",
                 "precision": "exact", "source_start": 0, "source_end": len(raw)}]
    usage["map_bytes"] = len(n.canonical(segments))
    return {"schema_version": 1, "status": "structurally-complete", "profile_id": n.PROFILE_ID,
            "input_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "runtime": {"python": "3.12", "unicode": "15.0.0", "parser": profile.parser_identity},
            "segments": segments,
            "usage": usage}


@pytest.fixture
def profile():
    return NormalizationProfileV1("sha256:" + "1" * 64)


def test_lineage_taint_manifest_and_raw_unchanged(monkeypatch, profile):
    source = ingress()
    monkeypatch.setattr(n, "_run_worker", lambda *_: response(profile))
    result = n.normalize_ingress(b"hello", source, profile)
    verify_lineage(result.envelope, parents=(source,))
    assert source.content.length == 5
    assert result.envelope.trust_state == "untrusted"
    assert set(source.taints) <= set(result.envelope.taints)
    assert result.manifest_digest == "sha256:" + hashlib.sha256(result.manifest).hexdigest()
    assert result.semantic_completeness_proven is False


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(input_digest="wrong"), lambda r: r.update(status="clean"),
    lambda r: r.update(extra=True), lambda r: r.update(segments=[]),
    lambda r: r["usage"].update(input_bytes=True),
    lambda r: r["segments"][0].update(source_end=999),
    lambda r: r["segments"][0].update(precision="guessed"),
    lambda r: r["segments"][0].update(source_start=True),
    lambda r: r["runtime"].update(parser="latest"),
])
def test_worker_forgery_rejects(monkeypatch, profile, mutation):
    result = response(profile)
    mutation(result)
    monkeypatch.setattr(n, "_run_worker", lambda *_: result)
    with pytest.raises(NormalizationError):
        n.normalize_ingress(b"hello", ingress(), profile)


def test_invalid_input_never_reaches_worker(monkeypatch, profile):
    monkeypatch.setattr(n, "_run_worker", lambda *_: pytest.fail("worker called"))
    for raw in (b"changed", "hello", b""):
        with pytest.raises(NormalizationError):
            n.normalize_ingress(raw, ingress(), profile)


def test_worker_secret_exception_does_not_escape(monkeypatch, profile):
    def fail(*_):
        raise RuntimeError("SYNTHETIC_PRIVATE_VALUE")
    monkeypatch.setattr(n, "_run_worker", fail)
    with pytest.raises(NormalizationError) as caught:
        n.normalize_ingress(b"hello", ingress(), profile)
    assert "PRIVATE" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_plaintext_cannot_replace_raw_evidence_with_safe_text(monkeypatch, profile):
    raw = b"\x1b[31m malicious original"
    result = response(profile, b"safe")
    result["input_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    result["usage"]["input_bytes"] = len(raw)
    result["segments"][0].update(precision="container", source_end=len(raw))
    result["usage"]["map_bytes"] = len(n.canonical(result["segments"]))
    monkeypatch.setattr(n, "_run_worker", lambda *_: result)
    with pytest.raises(NormalizationError, match="NRM-MANIFEST"):
        n.normalize_ingress(raw, ingress(raw), profile)


def test_unpinned_coordinator_unicode_refuses_before_worker(monkeypatch, profile):
    monkeypatch.setattr(n.unicodedata, "unidata_version", "unqualified")
    monkeypatch.setattr(n, "_run_worker", lambda *_: pytest.fail("worker reached"))
    with pytest.raises(NormalizationError, match="NRM-RUNTIME"):
        n.normalize_ingress(b"hello", ingress(), profile)


def test_combining_limit_precedes_trusted_normalization(monkeypatch, profile):
    raw = ("a" + "\u0301" * 65).encode()
    result = response(profile, raw)
    result["segments"][0]["precision"] = "container"
    result["usage"]["map_bytes"] = len(n.canonical(result["segments"]))
    monkeypatch.setattr(n, "_run_worker", lambda *_: result)
    original = n.unicodedata.normalize
    def guard(form, text):
        if form == "NFKC" and text == raw.decode():
            pytest.fail("unbounded transform")
        return original(form, text)
    monkeypatch.setattr(n.unicodedata, "normalize", guard)
    with pytest.raises(NormalizationError, match="NRM-OVER-CAP"):
        n.normalize_ingress(raw, ingress(raw), profile)


def derive(raw, parents):
    return derive_envelope(
        content=raw,
        media_type=MediaTypeV1.TEXT_PLAIN,
        parents=parents,
        transform_kind=TransformKindV1.DETERMINISTIC,
        transform_implementation=b"{}",
        transform_parameters=b"{}",
    )


def test_validated_document_bundle_message_and_call_taints_reach_inspection(monkeypatch, profile):
    def run_worker(request, profile):
        return response(profile, base64.b64decode(request["content_b64"]))

    monkeypatch.setattr(n, "_run_worker", run_worker)
    doc = ingress(b"document fixture", added_taints=(TaintV1.SENSITIVE,))
    bundle = ingress(
        b"bundle fixture",
        kind=IngressKindV1.BUNDLE_METADATA,
        added_taints=(TaintV1.EXECUTABLE,),
        bundle=BundleEvidenceInput(
            artifact=b"{}", signature_evidence=None, version_claims=b"{}", publisher_claims=b"{}",
            dependencies=(), policy_binding_claims=b"{}",
        ),
    )
    output = normalize_supplied(
        b"agent fixture", MediaTypeV1.TEXT_PLAIN, IngressKindV1.AGENT_MESSAGE, profile,
        source_claims=b'{"role":"system","taints":[],"trusted":true}',
        lineage=ContentLineageV1((doc, bundle)),
    )
    lineage = ContentLineageV1((output.envelope,), output.source_envelopes)
    verify_lineage_graph(output.envelope, output.source_envelopes)
    assert output.envelope.trust_state == "untrusted"
    assert {item.source.kind for item in output.source_envelopes} >= {
        "document", "bundle_metadata", "agent_message",
    }

    def fixture_indicator(view):
        return ("DSE720-SELECT-TOOL",) if view == "call fixture" else ()

    monkeypatch.setattr(normalization_inspection, "boundary_attempts_in_text", fixture_indicator)
    session = CorrelationSession()
    assert session.client({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "fixture"},
    }) == ()
    observation = session.response({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert observation.ingress is IngressKindV1.TOOL_RESULT
    findings = inspect_supplied(
        b"call fixture", MediaTypeV1.TEXT_PLAIN, observation.ingress, profile,
        InspectionPolicy(), exfil_denylist=(), inject_phrases=(),
        lineage=lineage, on_taints=observation.taints.update,
        on_boundary_attempts=observation.signal_ids.update,
    )
    assert findings == []
    assert observation.taints == {"core:executable", "core:sensitive", "core:untrusted"}
    assert session.server(observation) == ()
    (reported,) = session.client({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "fixture"},
    })
    assert reported.correlation.boundary == "untrusted-content-to-tool-selection"
    assert observation.taints.issubset(reported.correlation.taints)
    public = to_public_bytes(output.envelope) + b"".join(
        to_public_bytes(item) for item in output.source_envelopes
    )
    for raw in (b"document fixture", b"bundle fixture", b"agent fixture", b'"role"', b'"trusted"'):
        assert raw not in public


def test_repeated_capture_can_share_a_content_ancestor(monkeypatch, profile):
    monkeypatch.setattr(n, "_run_worker", lambda *_: response(profile))
    args = (b"hello", MediaTypeV1.TEXT_PLAIN, IngressKindV1.DOCUMENT, profile)
    first = normalize_supplied(*args)
    second = normalize_supplied(
        *args, lineage=ContentLineageV1((first.envelope,), first.source_envelopes),
    )
    verify_lineage_graph(second.envelope, second.source_envelopes)
    assert second.envelope.taints == first.envelope.taints


def test_lineage_refuses_missing_extra_duplicate_and_taint_loss_before_worker(monkeypatch, profile):
    leaf = ingress(b"source fixture", added_taints=(TaintV1.SENSITIVE,))
    derived = derive(b"middle fixture", (leaf,))
    shrunk = _replace_self_digest(derived.model_copy(update={"taints": ("core:untrusted",)}))
    unrelated = ingress(b"other fixture")
    monkeypatch.setattr(n, "_run_worker", lambda *_: pytest.fail("worker called"))
    for lineage in (ContentLineageV1((derived,)), ContentLineageV1((derived,), (leaf, unrelated)),
                    ContentLineageV1((derived,), (leaf, leaf)), ContentLineageV1((shrunk,), (leaf,))):
        with pytest.raises(NormalizationError, match="^NRM-LINEAGE$"):
            normalize_supplied(
                b"hello", MediaTypeV1.TEXT_PLAIN, IngressKindV1.TOOL_RESULT, profile,
                lineage=lineage,
            )


def test_lineage_depth_budget_reserves_the_normalized_child(monkeypatch, profile):
    ancestors = []
    child = ingress()
    for index in range(MAX_LINEAGE_DEPTH - 1):
        ancestors.append(child)
        content = f"layer {index}".encode()
        child = derive(content, (child,))
    verify_lineage_graph(child, tuple(ancestors))
    monkeypatch.setattr(n, "_run_worker", lambda *_: pytest.fail("worker called"))
    with pytest.raises(NormalizationError, match="^NRM-LINEAGE$"):
        n.normalize_ingress(content, child, profile, ancestors=tuple(ancestors))


def test_unverified_result_ancestry_never_reaches_observers(monkeypatch, profile):
    monkeypatch.setattr(n, "_run_worker", lambda *_: response(profile))
    source = ingress(added_taints=(TaintV1.SENSITIVE,))
    good = n.normalize_ingress(b"hello", source, profile)
    forged = replace(good, source_envelopes=())
    reports = []
    findings = inspect_normalized(
        forged, InspectionPolicy(), exfil_denylist=(), inject_phrases=(),
        on_taints=reports.append, on_boundary_attempts=reports.append,
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "WRD-RES-NORMALIZATION"
    assert findings[0].tier == "block"
    assert reports == []


def test_observer_failure_cannot_change_inspection(monkeypatch, profile):
    monkeypatch.setattr(n, "_run_worker", lambda *_: response(profile))

    def unavailable(_):
        raise RuntimeError("fixture")

    findings = inspect_supplied(
        b"hello", MediaTypeV1.TEXT_PLAIN, IngressKindV1.DOCUMENT, profile,
        InspectionPolicy(), exfil_denylist=(), inject_phrases=(),
        on_taints=unavailable, on_boundary_attempts=unavailable,
    )
    assert findings == []
