"""Coordinator distrusts worker claims and preserves raw envelope evidence."""

import hashlib
from dataclasses import asdict

import pytest

from mcp_warden import normalization as n
from mcp_warden.content_envelope import create_ingress, verify_lineage
from mcp_warden.content_models import IngressKindV1, MediaTypeV1, TransformKindV1
from mcp_warden.normalization_ipc import NormalizationError
from mcp_warden.normalization_models import NormalizationProfileV1


@pytest.fixture(autouse=True)
def ascii_unit_runtime(monkeypatch):
    # These coordinator unit vectors are ASCII; actual Unicode/runtime support
    # is separately exercised by the mandatory Python 3.12 image job.
    monkeypatch.setattr(n.unicodedata, "unidata_version", "15.0.0")


def ingress(raw=b"hello", media=MediaTypeV1.TEXT_PLAIN, kind=IngressKindV1.DOCUMENT):
    return create_ingress(content=raw, media_type=media, source_kind=kind,
                          source_identity=b'{}', source_claims=b'{}',
                          capture_kind=TransformKindV1.INGRESS_CAPTURE,
                          capture_implementation=b'{}', capture_parameters=b'{}')


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
