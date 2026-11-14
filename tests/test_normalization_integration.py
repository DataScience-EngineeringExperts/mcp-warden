"""Atomic universal-mode refusal and live/offline parity, independent of Docker."""

import hashlib
import json
from dataclasses import asdict

import pytest
from typer.testing import CliRunner

from mcp_warden import normalization as n
from mcp_warden import res_rules
from mcp_warden.cli import app
from mcp_warden.content_models import IngressKindV1, MediaTypeV1
from mcp_warden.framing import MODE_NEWLINE, Frame
from mcp_warden.guard_loop import GuardConfig, GuardState, StrictInspectionAbort
from mcp_warden.guard_result import handle_s2c
from mcp_warden.inspector import TraceError, analyze_trace
from mcp_warden.normalization_ingress import normalize_supplied
from mcp_warden.normalization_ipc import NormalizationError
from mcp_warden.normalization_models import NormalizationProfileV1

IMAGE = "sha256:" + "1"*64


@pytest.fixture
def worker(monkeypatch):
    def run(request, profile):
        import base64
        raw = base64.b64decode(request["content_b64"])
        text = raw.decode()
        segments = [{"text": text, "raw_text": text, "locator": "$", "precision": "container",
                     "source_start": 0, "source_end": len(raw)}]
        usage = dict.fromkeys(asdict(profile.budget), 1)
        usage.update(input_bytes=len(raw), expanded_bytes=len(raw), output_bytes=len(raw),
                     map_bytes=len(n.canonical(segments)))
        return {"schema_version": 1, "profile_id": n.PROFILE_ID,
                "status": "structurally-complete", "segments": segments, "usage": usage,
                "input_digest": "sha256:"+hashlib.sha256(raw).hexdigest(),
                "runtime": {"python": "3.12", "unicode": "15.0.0", "parser": "pypdf==7.1.0"}}
    monkeypatch.setattr(n, "_run_worker", run)


def frame(obj):
    raw = (json.dumps(obj) + "\n").encode()
    return Frame(raw=raw, body=raw.strip(), json=obj)


@pytest.mark.parametrize("kind", list(IngressKindV1))
def test_all_nine_supplied_adapters_derive_same_shared_evidence(worker, kind):
    result = normalize_supplied(b'{"text":"hello"}', MediaTypeV1.APPLICATION_JSON,
                                kind, NormalizationProfileV1(IMAGE))
    assert result.envelope.trust_state == "untrusted"
    assert result.envelope.parents
    assert result.segments[0].text == '{"text":"hello"}'


@pytest.mark.parametrize("kwargs", [{"audit_only": True}, {"no_block_ansi": True},
                                    {"no_block_deterministic": True}, {"no_block_policy": True}])
def test_universal_cli_rejects_shadow_flags(kwargs):
    flag = "--" + next(iter(kwargs)).replace("_", "-")
    result = CliRunner().invoke(app, ["guard", "--normalizer-image", IMAGE, flag, "echo"])
    assert result.exit_code == 2
    assert "NRM-PROFILE" in result.output


def test_guard_config_forces_both_strict_modes():
    cfg = GuardConfig(normalization_image=IMAGE)
    assert cfg.strict and cfg.strict_frame_cap
    with pytest.raises(NormalizationError):
        GuardConfig(normalization_image=IMAGE, audit_only=True)


@pytest.mark.parametrize("block", [{"type": "image", "data": "AAAA"},
                                 {"type": "unknown", "text": "hello"},
                                 {"type": "resource", "resource": {"uri": "https://example.com"}}])
def test_unknown_binary_and_reference_only_blocks_never_forward(worker, block):
    state = GuardState(config=GuardConfig(normalization_image=IMAGE))
    state.remember_request(1, "tools/call", "safe")
    obj = {"jsonrpc": "2.0", "id": 1, "result": {"content": [block]}}
    out = handle_s2c(state, frame(obj), MODE_NEWLINE)
    assert json.loads(out)["error"]["data"]["rule"] == "WRD-RES-NORMALIZATION"
    assert "result" not in json.loads(out)


def test_bad_frame_cannot_enter_legacy_pass_through():
    state = GuardState(config=GuardConfig(normalization_image=IMAGE))
    with pytest.raises(StrictInspectionAbort):
        handle_s2c(state, Frame(raw=b"secret", body=b"secret", json=None), MODE_NEWLINE)


def test_unknown_request_id_cannot_bypass_binary_block_validation(worker):
    state = GuardState(config=GuardConfig(normalization_image=IMAGE))
    out = handle_s2c(state, frame({"id": 999, "result": {"content": [
        {"type": "image", "data": "AA=="}]}}), MODE_NEWLINE)
    assert "result" not in json.loads(out)


def test_multiple_mcp_container_fields_are_all_validated(worker):
    state = GuardState(config=GuardConfig(normalization_image=IMAGE))
    state.remember_request(1, "tools/call", "tool")
    out = handle_s2c(state, frame({"id": 1, "result": {
        "content": [{"type": "text", "text": "safe"}],
        "messages": [{"content": {"type": "audio", "data": "AA=="}}]}}), MODE_NEWLINE)
    assert "result" not in json.loads(out)


def test_trace_duplicate_keys_and_flat_overflow_fail_closed(tmp_path):
    path = tmp_path / "trace"
    for data in ('{"direction":"s2c","direction":"c2s","frame":{}}', "\n" * 4097):
        path.write_text(data)
        with pytest.raises(TraceError):
            analyze_trace(path, normalization_profile=NormalizationProfileV1(IMAGE))


def test_sandbox_failure_blocks_before_sink_and_matches_offline(monkeypatch, tmp_path):
    def fail(*_):
        raise RuntimeError("SYNTHETIC_SECRET")
    monkeypatch.setattr(n, "_run_worker", fail)
    cfg = GuardConfig(normalization_image=IMAGE)
    findings = []
    state = GuardState(config=cfg, on_finding=findings.append)
    state.remember_request(1, "tools/call", "tool")
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "tool"}}
    obj = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "hello"}]}}
    out = handle_s2c(state, frame(obj), MODE_NEWLINE)
    assert "result" not in json.loads(out)
    assert b"SYNTHETIC_SECRET" not in out
    trace = tmp_path / "trace.jsonl"
    trace.write_text("\n".join(json.dumps({"direction": d, "frame": o})
                                for d, o in [("c2s", req), ("s2c", obj)]))
    offline = analyze_trace(trace, normalization_profile=NormalizationProfileV1(IMAGE))
    assert [(f.rule_id, f.message) for f in offline] == [(f.rule_id, f.message) for f in findings]


@pytest.mark.parametrize("method,result", [
    ("prompts/get", {"messages": [{"content": {"type": "image", "data": "AAAA"}}]}),
    ("resources/read", {"contents": [{"uri": "https://example.com"}]}),
])
def test_prompt_and_resource_delivery_is_mediated(worker, method, result):
    state = GuardState(config=GuardConfig(normalization_image=IMAGE))
    state.remember_request(1, method)
    out = handle_s2c(state, frame({"id": 1, "result": result}), MODE_NEWLINE)
    assert "result" not in json.loads(out)


def test_offline_requires_known_directions(worker, tmp_path):
    path = tmp_path / "trace"
    path.write_text(json.dumps({"id": 1, "result": {}}))
    with pytest.raises(TraceError):
        analyze_trace(path, normalization_profile=NormalizationProfileV1(IMAGE))


def test_raw_controls_are_inspected_before_transformed_view(monkeypatch):
    from mcp_warden.normalization_inspection import inspect_supplied
    from mcp_warden.normalization_models import NormalizationResultV1, NormalizedSegmentV1
    from mcp_warden.result_inspection import InspectionPolicy
    from mcp_warden.content_envelope import create_ingress
    from mcp_warden.content_models import TransformKindV1
    envelope = create_ingress(
        content=b"hello", media_type=MediaTypeV1.TEXT_PLAIN, source_kind=IngressKindV1.DOCUMENT,
        source_identity=b'{}', source_claims=b'{}', capture_kind=TransformKindV1.INGRESS_CAPTURE,
        capture_implementation=b'{}', capture_parameters=b'{}')
    result = NormalizationResultV1(
        segments=(NormalizedSegmentV1("hello", "\x1b[31mhello", "$", "container", 0, 10),),
        envelope=envelope, manifest_digest="test", manifest=b"{}")
    monkeypatch.setattr("mcp_warden.normalization_inspection.normalize_supplied", lambda *_: result)
    findings = inspect_supplied(b"x", MediaTypeV1.TEXT_PLAIN, IngressKindV1.DOCUMENT,
                                NormalizationProfileV1(IMAGE), InspectionPolicy(),
                                exfil_denylist=res_rules.SEED_EXFIL_DENYLIST,
                                inject_phrases=res_rules.SEED_INJECT_PHRASES)
    assert "WRD-RES-ANSI" in {f.rule_id for f in findings}
