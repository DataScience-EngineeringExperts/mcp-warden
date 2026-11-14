"""Adversarial parser corpus; execution does not substitute for sandbox proof."""
import base64
import importlib.util
import io
import sys
import zipfile
from pathlib import Path

import pytest

COMPONENT = Path(__file__).resolve().parents[1] / "components" / "normalizer"
sys.path.insert(0, str(COMPONENT))
sys.path.insert(0, str(COMPONENT.parents[1] / "src" / "mcp_warden"))
spec = importlib.util.spec_from_file_location("normalizer_worker", COMPONENT / "worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def request(data, media="text/plain", **limits):
    budget = dict(worker.CEILINGS)
    budget.update(limits)
    return {"schema_version": 1, "profile_id": worker.PROFILE, "content_b64":
            base64.b64encode(data).decode(), "media_type": media, "budget": budget}


def run(data, media="text/plain", **limits):
    return worker.process(request(data, media, **limits))


def texts(result):
    assert result["status"] == "structurally-complete", result
    return "\n".join(s["text"] for s in result["segments"])


def archive(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return out.getvalue()


def test_plain_unicode_controls_and_exactness():
    result = run("Ａ\u202esecret\x1b[31m".encode())
    assert texts(result) == "Asecret[31m"
    assert result["segments"][0]["raw_text"] == "Ａ\u202esecret\x1b[31m"
    assert result["segments"][0]["precision"] == "container"
    assert run(b"unchanged")["segments"][0]["precision"] == "exact"


@pytest.mark.parametrize(("data", "media", "expected"), [
    (b'{"\\u0069gnore":"\\u0073ecret"}', "application/json", "ignore"),
    (b'<x a="&#115;ecret"><!-- hidden -->ok</x>', "application/xml", "secret"),
    (b'<div hidden data-x="&#115;ecret">hidden</div><!-- covert -->', "text/html", "secret"),
    (b'"quoted,field",secret\r\n', "text/csv", "quoted,field"),
    (b'<!-- secret -->\n[hide](javascript:evil)', "text/markdown", "javascript:evil"),
])
def test_structured_preserves_hidden_and_decoded(data, media, expected):
    result = run(data, media)
    assert expected in texts(result)
    assert any(s["raw_text"] == data.decode() for s in result["segments"])


@pytest.mark.parametrize(("data", "media"), [
    (b'{"x":1,"x":2}', "application/json"),
    (b'{"x":NaN}', "application/json"),
    (b'<!DOCTYPE x [<!ENTITY y "bad">]><x>&y;</x>', "application/xml"),
    (b'<x>', "application/xml"),
    (b'"unfinished', "text/csv"),
    (b'\xff', "text/plain"),
    (b'', "text/plain"),
    (b'%PDF-1.7 garbage', "text/plain"),
])
def test_malformed_refuses(data, media):
    assert run(data, media)["status"] == "refused"


def test_zip_nested_and_member_metadata():
    data = archive([("inner.zip", archive([("secret.json", b'{"x":"secret"}')]))])
    result = run(data, "application/zip")
    assert "secret" in texts(result)
    assert "secret.json" in texts(result)
    assert result["usage"]["members"] == 2
    assert all(s["source_end"] == len(data) for s in result["segments"])


@pytest.mark.parametrize("name", ["../evil.txt", "/evil.txt", "a\\evil.txt", "C:/evil.txt", "a/./b.txt", "a//b.txt"])
def test_zip_traversal_refuses(name):
    assert run(archive([(name, b"secret")]), "application/zip")["status"] == "refused"


def test_zip_duplicate_unknown_empty_symlink_refuse():
    for entries in [[("a.txt", b"a"), ("a.txt", b"b")], [("x.exe", b"MZ")], [("a.txt", b"")]]:
        assert run(archive(entries), "application/zip")["status"] == "refused"
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        info = zipfile.ZipInfo("link.txt")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        z.writestr(info, "target")
    assert run(out.getvalue(), "application/zip")["status"] == "refused"


def test_root_cumulative_limits():
    data = archive([("a.txt", b"a" * 100), ("b.txt", b"b" * 100)])
    for limits in [{"expanded_bytes": 199}, {"members": 1}, {"output_bytes": 100}, {"work": 10}, {"spans": 1}, {"map_bytes": 10}]:
        assert run(data, "application/zip", **limits)["status"] == "refused"
    assert run(b'[[[1]]]', "application/json", depth=2)["status"] == "refused"
    assert run(("a" + "\u0301" * 3).encode(), combining_run=2)["status"] == "refused"


def test_email_decodes_headers_body_and_nested_attachment():
    data = (b'MIME-Version: 1.0\r\nSubject: =?utf-8?b?c2VjcmV0?=\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n'
            b'--x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGlkZGVu\r\n'
            b'--x\r\nContent-Type: application/json\r\nContent-Disposition: attachment; filename=x.json\r\n\r\n{"k":"secret"}\r\n--x--\r\n')
    result = run(data, "message/rfc822")
    assert "secret" in texts(result) and "hidden" in texts(result)
    assert result["usage"]["members"] == 2


@pytest.mark.parametrize("body", [b'@@@', b'YQ=', b'YQ==garbage'])
def test_email_invalid_base64_refuses(body):
    data = b'Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n' + body
    assert run(data, "message/rfc822")["status"] == "refused"


def test_runtime_request_and_determinism():
    result = run(b"repeat")
    assert result == run(b"repeat")
    assert result["runtime"] == {"python": "3.12", "unicode": "15.0.0", "parser": "pypdf==7.1.0"}
    invalid = request(b"a")
    invalid["unknown"] = True
    assert worker.process(invalid) == {"schema_version": 1, "status": "refused", "code": "NRM-PROTOCOL"}
