"""Constructive normalization properties over the pinned standalone parser."""

import base64
import importlib.util
import string
import sys
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

pytestmark = pytest.mark.skipif(sys.version_info[:2] != (3, 12), reason="pinned worker runtime")
pytest.importorskip("pypdf")
component = Path(__file__).resolve().parents[2] / "components" / "normalizer"
sys.path.insert(0, str(component))
sys.path.insert(0, str(component.parents[1] / "src" / "mcp_warden"))
spec = importlib.util.spec_from_file_location("fuzz_normalizer_worker", component / "worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def request(raw):
    return {"schema_version": 1, "profile_id": worker.PROFILE,
            "content_b64": base64.b64encode(raw).decode(), "media_type": "text/plain",
            "budget": dict(worker.CEILINGS)}


@settings(max_examples=1000, deadline=None)
@given(st.text(alphabet=string.ascii_letters + string.digits + " ", min_size=1, max_size=100))
def test_supported_ascii_is_not_vacuously_refused(text):
    result = worker.process(request(text.encode()))
    assert result["status"] == "structurally-complete"
    assert result["segments"][0]["text"] == text
    assert result["segments"][0]["precision"] == "exact"
    assert result == worker.process(request(text.encode()))


@settings(max_examples=1000, deadline=None)
@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=64))
def test_unicode_views_retain_raw_and_bound_source(text):
    raw = text.encode()
    result = worker.process(request(raw))
    if result["status"] == "refused":
        assert set(result) == {"schema_version", "status", "code"}
        assert result["code"].startswith("NRM-")
    else:
        segment = result["segments"][0]
        expected = "".join(c for c in unicodedata.normalize("NFKC", text)
                           if unicodedata.category(c) not in {"Cf", "Cc"} or c in "\n\r\t")
        assert segment["text"] == expected
        assert segment["raw_text"] == text
        assert (segment["source_start"], segment["source_end"]) == (0, len(raw))
