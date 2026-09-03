"""MCP Lock Format v1 conformance: run ``vectors/`` against the Python implementation.

The corpus under ``vectors/`` is the language-neutral definition of a conforming
implementation (docs/SPEC.md §12). This harness is the Python side of the CI
``conformance`` job; ``packages/lock-ts`` runs the identical corpus in TypeScript.
Set ``MCP_LOCK_VECTORS_DIR`` to point both harnesses at another copy of the
corpus (the CI mutation proof uses this to show a flipped digest fails BOTH).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from mcp_warden.drift import compute_drift
from mcp_warden.hashing import canon, hash_value
from mcp_warden.lockfile import build_lock
from mcp_warden.models import (
    CapturedPrompt,
    CapturedResource,
    CapturedSurface,
    CapturedTool,
    WardenLock,
)

VECTORS_DIR = Path(os.environ.get("MCP_LOCK_VECTORS_DIR") or Path(__file__).parent.parent / "vectors")
MANIFEST = json.loads((VECTORS_DIR / "manifest.json").read_text(encoding="utf-8"))
_ENTRIES = MANIFEST["vectors"]


def _load(entry: dict[str, str]) -> dict[str, Any]:
    return json.loads((VECTORS_DIR / entry["file"]).read_text(encoding="utf-8"))


def _by_kind(kind: str) -> list:
    return [pytest.param(e, id=e["id"]) for e in _ENTRIES if e["kind"] == kind]


def _surface(doc: dict[str, Any]) -> CapturedSurface:
    """Vendor-neutral surface document (MCP wire naming) -> CapturedSurface."""
    return CapturedSurface(
        command=doc.get("command", ""),
        args=list(doc.get("args", [])),
        url=doc.get("url"),
        protocol_version="2025-06-18",
        tools=[
            CapturedTool(name=t["name"], description=t.get("description"), input_schema=t.get("inputSchema"))
            for t in doc.get("tools", [])
        ],
        resources=[
            CapturedResource(
                uri=r["uri"], name=r.get("name"), description=r.get("description"), mime_type=r.get("mimeType")
            )
            for r in doc.get("resources", [])
        ],
        prompts=[
            CapturedPrompt(name=p["name"], description=p.get("description"), arguments=p.get("arguments"))
            for p in doc.get("prompts", [])
        ],
    )


def test_manifest_shape():
    assert MANIFEST["format"] == "mcp-lock-v1"
    assert MANIFEST["count"] == len(_ENTRIES) >= 25
    kinds = {e["kind"] for e in _ENTRIES}
    assert kinds == {"canonical", "digest", "drift", "malformed"}
    assert len({e["id"] for e in _ENTRIES}) == len(_ENTRIES), "vector ids must be unique"


@pytest.mark.parametrize("entry", _by_kind("canonical"))
def test_canonical(entry):
    v = _load(entry)
    assert canon(v["input"]).decode("utf-8") == v["expect"]["jcs"]
    assert hash_value(v["input"]) == v["expect"]["sha256"]


@pytest.mark.parametrize("entry", _by_kind("digest"))
def test_digest(entry):
    v = _load(entry)
    lock = build_lock(_surface(v["surface"]), [])
    doc = json.loads(lock.model_dump_json())
    for t in doc["tools"]:
        if t.get("inspection") is None:
            t.pop("inspection", None)
    exp = v["expect"]
    assert doc["server"]["command_digest"] == exp["server"]["command_digest"]
    assert doc["tools"] == exp["tools"]
    assert doc["resources"] == exp["resources"]
    assert doc["prompts"] == exp["prompts"]
    assert doc["overall_digest"] == exp["overall_digest"]


@pytest.mark.parametrize("entry", _by_kind("drift"))
def test_drift(entry):
    v = _load(entry)
    baseline = WardenLock.model_validate(v["lock"])
    current = build_lock(_surface(v["surface"]), [])
    got = [
        {"drift_class": d.drift_class, "severity": d.severity, "target": d.target, "detail": d.detail}
        for d in compute_drift(baseline, current)
    ]
    assert got == v["expect"]


@pytest.mark.parametrize("entry", _by_kind("malformed"))
def test_malformed_is_rejected(entry):
    v = _load(entry)
    assert v["expect"] == {"error": True}
    if "input_json" in v:
        # A JSON value the canonicalizer MUST reject: it parses, but is not Unicode text
        # (unpaired surrogate) or nests past the recursion bound. Either the parser or
        # canon() refusing it is a rejection; a wrong digest is not.
        with pytest.raises((ValueError, RecursionError)):
            canon(json.loads(v["input_json"]))
        return
    # json.JSONDecodeError and pydantic's ValidationError are both ValueError subclasses.
    with pytest.raises((ValueError, TypeError)):
        doc = json.loads(v["lock_text"]) if "lock_text" in v else v["lock"]
        WardenLock.model_validate(doc)
