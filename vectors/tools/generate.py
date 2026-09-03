"""Generate the MCP Lock Format v1 conformance corpus under ``vectors/``.

The Python implementation in ``src/mcp_warden`` is the reference; every expected
value below is DERIVED from it, so the corpus is regenerable rather than
hand-maintained:

    .venv/bin/python vectors/tools/generate.py

Any change to a hashed field's derivation (WARDEN_LOCK_SCHEMA.md §14.2) shows up
as a corpus diff in review — that is the point. Regenerate deliberately, never as
a side effect of "making the test pass".

Vector kinds (``vectors/README.md`` is the consumer-facing contract):

  canonical  JSON value            -> RFC 8785 bytes + ``sha256:`` digest
  digest     declared surface      -> per-entry hashes, entry digests, overall_digest
  drift      (baseline lock, observed surface) -> ordered drift items
  malformed  lock document that MUST be rejected by any conforming reader
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_warden.drift import compute_drift  # noqa: E402
from mcp_warden.hashing import canon, hash_value  # noqa: E402
from mcp_warden.lockfile import (  # noqa: E402
    _tool_entry,
    build_lock,
    compute_overall_digest,
    lock_to_pretty_json,
)
from mcp_warden.models import (  # noqa: E402
    CapturedPrompt,
    CapturedResource,
    CapturedSurface,
    CapturedTool,
    PinMetadata,
    WardenLock,
)

VECTORS_DIR = ROOT / "vectors"
CASES_DIR = VECTORS_DIR / "cases"

#: Everything under ``pin`` is outside ``overall_digest``; it is frozen to constants
#: so regenerating the corpus is byte-stable and never depends on the clock, the
#: installed version, or the environment.
FIXED_TIME = "2026-01-01T00:00:00Z"
FIXED_VERSION = "0.0.0"
PROTOCOL = "2025-06-18"
APPROVER = "vectors@example.invalid"


# --- surface adapter ----------------------------------------------------------


def surface_from_json(doc: dict[str, Any]) -> CapturedSurface:
    """Turn a vendor-neutral surface document (MCP wire naming) into a CapturedSurface."""
    tools = [
        CapturedTool(name=t["name"], description=t.get("description"), input_schema=t.get("inputSchema"))
        for t in doc.get("tools", [])
    ]
    resources = [
        CapturedResource(
            uri=r["uri"], name=r.get("name"), description=r.get("description"), mime_type=r.get("mimeType")
        )
        for r in doc.get("resources", [])
    ]
    prompts = [
        CapturedPrompt(name=p["name"], description=p.get("description"), arguments=p.get("arguments"))
        for p in doc.get("prompts", [])
    ]
    return CapturedSurface(
        command=doc.get("command", ""),
        args=list(doc.get("args", [])),
        url=doc.get("url"),
        protocol_version=PROTOCOL,
        tools=tools,
        resources=resources,
        prompts=prompts,
    )


def _frozen_pin(lock: WardenLock, approved: bool) -> PinMetadata:
    return PinMetadata(
        created_at=FIXED_TIME,
        warden_version=FIXED_VERSION,
        mcp_protocol_version=PROTOCOL,
        approved=approved,
        approver=APPROVER if approved else None,
        approved_at=FIXED_TIME if approved else None,
        approved_digest=lock.overall_digest if approved else None,
    )


def make_lock(surface_doc: dict[str, Any], *, approved: bool = False) -> dict[str, Any]:
    """Build the on-disk lock document for a surface, with a frozen ``pin`` block."""
    lock = build_lock(surface_from_json(surface_doc), [], approve=approved, approver=APPROVER)
    lock = lock.model_copy(update={"pin": _frozen_pin(lock, approved), "warden_version": FIXED_VERSION})
    return json.loads(lock_to_pretty_json(lock))


def lock_with_inspection(surface_doc: dict[str, Any], tool_name: str, inspection: dict[str, Any]) -> dict[str, Any]:
    """A baseline whose named tool carries a §11 inspection block (never produced by pin itself)."""
    surface = surface_from_json(surface_doc)
    lock = build_lock(surface, [])
    tools = []
    for captured, entry in zip(sorted(surface.tools, key=lambda t: t.name), lock.tools, strict=True):
        tools.append(_tool_entry(captured, inspection) if entry.name == tool_name else entry)
    overall = compute_overall_digest(lock.server, tools, lock.resources, lock.prompts)
    lock = lock.model_copy(update={"tools": tools, "overall_digest": overall})
    lock = lock.model_copy(update={"pin": _frozen_pin(lock, False), "warden_version": FIXED_VERSION})
    return json.loads(lock_to_pretty_json(lock))


def lock_at_schema_version(surface_doc: dict[str, Any], schema_version: int) -> dict[str, Any]:
    """An APPROVED baseline written at an older format level (drives schema-version-migrated)."""
    doc = make_lock(surface_doc, approved=True)
    payload = {
        "schema_version": schema_version,
        "server": {"command_digest": doc["server"]["command_digest"]},
        "tools": [t["entry_digest"] for t in doc["tools"]],
        "resources": [r["entry_digest"] for r in doc["resources"]],
        "prompts": [p["entry_digest"] for p in doc["prompts"]],
    }
    digest = hash_value(payload)
    doc["schema_version"] = schema_version
    doc["overall_digest"] = digest
    doc["pin"]["approved_digest"] = digest
    return doc


def drift_expect(lock_doc: dict[str, Any], surface_doc: dict[str, Any]) -> list[dict[str, Any]]:
    baseline = WardenLock.model_validate(lock_doc)
    current = build_lock(surface_from_json(surface_doc), [])
    return [
        {"drift_class": d.drift_class, "severity": d.severity, "target": d.target, "detail": d.detail}
        for d in compute_drift(baseline, current)
    ]


# --- surface builders --------------------------------------------------------


def obj(props: dict[str, Any], required: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": props}
    if required is not None:
        schema["required"] = required
    schema.update(extra)
    return schema


def tool(name: str, schema: Any = None, description: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"name": name}
    if description is not None:
        out["description"] = description
    if schema is not None:
        out["inputSchema"] = schema
    return out


def surface(
    tools: list[dict[str, Any]] | None = None,
    resources: list[dict[str, Any]] | None = None,
    prompts: list[dict[str, Any]] | None = None,
    *,
    command: str = "python",
    args: list[str] | None = None,
    url: str | None = None,
) -> dict[str, Any]:
    doc: dict[str, Any] = {}
    if url is not None:
        doc["url"] = url
    else:
        doc["command"] = command
        doc["args"] = args if args is not None else ["server.py"]
    doc["tools"] = tools or []
    doc["resources"] = resources or []
    doc["prompts"] = prompts or []
    return doc


def one_tool_surface(schema: Any, description: str | None = None, **kw: Any) -> dict[str, Any]:
    return surface([tool("t", schema, description)], **kw)


def schema_pair(
    ident: str, desc: str, base_schema: Any, cur_schema: Any
) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    """A drift case where only the single tool's inputSchema differs."""
    return ident, desc, one_tool_surface(base_schema), one_tool_surface(cur_schema)


# --- the corpus --------------------------------------------------------------

CLEAN_SURFACE = surface(
    tools=[
        tool(
            "read_file",
            obj({"path": {"type": "string", "description": "Path to read"}}, ["path"]),
            "Read the contents of a file from disk.",
        ),
        tool("list_dir", obj({"path": {"type": "string"}}, ["path"]), "List directory entries."),
    ],
    resources=[
        {"uri": "file:///etc/motd", "name": "motd", "description": "Message of the day", "mimeType": "text/plain"}
    ],
    prompts=[
        {
            "name": "summarize",
            "description": "Summarize a document.",
            "arguments": [{"name": "text", "description": "Text to summarize", "required": True}],
        }
    ],
    args=["tests/fixtures/clean_server.py"],
)

CANONICAL: list[tuple[str, str, Any]] = [
    ("sorted-keys-utf16", "Object keys sort by UTF-16 code units: 'A' < '_' < 'a' < 'b'.", {"b": 1, "a": 2, "A": 3, "_": 4}),
    ("nested-arrays", "Nesting + array order preserved; no insignificant whitespace.", {"x": {"y": [1, 2, {"z": None}]}, "w": []}),
    (
        "numbers-es6",
        "Numbers serialize per ES6 Number::toString (1e21 -> 1e+21, 1.0 -> 1, -0 -> 0, 1e-7).",
        {"a": 0.1, "b": 1e21, "c": 100, "d": 1.0, "e": -0.0, "f": 1e-7, "g": 123456789.125, "h": -5, "i": 9007199254740991},
    ),
    ("unicode-literal", "Non-ASCII is emitted literally as UTF-8, never \\uXXXX-escaped.", {"k": "café", "é": "ü", "日本": "語"}),
    ("control-escapes", "Only \\\" \\\\ \\b \\f \\n \\r \\t and \\u00XX (<0x20) are escaped; DEL and U+2028 stay literal.", "a\u0007b\n\t\"q\\ \u001f\u007f\u2028"),
    (
        "surrogate-key-order",
        "UTF-16 ordering puts an astral key (D83D DE00) before U+E000 and U+FF01; code-point order would not.",
        {"\uff01": 1, "\U0001f600": 2, "\ue000": 3},
    ),
    ("empty-string", "The empty string — the §5.1 absent-description digest.", ""),
    ("empty-object", "The empty object — the §5.1 absent-inputSchema digest.", {}),
    ("empty-array", "The empty array — the §5.1 absent-arguments digest.", []),
    ("scalars", "Literals true/false/null and zero.", [True, False, None, "", 0]),
    ("deep-nesting", "Deeply nested empties.", {"a": {"b": {"c": {"d": [[[]]]}}}}),
    ("key-escapes", "Keys are escaped like strings and sorted by their code units.", {'a"b': 1, "c\\d": 2, "e\nf": 3}),
]

DIGEST: list[tuple[str, str, dict[str, Any]]] = [
    (
        "minimal-single-tool",
        "One stdio server, one tool with a required path property.",
        surface([tool("read_file", obj({"path": {"type": "string"}}, ["path"]), "Read a file.")], command="node", args=["./server.js"]),
    ),
    ("clean-fixture", "The repo's clean fixture surface: two tools, one resource, one prompt.", CLEAN_SURFACE),
    (
        "absence-rules",
        "Absent description hashes \"\", absent inputSchema hashes {}, absent arguments hashes [], absent name/mimeType are null.",
        surface([tool("bare")], [{"uri": "res://bare"}], [{"name": "bare"}]),
    ),
    (
        "http-url-server",
        "A Streamable HTTP endpoint: command_digest covers {url}; command/args are empty.",
        surface([tool("ping", obj({}))], url="https://example.com/mcp"),
    ),
    (
        "malformed-input-schema",
        "A non-object inputSchema hashes as {} and yields an empty skeleton; it must not fail the digest.",
        surface([tool("weird", "not-a-schema"), tool("weirder", [1, 2])]),
    ),
    (
        "capabilities-and-refs",
        "Capability derivation from name/property tokens; in-document $ref followed, remote/sibling/cyclic refs are opaque leaves.",
        surface(
            [
                tool("run_shell_command", obj({"command": {"type": "string"}})),
                tool("writeFile", obj({"path": {"type": "string"}, "content": {"type": "string"}}, ["path", "content"])),
                tool("fetchUrl", obj({"url": {"type": "string", "format": "uri"}})),
                tool("sqlQuery", obj({"query": {"type": "string"}})),
                tool("read_file", obj({"path": {"type": "string"}})),
                tool(
                    "refs",
                    {
                        "type": "object",
                        "$defs": {"name": {"type": "string", "maxLength": 32}, "loop": {"$ref": "#/$defs/loop"}},
                        "properties": {
                            "who": {"$ref": "#/$defs/name"},
                            "remote": {"$ref": "https://example.com/s.json#/x"},
                            "sibling": {"$ref": "#/$defs/name", "description": "has a sibling"},
                            "cyclic": {"$ref": "#/$defs/loop"},
                            "escaped": {"$ref": "#/$defs/na%6de"},
                        },
                        "required": ["who"],
                    },
                ),
            ]
        ),
    ),
    (
        "enum-constraints-skeleton",
        "Enum canonical ordering, retained constraint keys, type lists, nested items, additionalProperties false.",
        surface(
            [
                tool(
                    "cfg",
                    obj(
                        {
                            "mode": {"type": ["null", "string"], "enum": ["b", "a", 1, True, None, {"k": 1}, [2]]},
                            "n": {"type": "integer", "minimum": 0, "maximum": 10},
                            "s": {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^x", "format": "email", "title": "cosmetic"},
                            "items": {"type": "array", "items": {"type": "string", "maxLength": 4}},
                            "nested": obj({"deep": {"type": "boolean", "default": True}}, ["deep"], additionalProperties=False),
                        },
                        ["mode"],
                        additionalProperties=False,
                    ),
                )
            ]
        ),
    ),
    (
        "entry-sorting",
        "Tools/prompts sort by name and resources by uri (code-point order) regardless of input order.",
        surface(
            [tool("b"), tool("a"), tool("B"), tool("_z")],
            [{"uri": "z://1"}, {"uri": "a://1"}, {"uri": "A://1"}],
            [{"name": "p2"}, {"name": "p1"}],
        ),
    ),
]

# (id, description, baseline_lock_doc_or_surface, current_surface). A baseline given as a
# surface is turned into an unapproved lock; a dict with "__lock__" is used verbatim.
_SIMPLE = one_tool_surface(obj({"x": {"type": "string"}}))

DRIFT: list[tuple[str, str, dict[str, Any], dict[str, Any]]] = [
    ("no-drift", "Identical surface: overall_digest matches, the drift set is empty.", _SIMPLE, _SIMPLE),
    ("server-identity", "argv changed -> server-identity (critical).", one_tool_surface(obj({}), args=["server.py"]), one_tool_surface(obj({}), args=["other.py"])),
    ("server-identity-url", "HTTP endpoint changed -> server-identity (critical).", one_tool_surface(obj({}), url="https://a.example.com/mcp"), one_tool_surface(obj({}), url="https://b.example.com/mcp")),
    ("tool-added", "A new tool name -> tool-added (high).", surface([tool("a", obj({}))]), surface([tool("a", obj({})), tool("b", obj({}))])),
    ("tool-removed", "A tool disappeared -> tool-removed (medium).", surface([tool("a", obj({})), tool("b", obj({}))]), surface([tool("a", obj({}))])),
    ("capability-added", "A command-like property appears -> capability-added shell-exec (high) plus the schema facts.", one_tool_surface(obj({"x": {}})), one_tool_surface(obj({"command": {}}))),
    ("capability-removed", "The command-like property disappears -> capability-removed (medium).", one_tool_surface(obj({"command": {}})), one_tool_surface(obj({"x": {}}))),
    ("description-modified", "Only the description changed -> description-modified (low).", one_tool_surface(obj({"x": {}}), "old"), one_tool_surface(obj({"x": {}}), "new")),
    ("description-and-schema", "Description AND schema changed: description-modified is suppressed in favour of the schema facts.", one_tool_surface(obj({"x": {}}), "old"), one_tool_surface(obj({"x": {}, "y": {"type": "string", "enum": ["a"]}}), "new")),
    ("resource-added", "resource-added (medium).", surface(), surface(resources=[{"uri": "file:///x", "name": "x"}])),
    ("resource-removed", "resource-removed (low).", surface(resources=[{"uri": "file:///x", "name": "x"}]), surface()),
    ("resource-modified", "Same uri, changed description -> resource-modified (low).", surface(resources=[{"uri": "file:///x", "name": "x", "description": "a"}]), surface(resources=[{"uri": "file:///x", "name": "x", "description": "b"}])),
    ("prompt-added", "prompt-added (medium).", surface(), surface(prompts=[{"name": "p"}])),
    ("prompt-removed", "prompt-removed (low).", surface(prompts=[{"name": "p"}]), surface()),
    ("prompt-modified", "Same name, changed arguments -> prompt-modified (low).", surface(prompts=[{"name": "p", "arguments": [{"name": "a"}]}]), surface(prompts=[{"name": "p", "arguments": [{"name": "a"}, {"name": "b"}]}])),
    ("unapproved-change", "Approved baseline + any surface change -> unapproved-change (high) alongside the entry drift.", {"__lock__": make_lock(one_tool_surface(obj({"x": {}}), "old"), approved=True)}, one_tool_surface(obj({"x": {}}), "new")),
    ("schema-version-migrated", "Approved baseline written at schema_version 2, same surface -> unapproved-change + schema-version-migrated advisory.", {"__lock__": lock_at_schema_version(_SIMPLE, 2)}, _SIMPLE),
    ("inspection-policy-modified", "Baseline tool carries a §11 inspection block, current does not -> inspection-policy-modified (medium).", {"__lock__": lock_with_inspection(_SIMPLE, "t", {"expected_output_charset": "extended", "may_return_urls": True})}, _SIMPLE),
    ("schema-modified-v1-fallback", "Baseline without a schema_skeleton (v1 lock) + changed schema -> single schema-modified (high).", {"__lock__": None}, one_tool_surface(obj({"a": {}, "b": {}}))),
    schema_pair("schema-modified-opaque-ref", "A remote $ref target changed -> opaque-leaf schema-modified (high) carrying both literals.", obj({"a": {"$ref": "https://example.com/a.json#/x"}}), obj({"a": {"$ref": "https://example.com/b.json#/x"}})),
    schema_pair("schema-modified-ref-redacted", "An opaque $ref whose target looks secret is redacted in detail.", obj({"a": {"$ref": "https://example.com/s.json#/apiKey"}}), obj({"a": {"$ref": "https://example.com/s.json#/token2"}})),
    schema_pair("schema-cosmetic-modified", "Only a cosmetic key changed: hash differs, skeleton identical -> schema-cosmetic-modified (low).", obj({"a": {"type": "string", "description": "old"}}), obj({"a": {"type": "string", "description": "new"}})),
    schema_pair("schema-required-removed", "", obj({"a": {"type": "string"}}, ["a"]), obj({})),
    schema_pair("schema-property-removed", "", obj({"a": {"type": "string"}}), obj({})),
    schema_pair("schema-required-unconstrained-added", "", obj({}), obj({"a": {"type": "string"}}, ["a"])),
    schema_pair("schema-required-added", "", obj({}), obj({"a": {"type": "string", "maxLength": 8}}, ["a"])),
    schema_pair("schema-unconstrained-added", "", obj({}), obj({"a": {"type": "string"}})),
    schema_pair("schema-property-added", "", obj({}), obj({"a": {"type": "string", "enum": ["x", "y"]}})),
    schema_pair("schema-type-broadened", "", obj({"a": {"type": "string"}}), obj({"a": {"type": ["string", "object"]}})),
    schema_pair("schema-type-narrowed", "", obj({"a": {"type": ["string", "object"]}}), obj({"a": {"type": "string"}})),
    schema_pair("schema-type-changed", "", obj({"a": {"type": "string"}}), obj({"a": {"type": "integer"}})),
    schema_pair("schema-type-any-to-typed", "any -> typed is a narrowing (low); typed -> any is a broadening (high).", obj({"a": {}, "b": {"type": "string"}}), obj({"a": {"type": "string"}, "b": {}})),
    schema_pair("schema-enum-widened", "", obj({"a": {"enum": ["x"]}}), obj({"a": {"enum": ["x", "y"]}})),
    schema_pair("schema-enum-narrowed", "", obj({"a": {"enum": ["x", "y"]}}), obj({"a": {"enum": ["x"]}})),
    schema_pair("schema-enum-removed", "", obj({"a": {"enum": ["x", "y"]}}), obj({"a": {}})),
    schema_pair("schema-enum-added", "", obj({"a": {}}), obj({"a": {"enum": ["x", "y"]}})),
    schema_pair("schema-enum-disjoint-is-widened", "Same size but different members counts as widening.", obj({"a": {"enum": ["x", "y"]}}), obj({"a": {"enum": ["x", "z"]}})),
    schema_pair("schema-constraint-relaxed-required-to-optional", "", obj({"a": {"type": "string"}}, ["a"]), obj({"a": {"type": "string"}})),
    schema_pair("schema-constraint-relaxed-maxlength-up", "detail is 'maxLength 64→4096'.", obj({"a": {"type": "string", "maxLength": 64}}), obj({"a": {"type": "string", "maxLength": 4096}})),
    schema_pair("schema-constraint-relaxed-pattern-removed", "", obj({"a": {"type": "string", "pattern": "^x$"}}), obj({"a": {"type": "string"}})),
    schema_pair("schema-constraint-relaxed-minimum-lowered", "", obj({"a": {"type": "integer", "minimum": 10}}), obj({"a": {"type": "integer", "minimum": 0}})),
    schema_pair("schema-constraint-relaxed-bound-removed", "Removing an upper bound relaxes; adding a lower bound tightens.", obj({"a": {"type": "integer", "maximum": 10}}), obj({"a": {"type": "integer", "minimum": 1}})),
    schema_pair("schema-additional-props-opened", "", obj({}, additionalProperties=False), obj({}, additionalProperties=True)),
    schema_pair("schema-additional-props-opened-to-object", "false -> a schema object is still the open-world escalation; detail carries the object.", obj({}, additionalProperties=False), obj({}, additionalProperties={"type": "string"})),
    schema_pair("schema-constraint-tightened", "maxLength down + additionalProperties object -> false are both tightenings (low).", obj({"a": {"type": "string", "maxLength": 4096}}, additionalProperties={"type": "string"}), obj({"a": {"type": "string", "maxLength": 16}}, additionalProperties=False)),
    schema_pair("schema-per-fact-emission", "required->optional AND string->string|null on one property emit two facts.", obj({"a": {"type": "string"}}, ["a"]), obj({"a": {"type": ["null", "string"]}})),
    schema_pair("schema-array-items-recursed", "Array items are diffed at the 'a[]' path.", obj({"a": {"type": "array", "items": {"type": "string", "maxLength": 4}}}), obj({"a": {"type": "array", "items": {"type": "string", "maxLength": 99}}})),
    schema_pair("schema-pattern-changed-tightened", "pattern changed (not removed) is a tightening with no value echoed.", obj({"a": {"type": "string", "pattern": "^api_key-AKIA1234567890$"}}), obj({"a": {"type": "string", "pattern": "^token-XYZ$"}})),
    schema_pair(
        "schema-ref-resolved-granular",
        "A constraint relaxed inside an in-document $ref target classifies granularly at the property path (R8).",
        {"type": "object", "$defs": {"n": {"type": "string", "maxLength": 8}}, "properties": {"who": {"$ref": "#/$defs/n"}}},
        {"type": "object", "$defs": {"n": {"type": "string", "maxLength": 800}}, "properties": {"who": {"$ref": "#/$defs/n"}}},
    ),
    (
        "mixed-multi-entry",
        "Several entries drift at once; items are ordered by (target, drift_class).",
        surface([tool("b", obj({"x": {"type": "string"}}), "d"), tool("a", obj({}))], [{"uri": "r://1"}], [{"name": "p"}]),
        surface([tool("b", obj({"x": {"type": "string"}, "command": {}}), "d2"), tool("c", obj({}))], [{"uri": "r://2"}], [{"name": "p", "description": "x"}]),
    ),
]

MALFORMED: list[tuple[str, str, Any]] = [
    ("invalid-json", "Not JSON at all.", "{not json"),
    ("missing-overall-digest", "Top-level overall_digest is required.", None),
    ("tools-not-array", "tools must be an array.", None),
    ("server-missing-command-digest", "server.command_digest is required.", None),
    ("schema-version-not-integer", "schema_version must be an integer.", None),
    ("missing-pin", "pin is required.", None),
    ("tool-missing-entry-digest", "Every tool entry carries entry_digest.", None),
]


def _malformed_doc(ident: str) -> Any:
    good = make_lock(one_tool_surface(obj({"x": {"type": "string"}})))
    bad = json.loads(json.dumps(good))
    if ident == "missing-overall-digest":
        del bad["overall_digest"]
    elif ident == "tools-not-array":
        bad["tools"] = {"t": bad["tools"][0]}
    elif ident == "server-missing-command-digest":
        del bad["server"]["command_digest"]
    elif ident == "schema-version-not-integer":
        bad["schema_version"] = "three"
    elif ident == "missing-pin":
        del bad["pin"]
    elif ident == "tool-missing-entry-digest":
        del bad["tools"][0]["entry_digest"]
    else:
        raise AssertionError(ident)
    # Sanity: the reference reader MUST reject it (fail closed).
    try:
        WardenLock.model_validate(bad)
    except Exception:
        return bad
    raise AssertionError(f"malformed vector {ident} was accepted by the reference reader")


# --- writer ------------------------------------------------------------------


def _write(path: Path, doc: dict[str, Any]) -> None:
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8")


def main() -> None:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    for old in CASES_DIR.glob("*.json"):
        old.unlink()
    entries: list[dict[str, str]] = []

    def add(kind: str, ident: str, description: str, body: dict[str, Any]) -> None:
        vid = f"{kind}/{ident}"
        fname = f"{kind}-{ident}.json"
        _write(CASES_DIR / fname, {"id": vid, "kind": kind, "description": description, **body})
        entries.append({"id": vid, "kind": kind, "file": f"cases/{fname}"})

    for ident, desc, value in CANONICAL:
        add("canonical", ident, desc, {"input": value, "expect": {"jcs": canon(value).decode("utf-8"), "sha256": hash_value(value)}})

    for ident, desc, surf in DIGEST:
        lock = make_lock(surf)
        add(
            "digest",
            ident,
            desc,
            {
                "surface": surf,
                "expect": {
                    "server": {"command_digest": lock["server"]["command_digest"]},
                    "tools": lock["tools"],
                    "resources": lock["resources"],
                    "prompts": lock["prompts"],
                    "overall_digest": lock["overall_digest"],
                },
            },
        )

    for ident, desc, base, cur in DRIFT:
        if isinstance(base, dict) and "__lock__" in base:
            lock = base["__lock__"]
            if lock is None:  # v1-style baseline: strip the skeleton
                lock = make_lock(one_tool_surface(obj({"a": {}})))
                lock["tools"][0]["schema_skeleton"] = None
        else:
            lock = make_lock(base)
        desc = desc or f"Drift class {ident} (see docs/SPEC.md §8)."
        add("drift", ident, desc, {"lock": lock, "surface": cur, "expect": drift_expect(lock, cur)})

    for ident, desc, text in MALFORMED:
        body: dict[str, Any] = {"expect": {"error": True}}
        if text is not None:
            body["lock_text"] = text
        else:
            body["lock"] = _malformed_doc(ident)
        add("malformed", ident, desc, body)

    manifest = {
        "format": "mcp-lock-v1",
        "schema_version": 3,
        "generator": "vectors/tools/generate.py",
        "count": len(entries),
        "vectors": entries,
    }
    _write(VECTORS_DIR / "manifest.json", manifest)
    kinds = {k: sum(1 for e in entries if e["kind"] == k) for k in ("canonical", "digest", "drift", "malformed")}
    print(f"wrote {len(entries)} vectors: {kinds}")


if __name__ == "__main__":
    main()
