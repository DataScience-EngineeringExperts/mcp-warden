"""``capture._model_dump`` must yield the WIRE view of an SDK model on every mcp line.

Two SDK-side changes in mcp 2.x would otherwise silently alter every committed lock:
model fields were renamed to snake_case (``input_schema``), and ``PromptArgument``
grew a ``title`` field whose ``None`` default the server never sent. Both are
absorbed here so ``pin``/``check`` digests are identical under 1.x and 2.x.
"""

from __future__ import annotations

import mcp.types as types

from mcp_warden.capture import _model_dump


def test_tool_dump_uses_wire_keys():
    tool = types.Tool(name="t", description="d", inputSchema={"type": "object"})
    data = _model_dump(tool)
    assert data["inputSchema"] == {"type": "object"}
    assert "input_schema" not in data


def test_prompt_argument_dump_omits_sdk_default_none_fields():
    prompt = types.Prompt(
        name="p",
        description="d",
        arguments=[types.PromptArgument(name="text", description="Text", required=True)],
    )
    args = _model_dump(prompt)["arguments"]
    assert args == [{"name": "text", "description": "Text", "required": True}]


def test_resource_dump_uses_wire_keys():
    res = types.Resource(uri="file:///x", name="n", mimeType="text/plain")
    data = _model_dump(res)
    assert data["mimeType"] == "text/plain" and "mime_type" not in data


def test_bare_prompt_argument_hashes_byte_identically_to_every_released_warden():
    # CSO review of #105, F1: a 1.x ``model_dump()`` always emitted the protocol
    # field set {name, description, required} with ``null`` for absent optionals,
    # and every lock ever written hashes those bytes. Dropping the nulls would
    # have changed ``arguments_hash`` for any prompt with a bare argument.
    from mcp_warden.capture import _normalize_prompt_argument
    from mcp_warden.hashing import canon, hash_arguments

    norm = _normalize_prompt_argument(types.PromptArgument(name="text"))
    assert canon([norm]) == b'[{"description":null,"name":"text","required":null}]'
    assert hash_arguments([norm]) == hash_arguments(
        [{"description": None, "name": "text", "required": None}]
    )
    assert "title" not in norm  # 2.x-only field, absent from the wire -> shed


def test_non_null_extra_prompt_argument_fields_are_kept():
    from mcp_warden.capture import _normalize_prompt_argument

    norm = _normalize_prompt_argument({"name": "n", "title": "Nice", "title2": None})
    assert norm == {"name": "n", "description": None, "required": None, "title": "Nice"}
