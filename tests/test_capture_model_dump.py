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
