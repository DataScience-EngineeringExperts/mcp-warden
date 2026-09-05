"""``nextCursor`` pagination in capture (CSO review of #105, F3).

A server may split ``tools/list`` / ``resources/list`` / ``prompts/list`` across
pages. Capture must drain every page, must produce the SAME digest as the same
surface served in one page, must fail CLOSED when a later page cannot be fetched
(a partial surface is not a surface), and must refuse a cursor chain that never
terminates.
"""

from __future__ import annotations

from types import SimpleNamespace

import mcp.types as types
import pytest

from mcp_warden.capture import (
    MAX_LIST_PAGES,
    CaptureError,
    _list_prompts,
    _list_resources,
    _list_tools,
)
from mcp_warden.lockfile import build_lock
from mcp_warden.models import CapturedSurface


def _tool(i: int) -> types.Tool:
    return types.Tool(name=f"t{i}", description=f"tool {i}", inputSchema={"type": "object"})


class _PagedSession:
    """Serves ``items`` in ``page_size`` chunks via the SDK's ``params=`` cursor protocol."""

    def __init__(self, items, page_size, key="tools", cursor_attr="nextCursor"):
        self.items, self.page_size, self.key, self.cursor_attr = items, page_size, key, cursor_attr
        self.calls: list[str | None] = []

    async def _page(self, params=None):
        cursor = params.cursor if params is not None else None
        self.calls.append(cursor)
        start = int(cursor) if cursor else 0
        chunk = self.items[start : start + self.page_size]
        nxt = str(start + self.page_size) if start + self.page_size < len(self.items) else None
        return SimpleNamespace(**{self.key: chunk, self.cursor_attr: nxt})

    async def list_tools(self, *, params=None):
        return await self._page(params)

    async def list_resources(self, *, params=None):
        return await self._page(params)

    async def list_prompts(self, *, params=None):
        return await self._page(params)


def _digest(tools) -> str:
    surface = CapturedSurface(command="x", args=[], protocol_version="2025-06-18", tools=tools)
    return build_lock(surface, []).overall_digest


@pytest.mark.anyio
async def test_two_page_server_captures_both_pages_and_matches_single_page_digest():
    items = [_tool(i) for i in range(5)]
    paged = await _list_tools(_PagedSession(items, page_size=2))
    single = await _list_tools(_PagedSession(items, page_size=100))
    assert [t.name for t in paged] == ["t0", "t1", "t2", "t3", "t4"]
    assert _digest(paged) == _digest(single)


@pytest.mark.anyio
async def test_cursor_is_passed_through_params_on_every_follow_up_page():
    session = _PagedSession([_tool(i) for i in range(3)], page_size=1)
    await _list_tools(session)
    assert session.calls == [None, "1", "2"]


@pytest.mark.anyio
async def test_snake_case_next_cursor_attribute_is_honoured():
    # mcp 2.x models expose ``next_cursor``; 1.x expose ``nextCursor``.
    session = _PagedSession([_tool(i) for i in range(3)], page_size=2, cursor_attr="next_cursor")
    assert len(await _list_tools(session)) == 3


@pytest.mark.anyio
async def test_prompts_and_resources_paginate_too():
    prompts = [types.Prompt(name=f"p{i}", description="d") for i in range(3)]
    resources = [types.Resource(uri=f"file:///r{i}", name=f"r{i}") for i in range(3)]
    got_p = await _list_prompts(_PagedSession(prompts, 2, key="prompts"))
    got_r = await _list_resources(_PagedSession(resources, 2, key="resources"))
    assert [p.name for p in got_p] == ["p0", "p1", "p2"]
    assert [r.uri for r in got_r] == ["file:///r0", "file:///r1", "file:///r2"]


@pytest.mark.anyio
async def test_never_terminating_cursor_chain_is_refused():
    class _Loop:
        async def list_tools(self, *, params=None):
            return SimpleNamespace(tools=[_tool(0)], nextCursor="again")

    with pytest.raises(CaptureError, match=str(MAX_LIST_PAGES)):
        await _list_tools(_Loop())


@pytest.mark.anyio
async def test_failure_on_a_later_page_fails_closed():
    class _Flaky:
        async def list_tools(self, *, params=None):
            if params is not None:
                raise RuntimeError("page 2 exploded")
            return SimpleNamespace(tools=[_tool(0)], nextCursor="1")

    with pytest.raises(CaptureError, match="page 2"):
        await _list_tools(_Flaky())


@pytest.mark.anyio
async def test_first_page_failure_stays_fail_open_for_capability_less_servers():
    class _NoTools:
        async def list_tools(self, *, params=None):
            raise RuntimeError("Method not found")

    assert await _list_tools(_NoTools()) == []
