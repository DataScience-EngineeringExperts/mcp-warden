"""``--max-pages`` and entry-identity uniqueness across pages (DSE-1539).

The page cap is configurable per run and still fails closed past it. A tool
name, prompt name or resource URI repeated on any page is refused: each is the
entry's identity in the name-keyed drift diff, so a repeat would let one entry
shadow the other.
"""

from __future__ import annotations

from types import SimpleNamespace

import mcp.types as types
import pytest
from typer.testing import CliRunner

import mcp_warden.cli as cli_mod
from mcp_warden.capture import MAX_LIST_PAGES, CaptureError, _capture_session, _list_tools
from mcp_warden.cli import app
from mcp_warden.models import CapturedSurface


def _tool(name: str) -> types.Tool:
    return types.Tool(name=name, description="d", inputSchema={"type": "object"})


class _Session:
    """Paged session (one item per page by default); ``initialize`` declares nothing known."""

    def __init__(self, tools=(), resources=(), prompts=(), page_size=1):
        self.sections = {"tools": list(tools), "resources": list(resources), "prompts": list(prompts)}
        self.page_size = page_size

    async def initialize(self):
        return SimpleNamespace(protocolVersion="2025-06-18")

    async def _page(self, key, params):
        items = self.sections[key]
        i = int(params.cursor) if params is not None else 0
        j = i + self.page_size
        nxt = str(j) if j < len(items) else None
        return SimpleNamespace(**{key: items[i:j], "nextCursor": nxt})

    async def list_tools(self, *, params=None):
        return await self._page("tools", params)

    async def list_resources(self, *, params=None):
        return await self._page("resources", params)

    async def list_prompts(self, *, params=None):
        return await self._page("prompts", params)


@pytest.mark.anyio
async def test_max_pages_caps_the_cursor_chain_and_fails_closed_past_it():
    session = _Session(tools=[_tool("a"), _tool("b"), _tool("c")])
    assert len(await _list_tools(session, max_pages=3)) == 3
    with pytest.raises(CaptureError, match="exceeded 2 pages"):
        await _list_tools(session, max_pages=2)


def test_default_cap_is_256():
    assert MAX_LIST_PAGES == 256


@pytest.mark.anyio
async def test_distinct_entries_across_pages_capture_cleanly():
    surface = await _capture_session(_Session(tools=[_tool("a"), _tool("b")]), MAX_LIST_PAGES)
    assert [t.name for t in surface["tools"]] == ["a", "b"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("session", "label"),
    [
        (_Session(tools=[_tool("a"), _tool("b"), _tool("a")]), "duplicate tool name 'a'"),
        (_Session(tools=[_tool("a"), _tool("a")], page_size=2), "duplicate tool name 'a'"),
        (
            _Session(resources=[types.Resource(uri="file:///r", name="r1"), types.Resource(uri="file:///r", name="r2")]),
            "duplicate resource URI 'file:///r'",
        ),
        (
            _Session(prompts=[types.Prompt(name="p"), types.Prompt(name="p", description="shadow")]),
            "duplicate prompt name 'p'",
        ),
    ],
)
async def test_identity_repeated_on_a_later_page_is_refused(session, label):
    with pytest.raises(CaptureError, match=label):
        await _capture_session(session, MAX_LIST_PAGES)


@pytest.mark.anyio
async def test_same_name_in_different_sections_is_not_a_duplicate():
    surface = await _capture_session(_Session(tools=[_tool("x")], prompts=[types.Prompt(name="x")]), MAX_LIST_PAGES)
    assert [t.name for t in surface["tools"]] == ["x"]
    assert [p.name for p in surface["prompts"]] == ["x"]


def test_cli_threads_max_pages_into_pin_and_rejects_zero(tmp_path, monkeypatch):
    seen: dict[str, int] = {}

    def fake_capture(command, args, timeout_s, max_pages):
        seen["max_pages"] = max_pages
        return CapturedSurface(command=command, args=args, protocol_version="2025-06-18", tools=[])

    monkeypatch.setattr(cli_mod, "capture_surface_sync", fake_capture)
    lock = tmp_path / "warden.lock"
    runner = CliRunner()
    result = runner.invoke(app, ["pin", "--lock", str(lock), "--max-pages", "7", "srv"])
    assert result.exit_code == 0, result.output
    assert seen["max_pages"] == 7
    assert runner.invoke(app, ["pin", "--lock", str(lock), "--max-pages", "0", "srv"]).exit_code == 2


def test_cli_threads_max_pages_into_check(tmp_path, monkeypatch):
    seen: dict[str, int] = {}

    def fake_check(command, args, lock, *, timeout_s, url, max_pages):
        seen["max_pages"] = max_pages
        raise CaptureError("stop here")

    monkeypatch.setattr(cli_mod, "run_check_full", fake_check)
    result = CliRunner().invoke(app, ["check", "--lock", str(tmp_path / "warden.lock"), "--max-pages", "9", "srv"])
    assert result.exit_code == 2, result.output
    assert seen["max_pages"] == 9


def test_server_controlled_names_in_capture_errors_are_not_console_markup(tmp_path, monkeypatch):
    def fake_capture(command, args, timeout_s, max_pages):
        raise CaptureError(f"duplicate tool name {'x[/red]'!r}; refusing to pin an ambiguous surface")

    monkeypatch.setattr(cli_mod, "capture_surface_sync", fake_capture)
    result = CliRunner().invoke(app, ["pin", "--lock", str(tmp_path / "warden.lock"), "srv"])
    assert result.exit_code == 2, result.output
    assert isinstance(result.exception, SystemExit)
