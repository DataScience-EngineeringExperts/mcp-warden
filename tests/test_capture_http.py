"""Tests for HTTP/SSE capture path (DSE-57).

Uses unittest.mock to avoid real network calls; verifies that
capture_surface_http routes through streamable_http_client and correctly
constructs CapturedSurface with url set.
"""

from __future__ import annotations

import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_warden.capture import (
    CaptureError,
    capture_surface_http,
    capture_surface_http_sync,
)
from mcp_warden.models import CapturedSurface

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tool(name: str = "echo", desc: str = "echo tool") -> MagicMock:
    t = MagicMock()
    t.model_dump.return_value = {"name": name, "description": desc, "inputSchema": None}
    return t


def _make_resource(uri: str = "res://x") -> MagicMock:
    r = MagicMock()
    r.model_dump.return_value = {"uri": uri, "name": "x", "description": None, "mimeType": None}
    return r


def _make_prompt(name: str = "greet") -> MagicMock:
    p = MagicMock()
    p.model_dump.return_value = {"name": name, "description": None, "arguments": None}
    return p


def _session_mock(tools=None, resources=None, prompts=None, protocol_version="2024-11-05"):
    """Return a mock ClientSession whose list_* methods return given items."""
    session = AsyncMock()
    init_result = MagicMock()
    init_result.protocolVersion = protocol_version
    session.initialize.return_value = init_result

    tools_result = MagicMock()
    tools_result.tools = tools or []
    session.list_tools.return_value = tools_result

    resources_result = MagicMock()
    resources_result.resources = resources or []
    session.list_resources.return_value = resources_result

    prompts_result = MagicMock()
    prompts_result.prompts = prompts or []
    session.list_prompts.return_value = prompts_result

    return session


@contextlib.asynccontextmanager
async def _fake_streamable_http(url, **kwargs):
    """Async context manager factory that yields the mocked streams."""
    read_stream = AsyncMock()
    write_stream = AsyncMock()
    get_session_id = MagicMock(return_value=None)
    yield read_stream, write_stream, get_session_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCaptureHttpAsync:
    @pytest.mark.anyio
    async def test_returns_surface_with_url_set(self):
        session = _session_mock(tools=[_make_tool()])
        with (
            patch("mcp_warden.capture.streamable_http_client", _fake_streamable_http),
            patch("mcp_warden.capture.ClientSession") as MockSession,
        ):
            MockSession.return_value.__aenter__ = AsyncMock(return_value=session)
            MockSession.return_value.__aexit__ = AsyncMock(return_value=False)

            surface = await capture_surface_http("http://localhost:8080/mcp", timeout_s=5.0)

        assert isinstance(surface, CapturedSurface)
        assert surface.url == "http://localhost:8080/mcp"
        assert surface.command == ""
        assert surface.args == []
        assert len(surface.tools) == 1
        assert surface.tools[0].name == "echo"

    @pytest.mark.anyio
    async def test_protocol_version_captured(self):
        session = _session_mock(protocol_version="2025-03-26")
        with (
            patch("mcp_warden.capture.streamable_http_client", _fake_streamable_http),
            patch("mcp_warden.capture.ClientSession") as MockSession,
        ):
            MockSession.return_value.__aenter__ = AsyncMock(return_value=session)
            MockSession.return_value.__aexit__ = AsyncMock(return_value=False)

            surface = await capture_surface_http("http://example.com/mcp", timeout_s=5.0)

        assert surface.protocol_version == "2025-03-26"

    @pytest.mark.anyio
    async def test_tools_resources_prompts_all_captured(self):
        session = _session_mock(
            tools=[_make_tool("t1"), _make_tool("t2")],
            resources=[_make_resource("res://a")],
            prompts=[_make_prompt("p1")],
        )
        with (
            patch("mcp_warden.capture.streamable_http_client", _fake_streamable_http),
            patch("mcp_warden.capture.ClientSession") as MockSession,
        ):
            MockSession.return_value.__aenter__ = AsyncMock(return_value=session)
            MockSession.return_value.__aexit__ = AsyncMock(return_value=False)

            surface = await capture_surface_http("http://example.com/mcp", timeout_s=5.0)

        assert len(surface.tools) == 2
        assert len(surface.resources) == 1
        assert len(surface.prompts) == 1

    @pytest.mark.anyio
    async def test_connection_error_raises_capture_error(self):
        @contextlib.asynccontextmanager
        async def _failing_client(url, **kwargs):
            raise RuntimeError("connection refused")
            yield  # pragma: no cover — unreachable; satisfies async-generator protocol

        with (
            patch("mcp_warden.capture.streamable_http_client", _failing_client),
        ):
            with pytest.raises(CaptureError, match="connection refused"):
                await capture_surface_http("http://bad-host/mcp", timeout_s=5.0)

    @pytest.mark.anyio
    async def test_timeout_raises_capture_error(self):
        import anyio

        @contextlib.asynccontextmanager
        async def _slow_client(url, **kwargs):
            read_stream = AsyncMock()
            write_stream = AsyncMock()
            get_session_id = MagicMock(return_value=None)
            yield read_stream, write_stream, get_session_id

        async def _slow_session_init(self_arg=None):
            await anyio.sleep(999)

        with patch("mcp_warden.capture.streamable_http_client", _slow_client):
            with patch("mcp_warden.capture.ClientSession") as MockSession:
                slow_session = AsyncMock()
                slow_session.initialize = _slow_session_init
                MockSession.return_value.__aenter__ = AsyncMock(return_value=slow_session)
                MockSession.return_value.__aexit__ = AsyncMock(return_value=False)

                with pytest.raises(CaptureError, match="did not complete the handshake"):
                    await capture_surface_http("http://slow/mcp", timeout_s=0.05)


class TestCaptureHttpSync:
    def test_sync_wrapper_returns_surface(self):
        session = _session_mock()
        with (
            patch("mcp_warden.capture.streamable_http_client", _fake_streamable_http),
            patch("mcp_warden.capture.ClientSession") as MockSession,
        ):
            MockSession.return_value.__aenter__ = AsyncMock(return_value=session)
            MockSession.return_value.__aexit__ = AsyncMock(return_value=False)

            surface = capture_surface_http_sync("http://localhost:9000/mcp", timeout_s=5.0)

        assert surface.url == "http://localhost:9000/mcp"
        assert isinstance(surface, CapturedSurface)
