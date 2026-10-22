"""Capability-aware capture against real stdio servers (DSE-1538).

Not a mock: each case spawns ``fixtures/capability_server.py`` as a child MCP
server through the official SDK, so the error codes asserted on are the ones the
installed SDK line actually sends.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_warden.capture import CaptureError, capture_surface_sync

SERVER = str(Path(__file__).parent / "fixtures" / "capability_server.py")
PY = sys.executable


def test_undeclared_sections_capture_as_empty():
    surface = capture_surface_sync(PY, [SERVER, "tools-only"])
    assert [t.name for t in surface.tools] == ["echo"]
    assert surface.resources == []
    assert surface.prompts == []


def test_declared_section_that_errors_fails_closed():
    # Before DSE-1538 this pinned a lock with no prompts and `check` stayed clean.
    with pytest.raises(CaptureError, match="prompts/list failed for a declared capability"):
        capture_surface_sync(PY, [SERVER, "broken-prompts"])
