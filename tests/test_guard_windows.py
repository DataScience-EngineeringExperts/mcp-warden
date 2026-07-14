"""Windows-lifecycle unit tests (GUARD_PROXY_V3.md §3.2, mcp-warden#10).

All tests run on any platform by monkeypatching ``_IS_WINDOWS`` and either:
  - injecting a mock ``ctypes.windll`` via ``patch(..., create=True)`` for
    low-level ctypes helpers (windll doesn't exist on non-Windows, so create=True
    is required to inject it in the test), or
  - patching the ``lifecycle._win32_*`` functions directly for higher-level tests.

Coverage:
  (a) _win32_send_ctrl — calls GenerateConsoleCtrlEvent; returns False on failure
  (b) _win32_create_and_assign_job — happy path and each failure mode
  (c) win32_register_child — stores handle on success; no entry on failure
  (d) win32_release_child — pops entry, calls CloseHandle; safe when pid absent
  (e) _teardown_windows async — CTRL_BREAK+child exits, CTRL_BREAK+no exit (terminate),
      CTRL_BREAK fails (terminate-only), on_note=None safe
  (f) teardown_child — routes to async _teardown_windows on non-POSIX
  (g) subprocess.CREATE_NEW_PROCESS_GROUP constant sanity check
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import mcp_warden.guard_lifecycle as lifecycle
from mcp_warden.guard_lifecycle import (
    _CTRL_BREAK_EVENT,
    _WIN_JOBS,
    _win32_send_ctrl,
    win32_register_child,
    win32_release_child,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_kernel32(*, create_job=1, set_info=1, open_proc=2, assign=1, ctrl_event=1):
    """Return a mock kernel32 where all calls succeed (non-zero) by default."""
    k = MagicMock()
    k.CreateJobObjectW.return_value = create_job
    k.SetInformationJobObject.return_value = set_info
    k.OpenProcess.return_value = open_proc
    k.AssignProcessToJobObject.return_value = assign
    k.GenerateConsoleCtrlEvent.return_value = ctrl_event
    k.CloseHandle.return_value = 1
    return k


def _windll_patch(kernel32):
    """Return a context manager that injects ``ctypes.windll.kernel32`` safely on any OS."""
    windll = MagicMock()
    windll.kernel32 = kernel32
    return patch("ctypes.windll", windll, create=True)


def _mock_proc(*, returncode=None, pid=1234):
    proc = MagicMock()
    proc.pid = pid
    proc.returncode = returncode
    proc.terminate = MagicMock()
    proc.stdin = AsyncMock()
    proc.wait = AsyncMock(return_value=None)
    return proc


# ---------------------------------------------------------------------------
# (a) _win32_send_ctrl
# ---------------------------------------------------------------------------

def test_send_ctrl_calls_generate_console_ctrl_event(monkeypatch):
    """_win32_send_ctrl calls GenerateConsoleCtrlEvent(ctrl_type, pid)."""
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    k = _fake_kernel32(ctrl_event=1)
    with _windll_patch(k):
        result = _win32_send_ctrl(1234, _CTRL_BREAK_EVENT)
    assert result is True
    k.GenerateConsoleCtrlEvent.assert_called_once_with(_CTRL_BREAK_EVENT, 1234)


def test_send_ctrl_returns_false_when_api_returns_zero(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    k = _fake_kernel32(ctrl_event=0)
    with _windll_patch(k):
        result = _win32_send_ctrl(1234, _CTRL_BREAK_EVENT)
    assert result is False


def test_send_ctrl_noop_on_non_windows(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", False)
    result = _win32_send_ctrl(999, _CTRL_BREAK_EVENT)
    assert result is False


def test_send_ctrl_swallows_exception(monkeypatch):
    """An exception from the ctypes call returns False without raising."""
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    k = MagicMock()
    k.GenerateConsoleCtrlEvent.side_effect = OSError("no console")
    with _windll_patch(k):
        result = _win32_send_ctrl(1, _CTRL_BREAK_EVENT)
    assert result is False


# ---------------------------------------------------------------------------
# (b) _win32_create_and_assign_job
# ---------------------------------------------------------------------------

def test_create_and_assign_job_happy_path(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    k = _fake_kernel32()
    with _windll_patch(k):
        handle = lifecycle._win32_create_and_assign_job(42)
    assert handle == 1
    k.CreateJobObjectW.assert_called_once()
    k.SetInformationJobObject.assert_called_once()
    k.OpenProcess.assert_called_once()
    k.AssignProcessToJobObject.assert_called_once()


def test_create_and_assign_job_create_fails_returns_none(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    k = _fake_kernel32(create_job=0)
    with _windll_patch(k):
        handle = lifecycle._win32_create_and_assign_job(42)
    assert handle is None


def test_create_and_assign_job_set_info_fails_closes_job(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    k = _fake_kernel32(set_info=0)
    with _windll_patch(k):
        handle = lifecycle._win32_create_and_assign_job(42)
    assert handle is None
    k.CloseHandle.assert_called_once_with(1)  # job handle was closed


def test_create_and_assign_job_open_process_fails(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    k = _fake_kernel32(open_proc=0)
    with _windll_patch(k):
        handle = lifecycle._win32_create_and_assign_job(42)
    assert handle is None


def test_create_and_assign_job_assign_fails(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    k = _fake_kernel32(assign=0)
    with _windll_patch(k):
        handle = lifecycle._win32_create_and_assign_job(42)
    assert handle is None


# ---------------------------------------------------------------------------
# (c) win32_register_child
# ---------------------------------------------------------------------------

def test_register_child_stores_handle_on_success(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    _WIN_JOBS.clear()
    k = _fake_kernel32()
    with _windll_patch(k):
        win32_register_child(55)
    assert 55 in _WIN_JOBS
    _WIN_JOBS.clear()


def test_register_child_no_entry_on_job_creation_failure(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    _WIN_JOBS.clear()
    k = _fake_kernel32(create_job=0)
    with _windll_patch(k):
        win32_register_child(56)
    assert 56 not in _WIN_JOBS


def test_register_child_noop_on_non_windows(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", False)
    _WIN_JOBS.clear()
    win32_register_child(99)
    assert 99 not in _WIN_JOBS


# ---------------------------------------------------------------------------
# (d) win32_release_child
# ---------------------------------------------------------------------------

def test_release_child_pops_entry_and_closes_handle(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    _WIN_JOBS[77] = 9999
    k = MagicMock()
    k.CloseHandle.return_value = 1
    with _windll_patch(k):
        win32_release_child(77)
    assert 77 not in _WIN_JOBS
    k.CloseHandle.assert_called_once_with(9999)


def test_release_child_noop_when_pid_not_registered(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    _WIN_JOBS.clear()
    k = MagicMock()
    with _windll_patch(k):
        win32_release_child(123)  # pid absent — must not raise
    k.CloseHandle.assert_not_called()


def test_release_child_noop_on_non_windows(monkeypatch):
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", False)
    _WIN_JOBS[88] = "handle"
    win32_release_child(88)
    assert 88 in _WIN_JOBS  # not touched on non-Windows
    _WIN_JOBS.pop(88, None)


# ---------------------------------------------------------------------------
# (e) _teardown_windows — async cases
# Mock _win32_send_ctrl at the lifecycle module level to avoid ctypes patching.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_teardown_windows_ctrl_break_sent_child_exits_quickly(monkeypatch):
    """CTRL_BREAK sent, child exits within grace -> terminate NOT called."""
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    _WIN_JOBS.clear()
    monkeypatch.setattr(lifecycle, "_win32_send_ctrl", lambda pid, ctrl: True)

    proc = _mock_proc(pid=1234)
    on_note_calls = []
    await lifecycle._teardown_windows(proc, on_note=on_note_calls.append)

    proc.terminate.assert_not_called()
    assert len(on_note_calls) == 1
    assert "CTRL_BREAK_EVENT" in on_note_calls[0].message


@pytest.mark.asyncio
async def test_teardown_windows_ctrl_break_sent_child_does_not_exit(monkeypatch):
    """CTRL_BREAK sent but grace expires -> terminate called as fallback."""
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    _WIN_JOBS.clear()
    monkeypatch.setattr(lifecycle, "_win32_send_ctrl", lambda pid, ctrl: True)
    monkeypatch.setattr(lifecycle, "TERM_GRACE_S", 0.01)

    proc = _mock_proc(pid=1234)

    async def _hang():
        await asyncio.sleep(100)

    proc.wait = _hang
    on_note_calls = []
    await lifecycle._teardown_windows(proc, on_note=on_note_calls.append)

    proc.terminate.assert_called_once()
    assert any("did not exit after CTRL_BREAK_EVENT" in n.message for n in on_note_calls)


@pytest.mark.asyncio
async def test_teardown_windows_ctrl_break_fails_terminate_only(monkeypatch):
    """CTRL_BREAK fails -> terminate-only path; appropriate note emitted."""
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    _WIN_JOBS.clear()
    monkeypatch.setattr(lifecycle, "_win32_send_ctrl", lambda pid, ctrl: False)

    proc = _mock_proc(pid=1234)
    on_note_calls = []
    await lifecycle._teardown_windows(proc, on_note=on_note_calls.append)

    proc.terminate.assert_called_once()
    assert any("CTRL_BREAK_EVENT failed" in n.message for n in on_note_calls)


@pytest.mark.asyncio
async def test_teardown_windows_on_note_none_is_safe(monkeypatch):
    """on_note=None must not raise in any teardown path."""
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    _WIN_JOBS.clear()
    monkeypatch.setattr(lifecycle, "_win32_send_ctrl", lambda pid, ctrl: True)

    proc = _mock_proc(pid=1234)
    await lifecycle._teardown_windows(proc, on_note=None)  # must not raise


@pytest.mark.asyncio
async def test_teardown_windows_job_protected_detail_in_note(monkeypatch):
    """When a job object is registered, the note mentions 'job object protected'."""
    monkeypatch.setattr(lifecycle, "_IS_WINDOWS", True)
    _WIN_JOBS[1234] = "fake_handle"  # simulate registered job
    monkeypatch.setattr(lifecycle, "_win32_send_ctrl", lambda pid, ctrl: True)

    proc = _mock_proc(pid=1234)
    on_note_calls = []
    await lifecycle._teardown_windows(proc, on_note=on_note_calls.append)

    _WIN_JOBS.clear()
    assert any("job object protected" in n.message for n in on_note_calls)


# ---------------------------------------------------------------------------
# (f) teardown_child routes to async _teardown_windows on non-POSIX
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_teardown_child_routes_to_windows_on_non_posix(monkeypatch):
    """teardown_child must await _teardown_windows when _IS_POSIX is False."""
    monkeypatch.setattr(lifecycle, "_IS_POSIX", False)

    called = []

    async def _fake_win(proc, on_note):
        called.append(proc.pid)

    monkeypatch.setattr(lifecycle, "_teardown_windows", _fake_win)

    proc = _mock_proc(pid=7777)
    proc.stdin.aclose = AsyncMock()
    await lifecycle.teardown_child(proc)

    assert called == [7777]


# ---------------------------------------------------------------------------
# (g) subprocess.CREATE_NEW_PROCESS_GROUP constant sanity check
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    __import__("os").name != "nt",
    reason="CREATE_NEW_PROCESS_GROUP only exists on Windows",
)
def test_create_new_process_group_constant():
    """On Windows: CREATE_NEW_PROCESS_GROUP must be 0x200 per Windows SDK."""
    import subprocess as _sp
    assert _sp.CREATE_NEW_PROCESS_GROUP == 0x00000200
