"""Non-POSIX platform refusal / opt-in coverage (v1.0, GUARD_PROXY_V3.md §3.3).

``guard`` must NOT silently run with a false sense of full runtime protection on a
non-POSIX platform. This module proves, by simulating a non-POSIX host through the
SAME ``os.name``-derived gate the lifecycle primitives already use (monkeypatching
``guard_lifecycle._IS_POSIX``):

  * (a) WITHOUT ``--allow-degraded-platform`` on a non-POSIX platform -> REFUSE:
        exit ``GUARD_PLATFORM_REFUSE_EXIT`` (2), a LOUD structured warning naming
        each reduced guarantee, and the child is NEVER spawned.
  * (b) WITH ``--allow-degraded-platform`` -> PROCEED: the same loud warning is
        emitted, then ``run_guard`` IS invoked (the gate does not block).
  * (c) POSIX path UNCHANGED: the gate is inert -- no warning, no refusal, the flag
        is a no-op, ``run_guard`` is reached exactly as today.
  * (d) Redaction: a secret planted in the server argv never reaches the warning.
  * Liveness: a no-op platform gate would FAIL these (a real spawn / exit-0 would
    leak through), so each asserts the gate actually did something.

Exit-code matrix invariant: the refusal uses ``2`` (config/usage refusal, like
every other ``cli_guard`` config error), DISTINCT from confirmed-drift (``check``
exit ``1``) and the strict / frame-cap abort (``3``). These tests assert ``== 2``
explicitly so a future collision is caught.
"""

from __future__ import annotations

import mcp_warden.cli_guard as cli_guard
import mcp_warden.guard_lifecycle as guard_lifecycle
from mcp_warden.guard_lifecycle import (
    ALLOW_DEGRADED_PLATFORM_FLAG,
    DEGRADED_GUARANTEES,
    GUARD_PLATFORM_REFUSE_EXIT,
    is_degraded_platform,
    platform_refusal_message,
)


# --- exit-code matrix invariant ------------------------------------------------


def test_platform_refuse_exit_does_not_collide():
    # 2 == config/usage refusal (every cli_guard config error). It must NOT be the
    # confirmed-drift code (check exit 1) nor the strict / frame-cap abort (3).
    from mcp_warden.guard import GUARD_FATAL_EXIT
    from mcp_warden.guard_strict import GUARD_STRICT_EXIT

    assert GUARD_PLATFORM_REFUSE_EXIT == 2
    assert GUARD_PLATFORM_REFUSE_EXIT == GUARD_FATAL_EXIT  # shares the config-error code
    assert GUARD_PLATFORM_REFUSE_EXIT != 1  # never collides with confirmed-drift
    assert GUARD_PLATFORM_REFUSE_EXIT != GUARD_STRICT_EXIT  # never collides with strict (3)


# --- is_degraded_platform reads the os.name gate -------------------------------


def test_is_degraded_platform_tracks_is_posix(monkeypatch):
    # Liveness: prove the predicate actually inverts _IS_POSIX (a no-op returning a
    # constant would fail one of these two assertions).
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", True)
    assert is_degraded_platform() is False
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", False)
    assert is_degraded_platform() is True


# --- the structured warning names each reduced guarantee + redacts -------------


def test_warning_names_every_reduced_guarantee():
    msg = platform_refusal_message("node", ["server.js"])
    # Liveness: the warning must actually enumerate the §3.2 reductions, not be a
    # vague "experimental" line (a no-op message would miss these).
    assert "NON-POSIX" in msg
    assert "DEGRADED" in msg
    for guarantee in DEGRADED_GUARANTEES:
        assert guarantee in msg, f"warning dropped a named guarantee: {guarantee!r}"
    # process-group / signal / teardown are the three named reductions.
    assert "process group" in msg or "process-group" in msg
    assert "signal" in msg
    assert "teardown" in msg


def test_warning_redacts_server_args_keeps_executable():
    # The server argv may carry secrets (API keys passed as CLI args). The warning
    # echoes argv[0] only + a redacted arg count -- NEVER the args (binding: redaction).
    secret = "SUPERSECRET-IN-ARGS-12345"
    msg = platform_refusal_message("node", ["server.js", "--api-key", secret])
    assert secret not in msg, "secret in server args leaked into the platform warning"
    assert "server.js" not in msg, "server arg leaked into the platform warning"
    assert "node" in msg, "argv[0] (the executable) should be shown for debuggability"
    assert "redacted" in msg


def test_warning_no_args_shows_bare_command():
    # With no args there is nothing to redact: argv[0] alone, no "redacted" count.
    msg = platform_refusal_message("python", [])
    assert "server: python" in msg
    assert "redacted" not in msg


# --- CLI gate: refuse WITHOUT the flag -----------------------------------------


def _spy_run_guard(monkeypatch):
    """Install a run_guard spy that records invocation; return the call-log dict."""
    calls: dict = {"invoked": False, "command": None, "args": None}

    def _spy(command, args, cfg, **kw):  # noqa: ANN001
        calls["invoked"] = True
        calls["command"] = command
        calls["args"] = list(args)
        return 0  # pretend a clean child exit

    monkeypatch.setattr(cli_guard, "run_guard", _spy)
    return calls


def _invoke_guard(*args: str):
    from typer.testing import CliRunner

    from mcp_warden.cli import app

    return CliRunner().invoke(app, ["guard", *args])


def test_cli_refuses_on_nonposix_without_flag(monkeypatch):
    # Simulate a non-POSIX host. WITHOUT --allow-degraded-platform the guard must
    # REFUSE: exit 2, the loud warning on stderr/output, and run_guard NEVER called.
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", False)
    calls = _spy_run_guard(monkeypatch)

    result = _invoke_guard("node", "server.js")

    assert result.exit_code == GUARD_PLATFORM_REFUSE_EXIT, result.output
    # Liveness: the child path was NOT entered (a no-op gate would have spawned it).
    assert calls["invoked"] is False, "guard must NOT spawn the child when it refuses"
    # The loud warning + the refusal error are surfaced.
    assert "NON-POSIX" in result.output
    assert "refusing to run guard" in result.output


def test_cli_refusal_redacts_server_args(monkeypatch):
    # The refusal message on a non-POSIX host must not leak a secret passed as a
    # server arg (binding: redaction on the new message path).
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", False)
    _spy_run_guard(monkeypatch)
    secret = "PLANTED-CLI-SECRET-999"

    result = _invoke_guard("node", "server.js", "--token", secret)

    assert result.exit_code == GUARD_PLATFORM_REFUSE_EXIT
    assert secret not in result.output, "secret in server args leaked into refusal output"


# --- CLI gate: PROCEED with the flag -------------------------------------------


def test_cli_proceeds_on_nonposix_with_flag(monkeypatch):
    # WITH --allow-degraded-platform on a non-POSIX host: the warning is still
    # emitted, but the gate does NOT block -> run_guard IS invoked and its exit
    # code (0 here) propagates.
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", False)
    calls = _spy_run_guard(monkeypatch)

    result = _invoke_guard(ALLOW_DEGRADED_PLATFORM_FLAG, "node", "server.js")

    assert result.exit_code == 0, result.output
    # Liveness: the child path WAS entered (the flag let it proceed).
    assert calls["invoked"] is True, "guard must proceed to run_guard with the opt-in flag"
    assert calls["command"] == "node"
    assert calls["args"] == ["server.js"]
    # The loud warning is STILL emitted even when proceeding (no silent degradation).
    assert "NON-POSIX" in result.output
    # ...but the refusal error line is NOT printed when we proceed.
    assert "refusing to run guard" not in result.output


# --- CLI gate: POSIX path is byte-for-byte unchanged ---------------------------


def test_cli_posix_path_unchanged_no_warning_no_refusal(monkeypatch):
    # On POSIX the gate is inert: no warning, the flag is a no-op, run_guard is
    # reached exactly as today (liveness: a broken gate would refuse here).
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", True)
    calls = _spy_run_guard(monkeypatch)

    result = _invoke_guard("node", "server.js")

    assert result.exit_code == 0, result.output
    assert calls["invoked"] is True, "POSIX path must reach run_guard"
    assert "NON-POSIX" not in result.output, "POSIX path must emit NO platform warning"
    assert "refusing to run guard" not in result.output


def test_cli_posix_path_ignores_the_flag(monkeypatch):
    # The opt-in flag is a complete no-op on POSIX: same clean run, no warning.
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", True)
    calls = _spy_run_guard(monkeypatch)

    result = _invoke_guard(ALLOW_DEGRADED_PLATFORM_FLAG, "node", "server.js")

    assert result.exit_code == 0, result.output
    assert calls["invoked"] is True
    assert "NON-POSIX" not in result.output
