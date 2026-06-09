"""``--strict`` fail-CLOSED coverage (issue #21, GUARD_PROXY_V3.md strict mode).

Every guard code path under ``--strict``:

  * Terminate sites (×4): each inspection entry point made to raise INSIDE the
    spawned guard child (via ``fault_guard_launcher.py``, which monkeypatches the
    function then runs the real CLI). Assert exit 3, exactly ONE structured
    ``strict_abort`` stderr line with the right ``site``, a ``-32003`` client
    error for the in-flight id (no hang), and the child reaped.
  * Negatives (no false-positive termination): truncated-at-EOF, over-cap,
    unparseable frame, a finding-sink that raises, normal clean EOF -> no abort.
  * Regression: default ``--no-strict`` fail-opens byte-identically.
  * Redaction (binding #4): a planted secret in the raising exception never
    reaches stderr OR the client error frame.
  * CLI threading: ``--strict`` -> ``GuardConfig.strict is True``.
  * Double-emission (binding #6): exactly one stderr line + exit 3.
  * BaseException non-swallow (binding #5): the abort is NOT caught by the pump's
    ``except Exception`` (it reaches exit 3, not the fail-open path).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import anyio

from mcp_warden.guard import GUARD_STRICT_EXIT, _find_strict_abort, _handle_strict_abort
from mcp_warden.guard_loop import GuardConfig, GuardState, StrictInspectionAbort

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures"
LAUNCHER = str(FIX / "fault_guard_launcher.py")
POISON = str(FIX / "poison_server.py")
LISTCHANGE = str(FIX / "listchange_server.py")
LISTLOCK = str(FIX / "clean_listchange.warden.lock")
PY = sys.executable


class StrictClient:
    """Drives a spawned fault-injecting ``guard`` over newline-framed JSON-RPC.

    Spawns ``fault_guard_launcher.py <site> <guard-args...> <server-argv...>`` so a
    chosen inspection function raises from inside the real guard child.
    """

    def __init__(self, site: str, *guard_args: str, server: str = POISON, secret: str | None = None):
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
        if secret is not None:
            env["FAULT_SECRET"] = secret
        cmd = [PY, LAUNCHER, site, *guard_args, PY, server]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, cwd=str(REPO), env=env,
        )

    def send(self, obj: dict) -> None:
        self.proc.stdin.write((json.dumps(obj) + "\n").encode())
        self.proc.stdin.flush()

    def read_frame(self) -> dict:
        line = self.proc.stdout.readline()
        if not line:
            raise EOFError("guard closed stdout")
        return json.loads(line.decode())

    def initialize(self) -> dict:
        self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "t", "version": "1"}}})
        init = self.read_frame()
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return init

    def finish(self, timeout: float = 15.0) -> tuple[int, str]:
        """Drain to EOF and return ``(exit_code, stderr_text)``.

        ``communicate`` closes stdin itself (signalling the guard's EOF teardown)
        then reads stdout/stderr to EOF — do NOT pre-close stdin or Python 3.11
        raises ``ValueError: I/O operation on closed file`` from ``communicate``.
        """
        try:
            _out, err = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            _out, err = self.proc.communicate()
            raise AssertionError("guard hung; killed")
        return self.proc.returncode, err.decode(errors="replace")


def _strict_abort_lines(stderr: str) -> list[dict]:
    """Parse every ``{"event":"strict_abort",...}`` JSON line out of stderr."""
    out = []
    for ln in stderr.splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if obj.get("event") == "strict_abort":
            out.append(obj)
    return out


# --- terminate sites (×4) ------------------------------------------------------


def _assert_terminated(client: StrictClient, in_flight_id: int, expect_site: str) -> str:
    """Read the client error frame, finish, and assert the strict-abort contract.

    Returns the stderr text for further (e.g. redaction) assertions.
    """
    frame = client.read_frame()  # the -32003 error for the in-flight id
    assert frame.get("id") == in_flight_id, f"expected error for id={in_flight_id}, got {frame}"
    assert frame["error"]["code"] == -32003
    assert frame["error"]["data"]["warden"] is True
    assert frame["error"]["data"]["stage"] == "strict_abort"
    assert frame["error"]["data"]["site"] == expect_site

    code, stderr = client.finish()
    assert code == GUARD_STRICT_EXIT, f"expected exit 3, got {code}; stderr={stderr!r}"

    aborts = _strict_abort_lines(stderr)
    assert len(aborts) == 1, f"expected exactly one strict_abort line, got {aborts}"
    assert aborts[0]["site"] == expect_site
    assert aborts[0]["rpc_id"] == in_flight_id
    return stderr


def test_terminate_result_inspect():
    client = StrictClient("inspect-result", "--strict", server=POISON)
    client.initialize()
    # tools/call whose RESULT inspection raises -> result-inspect abort.
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    _assert_terminated(client, 2, "result-inspect")


def test_terminate_request_policy(tmp_path):
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\ndefaults:\n  http_request:\n    deny_private: true\n")
    client = StrictClient("policy", "--strict", "--policy", str(policy), server=POISON)
    client.initialize()
    # tools/call REQUEST whose policy eval raises -> request-policy abort.
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "fetch", "arguments": {"url": "http://example/x"}}})
    _assert_terminated(client, 2, "request-policy")


def _drive_rugpull_until_second_list(client: StrictClient, second_list_id: int = 4) -> None:
    """Initialize, list (clean), trigger the rugpull, then send the 2nd tools/list."""
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    first = client.read_frame()
    assert first.get("id") == 2
    client.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "trigger_rugpull", "arguments": {}}})
    for _ in range(6):
        fr = client.read_frame()
        if fr.get("id") == 3:
            break
    client.send({"jsonrpc": "2.0", "id": second_list_id, "method": "tools/list"})


def test_terminate_list_gate_diverges():
    client = StrictClient("diverges", "--strict", "--lock", LISTLOCK, server=LISTCHANGE)
    _drive_rugpull_until_second_list(client, 4)
    _assert_terminated(client, 4, "list-gate")


def test_terminate_list_gate_hash_reraise():
    # binding #5: the nested _hash_live_tools error must RE-RAISE under strict
    # (not silently return no-divergence) and become a list-gate abort.
    client = StrictClient("hash", "--strict", "--lock", LISTLOCK, server=LISTCHANGE)
    _drive_rugpull_until_second_list(client, 4)
    _assert_terminated(client, 4, "list-gate")


# --- negatives: no false-positive termination under --strict -------------------


def _run_clean_session_strict(*guard_args: str, server: str = POISON) -> tuple[int, str]:
    """Run a clean strict session (no fault injected) and return (code, stderr)."""
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
    # site 'none' is unknown -> launcher would SystemExit; instead spawn the real
    # CLI directly for the no-fault negatives so nothing is monkeypatched.
    cmd = [PY, "-m", "mcp_warden.cli", "guard", *guard_args, PY, server]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0, cwd=str(REPO), env=env,
    )

    def send(obj: dict) -> None:
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        proc.stdin.flush()

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                     "clientInfo": {"name": "t", "version": "1"}}})
    proc.stdout.readline()
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    # A normal tools/call (clean result) -> inspected fine, no abort.
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
          "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    proc.stdout.readline()
    # communicate() closes stdin itself (EOF teardown); pre-closing it makes
    # Python 3.11 raise ValueError from communicate().
    _out, err = proc.communicate(timeout=15)
    return proc.returncode, err.decode(errors="replace")


def test_negative_clean_session_no_abort():
    code, stderr = _run_clean_session_strict("--strict")
    assert code == 0, f"clean strict session must exit 0, got {code}"
    assert _strict_abort_lines(stderr) == []


def test_negative_overcap_frame_fails_open_under_strict():
    # An over-cap frame is a documented resource limit, NOT an inspection error:
    # it must pass through (fail-open) even under --strict -> no abort.
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
    cmd = [PY, "-m", "mcp_warden.cli", "guard", "--strict", "--max-frame-bytes", "256", PY, POISON]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0, cwd=str(REPO), env=env,
    )
    big = "x" * 2048
    proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                             "clientInfo": {"name": big, "version": "1"}}}) + "\n").encode())
    proc.stdin.flush()
    _out, err = proc.communicate(timeout=15)  # closes stdin itself (no pre-close)
    stderr = err.decode(errors="replace")
    assert _strict_abort_lines(stderr) == [], "over-cap frame must NOT strict-abort"
    assert proc.returncode != GUARD_STRICT_EXIT


def test_negative_unparseable_frame_fails_open_under_strict():
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
    cmd = [PY, "-m", "mcp_warden.cli", "guard", "--strict", PY, POISON]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0, cwd=str(REPO), env=env,
    )
    proc.stdin.write(b"{ this is not valid json\n")
    proc.stdin.flush()
    _out, err = proc.communicate(timeout=15)  # closes stdin itself (no pre-close)
    stderr = err.decode(errors="replace")
    assert _strict_abort_lines(stderr) == [], "unparseable frame must NOT strict-abort"
    assert proc.returncode != GUARD_STRICT_EXIT


def test_negative_truncated_at_eof_fails_open_under_strict():
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
    cmd = [PY, "-m", "mcp_warden.cli", "guard", "--strict", PY, POISON]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0, cwd=str(REPO), env=env,
    )
    # Partial frame then EOF: a normal session end, NOT an inspection error.
    proc.stdin.write(b'{"jsonrpc": "2.0", "id": 1, "method": "init')
    proc.stdin.flush()
    _out, err = proc.communicate(timeout=15)  # closes stdin itself (no pre-close)
    stderr = err.decode(errors="replace")
    assert _strict_abort_lines(stderr) == [], "truncated-at-EOF must NOT strict-abort"
    assert proc.returncode != GUARD_STRICT_EXIT


# --- default --no-strict regression: byte-identical fail-open ------------------


def test_regression_result_inspect_fail_opens_without_strict():
    # Same injected fault, but NO --strict: the frame fail-opens (forwarded) and
    # the session exits cleanly (0) exactly as today.
    client = StrictClient("inspect-result", server=POISON)  # no --strict
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    frame = client.read_frame()
    assert frame.get("id") == 2
    assert "result" in frame, "fail-open must forward the original result frame"
    code, stderr = client.finish()
    assert code == 0, f"no-strict must exit 0, got {code}"
    assert _strict_abort_lines(stderr) == []


def test_regression_list_gate_hash_swallow_without_strict():
    # binding #5 non-strict invariant: the nested hash error stays SWALLOWED
    # (returns no-divergence) without --strict -> the rugged list is forwarded.
    client = StrictClient("hash", "--lock", LISTLOCK, server=LISTCHANGE)  # no --strict
    _drive_rugpull_until_second_list(client, 4)
    frame = client.read_frame()
    assert frame.get("id") == 4
    assert "result" in frame, "non-strict hash error must fail-open (forward the list)"
    code, stderr = client.finish()
    assert code == 0
    assert _strict_abort_lines(stderr) == []


# --- redaction (binding #4): planted secret must not leak ----------------------


def test_redaction_secret_absent_from_stderr_and_client_frame():
    secret = "SUPERSECRET123"
    client = StrictClient("inspect-result", "--strict", server=POISON, secret=secret)
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    frame = client.read_frame()
    assert frame["error"]["code"] == -32003
    frame_text = json.dumps(frame)
    code, stderr = client.finish()
    assert code == GUARD_STRICT_EXIT
    assert secret not in stderr, "secret leaked into stderr"
    assert secret not in frame_text, "secret leaked into the client error frame"
    # The sanitized exc_type is still present (proves we labeled the abort).
    aborts = _strict_abort_lines(stderr)
    assert aborts and aborts[0]["exc_type"] == "RuntimeError"


# --- CLI threading -------------------------------------------------------------


def test_cli_strict_sets_config_true():
    from typer.testing import CliRunner

    from mcp_warden.cli import app

    captured: dict = {}

    import mcp_warden.cli_guard as cg
    real_run = cg.run_guard

    def _spy(command, args, cfg, **kw):  # noqa: ANN001
        captured["strict"] = cfg.strict
        raise SystemExit(0)

    cg.run_guard = _spy
    try:
        CliRunner().invoke(app, ["guard", "--strict", "echo", "hi"])
        assert captured.get("strict") is True
        captured.clear()
        CliRunner().invoke(app, ["guard", "--no-strict", "echo", "hi"])
        assert captured.get("strict") is False
        captured.clear()
        CliRunner().invoke(app, ["guard", "echo", "hi"])
        assert captured.get("strict") is False
    finally:
        cg.run_guard = real_run


def test_config_default_strict_false():
    assert GuardConfig().strict is False
    assert GuardConfig(strict=True).strict is True


# --- double-emission (binding #6) ----------------------------------------------


def test_double_emission_single_stderr_line():
    # Two near-simultaneous tools/call results both raising: only ONE strict_abort
    # line + a single exit 3 (the strict_abort_fired flag dedups).
    client = StrictClient("inspect-result", "--strict", server=POISON)
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    client.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "y"}}})
    # Drain whatever the client gets; assert exactly one stderr abort line + exit 3.
    try:
        client.read_frame()
    except EOFError:
        pass
    code, stderr = client.finish()
    assert code == GUARD_STRICT_EXIT
    assert len(_strict_abort_lines(stderr)) == 1


# --- BaseException non-swallow (binding #5) ------------------------------------


def test_strict_abort_is_baseexception_not_exception():
    # It must NOT be catchable by `except Exception` (that's how the fail-open
    # handlers it's raised from would otherwise swallow it -> downgrade exit 3->2).
    assert issubclass(StrictInspectionAbort, BaseException)
    assert not issubclass(StrictInspectionAbort, Exception)
    abort = StrictInspectionAbort(site="result-inspect", tool="t", exc_type="RuntimeError", rpc_id=7)
    swallowed = False
    try:
        try:
            raise abort
        except Exception:  # noqa: BLE001 - intentionally proving it is NOT caught here
            swallowed = True
    except StrictInspectionAbort:
        pass
    assert swallowed is False, "StrictInspectionAbort was caught by except Exception"


def test_find_strict_abort_unwraps_exception_group():
    # The loop unwraps anyio's BaseExceptionGroup to find the abort.
    abort = StrictInspectionAbort(site="list-gate", tool="?", exc_type="ValueError", rpc_id=3)
    group = BaseExceptionGroup("tg", [ValueError("x"), abort])
    found = _find_strict_abort(group)
    assert found is abort
    nested = BaseExceptionGroup("outer", [BaseExceptionGroup("inner", [abort])])
    assert _find_strict_abort(nested) is abort
    assert _find_strict_abort(BaseExceptionGroup("g", [ValueError("x")])) is None


# --- rpc_id=None abort path (audit B2) -----------------------------------------


class _CollectSend:
    """Minimal client-facing send stream: collects every ``send``-ed bytes chunk."""

    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    async def send(self, data: bytes) -> None:
        self.chunks.append(data)


class _ExitedProc:
    """Fake already-exited child so ``teardown_child`` early-returns (returncode set)."""

    def __init__(self) -> None:
        self.returncode = 0  # already exited -> teardown_child is a no-op


def test_strict_abort_rpc_id_none_early_returns_but_still_emits_and_exits_3():
    # B2: a strict abort on a frame with NO JSON-RPC id (a notification, so
    # abort.rpc_id is None) and an EMPTY inflight map yields empty pending_ids.
    # Contract: synthesize_strict_abort EARLY-RETURNS (no -32003 client frame is
    # written), the structured stderr line STILL emits with "rpc_id": null, and
    # _handle_strict_abort still returns exit 3.
    state = GuardState(config=GuardConfig())  # inflight is empty by default
    assert not state.inflight, "precondition: no in-flight ids -> empty pending_ids"
    client_out = _CollectSend()
    client_err = _CollectSend()
    abort = StrictInspectionAbort(
        site="request-policy", tool="?", exc_type="RuntimeError", rpc_id=None
    )

    async def _run() -> int:
        return await _handle_strict_abort(
            state, _ExitedProc(), client_out, client_err, "newline", abort
        )

    code = anyio.run(_run)

    # Exits 3 even with no in-flight id to resolve.
    assert code == GUARD_STRICT_EXIT
    # synthesize_strict_abort early-returned: NO -32003 client frame was written
    # (the early-return path on empty pending_ids is exercised).
    assert client_out.chunks == [], "no client frame expected when pending_ids is empty"
    # The structured stderr line still emits, with rpc_id explicitly null.
    assert len(client_err.chunks) == 1, "exactly one structured stderr line expected"
    obj = json.loads(client_err.chunks[0].decode().strip())
    assert obj["event"] == "strict_abort"
    assert obj["site"] == "request-policy"
    assert obj["rpc_id"] is None, "rpc_id must serialize to null"
    # The dedup flag fired (single-emission guarantee).
    assert state.strict_abort_fired is True
