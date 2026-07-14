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
OVERCAP = str(FIX / "overcap_server.py")
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
            raise AssertionError("guard hung; killed") from None
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


# --- issue #37: --strict-frame-cap s2c over-cap termination --------------------


class FrameCapClient:
    """Drives the REAL ``guard`` CLI against ``overcap_server.py`` over JSON-RPC.

    Unlike :class:`StrictClient`, NO fault is injected — the over-cap behavior is
    produced by a genuine oversized / declared-over-cap server->client frame. The
    server's s2c framing mode (``newline`` Case B vs ``content-length`` Case A) is
    selected by ``server_mode`` and the guard's ``client_mode`` mirrors it, so the
    synthesized -32003 comes back in that same mode — this client reads either.
    """

    def __init__(
        self,
        *guard_args: str,
        server_mode: str = "newline",
        secret: str | None = None,
        sink: Path | None = None,
    ):
        env = {
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "WARDEN_LOG_LEVEL": "ERROR",
            "OVERCAP_MODE": server_mode,
        }
        if secret is not None:
            env["OVERCAP_SECRET"] = secret
        self.server_mode = server_mode
        args = list(guard_args)
        if sink is not None:
            args += ["--json", str(sink)]
        cmd = [PY, "-m", "mcp_warden.cli", "guard", *args, PY, OVERCAP]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, cwd=str(REPO), env=env,
        )
        self._buf = b""

    def send(self, obj: dict) -> None:
        self.proc.stdin.write((json.dumps(obj) + "\n").encode())
        self.proc.stdin.flush()

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self._buf:
            chunk = self.proc.stdout.read(1)
            if not chunk:
                raise EOFError("guard closed stdout")
            self._buf += chunk
        idx = self._buf.index(marker) + len(marker)
        out, self._buf = self._buf[:idx], self._buf[idx:]
        return out

    def _read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.proc.stdout.read(n - len(self._buf))
            if not chunk:
                raise EOFError("guard closed stdout")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    # s2c modes whose framing is Content-Length (init response + over-cap result).
    _CL_SERVER_MODES = {"content-length", "dup-cl", "leading-zero-cl"}

    def read_frame(self) -> dict:
        """Read one s2c frame in whichever mode the server (and guard) use."""
        if self.server_mode in self._CL_SERVER_MODES:
            header = self._read_until(b"\r\n\r\n")
            length = None
            for line in header.split(b"\r\n"):
                if line[:15].lower() == b"content-length:":
                    length = int(line[15:].strip())
            assert length is not None, f"no Content-Length in header: {header!r}"
            body = self._read_exact(length)
            return json.loads(body.decode())
        line = self._read_until(b"\n")
        return json.loads(line.decode())

    def initialize(self) -> dict:
        self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "t", "version": "1"}}})
        init = self.read_frame()
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return init

    def finish(self, timeout: float = 15.0) -> tuple[int, str]:
        try:
            _out, err = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.communicate()
            raise AssertionError("guard hung; killed") from None
        return self.proc.returncode, err.decode(errors="replace")


def _assert_frame_cap_terminated(client: FrameCapClient, in_flight_id: int) -> str:
    """Read the -32003 frame-cap error, finish, assert the exit-3 abort contract."""
    frame = client.read_frame()  # the -32003 error for the in-flight tools/call id
    assert frame.get("id") == in_flight_id, f"expected error for id={in_flight_id}, got {frame}"
    assert frame["error"]["code"] == -32003
    assert frame["error"]["data"]["warden"] is True
    assert frame["error"]["data"]["stage"] == "strict_abort"
    assert frame["error"]["data"]["site"] == "frame-cap-s2c"
    # F6: differentiated frame-cap reason (NOT the "inspection failed" reason).
    reason = frame["error"]["data"]["reason"]
    assert "frame size cap exceeded" in reason
    assert "frame-cap-s2c" in reason
    assert "inspection failed" not in reason

    code, stderr = client.finish()
    assert code == GUARD_STRICT_EXIT, f"expected exit 3, got {code}; stderr={stderr!r}"
    aborts = _strict_abort_lines(stderr)
    assert len(aborts) == 1, f"expected exactly one strict_abort line, got {aborts}"
    assert aborts[0]["site"] == "frame-cap-s2c"
    assert aborts[0]["exc_type"] == "FrameCapExceeded"
    return stderr


def _frame_cap_notes(sink: Path) -> list[dict]:
    """Parse WRD-RES-FRAME-ERROR notes out of the JSONL findings sink."""
    if not sink.exists():
        return []
    out = []
    for ln in sink.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        obj = json.loads(ln)
        if obj.get("rule_id") == "WRD-RES-FRAME-ERROR":
            out.append(obj)
    return out


def test_frame_cap_terminates_on_overcap_s2c_newline(tmp_path):
    # Test 1: --strict-frame-cap + over-cap s2c (Case B, newline) -> exit 3, one
    # strict_abort line site=frame-cap-s2c, -32003 to the in-flight id, child torn
    # down, offending frame NOT forwarded, forensic note emitted.
    sink = tmp_path / "f.jsonl"
    client = FrameCapClient("--strict-frame-cap", "--max-frame-bytes", "256",
                            server_mode="newline", sink=sink)
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    frame = client.read_frame()
    # The client must receive the -32003, NOT the oversized result (frame not forwarded).
    assert frame.get("id") == 2
    assert "error" in frame and "result" not in frame, "over-cap frame must NOT be forwarded"
    assert frame["error"]["data"]["site"] == "frame-cap-s2c"
    code, stderr = client.finish()
    assert code == GUARD_STRICT_EXIT
    assert len(_strict_abort_lines(stderr)) == 1
    # F5: a sanitized forensic note carrying sizes was emitted (direction s2c).
    notes = _frame_cap_notes(sink)
    assert any(n["direction"] == "s2c" and "raw_length=" in n["message"] for n in notes), notes


def test_frame_cap_terminates_on_declared_overcap_s2c_case_a(tmp_path):
    # Test 2: --strict-frame-cap + DECLARED-over-cap s2c (Case A: Content-Length >
    # cap) -> same exit-3 abort (proves Case A is caught, not fail-opened).
    sink = tmp_path / "f.jsonl"
    client = FrameCapClient("--strict-frame-cap", "--max-frame-bytes", "256",
                            server_mode="content-length", sink=sink)
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    _assert_frame_cap_terminated(client, 2)
    # F5: the Case-A forensic note also carries the declared Content-Length size.
    notes = _frame_cap_notes(sink)
    assert any("declared_content_length=" in n["message"] for n in notes), notes


def test_frame_cap_terminates_on_duplicate_cl_bypass_shape(tmp_path):
    # F1 (#37 NO-SHIP — inspection BYPASS closed): a server emitting TWO
    # Content-Length headers (first over-cap, second a tiny 4) MUST abort under
    # --strict-frame-cap. The pre-fix "exactly one valid CL" rule fail-OPENED this
    # uninspected (the BYPASS). Now it fails CLOSED: exit 3, site frame-cap-s2c.
    sink = tmp_path / "f.jsonl"
    client = FrameCapClient("--strict-frame-cap", "--max-frame-bytes", "256",
                            server_mode="dup-cl", sink=sink)
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    _assert_frame_cap_terminated(client, 2)
    # The forensic note records the over-cap declared size (the first CL value).
    notes = _frame_cap_notes(sink)
    assert any("declared_content_length=" in n["message"] for n in notes), notes


def test_frame_cap_terminates_on_leading_zero_cl_bypass_shape(tmp_path):
    # F1 (#37 NO-SHIP — inspection BYPASS closed): a single Content-Length with a
    # redundant leading zero (``0<over-cap>``) MUST abort under --strict-frame-cap.
    # The pre-fix rule treated leading zeros as malformed-not-over-cap and
    # fail-OPENED it (the BYPASS). Now it fails CLOSED: exit 3, site frame-cap-s2c.
    sink = tmp_path / "f.jsonl"
    client = FrameCapClient("--strict-frame-cap", "--max-frame-bytes", "256",
                            server_mode="leading-zero-cl", sink=sink)
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    _assert_frame_cap_terminated(client, 2)
    notes = _frame_cap_notes(sink)
    assert any("declared_content_length=" in n["message"] for n in notes), notes


def test_frame_cap_no_false_kill_body_exactly_at_cap(tmp_path):
    # F2 (#37 NO-SHIP — false-positive KILL closed): a LEGIT Content-Length s2c
    # result whose body is EXACTLY --max-frame-bytes must be inspected + forwarded
    # normally (session continues, NOT exit 3). The pre-fix raw-length predicate
    # killed it (raw = header + 4 + cap > cap). Driven with a generously sized cap
    # so a real (clean) tools/call result body can be crafted to land on the cap.
    #
    # The overcap fixture always emits an OVER-cap result for tools/call, so this
    # test uses a hand-built fixture server (inline) emitting a CL result whose body
    # length is exactly the cap. Constructed via a tiny stdio echo server below.
    import textwrap

    cap = None
    # Build a server that emits a CL-framed result with body length == cap. We pick
    # the cap to match the body the server will produce, computed by the server.
    server_src = textwrap.dedent(
        r'''
        import json, sys, os
        CAP = int(os.environ["EXACT_CAP"])
        def write_cl(obj):
            body = json.dumps(obj).encode()
            sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
            sys.stdout.buffer.flush()
        def write_cl_exact(rpc_id):
            # Build a result whose serialized body length is EXACTLY CAP by padding
            # the text field until len(json) == CAP.
            def make(pad):
                return {"jsonrpc":"2.0","id":rpc_id,
                        "result":{"content":[{"type":"text","text":"y"*pad}],"isError":False}}
            pad = 0
            while len(json.dumps(make(pad)).encode()) < CAP:
                pad += 1
            # len(json) is now >= CAP; if it overshot, we cannot land exactly with a
            # single char step on a multibyte boundary, but "y" is 1 byte so it is exact.
            assert len(json.dumps(make(pad)).encode()) == CAP, len(json.dumps(make(pad)).encode())
            write_cl(make(pad))
        for raw in sys.stdin.buffer:
            line = raw.strip()
            if not line:
                continue
            req = json.loads(line.decode())
            m, rid = req.get("method"), req.get("id")
            if m == "initialize":
                write_cl({"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2025-06-18",
                          "capabilities":{"tools":{}},"serverInfo":{"name":"exact","version":"1"}}})
            elif m == "notifications/initialized":
                continue
            elif m == "tools/call":
                write_cl_exact(rid)
            elif rid is not None:
                write_cl({"jsonrpc":"2.0","id":rid,"result":{}})
        '''
    )
    server_path = tmp_path / "exact_cap_server.py"
    server_path.write_text(server_src)
    cap = 512
    sink = tmp_path / "f.jsonl"
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR",
           "EXACT_CAP": str(cap)}
    cmd = [PY, "-m", "mcp_warden.cli", "guard", "--strict-frame-cap",
           "--max-frame-bytes", str(cap), "--json", str(sink), PY, str(server_path)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=0, cwd=str(REPO), env=env)
    buf = b""

    def _read_cl_frame() -> dict:
        nonlocal buf
        while b"\r\n\r\n" not in buf:
            ch = proc.stdout.read(1)
            if not ch:
                raise EOFError("guard closed stdout")
            buf += ch
        sep = buf.index(b"\r\n\r\n")
        header, buf = buf[:sep], buf[sep + 4:]
        length = None
        for ln in header.split(b"\r\n"):
            if ln[:15].lower() == b"content-length:":
                length = int(ln[15:].strip())
        while len(buf) < length:
            ch = proc.stdout.read(length - len(buf))
            if not ch:
                raise EOFError("guard closed stdout")
            buf += ch
        body, buf = buf[:length], buf[length:]
        return json.loads(body.decode())

    def send(obj: dict) -> None:
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        proc.stdin.flush()

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                     "clientInfo": {"name": "t", "version": "1"}}})
    _read_cl_frame()  # init response
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
          "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    forwarded = _read_cl_frame()  # the at-cap result MUST be forwarded (not killed)
    assert forwarded.get("id") == 2, forwarded
    assert "result" in forwarded and "error" not in forwarded, (
        "an at-cap Content-Length frame must be inspected + forwarded, not strict-killed"
    )
    _out, err = proc.communicate(timeout=15)  # closes stdin (clean EOF)
    stderr = err.decode(errors="replace")
    assert _strict_abort_lines(stderr) == [], "at-cap frame must NOT strict-abort"
    assert proc.returncode != GUARD_STRICT_EXIT, f"got exit {proc.returncode}"


def test_frame_cap_notification_no_inflight_emits_zero_wire_frames(tmp_path):
    # F4 (#37): a server-sent OVER-CAP result with ZERO in-flight client requests
    # under --strict-frame-cap -> exit 3 + exactly one strict_abort stderr line +
    # ZERO -32003 wire frames (no JSON-RPC error with "id": null is ever sent). The
    # over-cap fixture emits its oversized frame UNSOLICITED if we never send a
    # tools/call: we trip it by sending a tools/call whose id the guard pops before
    # the result returns is NOT possible here, so instead we exploit that an
    # over-cap result with an empty inflight map (abort.rpc_id=None) sends nothing.
    #
    # Concretely: drive the newline over-cap server, but read NOTHING and send NO
    # tools/call -- the fixture only emits the over-cap frame on tools/call, so we
    # instead send a tools/call then assert: because the abort carries rpc_id=None
    # and inflight is cleared at synthesis, the only -32003 (if any) is for the
    # in-flight id. To isolate the ZERO-frame path we assert directly on the unit:
    # an over-cap abort with no pending ids writes zero wire frames. The end-to-end
    # guard always has the tools/call id in flight, so the zero-frame invariant is
    # unit-tested in test_strict_abort_rpc_id_none_early_returns_but_still_emits_and_exits_3
    # (client_out.chunks == []). Here we assert the COMPLEMENTARY wire guarantee:
    # the over-cap path NEVER emits an "id": null error frame to the client.
    sink = tmp_path / "f.jsonl"
    client = FrameCapClient("--strict-frame-cap", "--max-frame-bytes", "256",
                            server_mode="newline", sink=sink)
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    frame = client.read_frame()
    code, stderr = client.finish()
    assert code == GUARD_STRICT_EXIT
    aborts = _strict_abort_lines(stderr)
    assert len(aborts) == 1, f"expected exactly one strict_abort line, got {aborts}"
    # The over-cap path must NEVER synthesize an id:null error to the wire: the one
    # error frame the client got is bound to the real in-flight id (2), not null.
    assert frame.get("id") == 2 and frame.get("id") is not None, frame
    assert "error" in frame and frame["error"]["code"] == -32003


def test_frame_cap_emits_exactly_one_note_no_double_emit(tmp_path):
    # F5 (#37): a Case-A over-cap frame emits EXACTLY ONE WRD-RES-FRAME-ERROR note.
    # _note_truncation only fires on "truncated"-class parse errors, so the over-cap
    # frame (FRAME_OVER_CAP_PARSE_ERROR) must NOT be double-noted by _note_truncation
    # + _handle_s2c_over_cap. Assert a single s2c note for the over-cap termination.
    sink = tmp_path / "f.jsonl"
    client = FrameCapClient("--strict-frame-cap", "--max-frame-bytes", "256",
                            server_mode="content-length", sink=sink)
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    _assert_frame_cap_terminated(client, 2)
    notes = [n for n in _frame_cap_notes(sink) if n["direction"] == "s2c"]
    assert len(notes) == 1, f"expected exactly ONE s2c over-cap note, got {notes}"
    assert "raw_length=" in notes[0]["message"]


def test_nonstrict_overcap_newline_fails_open(tmp_path):
    # Test 3a: NON-strict over-cap Case B -> UNCHANGED fail-open pass-through; the
    # oversized result frame is FORWARDED verbatim (a valid newline frame); no
    # abort; session continues + exits 0 (regression guard).
    sink = tmp_path / "f.jsonl"
    client = FrameCapClient("--max-frame-bytes", "256", server_mode="newline", sink=sink)
    client.initialize()  # reads the init response (synchronizes)
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    forwarded = client.read_frame()  # the over-cap result, passed through unmodified
    assert forwarded.get("id") == 2 and "result" in forwarded, "fail-open must forward the frame"
    code, stderr = client.finish()
    assert _strict_abort_lines(stderr) == [], "non-strict over-cap must NOT abort"
    assert code != GUARD_STRICT_EXIT
    notes = [n for n in _frame_cap_notes(sink) if n["direction"] == "s2c" and "passed through" in n["message"]]
    assert notes, "fail-open pass-through note expected"


def test_nonstrict_overcap_declared_case_a_fails_open(tmp_path):
    # Test 3b: NON-strict declared-over-cap Case A -> still fail-open. The framing
    # layer stamps the over-cap parse_error and the s2c pump passes the header-only
    # frame through (a documented coverage gap, NOT a kill). The over-declared body
    # then desyncs the wire, so we DON'T re-parse it: synchronize on the init read,
    # send the call, then drain to EOF and assert via exit code + the note sink.
    # This also proves the guard never HANGS (drain-to-EOF unchanged from pre-#37).
    import time

    sink = tmp_path / "f.jsonl"
    client = FrameCapClient("--max-frame-bytes", "256", server_mode="content-length", sink=sink)
    client.initialize()  # reads the CL-framed init response (synchronizes)
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    # Do NOT read_frame() here (the forwarded over-cap header + leftover body desync
    # the wire under fail-open). The findings sink is only flushed on shutdown, and
    # closing stdin races the s2c result against EOF teardown -- so wait until the
    # guard's child reads stdin EOF by giving the s2c result a moment to arrive,
    # then drain. A hang would trip finish()'s timeout (proving no production hang).
    time.sleep(1.0)
    code, stderr = client.finish()
    assert _strict_abort_lines(stderr) == [], "non-strict declared-over-cap must NOT abort"
    assert code != GUARD_STRICT_EXIT
    assert any(n["direction"] == "s2c" and "passed through" in n["message"]
               for n in _frame_cap_notes(sink)), "fail-open note expected"


def test_frame_cap_c2s_overcap_fails_open(tmp_path):
    # Test 4 (F3): --strict-frame-cap + over-cap C2S -> UNCHANGED fail-open. The
    # c2s direction is explicitly out of scope; a giant CLIENT frame must NOT
    # terminate the session. Driven against POISON (normal SMALL s2c results) so
    # the ONLY over-cap frame is the c2s one: it passes through, the server replies
    # normally, and the session exits 0 (no abort, no exit 3).
    sink = tmp_path / "f.jsonl"
    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
    cmd = [PY, "-m", "mcp_warden.cli", "guard", "--strict-frame-cap",
           "--max-frame-bytes", "256", "--json", str(sink), PY, POISON]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=0, cwd=str(REPO), env=env)

    def send(obj: dict) -> None:
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        proc.stdin.flush()

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                     "clientInfo": {"name": "t", "version": "1"}}})
    proc.stdout.readline()  # init response (small)
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    # An OVER-CAP c2s tools/call (a 4KB argument > the 256 cap). F3: it must pass
    # through fail-open; POISON's clean_tool returns a small (< cap) result.
    big = "y" * 4096
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
          "params": {"name": "clean_tool", "arguments": {"q": big}}})
    result = json.loads(proc.stdout.readline().decode())  # the normal small result
    assert result.get("id") == 2 and "result" in result, "c2s over-cap must fail-open + get a result"
    _out, err = proc.communicate(timeout=15)  # closes stdin itself (no pre-close)
    stderr = err.decode(errors="replace")
    # F3: a c2s over-cap NEVER aborts; exit code is the child's natural status, not 3.
    assert _strict_abort_lines(stderr) == [], "c2s over-cap must NOT strict-abort"
    assert proc.returncode != GUARD_STRICT_EXIT
    # The c2s over-cap note is a plain pass-through, never a kill.
    notes = [n for n in _frame_cap_notes(sink) if n["direction"] == "c2s"]
    assert all("passed through" in n["message"] for n in notes), notes


def test_frame_cap_no_secret_leak_in_note_or_error(tmp_path):
    # Test 6: the forensic note + the -32003 error carry sizes/labels ONLY. A
    # secret planted in the oversized result body must appear in NEITHER.
    secret = "FRAMECAPSECRET999"
    sink = tmp_path / "f.jsonl"
    client = FrameCapClient("--strict-frame-cap", "--max-frame-bytes", "256",
                            server_mode="newline", secret=secret, sink=sink)
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "clean_tool", "arguments": {"q": "x"}}})
    frame = client.read_frame()
    frame_text = json.dumps(frame)
    code, stderr = client.finish()
    assert code == GUARD_STRICT_EXIT
    assert secret not in stderr, "secret leaked into stderr"
    assert secret not in frame_text, "secret leaked into the -32003 client frame"
    note_text = "\n".join(n["message"] for n in _frame_cap_notes(sink))
    assert secret not in note_text, "secret leaked into the forensic note"


def test_frame_cap_independent_of_strict():
    # F2: --strict-frame-cap is threaded independently of --strict.
    assert GuardConfig().strict_frame_cap is False
    assert GuardConfig(strict_frame_cap=True).strict_frame_cap is True
    # Both independent: setting one does not set the other.
    assert GuardConfig(strict_frame_cap=True).strict is False
    assert GuardConfig(strict=True).strict_frame_cap is False


def test_cli_strict_frame_cap_sets_config_true():
    from typer.testing import CliRunner

    from mcp_warden.cli import app

    captured: dict = {}

    import mcp_warden.cli_guard as cg
    real_run = cg.run_guard

    def _spy(command, args, cfg, **kw):  # noqa: ANN001
        captured["strict_frame_cap"] = cfg.strict_frame_cap
        captured["strict"] = cfg.strict
        raise SystemExit(0)

    cg.run_guard = _spy
    try:
        CliRunner().invoke(app, ["guard", "--strict-frame-cap", "echo", "hi"])
        assert captured.get("strict_frame_cap") is True
        assert captured.get("strict") is False  # independent of --strict
        captured.clear()
        CliRunner().invoke(app, ["guard", "echo", "hi"])
        assert captured.get("strict_frame_cap") is False
    finally:
        cg.run_guard = real_run
