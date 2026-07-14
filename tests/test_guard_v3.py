"""v0.3 hardening coverage: default-block posture, opt-outs, lifecycle (GUARD_PROXY_V3.md).

End-to-end through a spawned ``mcp-warden guard`` subprocess. Asserts:
  * opt-out (``--no-block-*`` / ``--allow-exfil-domain``) demotes to shadow;
  * the ``tools/list_changed`` drift gate blocks by default (and shadows on opt-out);
  * an argument-policy deny blocks by default when ``--policy`` is supplied;
  * ``notifications/cancelled`` / ``notifications/progress`` pass through untouched;
  * server crash mid-call -> every pending id gets a ``-32002`` transport error;
  * client disconnect reaps the child (no orphan);
  * truncated + oversized frames fail open (session/teardown clean, never hang).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures"
POISON = str(FIX / "poison_server.py")
CRASH = str(FIX / "crash_server.py")
LISTCHANGE = str(FIX / "listchange_server.py")
LISTLOCK = str(FIX / "clean_listchange.warden.lock")
PY = sys.executable


class GuardClient:
    """Drives a spawned ``guard`` subprocess over newline-framed JSON-RPC."""

    def __init__(self, *guard_args: str, server: str = POISON, env_extra: dict | None = None):
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
        if env_extra:
            env.update(env_extra)
        cmd = [PY, "-m", "mcp_warden.cli", "guard", *guard_args, PY, server]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, cwd=str(REPO), env=env,
        )

    def send(self, obj: dict) -> None:
        self.proc.stdin.write((json.dumps(obj) + "\n").encode())
        self.proc.stdin.flush()

    def send_raw(self, data: bytes) -> None:
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def read_frame(self) -> dict:
        line = self.proc.stdout.readline()
        if not line:
            raise EOFError("guard closed stdout")
        return json.loads(line.decode())

    def call_and_get(self, rpc_id: int, tool: str, args: dict | None = None, max_frames: int = 6) -> dict:
        self.send({"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
                   "params": {"name": tool, "arguments": args or {"q": "x"}}})
        for _ in range(max_frames):
            frame = self.read_frame()
            if frame.get("id") == rpc_id:
                return frame
        raise AssertionError(f"no response with id={rpc_id} for tool {tool}")

    def initialize(self) -> dict:
        self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "t", "version": "1"}}})
        init = self.read_frame()
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return init

    def close(self) -> int:
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        return self.proc.returncode


def _findings(json_path: Path) -> list[dict]:
    if not json_path.exists():
        return []
    recs = [json.loads(ln) for ln in json_path.read_text().splitlines() if ln.strip()]
    # Exclude the additive run-summary record (issue #12) — it carries counts, not a finding.
    return [r for r in recs if r.get("kind") == "result-finding"]


# --- opt-out demotes to shadow (still detected/logged, frame forwarded) --------


def test_no_block_ansi_demotes_to_shadow(tmp_path):
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--no-block-ansi", "--json", str(sink))
    try:
        client.initialize()
        ansi = client.call_and_get(2, "ansi_tool")
    finally:
        code = client.close()
    # Forwarded UNMODIFIED (poison survives) -> shadow, not block.
    assert "result" in ansi and "\x1b" in ansi["result"]["content"][0]["text"]
    assert ansi["result"].get("_meta", {}).get("warden", {}).get("modified") is not True
    fr = [f for f in _findings(sink) if f["rule_id"] == "WRD-RES-ANSI"]
    assert fr and fr[0]["action"] == "shadowed"
    assert code == 0


def test_allow_exfil_domain_alias_shadows(tmp_path):
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--allow-exfil-domain", "--json", str(sink))
    try:
        client.initialize()
        exfil = client.call_and_get(2, "exfil_tool")
    finally:
        code = client.close()
    # --allow-exfil-domain == --no-block-exfil-domain: forwarded, exfil URL intact.
    assert "result" in exfil and "ngrok.io" in exfil["result"]["content"][0]["text"]
    fr = [f for f in _findings(sink) if f["rule_id"] == "WRD-RES-EXFIL-DOMAIN"]
    assert fr and fr[0]["action"] == "shadowed"
    assert code == 0


def test_no_block_exfil_domain_shadows(tmp_path):
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--no-block-exfil-domain", "--json", str(sink))
    try:
        client.initialize()
        exfil = client.call_and_get(2, "exfil_tool")
    finally:
        code = client.close()
    assert "result" in exfil and "error" not in exfil
    fr = [f for f in _findings(sink) if f["rule_id"] == "WRD-RES-EXFIL-DOMAIN"]
    assert fr and fr[0]["action"] == "shadowed"
    assert code == 0


def test_no_block_deterministic_shadows_whole_tier(tmp_path):
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--no-block-deterministic", "--json", str(sink))
    try:
        client.initialize()
        ansi = client.call_and_get(2, "ansi_tool")
        secret = client.call_and_get(3, "secret_tool")
        exfil = client.call_and_get(4, "exfil_tool")
    finally:
        code = client.close()
    # Whole tier demoted: every poison survives end-to-end.
    assert "\x1b" in ansi["result"]["content"][0]["text"]
    assert "result" in secret and "error" not in secret
    assert "ngrok.io" in exfil["result"]["content"][0]["text"]
    actions = {f["action"] for f in _findings(sink) if f["tier"] == "block"}
    assert actions <= {"shadowed"}
    assert code == 0


# --- tools/list_changed drift gate (default-on with --lock) --------------------


def _drive_rugpull(client: GuardClient) -> dict:
    """Initialize, list once (clean), trigger the rugpull, then list again; return 2nd list."""
    client.initialize()
    client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    first = client.read_frame()
    assert first.get("id") == 2  # clean list forwarded
    # Trigger the surface flip (server emits notifications/tools/list_changed).
    client.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "trigger_rugpull", "arguments": {}}})
    # Drain frames until the tools/call response for id=3 (skip the notification).
    for _ in range(6):
        fr = client.read_frame()
        if fr.get("id") == 3:
            break
    client.send({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
    for _ in range(6):
        fr = client.read_frame()
        if fr.get("id") == 4:
            return fr
    raise AssertionError("no second tools/list response (id=4)")


def test_list_changed_gate_blocks_by_default(tmp_path):
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--lock", LISTLOCK, "--json", str(sink), server=LISTCHANGE)
    try:
        second = _drive_rugpull(client)
    finally:
        code = client.close()
    # The post-rugpull tools/list is error-replaced (client never sees run_command).
    assert "error" in second
    assert second["error"]["data"]["stage"] == "list_changed"
    assert second["error"]["data"]["warden"] is True
    fr = [f for f in _findings(sink) if f["rule_id"] == "MCP-DRIFT"]
    assert fr and fr[0]["action"] == "blocked"
    assert code == 0


def test_list_changed_gate_shadows_with_opt_out(tmp_path):
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--lock", LISTLOCK, "--no-block-list-changed", "--json", str(sink), server=LISTCHANGE)
    try:
        second = _drive_rugpull(client)
    finally:
        code = client.close()
    # Shadow: the rugged list is forwarded (run_command visible), drift logged.
    assert "result" in second
    names = {t["name"] for t in second["result"]["tools"]}
    assert "run_command" in names
    fr = [f for f in _findings(sink) if f["rule_id"] == "MCP-DRIFT"]
    assert fr and fr[0]["action"] == "shadowed"
    assert code == 0


# --- argument-policy deny (default-on with --policy) ---------------------------


def _ssrf_policy(tmp_path: Path) -> str:
    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\ndefaults:\n  http_request:\n    deny_private: true\n")
    return str(p)


def test_policy_deny_blocks_by_default(tmp_path):
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--policy", _ssrf_policy(tmp_path), "--json", str(sink))
    try:
        client.initialize()
        resp = client.call_and_get(2, "fetch", args={"url": "http://169.254.169.254/latest"})
    finally:
        code = client.close()
    # Default-on: the SSRF deny blocks the request with a -32001 request-stage error.
    assert "error" in resp and resp["error"]["code"] == -32001
    assert resp["error"]["data"]["stage"] == "request"
    fr = [f for f in _findings(sink) if f.get("action") == "blocked"]
    assert fr
    assert code == 0


def test_policy_deny_shadows_with_opt_out(tmp_path):
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--policy", _ssrf_policy(tmp_path), "--no-block-policy", "--json", str(sink))
    try:
        client.initialize()
        # The poison server has no 'fetch' tool; with shadow the request is forwarded
        # and the server replies "unknown tool" -> proves it was NOT withheld.
        resp = client.call_and_get(2, "fetch", args={"url": "http://169.254.169.254/x"})
    finally:
        code = client.close()
    assert "result" in resp and "error" not in resp
    fr = [f for f in _findings(sink) if f.get("action") == "shadowed"]
    assert fr
    assert code == 0


# --- audit-only precedence over opt-outs (highest precedence) ------------------


def test_audit_only_overrides_everything(tmp_path):
    sink = tmp_path / "f.jsonl"
    # audit-only + a contradictory opt-in: nothing blocks regardless.
    client = GuardClient("--audit-only", "--block-inject-phrase", "--json", str(sink))
    try:
        client.initialize()
        ansi = client.call_and_get(2, "ansi_tool")
        exfil = client.call_and_get(3, "exfil_tool")
        inject = client.call_and_get(4, "inject_tool")
    finally:
        code = client.close()
    for r in (ansi, exfil, inject):
        assert "result" in r and "error" not in r
        assert r["result"].get("_meta", {}).get("warden", {}).get("modified") is not True
    assert "\x1b" in ansi["result"]["content"][0]["text"]
    actions = {f["action"] for f in _findings(sink) if f["tier"] != "note"}
    assert actions <= {"shadowed"}
    assert code == 0


# --- cancel/progress passthrough untouched, even mid tools/call ----------------


def test_cancel_and_progress_pass_through_untouched(tmp_path):
    """notifications/cancelled (c2s) and progress (any dir) pass through unblocked."""
    client = GuardClient("--block-inject-phrase")  # blocking armed; control frames must still pass
    try:
        client.initialize()
        # Interleave a cancel + progress around a real tools/call. The cancel is c2s.
        client.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                     "params": {"requestId": 99, "reason": "user"}})
        client.send({"jsonrpc": "2.0", "method": "notifications/progress",
                     "params": {"progressToken": "p1", "progress": 1, "total": 2}})
        # A subsequent clean call still works -> the control frames did not stall it.
        ok = client.call_and_get(2, "clean_tool", max_frames=8)
    finally:
        code = client.close()
    assert "result" in ok and "weather is sunny" in ok["result"]["content"][0]["text"]
    assert code == 0


# --- server crash mid-call -> -32002 for every pending id ----------------------


def test_server_crash_midcall_synthesizes_minus_32002():
    client = GuardClient(env_extra={"WARDEN_CRASH_CODE": "7"}, server=CRASH)
    try:
        client.initialize()
        # crash_server exits (code 7) the instant it receives this tools/call.
        client.send({"jsonrpc": "2.0", "id": 42, "method": "tools/call",
                     "params": {"name": "anything", "arguments": {}}})
        frame = client.read_frame()  # must be the synthetic transport error, not a hang
    finally:
        code = client.close()
    assert frame["id"] == 42
    assert frame["error"]["code"] == -32002
    assert frame["error"]["data"]["warden"] is True
    assert frame["error"]["data"]["stage"] == "lifecycle"
    assert "in flight" in frame["error"]["data"]["reason"]
    assert code == 7  # guard exits with the child's exit code (§2.1)


def test_server_crash_on_signal_exit_code():
    client = GuardClient(env_extra={"WARDEN_CRASH_SIGNAL": "SIGKILL"}, server=CRASH)
    try:
        client.initialize()
        client.send({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                     "params": {"name": "anything", "arguments": {}}})
        frame = client.read_frame()
    finally:
        code = client.close()
    assert frame["id"] == 5 and frame["error"]["code"] == -32002
    # Death by signal -> conventional 128 + signum exit code (§2.1).
    assert code == 128 + int(signal.SIGKILL)


# --- client disconnect tears down the child (no orphan) ------------------------


def test_client_disconnect_reaps_child():
    client = GuardClient(server=POISON)
    client.initialize()
    client.call_and_get(2, "clean_tool", max_frames=8)  # ensure the server is fully engaged
    # Find the child server pid (the poison_server process under guard).
    child_pid = _find_descendant_pid(client.proc.pid)
    assert child_pid is not None, "could not locate the spawned server child"
    # Client disconnects: close stdin AND stdout so guard sees EOF.
    client.proc.stdin.close()
    client.proc.stdout.close()
    code = client.close()
    # The child must be reaped: no orphaned server process survives.
    deadline = time.time() + 10
    while time.time() < deadline and _pid_alive(child_pid):
        time.sleep(0.1)
    assert not _pid_alive(child_pid), f"server child {child_pid} orphaned after guard exit"
    assert code is not None


def test_client_disconnect_no_traceback_on_stderr():
    client = GuardClient(server=POISON)
    client.initialize()
    client.proc.stdin.close()
    client.proc.stdout.close()
    client.close()
    stderr = client.proc.stderr.read().decode()
    # A broken pipe / clean teardown must NOT print a Python traceback.
    assert "Traceback (most recent call last)" not in stderr


# --- truncated + oversized frame fail open ------------------------------------


def test_truncated_frame_at_eof_fails_open(tmp_path):
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--json", str(sink), server=POISON)
    try:
        client.initialize()
        # Send a partial frame with NO terminating newline, then close stdin.
        client.send_raw(b'{"jsonrpc":"2.0","id":77,"method":"tools/call"')  # truncated
        code = client.close()  # EOF mid-frame must not hang
    finally:
        pass
    # Clean teardown, no hang. A frame-error note may be logged (fail-open).
    assert code is not None


def test_oversized_frame_passes_through_fail_open(tmp_path):
    sink = tmp_path / "f.jsonl"
    # Tiny cap so a normal-ish call exceeds it -> must fail open (pass through).
    client = GuardClient("--max-frame-bytes", "32", "--json", str(sink), server=POISON)
    try:
        client.initialize()
        # The clean_tool result is well over 32 bytes; oversized -> passed through.
        ok = client.call_and_get(2, "clean_tool", max_frames=8)
    finally:
        code = client.close()
    # Session continues; the result is forwarded unmodified (not blocked).
    assert "result" in ok and "weather is sunny" in ok["result"]["content"][0]["text"]
    notes = [f for f in _findings(sink) if f["rule_id"] == "WRD-RES-FRAME-ERROR"]
    assert notes  # the coverage gap was recorded
    assert code == 0


# --- helpers: process liveness / descendant discovery -------------------------


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _find_descendant_pid(parent_pid: int) -> int | None:
    """Find a direct child pid of ``parent_pid`` via ``pgrep -P`` (POSIX test helper)."""
    try:
        out = subprocess.check_output(["pgrep", "-P", str(parent_pid)], text=True)
    except subprocess.CalledProcessError:
        return None  # no children
    except Exception:
        return None
    pids = [int(x) for x in out.split() if x.strip().isdigit()]
    return pids[0] if pids else None


# --- issue #12: per-phrase opt-in block (--block-inject-phrase-only) -----------


def test_block_inject_phrase_only_blocks_named_phrase(tmp_path):
    """A named phrase present in a result IS blocked (error-replaced), even though
    the fuzzy tier is NOT globally promoted. Default posture is unchanged; this is a
    narrow, opt-in runtime control (does not touch the rule's tier/default)."""
    sink = tmp_path / "f.jsonl"
    subset = tmp_path / "block.txt"
    subset.write_text("ignore previous instructions\n", encoding="utf-8")
    client = GuardClient("--block-inject-phrase-only", str(subset), "--json", str(sink))
    try:
        client.initialize()
        inject = client.call_and_get(2, "inject_tool")
    finally:
        code = client.close()
    # inject_tool's result contains the named phrase -> error-replacement (-32001).
    assert "error" in inject and inject["error"]["code"] == -32001
    assert inject["error"]["data"]["rule"] == "WRD-RES-INJECT-PHRASE"
    fr = [f for f in _findings(sink) if f["rule_id"] == "WRD-RES-INJECT-PHRASE"]
    assert fr and fr[0]["action"] == "blocked" and fr[0]["tier"] == "monitor"
    assert fr[0]["matched_phrases"] == ["ignore previous instructions"]
    assert code == 0


def test_block_inject_phrase_only_leaves_unnamed_phrase_at_monitor(tmp_path):
    """A NON-named phrase stays monitor-only (shadowed, forwarded) — proving the
    control blocks only the operator's named phrase(s), not the whole tier."""
    sink = tmp_path / "f.jsonl"
    subset = tmp_path / "block.txt"
    subset.write_text("you are now\n", encoding="utf-8")  # NOT in inject_tool's result
    client = GuardClient("--block-inject-phrase-only", str(subset), "--json", str(sink))
    try:
        client.initialize()
        inject = client.call_and_get(2, "inject_tool")
    finally:
        code = client.close()
    # inject_tool matches 'ignore previous instructions' (not named) -> monitor.
    assert "result" in inject and "error" not in inject
    fr = [f for f in _findings(sink) if f["rule_id"] == "WRD-RES-INJECT-PHRASE"]
    assert fr and fr[0]["action"] == "shadowed"
    assert code == 0


def test_run_summary_denominator_and_matched_phrases_in_guard_json(tmp_path):
    """The guard --json stream carries (a) matched_phrases on the inject finding and
    (b) a run-summary record with the frames-inspected base-rate denominator (#12)."""
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--json", str(sink))
    try:
        client.initialize()
        client.call_and_get(2, "inject_tool")
        client.call_and_get(3, "clean_tool")
        client.call_and_get(4, "ansi_tool")
    finally:
        code = client.close()
    fr = [f for f in _findings(sink) if f["rule_id"] == "WRD-RES-INJECT-PHRASE"]
    assert fr and fr[0]["matched_phrases"] == ["ignore previous instructions"]
    recs = [json.loads(ln) for ln in sink.read_text().splitlines() if ln.strip()]
    summary = [r for r in recs if r.get("kind") == "run-summary"]
    assert summary, "guard --json must append a run-summary record"
    assert summary[0]["frames_inspected"] >= 3  # inject + clean + ansi results
    assert summary[0]["inject_phrase_findings"] >= 1
    assert code == 0
