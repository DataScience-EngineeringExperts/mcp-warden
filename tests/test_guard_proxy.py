"""Headline acceptance test: a REAL tools/call through guard (not mocked).

client -> `mcp-warden guard` (spawned subprocess) -> poison fixture server.

Asserts the v0.2 wire contract (GUARD_PROXY.md §5, §7):
  (a) shadow-default logs all four findings and blocks nothing;
  (b) --block-ansi --block-exfil-domain redacts ANSI in place (_meta.warden.modified)
      and turns the exfil result into a -32001 error;
  (c) WRD-RES-INJECT-PHRASE stays monitor-only (never blocks);
  (d) a forced framing error passes through and the session survives.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
POISON = str(REPO / "tests" / "fixtures" / "poison_server.py")
PY = sys.executable


class GuardClient:
    """Drives a spawned `guard` subprocess over newline-framed JSON-RPC."""

    def __init__(self, *guard_args: str, env_extra: dict | None = None):
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "WARDEN_LOG_LEVEL": "ERROR"}
        if env_extra:
            env.update(env_extra)
        cmd = [PY, "-m", "mcp_warden.cli", "guard", *guard_args, PY, POISON]
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            cwd=str(REPO),
            env=env,
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

    def call_and_get(self, rpc_id: int, tool: str, max_frames: int = 6) -> dict:
        """Send a tools/call and return the frame whose id matches (skipping notifications)."""
        self.send({"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call", "params": {"name": tool, "arguments": {"q": "x"}}})
        for _ in range(max_frames):
            frame = self.read_frame()
            if frame.get("id") == rpc_id:
                return frame
        raise AssertionError(f"no response with id={rpc_id} for tool {tool}")

    def initialize(self) -> dict:
        self.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
            }
        )
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
    return [json.loads(ln) for ln in json_path.read_text().splitlines() if ln.strip()]


def test_acceptance_shadow_default_detects_all_blocks_nothing(tmp_path):
    """(a) shadow-default: all four findings logged; nothing blocked/modified."""
    sink = tmp_path / "findings.jsonl"
    client = GuardClient("--json", str(sink))
    try:
        init = client.initialize()
        assert "result" in init  # initialize forwarded untouched

        ansi = client.call_and_get(2, "ansi_tool")
        secret = client.call_and_get(3, "secret_tool")
        exfil = client.call_and_get(4, "exfil_tool")
        inject = client.call_and_get(5, "inject_tool")
    finally:
        code = client.close()

    # Every response is a passed-through RESULT (no -32001, no _meta modification).
    for r in (ansi, secret, exfil, inject):
        assert "result" in r and "error" not in r
        assert r["result"].get("_meta", {}).get("warden", {}).get("modified") is not True

    # The poison survives end-to-end (proves pass-through, not block).
    assert "\x1b" in ansi["result"]["content"][0]["text"]
    assert "ngrok.io" in exfil["result"]["content"][0]["text"]

    rules = {f["rule_id"] for f in _findings(sink)}
    assert {"WRD-RES-ANSI", "WRD-RES-SECRET-ECHO", "WRD-RES-EXFIL-DOMAIN", "WRD-RES-INJECT-PHRASE"} <= rules
    # Nothing was blocked or modified in shadow mode.
    actions = {f["action"] for f in _findings(sink) if f["tier"] != "note"}
    assert actions <= {"shadowed"}
    assert code == 0


def test_acceptance_block_ansi_and_exfil(tmp_path):
    """(b) --block-ansi redacts in place; --block-exfil-domain error-replaces. (c) inject stays monitor."""
    client = GuardClient("--block-ansi", "--block-exfil-domain")
    try:
        client.initialize()
        ansi = client.call_and_get(2, "ansi_tool")
        exfil = client.call_and_get(3, "exfil_tool")
        secret = client.call_and_get(4, "secret_tool")
        inject = client.call_and_get(5, "inject_tool")
    finally:
        code = client.close()

    # ANSI -> redacted-content in place.
    assert "result" in ansi
    meta = ansi["result"]["_meta"]["warden"]
    assert meta["modified"] is True and "WRD-RES-ANSI" in meta["rules"]
    assert "\x1b" not in ansi["result"]["content"][0]["text"]

    # EXFIL -> error-replacement (-32001).
    assert "error" in exfil
    assert exfil["error"]["code"] == -32001
    assert exfil["error"]["data"]["warden"] is True
    assert exfil["error"]["data"]["stage"] == "response"
    assert exfil["error"]["data"]["rule"] == "WRD-RES-EXFIL-DOMAIN"
    assert exfil["error"]["data"]["tool"] == "exfil_tool"

    # SECRET-ECHO + INJECT-PHRASE not blocked here -> pass through (c: inject monitor-only).
    assert "result" in secret and "error" not in secret
    assert "result" in inject and "error" not in inject
    assert code == 0


def test_acceptance_inject_never_blocks_even_in_block_run(tmp_path):
    """(c) Even with deterministic blocking on, INJECT-PHRASE is detected but never blocked."""
    sink = tmp_path / "f.jsonl"
    client = GuardClient("--block-deterministic", "--json", str(sink))
    try:
        client.initialize()
        inject = client.call_and_get(2, "inject_tool")
    finally:
        code = client.close()
    # The injection result is NOT blocked (still a passed-through result).
    assert "result" in inject and "error" not in inject
    fr = [f for f in _findings(sink) if f["rule_id"] == "WRD-RES-INJECT-PHRASE"]
    assert fr and fr[0]["action"] == "shadowed" and fr[0]["tier"] == "monitor"
    assert code == 0


def test_acceptance_forced_framing_error_passes_through_session_survives(tmp_path):
    """(d) A malformed frame passes through; a subsequent tools/call still works."""
    client = GuardClient()
    try:
        client.initialize()
        client.send_raw(b"this is not valid json at all\n")  # forced framing/parse error
        # The session must survive: a subsequent well-formed call still returns.
        result = client.call_and_get(7, "clean_tool", max_frames=8)
    finally:
        code = client.close()
    assert "result" in result
    assert "weather is sunny" in result["result"]["content"][0]["text"]
    assert code == 0  # guard exited cleanly; the framing error never killed the session
