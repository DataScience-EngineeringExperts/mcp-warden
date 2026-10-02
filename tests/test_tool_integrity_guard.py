"""A v4 runtime list gate blocks metadata-only changes before client ingestion."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from mcp_warden.capture import capture_surface_sync
from mcp_warden.lockfile import build_lock, write_lock


@pytest.mark.parametrize("mutation", [
    {"annotations": {"destructiveHint": True}},
    {"outputSchema": {"type": "object", "properties": {"value": {"type": "number"}}}},
])
def test_real_guard_blocks_metadata_change(tmp_path, mutation):
    fixture = Path(__file__).parent / "fixtures" / "tool_integrity_server.py"
    declaration = tmp_path / "definition.json"
    tool = {"name": "read_record", "inputSchema": {"type": "object"},
            "annotations": {"destructiveHint": False},
            "outputSchema": {"type": "object", "properties": {"value": {"type": "string"}}}}
    declaration.write_text(json.dumps(tool))
    argv = [str(fixture), str(declaration)]
    lock = tmp_path / "warden.lock"
    write_lock(build_lock(capture_surface_sync(sys.executable, argv), []), lock)
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_warden.cli", "guard", "--lock", str(lock), sys.executable, *argv],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        env={**os.environ, "WARDEN_LOG_LEVEL": "ERROR"},
    )
    frames = queue.Queue()

    def read_frames():
        for line in iter(proc.stdout.readline, b""):
            frames.put(line)
        frames.put(b"")

    reader = threading.Thread(target=read_frames, daemon=True)
    reader.start()

    def send(frame):
        proc.stdin.write((json.dumps(frame) + "\n").encode())
        proc.stdin.flush()

    def receive():
        return json.loads(frames.get(timeout=30))

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})
        assert receive()["id"] == 1
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert "result" in receive()
        declaration.write_text(json.dumps(tool | mutation))
        send({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        changed = receive()
        assert changed["id"] == 3
        assert changed["error"]["data"]["stage"] == "list_changed"
        assert "result" not in changed
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()
        reader.join(timeout=1)
    assert proc.returncode == 0
