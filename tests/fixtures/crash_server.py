"""CRASH-MID-CALL fixture server (raw stdio JSON-RPC) — for v0.3 lifecycle tests.

A minimal newline-framed JSON-RPC server that:
  * answers ``initialize`` normally,
  * on the FIRST ``tools/call`` it receives, exits IMMEDIATELY (no response),
    with an exit code chosen by the ``WARDEN_CRASH_CODE`` env var (default 7) —
    or, if ``WARDEN_CRASH_SIGNAL`` is set, kills itself with that signal.

This drives GUARD_PROXY_V3.md §2.1: guard must synthesize a ``-32002`` transport
error for the pending ``tools/call`` id and exit with the child's status. Run
directly: ``python crash_server.py``.
"""

from __future__ import annotations

import json
import os
import signal
import sys


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    crash_code = int(os.environ.get("WARDEN_CRASH_CODE", "7"))
    crash_signal = os.environ.get("WARDEN_CRASH_SIGNAL")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        if method == "initialize":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "crash-fixture", "version": "1"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/call":
            # Crash mid-call: exit/kill WITHOUT sending a response for this id.
            sys.stdout.flush()
            if crash_signal:
                os.kill(os.getpid(), getattr(signal, crash_signal))
            os._exit(crash_code)
        else:
            # Unknown request: minimal empty result so the session can proceed.
            if msg.get("id") is not None:
                _send({"jsonrpc": "2.0", "id": msg.get("id"), "result": {}})


if __name__ == "__main__":
    main()
