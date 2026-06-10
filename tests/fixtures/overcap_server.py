"""Over-cap frame fixture MCP server (raw stdio) — for issue #37 strict-frame-cap.

A minimal hand-rolled JSON-RPC stdio server (NO MCP SDK) so a single ``tools/call``
result can be emitted as a deliberately OVER-``--max-frame-bytes`` server->client
frame, in either of the two over-cap shapes the guard's s2c pump must catch:

  * ``OVERCAP_MODE=newline`` (default) — Case B: a newline-framed result whose
    body is padded well past the cap. The whole body lands in ``frame.raw`` so the
    pump's ``len(frame.raw) > cap`` check fires.
  * ``OVERCAP_MODE=content-length`` — Case A: a Content-Length-framed result that
    DECLARES ``Content-Length`` greater than the cap (a real body of that size is
    written too, but the framing layer rejects on the declared length before
    reading it). This exercises ``FRAME_OVER_CAP_PARSE_ERROR``.
  * ``OVERCAP_MODE=dup-cl`` — Case A BYPASS shape (issue #37 FIX 1): two
    ``Content-Length`` headers, the first OVER cap and the second a tiny ``4``.
    The pre-fix "exactly one valid Content-Length" rule fail-OPENED this
    (uninspected pass-through). With the fail-CLOSED marker it must abort.
  * ``OVERCAP_MODE=leading-zero-cl`` — Case A BYPASS shape (issue #37 FIX 1): a
    single ``Content-Length`` with a redundant leading zero (``0<over-cap>``). The
    pre-fix rule treated leading zeros as "malformed, not over-cap" and fail-OPENED
    it; the fail-CLOSED marker must abort.

Env:
    OVERCAP_MODE             -> ``newline`` | ``content-length`` | ``dup-cl`` |
                                ``leading-zero-cl`` (default newline).
    OVERCAP_DECLARED_LENGTH  -> the Content-Length value to DECLARE in Case A
                                (default 100000); set it above the guard's cap.
    OVERCAP_SECRET           -> if set, embedded in the oversized result body so a
                                test can assert it never leaks into the forensic
                                note or the -32003 client frame.

The client (the guard) speaks newline framing on the c2s direction; this server
reads newline-delimited requests on stdin regardless of its s2c output mode.

Run directly: ``python overcap_server.py``.
"""

from __future__ import annotations

import json
import os
import sys

_MODE = os.environ.get("OVERCAP_MODE", "newline")
_DECLARED = int(os.environ.get("OVERCAP_DECLARED_LENGTH", "100000"))
_SECRET = os.environ.get("OVERCAP_SECRET", "")

# Modes whose s2c stream is Content-Length framed (so the init response below
# must ALSO be CL-framed, or the guard's FrameReader latches newline mode first).
_CL_MODES = {"content-length", "dup-cl", "leading-zero-cl"}


def _write_framed(obj: dict) -> None:
    """Emit a JSON-RPC object in the configured s2c framing mode.

    The s2c stream mode is FIXED from the first frame's bytes, so EVERY frame
    (including the initialize response) must use the same mode the over-cap result
    will use — otherwise the guard's FrameReader latches newline mode on the init
    response and never sees Content-Length framing for Case A.
    """
    body = json.dumps(obj).encode()
    if _MODE in _CL_MODES:
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        sys.stdout.buffer.write(header + body)
    else:
        sys.stdout.buffer.write(body + b"\n")
    sys.stdout.buffer.flush()


def _write_oversized_newline(rpc_id: object) -> None:
    """Emit a newline-framed tools/call result padded past any sane cap (Case B)."""
    padding = "x" * 4096
    text = f"{_SECRET} oversized result {padding}".strip()
    obj = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    }
    data = (json.dumps(obj) + "\n").encode()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def _write_declared_overcap(rpc_id: object) -> None:
    """Emit a Content-Length-framed result that DECLARES a length > cap (Case A).

    The declared ``Content-Length`` is OVERCAP_DECLARED_LENGTH; a real body of that
    exact length is written so the frame is well-formed on the wire. The guard's
    framing layer rejects on the declared length (FRAME_OVER_CAP_PARSE_ERROR) before
    reading the body, so the body content is irrelevant to the abort path.
    """
    base = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"content": [{"type": "text", "text": f"{_SECRET} declared-overcap"}], "isError": False},
        }
    )
    body = base.encode()
    if len(body) < _DECLARED:
        body = body + b" " * (_DECLARED - len(body))
    header = f"Content-Length: {_DECLARED}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header + body)
    sys.stdout.buffer.flush()


def _write_dup_cl_overcap(_rpc_id: object) -> None:
    """Emit a header with TWO Content-Length values: an over-cap one then a tiny 4.

    Issue #37 FIX 1 BYPASS shape. The guard's framing layer never reads a body for
    a declared-over-cap header (it stamps FRAME_OVER_CAP_PARSE_ERROR on the header
    block), so only the header block is written. A 4-byte ``body`` follows merely so
    the bytes after the blank line are well-formed; it is never consumed by the
    guard under the fail-CLOSED abort and the session terminates regardless.
    """
    header = f"Content-Length: {_DECLARED}\r\nContent-Length: 4\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header + b"null")
    sys.stdout.buffer.flush()


def _write_leading_zero_cl_overcap(_rpc_id: object) -> None:
    """Emit a single Content-Length with a redundant leading zero (``0<over-cap>``).

    Issue #37 FIX 1 BYPASS shape. As with the duplicate case, the body is never read
    by the guard on the over-cap parse path, so only the header block is written.
    """
    header = f"Content-Length: 0{_DECLARED}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header + b"null")
    sys.stdout.buffer.flush()


def _emit_result(rpc_id: object) -> None:
    """Emit the over-cap tools/call result in the configured mode."""
    if _MODE == "content-length":
        _write_declared_overcap(rpc_id)
    elif _MODE == "dup-cl":
        _write_dup_cl_overcap(rpc_id)
    elif _MODE == "leading-zero-cl":
        _write_leading_zero_cl_overcap(rpc_id)
    else:
        _write_oversized_newline(rpc_id)


def main() -> None:
    """Serve a tiny JSON-RPC stdio loop over newline-framed client requests."""
    for raw in sys.stdin.buffer:
        line = raw.strip()
        if not line:
            continue
        try:
            req = json.loads(line.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        method = req.get("method")
        rpc_id = req.get("id")
        if method == "initialize":
            _write_framed(
                {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "overcap-fixture", "version": "1"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue  # notification: no response
        elif method == "tools/call":
            _emit_result(rpc_id)  # the OVER-CAP server->client frame
        elif rpc_id is not None:
            # Any other request gets a minimal empty result so the client never hangs.
            _write_framed({"jsonrpc": "2.0", "id": rpc_id, "result": {}})


if __name__ == "__main__":
    main()
