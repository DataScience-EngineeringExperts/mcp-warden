"""Unit tests for the stdio framers (GUARD_PROXY.md §2.4)."""

from __future__ import annotations

import json

from mcp_warden.framing import (
    MODE_CONTENT_LENGTH,
    MODE_NEWLINE,
    FrameReader,
)


class _Feeder:
    """An async receive() that yields preset chunks, then EOF (b'')."""

    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)

    async def receive(self) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


async def _read_all(reader: FrameReader) -> list:
    frames = []
    while True:
        f = await reader.read_frame()
        if f is None:
            break
        frames.append(f)
    return frames


async def test_newline_framing_detects_and_reads():
    a = json.dumps({"id": 1, "method": "initialize"}).encode()
    b = json.dumps({"id": 2, "method": "tools/call"}).encode()
    reader = FrameReader(_Feeder([a + b"\n", b + b"\n"]).receive, max_frame_bytes=1 << 20)
    frames = await _read_all(reader)
    assert reader.mode == MODE_NEWLINE
    assert [f.json["id"] for f in frames] == [1, 2]
    # Pass-through preserves original bytes (incl. the newline).
    assert frames[0].raw == a + b"\n"


async def test_newline_framing_split_across_chunks():
    obj = json.dumps({"id": 5, "method": "ping"}).encode()
    # Split a single frame across three receive() calls.
    reader = FrameReader(_Feeder([obj[:4], obj[4:10], obj[10:] + b"\n"]).receive, max_frame_bytes=1 << 20)
    frames = await _read_all(reader)
    assert len(frames) == 1 and frames[0].json["id"] == 5


async def test_content_length_framing():
    obj = json.dumps({"id": 3, "method": "tools/list"}).encode()
    wire = f"Content-Length: {len(obj)}\r\n\r\n".encode() + obj
    reader = FrameReader(_Feeder([wire]).receive, max_frame_bytes=1 << 20)
    frames = await _read_all(reader)
    assert reader.mode == MODE_CONTENT_LENGTH
    assert len(frames) == 1 and frames[0].json["id"] == 3
    assert frames[0].raw == wire  # original bytes preserved


async def test_content_length_split_across_chunks():
    obj = json.dumps({"id": 4}).encode()
    header = f"Content-Length: {len(obj)}\r\n\r\n".encode()
    reader = FrameReader(_Feeder([header[:10], header[10:] + obj[:2], obj[2:]]).receive, max_frame_bytes=1 << 20)
    frames = await _read_all(reader)
    assert len(frames) == 1 and frames[0].json["id"] == 4


async def test_malformed_json_returns_frame_with_parse_error():
    reader = FrameReader(_Feeder([b"not json at all\n"]).receive, max_frame_bytes=1 << 20)
    f = await reader.read_frame()
    assert f is not None and f.json is None and f.parse_error
    assert f.raw == b"not json at all\n"  # still forwardable (fail-open)
