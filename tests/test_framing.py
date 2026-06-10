"""Unit tests for the stdio framers (GUARD_PROXY.md §2.4)."""

from __future__ import annotations

import json

from mcp_warden.framing import (
    FRAME_OVER_CAP_PARSE_ERROR,
    MODE_CONTENT_LENGTH,
    MODE_NEWLINE,
    FrameReader,
    _declared_length_over_cap,
    _parse_content_length,
    declared_over_cap_value,
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


# --- issue #37: declared-over-cap detection (Case A) ---------------------------


def test_declared_length_over_cap_true_for_single_valid_over_cap():
    # A single valid digit Content-Length strictly > cap.
    assert _declared_length_over_cap(b"Content-Length: 500", 256) is True
    assert _declared_length_over_cap(b"content-length: 257", 256) is True  # case-insensitive


def test_declared_length_over_cap_false_for_at_or_under_cap():
    assert _declared_length_over_cap(b"Content-Length: 256", 256) is False  # equal: not over
    assert _declared_length_over_cap(b"Content-Length: 10", 256) is False


def test_declared_length_over_cap_false_for_missing_or_nondigit():
    # Missing header.
    assert _declared_length_over_cap(b"X-Other: 1", 256) is False
    # Non-digit value (sign / whitespace / letters) is not a numeric over-cap candidate.
    assert _declared_length_over_cap(b"Content-Length: -500", 256) is False
    assert _declared_length_over_cap(b"Content-Length: 5x0", 256) is False


def test_declared_length_over_cap_fail_closed_on_bypass_shapes():
    # FIX 1 (#37 NO-SHIP): the over-cap marker must be FAIL-CLOSED so a malicious
    # server cannot evade inspection with a duplicate or leading-zero Content-Length.
    # Duplicate where the FIRST is over-cap (old "exactly one" rule fail-OPENED this).
    assert _declared_length_over_cap(b"Content-Length: 100000\r\nContent-Length: 4", 256) is True
    # Duplicate where the SECOND is over-cap.
    assert _declared_length_over_cap(b"Content-Length: 4\r\nContent-Length: 100000", 256) is True
    # Leading-zero over-cap value (old rule treated it as malformed -> fail-open).
    assert _declared_length_over_cap(b"Content-Length: 0100000", 256) is True
    # Two values BOTH over cap -> still True.
    assert _declared_length_over_cap(b"Content-Length: 500\r\nContent-Length: 600", 256) is True
    # A duplicate where NEITHER exceeds the cap stays False (nothing over-cap).
    assert _declared_length_over_cap(b"Content-Length: 4\r\nContent-Length: 10", 256) is False


def test_declared_over_cap_value_returns_first_over_cap_size():
    # FIX 3 (#37): the diagnostic helper returns the first over-cap declared value
    # (same lenient scan as the marker) so the forensic note size cannot disagree.
    assert declared_over_cap_value(b"Content-Length: 100000", 256) == 100000
    assert declared_over_cap_value(b"content-length: 0100000", 256) == 100000  # lenient leading zero
    # First over-cap wins across duplicates.
    assert declared_over_cap_value(b"Content-Length: 100000\r\nContent-Length: 4", 256) == 100000
    assert declared_over_cap_value(b"Content-Length: 4\r\nContent-Length: 99999", 256) == 99999
    # No over-cap header (or no Content-Length at all, e.g. a Case B newline frame) -> None.
    assert declared_over_cap_value(b"Content-Length: 10", 256) is None
    assert declared_over_cap_value(b"X-Other: 1", 256) is None
    assert declared_over_cap_value(b"Content-Length: -500", 256) is None


async def test_declared_over_cap_frame_uses_distinct_parse_error():
    # End-to-end: a Content-Length-framed header declaring > cap surfaces the
    # distinct FRAME_OVER_CAP_PARSE_ERROR marker (the body is never read).
    header = b"Content-Length: 100000\r\n\r\n"
    reader = FrameReader(_Feeder([header]).receive, max_frame_bytes=256)
    f = await reader.read_frame()
    assert f is not None and f.json is None
    assert f.parse_error == FRAME_OVER_CAP_PARSE_ERROR
    # A NON-over-cap parse failure keeps the generic string (regression).
    bad = b"Content-Length: abc\r\n\r\n"
    reader2 = FrameReader(_Feeder([bad]).receive, max_frame_bytes=256)
    f2 = await reader2.read_frame()
    assert f2 is not None and f2.parse_error == "missing/invalid Content-Length"


def test_parse_content_length_unchanged_for_over_cap():
    # _declared_length_over_cap is a SEPARATE helper: _parse_content_length still
    # returns None for an over-cap declared length exactly as the #17 suite pins.
    assert _parse_content_length(b"Content-Length: 100000", 256) is None
    assert _parse_content_length(b"Content-Length: 200", 256) == 200
