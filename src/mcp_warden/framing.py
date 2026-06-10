"""stdio JSON-RPC framing for the guard proxy (GUARD_PROXY.md §2.4).

One reader, one framer, one frame at a time per direction (§2.3) — NO threads,
NO concurrent partial-frame readers on the same stream. Supports BOTH:

  * **newline framing** (MCP stdio default): one JSON object per ``\\n`` line.
  * **Content-Length framing** (LSP-style): a CRLF header block ending in a blank
    line, then exactly ``Content-Length`` body bytes.

The mode is detected from the first bytes of the stream and fixed per stream.
A pass-through frame forwards its ORIGINAL bytes (no re-serialization); only a
modified frame is re-serialized in the same mode (§2.4).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("mcp_warden.framing")

MODE_NEWLINE = "newline"
MODE_CONTENT_LENGTH = "content-length"

_CL_PREFIX = b"content-length:"

#: Distinct ``Frame.parse_error`` string set by ``_read_content_length`` when a
#: Content-Length-framed message declares a length GREATER than
#: ``max_frame_bytes`` (issue #37, Case A). The body is never read (so
#: ``len(frame.raw)`` stays small — the header only), which means the s2c pump's
#: ``len(frame.raw) > cap`` check would MISS it. The pump compares
#: ``frame.parse_error`` against this exact constant to recognize a declared
#: over-cap frame and (under ``--strict-frame-cap``) fail-CLOSE it. A non-over-cap
#: parse failure keeps the generic ``"missing/invalid Content-Length"`` string.
FRAME_OVER_CAP_PARSE_ERROR = "declared Content-Length exceeds max-frame-bytes"


@dataclass
class Frame:
    """One complete framed JSON-RPC message.

    Attributes:
        raw: The full ORIGINAL wire bytes of the frame, including any framing
            header + the body + terminator. Forwarded verbatim on pass-through.
        body: The JSON body bytes (without framing/terminator).
        json: The parsed JSON object, or ``None`` if the body did not parse.
        parse_error: The parse error message if ``json is None`` (else ``""``).
    """

    raw: bytes
    body: bytes
    json: dict[str, Any] | None
    parse_error: str = ""


class FrameReader:
    """Incremental, single-reader framer over an async byte receive stream.

    Detects the framing mode from the first bytes and reads one complete
    :class:`Frame` per call. EOF yields ``None``.

    Args:
        receive: A callable ``async () -> bytes`` returning the next chunk
            (``b""`` on EOF). Typically an anyio stream's ``receive``.
        max_frame_bytes: Per-frame size cap; a frame whose declared/observed
            size exceeds this is still returned (with the raw bytes) so the
            caller can fail-open and pass it through (§2.5).
    """

    def __init__(self, receive, max_frame_bytes: int) -> None:
        self._receive = receive
        self._buf = bytearray()
        self._eof = False
        self.mode: str | None = None
        self.max_frame_bytes = max_frame_bytes

    async def _fill(self) -> bool:
        """Pull one more chunk into the buffer. Returns False at EOF."""
        if self._eof:
            return False
        try:
            chunk = await self._receive()
        except Exception as exc:  # stream closed mid-read
            logger.debug("receive raised (treating as EOF): %s", exc)
            self._eof = True
            return False
        if not chunk:
            self._eof = True
            return False
        self._buf.extend(chunk)
        return True

    def _detect_mode(self) -> None:
        """Detect framing mode from the buffer head once enough bytes exist."""
        if self.mode is not None:
            return
        head = bytes(self._buf[:64]).lstrip()
        if head[: len(_CL_PREFIX)].lower() == _CL_PREFIX:
            self.mode = MODE_CONTENT_LENGTH
        elif b"\n" in self._buf or len(self._buf) >= 64:
            # A newline (or a full small buffer) with no CL header => newline mode.
            self.mode = MODE_NEWLINE

    async def read_frame(self) -> Frame | None:
        """Read one complete frame (or ``None`` at EOF).

        Returns:
            The next :class:`Frame`, or ``None`` when the stream is exhausted.
        """
        while self.mode is None:
            self._detect_mode()
            if self.mode is not None:
                break
            if not await self._fill():
                # EOF before we could detect: flush any trailing bytes as a frame.
                if self._buf:
                    self.mode = MODE_NEWLINE
                    break
                return None
        if self.mode == MODE_CONTENT_LENGTH:
            return await self._read_content_length()
        return await self._read_newline()

    async def _read_newline(self) -> Frame | None:
        """Read a newline-delimited frame."""
        while True:
            nl = self._buf.find(b"\n")
            if nl != -1:
                line = bytes(self._buf[: nl + 1])  # include the newline in raw
                del self._buf[: nl + 1]
                body = line.rstrip(b"\r\n")
                if not body.strip():
                    # Blank line between frames; skip but keep going.
                    if not self._buf and self._eof:
                        return None
                    continue
                return _parse_frame(line, body)
            if not await self._fill():
                if self._buf:
                    line = bytes(self._buf)
                    self._buf.clear()
                    body = line.rstrip(b"\r\n")
                    if not body.strip():
                        return None
                    return _parse_frame(line, body)
                return None

    async def _read_content_length(self) -> Frame | None:
        """Read a Content-Length-framed message (header block + body)."""
        while b"\r\n\r\n" not in self._buf:
            if not await self._fill():
                if self._buf:  # truncated header at EOF -> surface as parse error
                    raw = bytes(self._buf)
                    self._buf.clear()
                    return Frame(raw=raw, body=b"", json=None, parse_error="truncated header at EOF")
                return None
        sep = self._buf.find(b"\r\n\r\n")
        header_bytes = bytes(self._buf[:sep])
        length = _parse_content_length(header_bytes, self.max_frame_bytes)
        if length is None:
            raw = bytes(self._buf[: sep + 4])
            del self._buf[: sep + 4]
            # Distinguish a declared-over-cap header (issue #37, Case A) from any
            # other malformed/missing Content-Length. Over-cap is the ONLY case
            # the s2c pump may fail-CLOSE under --strict-frame-cap; every other
            # parse failure stays the generic fail-open note. The body is never
            # read in either case, so raw is the header block only (no body/secret
            # bytes are ever buffered here).
            if _declared_length_over_cap(header_bytes, self.max_frame_bytes):
                parse_error = FRAME_OVER_CAP_PARSE_ERROR
            else:
                parse_error = "missing/invalid Content-Length"
            return Frame(raw=raw, body=b"", json=None, parse_error=parse_error)
        body_start = sep + 4
        while len(self._buf) < body_start + length:
            if not await self._fill():
                raw = bytes(self._buf)
                self._buf.clear()
                return Frame(raw=raw, body=b"", json=None, parse_error="truncated body at EOF")
        raw = bytes(self._buf[: body_start + length])
        body = bytes(self._buf[body_start : body_start + length])
        del self._buf[: body_start + length]
        return _parse_frame(raw, body)


def _parse_content_length(header_bytes: bytes, max_frame_bytes: int) -> int | None:
    """Parse the Content-Length value from a header block (case-insensitive).

    A conformant Content-Length is a run of ASCII digits only. Python's ``int``
    is too permissive for an untrusted wire header — it accepts a leading sign
    (``-5`` -> a NEGATIVE length that mis-slices the body), digit-group
    underscores (``1_000``), surrounding whitespace, and non-ASCII Unicode
    digits. Any of those is a malformed frame, so we require ``^[0-9]+$`` and
    return ``None`` otherwise (surfaced upstream as the visible fail-open
    ``parse_error``). See issue #17 fuzz Finding A.

    Hardening (issue #17 code audit, B1/B2/B9):

    * **B1 — duplicate/multiple Content-Length (request-smuggling class).** We
      scan EVERY header line and collect EVERY ``Content-Length`` value rather
      than returning on the first one found. A frame is accepted only when there
      is EXACTLY ONE occurrence and it is valid. Zero, a duplicate (even of equal
      values), or any malformed occurrence => ``None`` (visible ``parse_error``
      fail-open). An early-exit on the first line let a malformed-first +
      valid-second (or two-different-values) header desync the framer / turn a
      frame into an uninspected pass-through.
    * **B2 — upper bound.** ``isdigit()`` accepts arbitrarily huge integers
      (e.g. ``2**63``); the framer would then block reading a body that never
      arrives (``max_frame_bytes`` is a fail-open pass-through cap per
      GUARD_PROXY_V3 §2.4 — it does NOT bound the declared length). A declared
      length larger than ``max_frame_bytes`` can never be satisfied by a frame
      the reader will accept, so we reject it here => ``None`` (parse_error),
      never a blocking read. The bound is threaded from
      ``FrameReader.max_frame_bytes``.
    * **B9 — leading zeros.** ``007`` is non-conformant per RFC 7230 §3.3.2;
      rejected (any value with a redundant leading zero), which falls out of the
      single-valid-only scan cheaply.
    """
    values: list[bytes] = []
    for line in header_bytes.split(b"\r\n"):
        if line[: len(_CL_PREFIX)].lower() == _CL_PREFIX:
            values.append(line[len(_CL_PREFIX) :].strip())
    # B1: exactly one Content-Length header, or it is malformed -> reject.
    if len(values) != 1:
        return None
    value = values[0]
    # bytes.isdigit() is already ASCII-0-9-only (no sign/underscore/whitespace/
    # unicode digits), so a separate .isascii() check (B8) is redundant here.
    if not value.isdigit():
        return None
    # B9: RFC 7230 forbids leading zeros (``007``); a lone ``0`` is still valid.
    if len(value) > 1 and value[:1] == b"0":
        return None
    n = int(value)
    # B2: a length the reader can never satisfy must fail-open as parse_error,
    # not hang on a body that will never arrive.
    if n > max_frame_bytes:
        return None
    return n


def _declared_length_over_cap(header_bytes: bytes, max_frame_bytes: int) -> bool:
    """Whether a header block declares ANY Content-Length over the cap (FAIL-CLOSED).

    A pure helper used ONLY to distinguish issue #37's Case A (a server padding a
    result by declaring ``Content-Length > max_frame_bytes``) from every other
    reason ``_parse_content_length`` returns ``None`` (missing / non-digit / ``<=
    cap``). It is a SEPARATE function on purpose: ``_parse_content_length`` is
    pinned by the issue #17 fuzz suite and MUST NOT be modified.

    Security posture (issue #37 NO-SHIP fix — inspection BYPASS closed): this is a
    SECURITY GATE, so it over-approximates toward FAIL-CLOSED. The earlier
    "exactly one valid Content-Length > cap" rule let a malicious server EVADE the
    over-cap marker (and thus fail-open uninspected) with a duplicate header
    (``Content-Length: 100000\\r\\nContent-Length: 4``) or a leading-zero value
    (``Content-Length: 0100000``). To close every bypass shape we scan ALL header
    lines and return ``True`` if ANY ``content-length:``-prefixed line carries an
    all-digit stripped value strictly greater than ``max_frame_bytes`` — lenient
    on leading zeros and duplicates (any candidate over cap wins). Over-flagging a
    benign frame as over-cap (the over-approximation cost) merely fails it closed,
    which is the correct direction for a guard; under-flagging a malicious one
    (the old behavior) was the bug.

    Args:
        header_bytes: The CRLF header block (without the trailing blank line),
            exactly as passed to ``_parse_content_length``.
        max_frame_bytes: The per-frame cap.

    Returns:
        ``True`` iff ANY Content-Length header line has an all-digit value
        strictly greater than ``max_frame_bytes``; ``False`` otherwise.
    """
    for line in header_bytes.split(b"\r\n"):
        if line[: len(_CL_PREFIX)].lower() == _CL_PREFIX:
            value = line[len(_CL_PREFIX) :].strip()
            # Lenient on leading zeros (``0100000``) and duplicates: any all-digit
            # candidate over the cap fails the frame closed. Non-digit values
            # (sign/whitespace/letters) are not numeric over-cap candidates.
            if value.isdigit() and int(value) > max_frame_bytes:
                return True
    return False


def declared_over_cap_value(header_bytes: bytes, max_frame_bytes: int) -> int | None:
    """First declared Content-Length value that is all-digit and over the cap, else None.

    Diagnostic counterpart to :func:`_declared_length_over_cap` (issue #37 FIX 3):
    the s2c forensic note needs the actual server-asserted size to record. Uses the
    SAME lenient scan (all header lines; leading zeros / duplicates tolerated) so
    the note value can never disagree with the over-cap decision. SIZES ONLY — this
    only ever returns an integer parsed from a Content-Length header; it never reads
    or returns any body bytes.

    Args:
        header_bytes: The CRLF header block (Case A: the over-cap frame's header).
        max_frame_bytes: The per-frame cap.

    Returns:
        The FIRST over-cap all-digit Content-Length value, or ``None`` when no
        header line declares an over-cap length (e.g. Case B newline frames carry
        no Content-Length at all).
    """
    for line in header_bytes.split(b"\r\n"):
        if line[: len(_CL_PREFIX)].lower() == _CL_PREFIX:
            value = line[len(_CL_PREFIX) :].strip()
            if value.isdigit() and int(value) > max_frame_bytes:
                return int(value)
    return None


def _parse_frame(raw: bytes, body: bytes) -> Frame:
    """Parse a frame body into JSON, capturing parse errors (fail-open upstream)."""
    try:
        obj = json.loads(body)
        if not isinstance(obj, dict):
            return Frame(raw=raw, body=body, json=None, parse_error="frame body is not a JSON object")
        return Frame(raw=raw, body=body, json=obj)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return Frame(raw=raw, body=body, json=None, parse_error=str(exc))


def serialize_frame(obj: dict[str, Any], mode: str) -> bytes:
    """Serialize a (modified) JSON object back into wire bytes for ``mode``.

    Args:
        obj: The JSON-RPC object to emit.
        mode: ``MODE_NEWLINE`` or ``MODE_CONTENT_LENGTH``.

    Returns:
        The framed wire bytes.
    """
    body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if mode == MODE_CONTENT_LENGTH:
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        return header + body
    return body + b"\n"
