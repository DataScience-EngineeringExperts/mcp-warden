"""Bounded, versioned JSON framing shared with the isolated parser component."""

from __future__ import annotations

import io
import json
import struct
from typing import BinaryIO

MAX_FRAME = 64 * 1024
MAX_MESSAGE = 64 * 1024 * 1024
MAX_DEPTH = 32
MAX_STRUCTURAL_TOKENS = 200_000


class NormalizationError(Exception):
    """Stable input-free refusal; never render parser or subprocess exceptions."""

    def __init__(self, code: str = "NRM-MALFORMED") -> None:
        self.code = code
        super().__init__(code)


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise NormalizationError()
        result[key] = value
    return result


def canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise NormalizationError() from None


def encode_message(value: dict) -> bytes:
    if type(value) is not dict:
        raise NormalizationError()
    data = canonical(value)
    if len(data) > MAX_MESSAGE:
        raise NormalizationError("NRM-OVER-CAP")
    return b"".join(struct.pack(">I", len(part)) + part
                    for offset in range(0, len(data), MAX_FRAME)
                    if (part := data[offset:offset + MAX_FRAME])) + b"\0\0\0\0"


def _exact(stream: BinaryIO, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise NormalizationError("NRM-PROTOCOL")
        data.extend(chunk)
    return bytes(data)


def read_message(stream: BinaryIO) -> dict:
    data = bytearray()
    while True:
        size = struct.unpack(">I", _exact(stream, 4))[0]
        if size == 0:
            break
        if size > MAX_FRAME or len(data) + size > MAX_MESSAGE:
            raise NormalizationError("NRM-OVER-CAP")
        data.extend(_exact(stream, size))
    if stream.read(1):
        raise NormalizationError("NRM-PROTOCOL")
    depth = tokens = 0
    quoted = escaped = False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        else:
            if char in (34, 91, 123, 44, 58):
                tokens += 1
                if tokens > MAX_STRUCTURAL_TOKENS:
                    raise NormalizationError("NRM-OVER-CAP")
            if char == 34:
                quoted = True
            elif char in (91, 123):
                depth += 1
                if depth > MAX_DEPTH:
                    raise NormalizationError("NRM-OVER-CAP")
            elif char in (93, 125):
                depth -= 1
                if depth < 0:
                    raise NormalizationError()
    if depth or quoted or escaped:
        raise NormalizationError()
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(NormalizationError()))
    except (ValueError, UnicodeError, RecursionError):
        raise NormalizationError() from None
    if type(value) is not dict:
        raise NormalizationError()
    return value


def decode_message(data: bytes) -> dict:
    if type(data) is not bytes or len(data) > MAX_MESSAGE + (MAX_MESSAGE // MAX_FRAME + 1) * 4:
        raise NormalizationError("NRM-OVER-CAP")
    return read_message(io.BytesIO(data))
