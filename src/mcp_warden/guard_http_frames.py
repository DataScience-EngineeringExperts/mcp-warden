"""Bounded framing and credential checks for the Streamable HTTP guard."""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import AsyncIterable, AsyncIterator
from contextlib import contextmanager
from typing import Any

import anyio

from .framing import MODE_NEWLINE, Frame, serialize_frame

_CHUNK_BYTES = 64 * 1024
_SSE_END = re.compile(rb"[\r\n]")
_STDIO_END = re.compile(rb"\n")
SUPPORTED_VERSIONS = {"2025-03-26", "2025-06-18", "2025-11-25"}
_SERVER_NOTIFICATIONS = {
    "notifications/cancelled", "notifications/progress", "notifications/message",
    "notifications/tools/list_changed", "notifications/resources/list_changed",
    "notifications/resources/updated", "notifications/prompts/list_changed",
}
SUPPORTED_REQUESTS = {
    "ping", "tools/list", "tools/call", "resources/list", "resources/templates/list",
    "resources/read", "resources/subscribe", "resources/unsubscribe", "prompts/list",
    "prompts/get", "logging/setLevel", "completion/complete",
}



class TransportFailure(Exception):
    """A fixed, safe reason for refusing a transport operation."""


class ClientWriteFailure(TransportFailure):
    """The downstream pipe may contain a partial frame and cannot be used again."""


class FrameLimit(TransportFailure):
    def __init__(self):
        super().__init__("frame limit exceeded")


async def bounded_lines(
    chunks: AsyncIterable[bytes], limit: int, *, sse: bool = False
) -> AsyncIterator[bytes]:
    """Yield complete lines, checking each append against the cap first."""
    buf = bytearray()
    skip_lf = False
    endings = _SSE_END if sse else _STDIO_END
    async for chunk in chunks:
        if not chunk:
            continue
        start = int(skip_lf and chunk.startswith(b"\n"))
        skip_lf = False
        for end in endings.finditer(chunk, start):
            index = end.start()
            if index < start:
                continue
            if len(buf) + index - start > limit:
                raise FrameLimit()
            buf.extend(memoryview(chunk)[start:index])
            yield bytes(buf)
            buf.clear()
            start = index + 1
            if sse and chunk[index] == 13:
                skip_lf = start == len(chunk)
                if chunk[start:start + 1] == b"\n":
                    start += 1
        if len(buf) + len(chunk) - start > limit:
            raise FrameLimit()
        buf.extend(memoryview(chunk)[start:])
    if buf and not sse:
        raise TransportFailure("incomplete input frame")


async def bounded_body(chunks: AsyncIterable[bytes], limit: int) -> bytes:
    buf = bytearray()
    async for chunk in chunks:
        if len(buf) + len(chunk) > limit:
            raise FrameLimit()
        buf.extend(chunk)
    return bytes(buf)


def _unique_object(pairs: list[tuple]) -> dict:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError
    return obj


def _invalid_constant(_value: str):
    raise ValueError


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError
    return number


def parse_frame(body: bytes, credentials: tuple[str, ...]) -> Frame:
    try:
        obj = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_constant=_invalid_constant, parse_float=_finite_float)
        if type(obj) is not dict or obj.get("jsonrpc") != "2.0":
            raise ValueError
        if credentials and contains_credential(obj, credentials):
            raise TransportFailure("credential-bearing frame refused")
        raw = serialize_frame(obj, MODE_NEWLINE) if b"\n" in body else body + b"\n"
    except (ValueError, RecursionError):
        raise TransportFailure("invalid JSON-RPC frame") from None
    return Frame(raw, body, obj)


def contains_credential(value: Any, credentials: tuple[str, ...]) -> bool:
    """Check decoded keys and values so JSON escaping cannot conceal a known secret."""
    if type(value) is str:
        return any(secret in value for secret in credentials)
    if type(value) is dict:
        return any(contains_credential(k, credentials) or contains_credential(v, credentials)
                   for k, v in value.items())
    if type(value) is list:
        return any(contains_credential(item, credentials) for item in value)
    return False


def valid_rpc_id(rpc_id: Any) -> bool:
    return ((type(rpc_id) is int and rpc_id.bit_length() <= 64)
            or (type(rpc_id) is str and 0 < len(rpc_id) <= 256 and rpc_id.isascii()))


def check_notification(obj: dict, method: Any, rpc_id, progress_token) -> None:
    if (type(method) is not str or method not in _SERVER_NOTIFICATIONS
            or "id" in obj or "result" in obj or "error" in obj
            or type(obj.get("params", {})) is not dict):
        raise TransportFailure("unsupported upstream notification or request")
    params = obj.get("params", {})
    if method == "notifications/progress":
        token = params.get("progressToken")
        if (progress_token is None or not valid_rpc_id(token)
                or token != progress_token):
            raise TransportFailure("unmatched upstream progress notification")
    if method == "notifications/cancelled":
        cancelled_id = params.get("requestId")
        if rpc_id is None or not valid_rpc_id(cancelled_id) or cancelled_id != rpc_id:
            raise TransportFailure("unmatched upstream cancellation notification")


def checked_reply(frame: Frame, expected_id, request_method: str, has_lock: bool) -> Frame:
    obj = frame.json
    rpc_id = obj.get("id")
    if (expected_id is None or not valid_rpc_id(rpc_id) or rpc_id != expected_id
            or ("result" in obj) == ("error" in obj)):
        raise TransportFailure("unexpected upstream reply")
    if "error" in obj:
        error = obj["error"]
        if (type(error) is not dict or type(error.get("code")) is not int
                or not -(2**31) <= error["code"] < 2**31
                or error["code"] in {-32001, -32002, -32003}):
            raise TransportFailure("invalid upstream error")
        safe = {"jsonrpc": "2.0", "id": rpc_id, "error": {
            "code": error["code"], "message": "Upstream MCP request failed",
        }}
        body = serialize_frame(safe, MODE_NEWLINE)
        frame = Frame(body, body[:-1], safe)
    else:
        result = obj["result"]
        if type(result) is not dict:
            raise TransportFailure("invalid upstream result")
        _validate_result(request_method, result, has_lock)
        if request_method == "initialize" and "tasks" in result["capabilities"]:
            del result["capabilities"]["tasks"]
            body = serialize_frame(obj, MODE_NEWLINE)
            frame = Frame(body, body[:-1], obj)
    if request_method == "initialize" and "error" in obj:
        raise TransportFailure("upstream initialization failed")
    return frame


def _validate_result(method: str, result: dict, has_lock: bool) -> None:
    if method == "initialize":
        version = result.get("protocolVersion")
        if (type(version) is not str or version not in SUPPORTED_VERSIONS
                or type(result.get("capabilities")) is not dict
                or type(result.get("serverInfo")) is not dict):
            raise TransportFailure("unsupported upstream initialization")
    elif method == "tools/list":
        tools = result.get("tools")
        if (type(tools) is not list or any(type(tool) is not dict
                or type(tool.get("name")) is not str or not tool["name"]
                or type(tool.get("inputSchema")) is not dict for tool in tools)
                or len({tool["name"] for tool in tools}) != len(tools)):
            raise TransportFailure("invalid upstream tools list")
        if has_lock:
            if result.get("nextCursor") is not None:
                raise TransportFailure("paginated tool lists with a runtime lock are unsupported")


class PipeIO:
    """Cancellable POSIX pipe I/O with kernel backpressure and no writer queue."""

    def __init__(self, reader: int, writer: int):
        self.reader = reader
        self.writer = writer

    async def chunks(self) -> AsyncIterator[bytes]:
        while True:
            try:
                chunk = os.read(self.reader, _CHUNK_BYTES)
            except BlockingIOError:
                await anyio.wait_readable(self.reader)
                continue
            if not chunk:
                return
            yield chunk

    async def send(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            try:
                view = view[os.write(self.writer, view):]
            except BlockingIOError:
                await anyio.wait_writable(self.writer)


@contextmanager
def nonblocking_pipes(reader: int, writer: int):
    saved = {fd: os.get_blocking(fd) for fd in (reader, writer)}
    try:
        for fd in saved:
            os.set_blocking(fd, False)
        yield PipeIO(reader, writer)
    finally:
        for fd, blocking in saved.items():
            os.set_blocking(fd, blocking)
