"""Bounded HTTP exchange and resumable MCP POST response streams."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http.cookiejar import DefaultCookiePolicy

import anyio
import httpx2 as httpx

from .guard_http_frames import FrameLimit, TransportFailure, bounded_body, bounded_lines

_SESSION = "MCP-Session-Id"
_VERSION = "MCP-Protocol-Version"
_ACCEPT = "application/json, text/event-stream"
_HTTP_ID = re.compile(r"[!-~]{1,256}")
_BEARER = re.compile(r"[A-Za-z0-9._~+/-]{1,4096}=*")
_MAX_RESUMES = 4


class SessionExpired(TransportFailure):
    def __init__(self):
        super().__init__("upstream session expired; reconnect the adapter")


class _NoCookies(DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False


def checked_endpoint(url: str, token: str | None) -> httpx.URL:
    try:
        target = httpx.URL(url)
    except (ValueError, httpx.InvalidURL):
        raise TransportFailure("invalid upstream URL") from None
    loopback = target.host in {"127.0.0.1", "::1", "localhost"}
    if (not target.host or target.userinfo or target.query or target.fragment
            or not (target.scheme == "https" or (target.scheme == "http" and loopback))):
        raise TransportFailure("HTTPS required outside loopback; URL credentials and query are unsupported")
    if token is not None and (len(token) > 4096 or not _BEARER.fullmatch(token)
                              or token in url or token in str(target)):
        raise TransportFailure("invalid upstream bearer credential")
    return target


@dataclass
class _Cursor:
    event_id: str | None = None
    retry: float = 0.0


async def sse_messages(chunks, limit: int, cursor: _Cursor) -> AsyncIterator[bytes]:
    data = bytearray()
    event_type = b""
    event_id = None
    first_line = True
    async for line in bounded_lines(chunks, limit + 7, sse=True):
        if first_line:
            first_line = False
            line = line.removeprefix(b"\xef\xbb\xbf")
        if not line:
            if event_type not in {b"", b"message"}:
                raise TransportFailure("unsupported upstream SSE event")
            if event_id is not None:
                cursor.event_id = event_id or None
            if len(data) > 1:
                yield bytes(data[:-1])
            data.clear()
            event_type = b""
            event_id = None
            continue
        field, _, value = line.partition(b":")
        value = value.removeprefix(b" ")
        if field == b"data":
            if len(data) + len(value) > limit:
                raise FrameLimit()
            data.extend(value)
            data.append(10)
        elif field == b"event":
            event_type = value
        elif field == b"id":
            candidate = value.decode("ascii", errors="replace")
            if candidate and not _HTTP_ID.fullmatch(candidate):
                raise TransportFailure("invalid upstream SSE cursor")
            event_id = candidate
        elif field == b"retry" and value.isdigit():
            # A retry beyond this limit cannot fit the supported call deadline.
            cursor.retry = int(value) / 1000 if len(value) <= 7 else float("inf")


class HTTPTransport:
    def __init__(self, url: httpx.URL, token: str | None, *, limit: int, timeout: float,
                 concurrency: int, transport=None):
        self.url = url
        self.token = token
        self.limit = limit
        self.timeout = timeout
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        # HTTP client logs can include URLs or raw response headers. This adapter
        # reports fixed failure reasons, including when the library fails.
        for logger in ("httpx", "httpx2", "httpcore", "httpcore2", "h11"):
            logging.getLogger(logger).setLevel(logging.CRITICAL + 1)
        self.client = httpx.AsyncClient(
            trust_env=False, follow_redirects=False,
            limits=httpx.Limits(max_connections=concurrency * 2 + 2,
                                max_keepalive_connections=concurrency + 1),
            timeout=httpx.Timeout(timeout, read=None),
            transport=transport,
        )
        self.client.cookies.jar.set_policy(_NoCookies())

    @property
    def credentials(self) -> tuple[str, ...]:
        return tuple(secret for secret in (self.token, self.session_id) if secret is not None)

    def _headers(self, *, method: str, resume: str | None = None) -> dict[str, str]:
        headers = {"Accept": "text/event-stream" if method == "GET" else _ACCEPT,
                   "Accept-Encoding": "identity"}
        if method == "POST":
            headers["Content-Type"] = "application/json"
        if self.token is not None:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.session_id is not None:
            headers[_SESSION] = self.session_id
        if self.protocol_version is not None:
            headers[_VERSION] = self.protocol_version
        if resume is not None:
            headers["Last-Event-ID"] = resume
        return headers

    def _check_headers(self, response: httpx.Response, *, initialize: bool = False) -> None:
        # Capture the session before body/status-policy checks so it can be
        # terminated even if initialization fails after a valid 200 response.
        sessions = response.headers.get_list(_SESSION)
        if sessions:
            if len(sessions) != 1 or not _HTTP_ID.fullmatch(sessions[0]):
                raise TransportFailure("invalid upstream session header")
            if initialize and response.status_code == 200:
                self.session_id = sessions[0]
            elif sessions[0] != self.session_id:
                raise TransportFailure("unexpected upstream session header")
        if response.status_code == 404 and self.session_id is not None:
            raise SessionExpired()
        encoding = response.headers.get("Content-Encoding", "identity").lower()
        if encoding != "identity":
            raise TransportFailure("upstream content encoding is unsupported")
        length = response.headers.get("Content-Length")
        if length is not None:
            if not re.fullmatch(r"[0-9]{1,20}", length):
                raise TransportFailure("invalid upstream content length")
            if int(length) > self.limit:
                raise FrameLimit()

    @asynccontextmanager
    async def _stream(self, method: str, *, body: bytes | None = None, resume: str | None = None):
        request = self.client.build_request(
            method, self.url, headers=self._headers(method=method, resume=resume), content=body,
        )
        with anyio.fail_after(self.timeout):
            response = await self.client.send(request, stream=True)
        try:
            yield response
        finally:
            with anyio.move_on_after(0.5, shield=True):
                await response.aclose()

    async def frames(self, body: bytes | None, *, initialize: bool = False) -> AsyncIterator[bytes]:
        """Yield complete bounded frames. Resume by cursor and never resend a POST."""
        cursor = _Cursor()
        unsolicited = body is None
        method = "GET" if unsolicited else "POST"
        for attempt in range(_MAX_RESUMES + 1):
            resume = cursor.event_id
            try:
                async with self._stream(method, body=body, resume=resume) as response:
                    self._check_headers(response, initialize=initialize and attempt == 0)
                    if unsolicited and attempt == 0 and response.status_code == 405:
                        return
                    if response.status_code != 200:
                        raise TransportFailure("upstream HTTP request failed")
                    media_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                    if media_type == "application/json" and method == "POST":
                        yield await bounded_body(response.aiter_raw(), self.limit)
                        return
                    if media_type != "text/event-stream":
                        raise TransportFailure("unsupported upstream response type")
                    async for frame in sse_messages(response.aiter_raw(), self.limit, cursor):
                        yield frame
            except httpx.TransportError:
                if cursor.event_id is None:
                    raise TransportFailure("upstream connection interrupted") from None
            if cursor.event_id is None or attempt == _MAX_RESUMES:
                if unsolicited:
                    raise TransportFailure("upstream notification stream ended")
                return
            if cursor.retry >= self.timeout:
                raise TransportFailure("upstream resume delay exceeds the guard deadline")
            await anyio.sleep(cursor.retry)
            method, body = "GET", None

    async def notify(self, body: bytes) -> None:
        async with self._stream("POST", body=body) as response:
            self._check_headers(response)
            if response.status_code != 202:
                raise TransportFailure("upstream notification refused")

    async def close(self) -> None:
        with anyio.move_on_after(2, shield=True):
            if self.session_id is not None:
                try:
                    async with self._stream("DELETE"):
                        pass
                except Exception:
                    pass
        with anyio.move_on_after(0.5, shield=True):
            try:
                await self.client.aclose()
            except Exception:
                pass
