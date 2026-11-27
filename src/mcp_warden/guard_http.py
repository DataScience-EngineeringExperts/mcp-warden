"""Mediate one Streamable HTTP session behind the laptop harness stdio adapter."""

from __future__ import annotations

import logging
import math
import signal
import sys
from contextlib import aclosing
from dataclasses import dataclass
from typing import Any

import anyio
import httpx2 as httpx

from .framing import MODE_NEWLINE, Frame, serialize_frame
from .guard_http_frames import (
    SUPPORTED_REQUESTS,
    SUPPORTED_VERSIONS,
    ClientWriteFailure,
    FrameLimit,
    TransportFailure,
    bounded_lines,
    check_notification,
    checked_reply,
    nonblocking_pipes,
    parse_frame,
    valid_rpc_id,
)
from .guard_http_policy import inspect_response
from .guard_http_transport import HTTPTransport, SessionExpired, checked_endpoint
from .guard_loop import GuardState, StrictInspectionAbort, handle_c2s, handle_s2c
from .wire_block import strict_abort_error, transport_error

logger = logging.getLogger("mcp_warden.guard")
_END_WRITE_TIMEOUT = 0.5
_MAX_REQUEST_IDS = 65_536


@dataclass
class _Flight:
    rpc_id: int | str
    method: str
    progress_token: Any
    scope: anyio.CancelScope
    finished: anyio.Event
    cancelled: bool = False


class _Session:
    def __init__(self, transport: HTTPTransport, state: GuardState, io, timeout: float,
                 concurrency: int):
        self.transport = transport
        self.state = state
        self.io = io
        self.timeout = timeout
        self.concurrency = concurrency
        self.phase = "new"
        self.active: dict[int | str, _Flight] = {}
        self.request_ids: set[int | str] = set()
        self.writer = anyio.Lock()
        self.dns_workers = anyio.CapacityLimiter(2)
        self.output_failed = False
        self.tasks: anyio.abc.TaskGroup
        self.failure: tuple[str, str | None] | None = None

    async def run(self, *, stop_signals: bool) -> int:
        try:
            async with anyio.create_task_group() as self.tasks:
                if stop_signals:
                    await self.tasks.start(self.watch_signals)
                try:
                    async for body in bounded_lines(self.io.chunks(), self.transport.limit):
                        await self.dispatch(parse_frame(body, self.transport.credentials))
                except (Exception, StrictInspectionAbort) as exc:
                    self.stop(exc)
                self.tasks.cancel_scope.cancel()
        finally:
            await self.transport.close()
        if self.failure is None:
            return 0
        reason, site = self.failure
        if not self.output_failed:
            try:
                for flight in self.active.values():
                    if not flight.cancelled:
                        await self.write_error(flight.rpc_id, reason, site=site, timeout=_END_WRITE_TIMEOUT)
            except ClientWriteFailure:
                pass
        if site:
            logger.error("HTTP guard strict_abort: %s (%s)", reason, site)
        else:
            logger.error("HTTP guard: %s", reason)
        return 3 if site else 2

    async def watch_signals(self, *, task_status=anyio.TASK_STATUS_IGNORED) -> None:
        with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as received:
            task_status.started()
            async for _ in received:
                self.tasks.cancel_scope.cancel()
                return

    def stop(self, exc: BaseException) -> None:
        if self.failure is None:
            if isinstance(exc, StrictInspectionAbort):
                self.failure = ("inspection failed", exc.site)
            elif isinstance(exc, FrameLimit):
                self.failure = ("frame limit exceeded", "transport-frame")
            elif isinstance(exc, TransportFailure):
                self.failure = (str(exc), None)
            else:
                self.failure = ("local or upstream connection failed", None)
        self.tasks.cancel_scope.cancel()

    async def write(self, out: bytes, *, timeout: float | None = None) -> None:
        if len(out) - 1 > self.transport.limit:
            raise FrameLimit()
        async with self.writer:
            try:
                # Cancellation cannot leave a partial newline frame in stdout.
                with anyio.fail_after(timeout or self.timeout, shield=True):
                    await self.io.send(out)
            except (TimeoutError, OSError):
                self.output_failed = True
                raise ClientWriteFailure("client output closed or stalled") from None

    async def write_error(self, rpc_id, reason: str, *, site: str | None = None,
                          timeout: float | None = None) -> None:
        error = (strict_abort_error(rpc_id, site=site, reason=reason) if site else
                 transport_error(rpc_id, reason=reason, message="mcp-warden: HTTP guard refused delivery"))
        await self.write(serialize_frame(error, MODE_NEWLINE), timeout=timeout)

    def complete(self, flight: _Flight) -> None:
        self.active.pop(flight.rpc_id, None)
        self.state.method_for(flight.rpc_id)
        self.state.tool_for(flight.rpc_id)

    async def dispatch(self, frame: Frame) -> None:
        obj = frame.json
        method = obj.get("method")
        params = obj.get("params", {})
        if (type(method) is not str or not method or len(method) > 128
                or type(params) is not dict or "result" in obj or "error" in obj):
            raise TransportFailure("invalid client request")
        if method.startswith("notifications/"):
            if "id" in obj:
                raise TransportFailure("invalid client notification")
            await self.notification(frame, method, params)
            return
        rpc_id = obj.get("id")
        if not valid_rpc_id(rpc_id) or rpc_id in self.request_ids:
            raise TransportFailure("invalid or duplicate client request ID")
        if len(self.request_ids) >= _MAX_REQUEST_IDS:
            raise TransportFailure("session request ID limit exceeded; reconnect the adapter")
        self.request_ids.add(rpc_id)
        if self.phase != "ready" and not (self.phase == "new" and method == "initialize"):
            raise TransportFailure("client initialization required")
        if method == "initialize":
            if self.phase != "new" or (type(params.get("protocolVersion")) is not str
                                       or params["protocolVersion"] not in SUPPORTED_VERSIONS):
                raise TransportFailure("unsupported initialization")
            self.phase = "initializing"
        elif "task" in params:
            await self.write_error(rpc_id, "task-augmented client requests are unsupported")
            return
        elif method not in SUPPORTED_REQUESTS:
            await self.write_error(rpc_id, "unsupported client request")
            return
        elif method == "tools/call" and (type(params.get("name")) is not str
                                        or not params["name"] or len(params["name"]) > 256
                                        or type(params.get("arguments", {})) is not dict):
            raise TransportFailure("invalid tool call")
        if len(self.active) >= self.concurrency:
            await self.write_error(rpc_id, "request concurrency limit exceeded")
            return
        progress = params.get("_meta", {})
        progress = progress.get("progressToken") if type(progress) is dict else None
        if progress is not None and not valid_rpc_id(progress):
            raise TransportFailure("invalid progress token")
        flight = _Flight(rpc_id, method, progress, anyio.CancelScope(), anyio.Event())
        self.active[rpc_id] = flight
        out = handle_c2s(self.state, frame, MODE_NEWLINE)
        if not out:
            blocked = self.state.pending_client_error
            self.state.pending_client_error = None
            await self.write(blocked)
            self.complete(flight)
            return
        if method == "initialize":
            # The adapter does not offer server-to-client RPC (sampling, roots,
            # elicitation or tasks). Retain the client info and requested version.
            out = serialize_frame({**obj, "params": {**params, "capabilities": {}}}, MODE_NEWLINE)
        self.tasks.start_soon(self.exchange, flight, out[:-1])

    async def notification(self, frame: Frame, method: str, params: dict) -> None:
        if method == "notifications/initialized" and self.phase == "awaiting-initialized":
            with anyio.fail_after(self.timeout):
                await self.transport.notify(handle_c2s(self.state, frame, MODE_NEWLINE)[:-1])
            self.phase = "ready"
            self.tasks.start_soon(self.listen)
            return
        if method != "notifications/cancelled" or self.phase != "ready":
            raise TransportFailure("unsupported client notification")
        rpc_id = params.get("requestId")
        if not valid_rpc_id(rpc_id):
            raise TransportFailure("invalid cancellation request ID")
        flight = self.active.get(rpc_id)
        if flight is not None and not flight.cancelled:
            flight.cancelled = True
            # Interrupt the response reader immediately. Its admission slot is
            # held until the cancellation POST finishes.
            flight.scope.cancel()
            body = handle_c2s(self.state, frame, MODE_NEWLINE)[:-1]
            self.tasks.start_soon(self.cancel_remote, flight, body)

    async def cancel_remote(self, flight: _Flight, body: bytes) -> None:
        try:
            with anyio.fail_after(self.timeout):
                await self.transport.notify(body)
        except (Exception, StrictInspectionAbort) as exc:
            self.stop(exc)
        else:
            await flight.finished.wait()
            self.complete(flight)

    async def exchange(self, flight: _Flight, body: bytes) -> None:
        with flight.scope:
            try:
                with anyio.fail_after(self.timeout):
                    async with aclosing(
                        self.transport.frames(body, initialize=flight.method == "initialize")
                    ) as frames:
                        async for chunk in frames:
                            if await self.server_frame(chunk, flight):
                                if not flight.cancelled:
                                    self.complete(flight)
                                return
                raise TransportFailure("upstream ended before replying")
            except (StrictInspectionAbort, SessionExpired, FrameLimit, ClientWriteFailure) as exc:
                self.stop(exc)
            except TimeoutError:
                await self.refuse(flight, "upstream request timed out")
            except TransportFailure as exc:
                await self.refuse(flight, str(exc))
            except (OSError, httpx.HTTPError):
                await self.refuse(flight, "upstream connection failed")
            except Exception as exc:
                self.stop(exc)
            finally:
                flight.finished.set()

    async def refuse(self, flight: _Flight, reason: str) -> None:
        if flight.method == "initialize":
            self.stop(TransportFailure(reason))
            return
        if flight.cancelled:
            return
        try:
            await self.write_error(flight.rpc_id, reason)
        except (FrameLimit, ClientWriteFailure) as exc:
            self.stop(exc)
        else:
            self.complete(flight)

    async def listen(self) -> None:
        try:
            async with aclosing(self.transport.frames(None)) as frames:
                async for chunk in frames:
                    await self.server_frame(chunk, None)
        except (Exception, StrictInspectionAbort) as exc:
            self.stop(exc)

    async def server_frame(self, data: bytes, flight: _Flight | None) -> bool:
        frame = parse_frame(data, self.transport.credentials)
        obj = frame.json
        method = obj.get("method")
        if "method" in obj:
            check_notification(obj, method, flight.rpc_id if flight else None,
                               flight.progress_token if flight else None)
            await self.write(handle_s2c(self.state, frame, MODE_NEWLINE))
            return False

        if flight is None:
            raise TransportFailure("unexpected upstream reply")
        frame = checked_reply(frame, flight.rpc_id, flight.method, self.state.lock is not None)
        if flight.method == "initialize":
            self.transport.protocol_version = frame.json["result"]["protocolVersion"]
        elif flight.method == "tools/list" and "result" in frame.json and self.state.lock is not None:
            self.state.list_changed_pending = True
        out = await inspect_response(self.state, frame, flight.method, flight.rpc_id, self.dns_workers)
        if flight.method == "initialize" and out != frame.raw:
            raise TransportFailure("upstream initialization was refused")
        await self.write(out)
        if flight.method == "initialize":
            self.phase = "awaiting-initialized"
        return True



async def run_http_guard_async(url, token, state, io, *, timeout, concurrency, transport=None,
                               stop_signals=False):
    endpoint = checked_endpoint(url, token)
    if state.config.normalization_image is not None:
        raise TransportFailure("universal normalization is unsupported over Streamable HTTP")
    if (not math.isfinite(timeout) or not 0 < timeout <= 600 or not 1 <= concurrency <= 32
            or state.config.max_inflight < 1 or not 1024 <= state.config.max_frame_bytes <= 8 * 1024 * 1024):
        raise TransportFailure("invalid HTTP guard timeout or resource limits")
    concurrency = min(state.config.max_inflight, concurrency)
    state.config.strict = state.config.strict_frame_cap = True
    upstream = HTTPTransport(endpoint, token, limit=state.config.max_frame_bytes, timeout=timeout,
                             concurrency=concurrency, transport=transport)
    return await _Session(upstream, state, io, timeout, concurrency).run(stop_signals=stop_signals)


def run_http_guard(url, token, state, *, timeout, concurrency) -> int:
    async def run() -> int:
        try:
            with nonblocking_pipes(sys.stdin.fileno(), sys.stdout.fileno()) as io:
                return await run_http_guard_async(url, token, state, io, timeout=timeout,
                                                  concurrency=concurrency, stop_signals=True)
        except TransportFailure as exc:
            logger.error("HTTP guard: %s", exc)
        except (Exception, KeyboardInterrupt):
            logger.error("HTTP guard: adapter stopped")
        return 2

    return anyio.run(run)
