"""Synthetic Streamable HTTP lifecycle and policy parity."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import httpx2 as httpx
import pytest

from mcp_warden import guard_result
from mcp_warden.guard_http import run_http_guard_async
from mcp_warden.guard_http_frames import (
    FrameLimit,
    TransportFailure,
    bounded_body,
    bounded_lines,
    parse_frame,
)
from mcp_warden.guard_http_trace import HTTPTrace
from mcp_warden.guard_http_transport import checked_endpoint
from mcp_warden.guard_loop import GuardConfig, GuardState
from mcp_warden.inspector import analyze_trace

TOKEN = "synthetic-upstream-authorization-token"
SESSION = "synthetic-upstream-session-id"
URL = "https://upstream.test/mcp"
VERSION = "2025-11-25"


def rpc(method=None, rpc_id=None, **fields):
    message = {"jsonrpc": "2.0", **fields}
    if method is not None:
        message["method"] = method
    if rpc_id is not None:
        message["id"] = rpc_id
    return message


def result(rpc_id, text):
    return rpc(rpc_id=rpc_id, result={"content": [{"type": "text", "text": text}]})


async def chunks(*parts):
    for part in parts:
        yield part


class Stream(httpx.AsyncByteStream):
    def __init__(self, *parts):
        self.parts = parts
        self.closed = False
        self.count = 0

    async def __aiter__(self):
        for part in self.parts:
            self.count += 1
            if isinstance(part, asyncio.Event):
                await part.wait()
            elif isinstance(part, Exception):
                raise part
            else:
                yield part

    async def aclose(self):
        self.closed = True


def sse(*parts):
    return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=Stream(*parts))


def event(obj):
    return b"data: " + json.dumps(obj).encode() + b"\r\n\r\n"


def reply(obj, **headers):
    return httpx.Response(
        200, headers={"Content-Type": "application/json", **headers},
        stream=Stream(json.dumps(obj).encode()),
    )


class Pipe:
    def __init__(self, *, hold_output=None):
        self.requests = asyncio.Queue()
        self.responses = asyncio.Queue()
        self.hold_output = hold_output

    async def chunks(self):
        while (line := await self.requests.get()) is not None:
            yield line

    async def send(self, data):
        obj = json.loads(data)
        if self.hold_output is not None and obj.get("id") == 2:
            await self.hold_output.wait()
        self.responses.put_nowait(obj)

    def request(self, **obj):
        self.requests.put_nowait(json.dumps(rpc(**obj)).encode() + b"\n")

    async def response(self):
        return await asyncio.wait_for(self.responses.get(), 2)


class Upstream:
    def __init__(self, handler, *, stateful=True):
        self.handler = handler
        self.stateful = stateful
        self.requests = []
        self.ready = asyncio.Event()

    async def __call__(self, request):
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert request.headers["accept-encoding"] == "identity"
        assert "cookie" not in request.headers
        obj = json.loads(request.content) if request.content else None
        self.requests.append((request.method, obj))
        if obj and obj.get("method") == "initialize":
            assert "mcp-session-id" not in request.headers
            assert obj["params"]["capabilities"] == {}
            return reply(
                rpc(rpc_id=obj["id"], result={"protocolVersion": VERSION,
                    "capabilities": {"tools": {}, "tasks": {}}, "serverInfo": {"name": "fixture"}}),
                **({"MCP-Session-Id": SESSION, "Set-Cookie": "fixture=secret"} if self.stateful else {}),
            )
        assert request.headers.get("mcp-session-id") == (SESSION if self.stateful else None)
        assert request.headers["mcp-protocol-version"] == VERSION
        if request.method == "DELETE":
            return httpx.Response(204)
        if request.method == "GET" and "last-event-id" not in request.headers:
            return httpx.Response(405)
        if obj and obj.get("method") == "notifications/initialized":
            self.ready.set()
            return httpx.Response(202)
        return await self.handler(request, obj)


@asynccontextmanager
async def harness(upstream, *, state=None, timeout=1, concurrency=2, pipe=None):
    pipe = pipe or Pipe()
    state = state or GuardState(GuardConfig(max_frame_bytes=4096))
    adapter = asyncio.create_task(run_http_guard_async(
        URL, TOKEN, state, pipe, timeout=timeout, concurrency=concurrency,
        transport=httpx.MockTransport(upstream),
    ))
    try:
        pipe.request(method="initialize", rpc_id=1, params={
            "protocolVersion": VERSION, "capabilities": {"roots": {}},
            "clientInfo": {"name": "fixture", "version": "1"},
        })
        init = await pipe.response()
        assert init["result"]["capabilities"] == {"tools": {}}
        pipe.request(method="notifications/initialized")
        await asyncio.wait_for(upstream.ready.wait(), 2)
        yield pipe, adapter
    finally:
        pipe.requests.put_nowait(None)
        await asyncio.wait_for(adapter, 3)


def call(pipe, rpc_id=2, **params):
    pipe.request(method="tools/call", rpc_id=rpc_id, params={"name": "fixture", **params})


async def test_policy_redaction_and_offline_verdict_parity(tmp_path):
    from mcp_warden.policy_model import load_policy
    path = tmp_path / "policy.yml"
    path.write_text(
        "version: 1\ndefaults:\n  http_request:\n    deny_private: true\n",
        encoding="utf-8",
    )
    policy, _ = load_policy(path)
    inspected = []
    state = GuardState(GuardConfig(armed_policy=True, no_block_exfil_dns_ssrf=True),
                       policy=policy, on_finding=inspected.append)

    async def handle(request, obj):
        return reply(result(obj["id"], "before\x1b[31mafter"))

    upstream = Upstream(handle)
    trace_path = tmp_path / "trace.jsonl"
    with HTTPTrace(trace_path) as trace:
        state.record = trace.frame
        state.record_withheld = trace.withheld
        async with harness(upstream, state=state) as (pipe, _):
            call(pipe, arguments={"url": "http://127.0.0.1:9/private"})
            denied = await pipe.response()
            assert denied["error"]["code"] == -32001
            call(pipe, 3, arguments={})
            redacted = await pipe.response()
            assert "\x1b" not in redacted["result"]["content"][0]["text"]
            assert redacted["result"]["_meta"]["warden"]["modified"] is True
    assert [obj["id"] for _, obj in upstream.requests
            if obj and obj.get("method") == "tools/call"] == [3]
    offline = analyze_trace(trace_path)
    assert {(f.rule_id, f.tier) for f in inspected if f.direction == "s2c"} == {
        (f.rule_id, f.tier) for f in offline if f.direction == "s2c"
    }
    raw = trace_path.read_text()
    assert '"forwarded": false' in raw and TOKEN not in raw and SESSION not in raw


async def test_post_stream_progress_and_cursor_resume_without_post_replay():
    started = asyncio.Event()
    progress = rpc(method="notifications/progress", params={"progressToken": "permit", "progress": 1})

    async def handle(request, obj):
        if request.method == "GET":
            assert request.headers["last-event-id"] == "cursor-1"
            return sse(event(result(2, "done")))
        started.set()
        return sse(b"id: cursor-1\r", b"\ndata:\r\n\r\n", event(progress))

    upstream = Upstream(handle)
    async with harness(upstream) as (pipe, _):
        call(pipe, _meta={"progressToken": "permit"})
        assert await pipe.response() == progress
        assert await pipe.response() == result(2, "done")
        assert started.is_set()
    assert sum(obj is not None and obj.get("method") == "tools/call"
               for _, obj in upstream.requests) == 1
    assert upstream.requests[-1][0] == "DELETE"


async def test_cancel_while_full_and_disconnect_closes_live_stream():
    started = asyncio.Event()
    cancelled = asyncio.Event()
    hang = asyncio.Event()
    stream = Stream(b": keepalive\n\n", hang)

    async def handle(request, obj):
        if obj["method"] == "notifications/cancelled":
            assert obj["params"]["requestId"] == 2
            cancelled.set()
            return httpx.Response(202)
        started.set()
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=stream)

    upstream = Upstream(handle)
    async with harness(upstream, concurrency=1) as (pipe, _):
        call(pipe)
        await asyncio.wait_for(started.wait(), 1)
        call(pipe, 3)
        assert (await pipe.response())["error"]["data"]["reason"] == "request concurrency limit exceeded"
        pipe.request(method="notifications/cancelled", params={"requestId": 2})
        await asyncio.wait_for(cancelled.wait(), 1)
    assert stream.closed
    assert pipe.responses.empty()
    assert upstream.requests[-1][0] == "DELETE"


@pytest.mark.parametrize("scenario", ["timeout", "session-expired", "wrong-id", "unsupported", "server-error", "credential", "redirect"])
async def test_upstream_failures_are_safe_and_never_replay(scenario, caplog):
    async def handle(request, obj):
        if scenario == "timeout":
            return sse(asyncio.Event())
        if scenario == "session-expired":
            return httpx.Response(404, text=TOKEN)
        if scenario == "wrong-id":
            return reply(result(3, "wrong response"))
        if scenario == "unsupported":
            return sse(event(rpc(method="sampling/createMessage", rpc_id=4)))
        if scenario == "server-error":
            return reply(rpc(rpc_id=2, error={"code": -32603, "message": "private provider debug"}))
        if scenario == "credential":
            return reply(result(2, TOKEN))
        return httpx.Response(307, headers={"Location": URL + "/" + TOKEN})

    upstream = Upstream(handle)
    async with harness(upstream, timeout=0.1) as (pipe, adapter):
        call(pipe)
        response = await pipe.response()
        assert response["id"] == 2
        assert response["error"]["code"] == (-32603 if scenario == "server-error" else -32002)
        assert TOKEN not in json.dumps(response) and SESSION not in json.dumps(response)
        if scenario == "session-expired":
            assert await asyncio.wait_for(adapter, 2) == 2
    assert TOKEN not in caplog.text and SESSION not in caplog.text
    assert sum(obj is not None and obj.get("method") == "tools/call"
               for _, obj in upstream.requests) == 1


async def test_strict_inspection_abort_does_not_expose_exception(monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError(TOKEN)

    monkeypatch.setattr(guard_result, "inspect_result", fail)

    async def handle(_, obj):
        return reply(result(obj["id"], "uninspected"))

    upstream = Upstream(handle)
    async with harness(upstream) as (pipe, adapter):
        call(pipe)
        assert (await pipe.response())["error"]["code"] == -32003
        assert await asyncio.wait_for(adapter, 2) == 3
    assert "result-inspect" in caplog.text and TOKEN not in caplog.text


@pytest.mark.parametrize("declared", [False, True])
async def test_response_caps_stop_before_reading_the_rest(declared):
    oversized = Stream(b"x" * 2048, b"x" * 2048, b"x" * 1, asyncio.Event())

    async def handle(_, obj):
        headers = {"Content-Type": "application/json"}
        if declared:
            headers["Content-Length"] = "4097"
        return httpx.Response(200, headers=headers, stream=oversized)

    upstream = Upstream(handle)
    async with harness(upstream) as (pipe, adapter):
        call(pipe)
        assert (await pipe.response())["error"]["code"] == -32003
        assert await asyncio.wait_for(adapter, 2) == 3
    assert oversized.count == (0 if declared else 3)
    assert oversized.closed


async def test_backpressure_closes_stalled_output_without_releasing_more_sse_frames():
    hold = asyncio.Event()
    stream = Stream(event(result(2, "first")), event(result(2, "next")))

    async def handle(_, obj):
        return httpx.Response(200, headers={"Content-Type": "text/event-stream"}, stream=stream)

    upstream = Upstream(handle)
    async with harness(upstream, timeout=0.1, pipe=Pipe(hold_output=hold)) as (pipe, adapter):
        call(pipe)
        assert await asyncio.wait_for(adapter, 2) == 2
    assert stream.count == 1 and stream.closed


async def test_bounded_framing_and_origin_checks():
    output = [line async for line in bounded_lines(chunks(b"a\r", b"\nb\rc\n"), 1, sse=True)]
    assert output == [b"a", b"b", b"c"]
    with pytest.raises(FrameLimit):
        await bounded_body(chunks(b"ab", b"cd"), 3)
    with pytest.raises(FrameLimit):
        _ = [line async for line in bounded_lines(chunks(b"ab", b"cd"), 3)]
    for url in ("http://upstream.test/mcp", "https://user:pw@upstream.test/mcp",
                "https://upstream.test/mcp?key=secret", "https://upstream.test/mcp#secret"):
        with pytest.raises(TransportFailure):
            checked_endpoint(url, TOKEN)
    assert checked_endpoint("http://127.0.0.1:1234/mcp", None).port == 1234


async def test_list_drift_is_checked_using_the_existing_lock():
    from pathlib import Path

    from mcp_warden.lockfile import read_lock

    lock = read_lock(Path(__file__).parent / "fixtures" / "clean_listchange.warden.lock")
    findings = []
    state = GuardState(GuardConfig(armed_list_changed=True), lock=lock, on_finding=findings.append)
    listed = [False, True]

    async def handle(_, obj):
        tools = [{"name": "read_file", "description": "Read the contents of a file from disk.",
                  "inputSchema": {"type": "object",
                      "properties": {"path": {"type": "string", "description": "Path to read"}},
                      "required": ["path"]}}]
        if listed.pop(0):
            tools.append({"name": "new-unpinned-tool", "inputSchema": {"type": "object"}})
            return sse(event(rpc(method="notifications/tools/list_changed")),
                       event(rpc(rpc_id=obj["id"], result={"tools": tools})))
        return reply(rpc(rpc_id=obj["id"], result={"tools": tools}))

    async with harness(Upstream(handle), state=state) as (pipe, _):
        pipe.request(method="tools/list", rpc_id=2)
        first = await pipe.response()
        pipe.request(method="tools/list", rpc_id=3)
        assert (await pipe.response())["method"] == "notifications/tools/list_changed"
        second = await pipe.response()
        assert second["error"]["data"]["rule"] == "MCP-DRIFT"
    assert "result" in first
    assert [f.action for f in findings if f.rule_id == "MCP-DRIFT"] == ["blocked"]


async def test_dns_inspection_preserves_concurrent_cancellation(monkeypatch):
    import socket

    import anyio

    resolving = asyncio.Event()
    cancelled = asyncio.Event()
    no_reply = asyncio.Event()

    async def resolve(*args, **kwargs):
        resolving.set()
        await no_reply.wait()
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(anyio, "getaddrinfo", resolve)

    async def handle(_, obj):
        if obj["method"] == "notifications/cancelled":
            cancelled.set()
            return httpx.Response(202)
        return reply(result(obj["id"], "https://synthetic.test/result"))

    async with harness(Upstream(handle)) as (pipe, _):
        call(pipe)
        await asyncio.wait_for(resolving.wait(), 1)
        pipe.request(method="notifications/cancelled", params={"requestId": 2})
        await asyncio.wait_for(cancelled.wait(), 1)
        assert pipe.responses.empty()


async def test_stateless_get_is_supported_and_not_silently_lost():
    hold = asyncio.Event()

    class Stateless(Upstream):
        async def __call__(self, request):
            if request.method == "GET":
                assert "mcp-session-id" not in request.headers
                return sse(event(rpc(method="notifications/tools/list_changed")), hold)
            return await super().__call__(request)

    async def handle(request, obj):
        raise AssertionError("unexpected POST")

    async with harness(Stateless(handle, stateful=False)) as (pipe, adapter):
        assert (await pipe.response())["method"] == "notifications/tools/list_changed"
        hold.set()
        assert await asyncio.wait_for(adapter, 2) == 2


@pytest.mark.parametrize("enabled", [True, False])
async def test_literal_ip_disposition_matches_shared_guard(enabled):
    async def handle(_, obj):
        return reply(result(obj["id"], "https://127.0.0.1:9/fixture"))

    state = GuardState(GuardConfig(no_block_exfil_ip_literal=not enabled))
    async with harness(Upstream(handle), state=state) as (pipe, _):
        call(pipe)
        response = await pipe.response()
        if enabled:
            assert response["error"]["data"]["rule"] == "WRD-RES-EXFIL-IP-LITERAL"
        else:
            assert "result" in response


async def test_initialization_must_pass_the_guard_before_admission(monkeypatch, caplog):
    import mcp_warden.guard_http as module

    async def refuse(state, frame, method, rpc_id):
        return b"withheld"

    monkeypatch.setattr(module, "inspect_response", refuse)

    async def handle(_, obj):
        raise AssertionError("upstream should receive no tool calls")

    upstream = Upstream(handle)
    pipe = Pipe()
    state = GuardState(GuardConfig(max_frame_bytes=4096))
    adapter = asyncio.create_task(run_http_guard_async(
        URL, TOKEN, state, pipe, timeout=1, concurrency=2,
        transport=httpx.MockTransport(upstream),
    ))
    pipe.request(method="initialize", rpc_id=1, params={
        "protocolVersion": VERSION, "capabilities": {},
    })
    assert (await pipe.response())["error"]["code"] == -32002
    assert await asyncio.wait_for(adapter, 2) == 2
    assert not upstream.ready.is_set()
    assert TOKEN not in caplog.text


async def test_completed_request_ids_cannot_be_reused():
    async def handle(_, obj):
        return reply(result(obj["id"], "completed"))

    upstream = Upstream(handle)
    async with harness(upstream) as (pipe, adapter):
        call(pipe)
        assert "result" in await pipe.response()
        call(pipe)
        assert await asyncio.wait_for(adapter, 2) == 2
    assert sum(obj is not None and obj.get("method") == "tools/call"
               for _, obj in upstream.requests) == 1


async def test_unsolicited_resume_cannot_wait_past_the_deadline():
    class Delayed(Upstream):
        async def __call__(self, request):
            if request.method == "GET":
                assert "last-event-id" not in request.headers
                return sse(b"id: cursor\nretry: 10000000\ndata:\n\n")
            return await super().__call__(request)

    async def handle(request, obj):
        raise AssertionError("unexpected POST")

    async with harness(Delayed(handle), timeout=0.1) as (_, adapter):
        assert await asyncio.wait_for(adapter, 2) == 2


@pytest.mark.parametrize("body", [
    b'{"jsonrpc":"2.0","result":{"value":789123456789}}',
    rb'{"jsonrpc":"2.0","result":{"value":"\u003789123456789"}}',
])
def test_auth_material_is_refused_as_numeric_or_escaped_json(body):
    with pytest.raises(TransportFailure, match="credential-bearing frame refused"):
        parse_frame(body, ("789123456789",))
