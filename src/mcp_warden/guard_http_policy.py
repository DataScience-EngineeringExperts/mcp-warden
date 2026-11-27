"""Async network IO for the existing guard's HTTP result inspection path."""

from __future__ import annotations

import socket

import anyio

from .framing import MODE_NEWLINE, Frame
from .guard_loop import GuardState, StrictInspectionAbort
from .guard_result import _dns_findings, _dns_targets, handle_s2c
from .res_dns import classify_resolved

_MAX_DNS_HOSTS = 32
_DNS_TIMEOUT_SECONDS = 1


async def inspect_response(state: GuardState, frame: Frame, method: str, rpc_id) -> bytes:
    findings = []
    if (method == "tools/call" and "result" in frame.json
            and state.config.category_enabled("WRD-RES-EXFIL-DNS-SSRF")):
        try:
            tool = state.inflight_tool[rpc_id]
            targets, hosts = _dns_targets(frame.json["result"])
            if len(hosts) > _MAX_DNS_HOSTS:
                raise ValueError
            if hosts:
                findings = _dns_findings(targets, tool, await _resolve(hosts))
        except Exception:
            raise StrictInspectionAbort(
                site="result-dns", tool="?", exc_type="DNSInspectionFailure", rpc_id=rpc_id,
            ) from None
    return handle_s2c(state, frame, MODE_NEWLINE, dns_findings=findings)


async def _resolve(hosts: list[str]) -> list[tuple[str, str, str]]:
    hits = []

    async def lookup(host):
        try:
            info = await anyio.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError:
            return
        hits.extend(classify_resolved(host, list({addr[0] for *_, addr in info})))

    with anyio.move_on_after(_DNS_TIMEOUT_SECONDS):
        async with anyio.create_task_group() as group:
            for host in hosts:
                group.start_soon(lookup, host)
    return sorted(hits)
