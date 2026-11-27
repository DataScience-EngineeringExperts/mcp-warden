"""Async network IO for the existing guard's HTTP result inspection path."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import anyio

from .framing import MODE_NEWLINE, Frame
from .guard_http_frames import bounded_body
from .guard_loop import GuardState, StrictInspectionAbort
from .guard_result import _dns_findings, _dns_targets, handle_s2c

_MAX_DNS_HOSTS = 32
_DNS_TIMEOUT_SECONDS = 1
_MAX_DNS_OUTPUT = 64 * 1024


async def inspect_response(state: GuardState, frame: Frame, method: str, rpc_id,
                           limiter: anyio.CapacityLimiter) -> bytes:
    findings = []
    if (method == "tools/call" and "result" in frame.json
            and state.config.category_enabled("WRD-RES-EXFIL-DNS-SSRF")):
        try:
            tool = state.inflight_tool[rpc_id]
            targets, hosts = _dns_targets(frame.json["result"])
            if len(hosts) > _MAX_DNS_HOSTS:
                raise ValueError
            if hosts:
                findings = _dns_findings(targets, tool, await _resolve(hosts, limiter))
        except Exception:
            raise StrictInspectionAbort(
                site="result-dns", tool="?", exc_type="DNSInspectionFailure", rpc_id=rpc_id,
            ) from None
    return handle_s2c(state, frame, MODE_NEWLINE, dns_findings=findings)


async def _resolve(hosts: list[str], limiter: anyio.CapacityLimiter) -> list[tuple[str, str, str]]:
    # An event-loop timeout cannot interrupt libc DNS or reap its executor
    # threads at shutdown. Own the subprocess explicitly instead.
    env = {"PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    with anyio.fail_after(_DNS_TIMEOUT_SECONDS):
        async with limiter:
            child = await anyio.open_process(
                [sys.executable, "-P", "-m", "mcp_warden.res_dns"], env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            try:
                await child.stdin.send(json.dumps(hosts).encode("ascii"))
                await child.stdin.aclose()
                output = await bounded_body(child.stdout, _MAX_DNS_OUTPUT)
                if await child.wait() != 0:
                    raise RuntimeError("DNS worker failed")
                return [tuple(hit) for hit in json.loads(output)]
            finally:
                with anyio.CancelScope(shield=True):
                    if child.returncode is None:
                        try:
                            child.kill()
                        except ProcessLookupError:
                            pass
                    await child.aclose()
