"""Compare warm MCP request latency on the builder using the loopback fixture."""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from time import perf_counter_ns

import httpx2 as httpx
from tests.fixtures.guard_http_loopback import TOKEN, VERSION, server

ROOT = Path(__file__).resolve().parents[1]
INITIALIZE = {
    "id": 0, "method": "initialize", "params": {
        "protocolVersion": VERSION, "capabilities": {},
        "clientInfo": {"name": "benchmark", "version": "1"},
    },
}
INITIALIZED = {"method": "notifications/initialized"}


@contextmanager
def through_guard(*args):
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_warden.cli", "guard", "--quiet", *args],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "DSE1077_BENCH_TOKEN": TOKEN},
    )

    def request(message):
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", **message}).encode() + b"\n")
        proc.stdin.flush()
        if "id" in message:
            return json.loads(proc.stdout.readline())

    try:
        yield request
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=10)
        finally:
            if proc.returncode is None:
                proc.kill()
                proc.wait()
        if proc.returncode:
            raise RuntimeError("benchmark guard exited with an error")


@contextmanager
def direct_http(url):
    headers = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json, text/event-stream",
               "Accept-Encoding": "identity"}
    with httpx.Client(trust_env=False, timeout=5) as client:
        def request(message):
            response = client.post(url, headers=headers, json={"jsonrpc": "2.0", **message})
            response.raise_for_status()
            if message["method"] == "initialize":
                headers["MCP-Session-Id"] = response.headers["MCP-Session-Id"]
                headers["MCP-Protocol-Version"] = VERSION
            return response.json() if "id" in message else None

        yield request


def measure(request, size, count):
    assert request(INITIALIZE)["result"]["protocolVersion"] == VERSION
    request(INITIALIZED)
    durations = []
    for i in range(count + 20):
        msg = {"id": i + 1, "method": "tools/call",
               "params": {"name": "echo", "arguments": {"size": size}}}
        start = perf_counter_ns()
        reply = request(msg)
        elapsed = perf_counter_ns() - start
        assert len(reply["result"]["content"][0]["text"]) == size
        if i >= 20:
            durations.append(elapsed / 1_000_000)
    return {
        "p50_ms": round(statistics.median(durations), 3),
        "p95_ms": round(statistics.quantiles(durations, n=100, method="inclusive")[94], 3),
    }


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--count", type=int, default=200)
    args = cli.parse_args()
    fixture = str(ROOT / "tests" / "fixtures" / "guard_http_loopback.py")
    with server() as (url, _):
        for size in (8, 65_536):
            by_route = {}
            for name, route in (
                ("direct_http", direct_http(url)),
                ("guard_http", through_guard("--url", url, "--http-token-env", "DSE1077_BENCH_TOKEN")),
                ("guard_stdio", through_guard(sys.executable, fixture)),
            ):
                with route as request:
                    by_route[name] = measure(request, size, args.count)
            print(json.dumps({"bytes": size, "samples": args.count, **by_route}))


if __name__ == "__main__":
    main()
