"""Exercise the CLI over real stdio pipes and a synthetic loopback endpoint."""

from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

from tests.fixtures.guard_http_loopback import TOKEN, VERSION, server

pytestmark = pytest.mark.skipif(os.name != "posix", reason="HTTP adapter uses POSIX stdio")


async def test_cli_subprocess_connects_applies_shared_policy_and_deletes_session(tmp_path):
    trace = tmp_path / "trace.jsonl"
    with server() as (url, deleted):
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "mcp_warden.cli", "guard", "--quiet", "--url", url,
            "--http-token-env", "DSE1077_TEST_TOKEN", "--record", str(trace),
            env={**os.environ, "DSE1077_TEST_TOKEN": TOKEN, "WARDEN_LOG_LEVEL": "DEBUG"},
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def send(**message):
            process.stdin.write(json.dumps({"jsonrpc": "2.0", **message}).encode() + b"\n")
            await process.stdin.drain()

        async def receive():
            return json.loads(await asyncio.wait_for(process.stdout.readline(), 5))

        try:
            await send(id=1, method="initialize", params={
                "protocolVersion": VERSION, "capabilities": {},
                "clientInfo": {"name": "fixture", "version": "1"},
            })
            assert (await receive())["result"]["protocolVersion"] == VERSION
            await send(method="notifications/initialized")
            await send(id=2, method="tools/call", params={
                "name": "echo", "arguments": {"size": 8},
            })
            assert (await receive())["result"]["content"][0]["text"] == "aaaaaaaa"
            process.terminate()
            _, stderr = await asyncio.wait_for(process.communicate(), 5)
        finally:
            if process.returncode is None:
                process.kill()
                await process.communicate()
        assert process.returncode == 0 and deleted.is_set()
        assert TOKEN.encode() not in stderr
    assert TOKEN not in trace.read_text()
    assert trace.stat().st_mode & 0o777 == 0o600
