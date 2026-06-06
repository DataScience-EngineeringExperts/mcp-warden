"""The ``guard`` stdio proxy runner (GUARD_PROXY.md §1, §2.3, §2.6).

Single async event loop (anyio). Spawns the child MCP server as an argv array in
its OWN process group, forwards signals to the child, runs two direction tasks
(client->server, server->client) — each with ONE reader/framer — and exits with
the child's exit code.

The frame-handling/inspection/block logic lives in ``guard_loop.py``; this module
owns process lifecycle, the byte plumbing, and signal forwarding.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
from typing import Any, Callable

import anyio
from anyio.abc import Process

from .framing import FrameReader
from .guard_loop import GuardConfig, GuardState, handle_c2s, handle_s2c

logger = logging.getLogger("mcp_warden.guard")

GUARD_FATAL_EXIT = 2

#: Signals forwarded to the child process group (§2.6). POSIX only.
_FORWARD_SIGNALS = (
    [signal.SIGINT, signal.SIGTERM, signal.SIGHUP] if hasattr(signal, "SIGHUP") else [signal.SIGINT, signal.SIGTERM]
)


async def _pump_client_to_server(
    state: GuardState,
    reader: FrameReader,
    server_stdin,
    client_stdout,
) -> None:
    """Read client frames, enforce request policy, forward to server stdin (§4.1)."""
    try:
        while True:
            frame = await reader.read_frame()
            if frame is None:
                break
            if len(frame.raw) > state.config.max_frame_bytes:
                # Over-cap: pass through unmodified with a frame-error note (§2.5).
                from .guard_loop import _frame_error_note

                state.emit(_frame_error_note("c2s", None, "frame exceeds max-frame-bytes (passed through)"))
                out = frame.raw
            else:
                out = handle_c2s(state, frame, reader.mode or "newline")
            if state.pending_client_error is not None:
                # A request was withheld; send the synthesized error back to client.
                await client_stdout.send(state.pending_client_error)
                state.pending_client_error = None
                continue
            if out:
                await server_stdin.send(out)
    except anyio.BrokenResourceError:
        logger.debug("client->server pump: stream closed")
    finally:
        try:
            await server_stdin.aclose()
        except Exception:  # noqa: BLE001 - best-effort close on shutdown
            pass


async def _pump_server_to_client(
    state: GuardState,
    reader: FrameReader,
    client_stdout,
) -> None:
    """Read server frames, inspect tools/call results, forward to client (§4.2)."""
    try:
        while True:
            frame = await reader.read_frame()
            if frame is None:
                break
            if len(frame.raw) > state.config.max_frame_bytes:
                from .guard_loop import _frame_error_note

                state.emit(_frame_error_note("s2c", None, "frame exceeds max-frame-bytes (passed through)"))
                out = frame.raw
            else:
                out = handle_s2c(state, frame, reader.mode or "newline")
            if out:
                await client_stdout.send(out)
    except anyio.BrokenResourceError:
        logger.debug("server->client pump: stream closed")


async def _pump_stderr(server_stderr, client_stderr) -> None:
    """Forward child stderr to guard stderr unmodified/uninspected (§4.5)."""
    try:
        async for chunk in server_stderr:
            await client_stderr.send(chunk)
    except anyio.BrokenResourceError:
        pass


def _install_signal_forwarding(tg: anyio.abc.TaskGroup, proc: Process) -> None:
    """Forward guard signals to the child's process group (§2.6, POSIX)."""

    async def _watch() -> None:
        if not hasattr(signal, "SIGINT"):
            return
        with anyio.open_signal_receiver(*_FORWARD_SIGNALS) as sigs:
            async for signum in sigs:
                logger.info("guard received signal %s; forwarding to child pgrp", signum)
                _signal_child(proc, signum)

    try:
        tg.start_soon(_watch)
    except Exception as exc:  # signal receiver unavailable (e.g. non-main thread)
        logger.debug("signal forwarding unavailable: %s", exc)


def _signal_child(proc: Process, signum: int) -> None:
    """Send a signal to the child's process group (best-effort)."""
    pid = proc.pid
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(pid), signum)
        else:  # Windows: experimental best-effort
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError) as exc:
        logger.debug("could not signal child %s: %s", pid, exc)


async def run_guard_async(
    command: str,
    args: list[str],
    state: GuardState,
    *,
    stdin=None,
    stdout=None,
    stderr=None,
) -> int:
    """Run the guard proxy until the child exits; return the child's exit code.

    Args:
        command: ``argv[0]`` of the server launch (argv array; NEVER a shell).
        args: Remaining argv.
        state: The configured :class:`GuardState`.
        stdin/stdout/stderr: Override byte streams (used by tests). Defaults to
            the real process stdio when ``None``.

    Returns:
        The child's exit code (or :data:`GUARD_FATAL_EXIT` on guard fatal error).
    """
    client_in = stdin if stdin is not None else _wrap_recv(sys.stdin.buffer)
    client_out = stdout if stdout is not None else _wrap_send(sys.stdout.buffer)
    client_err = stderr if stderr is not None else _wrap_send(sys.stderr.buffer)

    posix_kwargs: dict[str, Any] = {}
    if os.name == "posix":
        posix_kwargs["start_new_session"] = True  # own process group (§2.6)

    try:
        proc = await anyio.open_process(
            [command, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **posix_kwargs,
        )
    except FileNotFoundError:
        logger.error("guard: server command not found: %s", command)
        return GUARD_FATAL_EXIT
    except Exception as exc:  # spawn failure
        logger.error("guard: failed to spawn child: %s", exc)
        return GUARD_FATAL_EXIT

    c2s_reader = FrameReader(client_in.receive, state.config.max_frame_bytes)
    s2c_reader = FrameReader(proc.stdout.receive, state.config.max_frame_bytes)

    async with anyio.create_task_group() as tg:
        _install_signal_forwarding(tg, proc)
        tg.start_soon(_pump_client_to_server, state, c2s_reader, proc.stdin, client_out)
        tg.start_soon(_pump_server_to_client, state, s2c_reader, client_out)
        if proc.stderr is not None:
            tg.start_soon(_pump_stderr, proc.stderr, client_err)
        await proc.wait()
        tg.cancel_scope.cancel()

    code = proc.returncode if proc.returncode is not None else 0
    logger.info("guard: child exited with code %s", code)
    return code


def _wrap_recv(binary_io):
    """Adapt a blocking binary stdin to an async receive() over a thread.

    Uses ``os.read`` on the underlying fd so a small line returns immediately
    (a buffered ``read(n)`` would block for the full ``n`` bytes and stall the
    incremental framer). Falls back to ``read(65536)`` if no fileno is available.
    """
    fileno = None
    try:
        fileno = binary_io.fileno()
    except (OSError, AttributeError, ValueError):
        fileno = None

    class _Recv:
        async def receive(self) -> bytes:
            if fileno is not None:
                return await anyio.to_thread.run_sync(lambda: os.read(fileno, 65536))
            return await anyio.to_thread.run_sync(lambda: binary_io.read(65536))

    return _Recv()


def _wrap_send(binary_io):
    """Adapt a blocking binary stdout/stderr to an async send()."""

    class _Send:
        async def send(self, data: bytes) -> None:
            def _write() -> None:
                binary_io.write(data)
                binary_io.flush()

            await anyio.to_thread.run_sync(_write)

        async def aclose(self) -> None:
            return None

    return _Send()


def run_guard(
    command: str,
    args: list[str],
    config: GuardConfig,
    *,
    lock: Any = None,
    policy: Any = None,
    exfil_denylist: tuple[str, ...] | None = None,
    inject_phrases: tuple[str, ...] | None = None,
    on_finding: Callable | None = None,
    record: Callable | None = None,
) -> int:
    """Synchronous entry point for the CLI: build state and run the loop.

    Args:
        command/args: The server launch argv.
        config: The :class:`GuardConfig`.
        lock/policy: Optional loaded lock + policy.
        exfil_denylist/inject_phrases: Merged seed+org lists (defaults to seed).
        on_finding/record: Optional sinks.

    Returns:
        The child's exit code.
    """
    from . import res_rules

    state = GuardState(
        config=config,
        lock=lock,
        policy=policy,
        exfil_denylist=exfil_denylist or res_rules.SEED_EXFIL_DENYLIST,
        inject_phrases=inject_phrases or res_rules.SEED_INJECT_PHRASES,
        on_finding=on_finding,
        record=record,
    )
    return anyio.run(run_guard_async, command, args, state)
