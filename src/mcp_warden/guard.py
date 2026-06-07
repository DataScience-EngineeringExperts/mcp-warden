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
import subprocess
import sys
from typing import Any, Callable

import anyio
from anyio.abc import Process

from .framing import MODE_NEWLINE, FrameReader
from .guard_io import wrap_recv, wrap_send
from .guard_lifecycle import exit_code_for_child, forward_signals, synthesize_pending_errors, teardown_child
from .guard_loop import GuardConfig, GuardState, handle_c2s, handle_s2c

logger = logging.getLogger("mcp_warden.guard")

GUARD_FATAL_EXIT = 2
GUARD_TRANSPORT_EXIT = 2  # client-disconnect transport exit (v0.1 IO-error code)


class _Channels:
    """Shared, single-loop-owned signals between the pumps and the teardown path."""

    def __init__(self) -> None:
        #: Client-facing framing mode observed on s2c (for synthesizing -32002).
        self.client_mode: str = MODE_NEWLINE
        #: True once the client closed its end (EOF on guard stdin) -> §2.2 teardown.
        self.client_eof: bool = False
        #: True once a broken-pipe was seen on client stdout (clean teardown).
        self.client_pipe_broken: bool = False


async def _pump_client_to_server(
    state: GuardState,
    reader: FrameReader,
    server_stdin,
    client_stdout,
    chan: "_Channels",
) -> None:
    """Read client frames, enforce request policy, forward to server stdin (§4.1).

    On client EOF (stdin closed) sets ``chan.client_eof`` so the main loop runs
    the §2.2 process-group teardown. A truncated/partial frame at EOF is
    discarded with a ``WRD-RES-FRAME-ERROR`` note (fail-open, §2.3) — never hung.
    """
    try:
        while True:
            frame = await reader.read_frame()
            if frame is None:
                chan.client_eof = True
                break
            _note_truncation(state, "c2s", frame)
            if len(frame.raw) > state.config.max_frame_bytes:
                # Over-cap: pass through unmodified with a frame-error note (§2.4).
                from .guard_loop import _frame_error_note

                state.emit(_frame_error_note("c2s", None, "frame exceeds max-frame-bytes (passed through)"))
                out = frame.raw
            else:
                out = handle_c2s(state, frame, reader.mode or MODE_NEWLINE)
            if state.pending_client_error is not None:
                # A request was withheld; send the synthesized error back to client.
                await client_stdout.send(state.pending_client_error)
                state.pending_client_error = None
                continue
            if out:
                await server_stdin.send(out)
    except anyio.BrokenResourceError:
        # The server pipe broke (child gone). Treat as EOF on this direction.
        logger.debug("client->server pump: server stream closed")
    finally:
        try:
            await server_stdin.aclose()
        except Exception:  # noqa: BLE001 - best-effort close on shutdown
            pass


async def _pump_server_to_client(
    state: GuardState,
    reader: FrameReader,
    client_stdout,
    chan: "_Channels",
) -> None:
    """Read server frames, inspect tools/call results, forward to client (§4.2).

    Records the client-facing framing mode for later ``-32002`` synthesis. A
    broken pipe on client stdout is a CLEAN teardown (client gone), not a crash:
    no traceback (§2.2.3).
    """
    try:
        while True:
            frame = await reader.read_frame()
            if frame is None:
                break
            chan.client_mode = reader.mode or MODE_NEWLINE
            _note_truncation(state, "s2c", frame)
            if len(frame.raw) > state.config.max_frame_bytes:
                from .guard_loop import _frame_error_note

                state.emit(_frame_error_note("s2c", None, "frame exceeds max-frame-bytes (passed through)"))
                out = frame.raw
            else:
                out = handle_s2c(state, frame, reader.mode or MODE_NEWLINE)
            if out:
                try:
                    await client_stdout.send(out)
                except anyio.BrokenResourceError:
                    chan.client_pipe_broken = True
                    logger.debug("server->client pump: client stdout closed (clean teardown)")
                    break
    except anyio.BrokenResourceError:
        logger.debug("server->client pump: stream closed")


def _note_truncation(state: GuardState, direction: str, frame) -> None:
    """Emit a WRD-RES-FRAME-ERROR note for a truncated frame at EOF (§2.3, fail-open)."""
    if frame.json is None and frame.parse_error and "truncated" in frame.parse_error:
        from .guard_loop import _frame_error_note

        state.emit(_frame_error_note(direction, None, frame.parse_error))


async def _pump_stderr(server_stderr, client_stderr) -> None:
    """Forward child stderr to guard stderr unmodified/uninspected (§4.5)."""
    try:
        async for chunk in server_stderr:
            await client_stderr.send(chunk)
    except anyio.BrokenResourceError:
        pass


def _install_signal_forwarding(tg: anyio.abc.TaskGroup, proc: Process) -> None:
    """Forward guard signals to the child's process group (§2.6, POSIX-only)."""
    sigs = list(forward_signals())
    if not sigs:
        return  # Windows or no signal model: nothing to forward here

    async def _watch() -> None:
        with anyio.open_signal_receiver(*sigs) as receiver:
            async for signum in receiver:
                logger.info("guard received signal %s; forwarding to child pgrp", signum)
                _signal_child(proc, signum)

    try:
        tg.start_soon(_watch)
    except Exception as exc:  # signal receiver unavailable (e.g. non-main thread)
        logger.debug("signal forwarding unavailable: %s", exc)


def _signal_child(proc: Process, signum: int) -> None:
    """Send a signal to the child's process group (best-effort, POSIX)."""
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
    client_in = stdin if stdin is not None else wrap_recv(sys.stdin.buffer)
    client_out = stdout if stdout is not None else wrap_send(sys.stdout.buffer)
    client_err = stderr if stderr is not None else wrap_send(sys.stderr.buffer)

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
    chan = _Channels()

    async def _watch_child(tg: anyio.abc.TaskGroup) -> None:
        """Await child exit; cancel the loop so teardown can run (§2.1)."""
        await proc.wait()
        tg.cancel_scope.cancel()

    async def _watch_client_eof(tg: anyio.abc.TaskGroup) -> None:
        """Poll for client EOF; cancel the loop so the §2.2 teardown can run."""
        while not chan.client_eof and not chan.client_pipe_broken:
            await anyio.sleep(0.02)
            if proc.returncode is not None:
                return  # child already exiting; _watch_child owns the cancel
        tg.cancel_scope.cancel()

    async with anyio.create_task_group() as tg:
        _install_signal_forwarding(tg, proc)
        tg.start_soon(_pump_client_to_server, state, c2s_reader, proc.stdin, client_out, chan)
        tg.start_soon(_pump_server_to_client, state, s2c_reader, client_out, chan)
        if proc.stderr is not None:
            tg.start_soon(_pump_stderr, proc.stderr, client_err)
        tg.start_soon(_watch_child, tg)
        tg.start_soon(_watch_client_eof, tg)

    # Decide the teardown path: client gone first vs child exited first (§2.1/§2.2).
    client_gone = (chan.client_eof or chan.client_pipe_broken) and proc.returncode is None
    if client_gone:
        # §2.2: no synthetic responses are owed to a gone client; reap the child.
        await teardown_child(proc, on_note=state.emit)
        code = exit_code_for_child(proc.returncode) if proc.returncode is not None else GUARD_TRANSPORT_EXIT
        logger.info("guard: client disconnected; child reaped, exit code %s", code)
        return code

    # §2.1: child exited (possibly mid-call). Synthesize -32002 for every pending
    # id BEFORE the client pipes close, then exit with the child's status.
    await synthesize_pending_errors(state, client_out, chan.client_mode, proc.returncode)
    code = exit_code_for_child(proc.returncode)
    logger.info("guard: child exited with code %s", code)
    return code


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
