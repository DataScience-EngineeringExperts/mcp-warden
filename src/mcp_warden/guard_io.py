"""Async stdio adapters for the guard proxy (GUARD_PROXY.md §2.3).

Bridges the real process's **blocking** binary stdin/stdout/stderr to the
``receive()`` / ``send()`` async interface the single-loop framer expects, using
``anyio.to_thread`` so the event loop is never blocked. Kept out of ``guard.py``
to respect the per-module LOC budget.
"""

from __future__ import annotations

import os

import anyio


def wrap_recv(binary_io):
    """Adapt a blocking binary stdin to an async ``receive()`` over a thread.

    Uses ``os.read`` on the underlying fd so a small line returns immediately
    (a buffered ``read(n)`` would block for the full ``n`` bytes and stall the
    incremental framer). Falls back to ``read(65536)`` if no fileno is available.

    Args:
        binary_io: A blocking binary read stream (e.g. ``sys.stdin.buffer``).

    Returns:
        An object exposing ``async receive() -> bytes`` (``b""`` at EOF).
    """
    fileno = None
    try:
        fileno = binary_io.fileno()
    except (OSError, AttributeError, ValueError):
        fileno = None

    class _Recv:
        async def receive(self) -> bytes:
            # abandon_on_cancel=True: when the loop is cancelled mid-read (e.g. the
            # child exited and the teardown path must run), do NOT wait for this
            # blocking client-stdin read to return — abandon the thread so the task
            # group exits promptly. Otherwise a still-connected client would deadlock
            # teardown (the read never completes). The proxy is shutting down anyway.
            if fileno is not None:
                return await anyio.to_thread.run_sync(lambda: os.read(fileno, 65536), abandon_on_cancel=True)
            return await anyio.to_thread.run_sync(lambda: binary_io.read(65536), abandon_on_cancel=True)

    return _Recv()


def wrap_send(binary_io):
    """Adapt a blocking binary stdout/stderr to an async ``send()``.

    Args:
        binary_io: A blocking binary write stream (e.g. ``sys.stdout.buffer``).

    Returns:
        An object exposing ``async send(data: bytes)`` + ``async aclose()``.
    """

    class _Send:
        async def send(self, data: bytes) -> None:
            def _write() -> None:
                binary_io.write(data)
                binary_io.flush()

            await anyio.to_thread.run_sync(_write)

        async def aclose(self) -> None:
            return None

    return _Send()
