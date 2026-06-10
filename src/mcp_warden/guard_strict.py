"""Strict (``--strict``) fail-CLOSED abort handling (GUARD_PROXY_V3.md §5).

Extracted from ``guard.py`` to keep that module under the LOC budget. This module
owns the two strict-only helpers — unwrapping an anyio ``(Base)ExceptionGroup`` to
find a :class:`StrictInspectionAbort`, and the fail-CLOSE teardown ordering — plus
the dedicated strict exit code.

Dependency direction (no import cycle): ``guard.py`` imports FROM this module and
NEVER the reverse. The helpers take every object they need (state / process /
streams / the client framing mode) as PARAMETERS rather than importing back from
``guard.py``; the ``client_mode: str`` parameter stands in for the ``_Channels``
field so this module has zero dependency on ``guard.py``'s plumbing types.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from anyio.abc import Process

from .guard_lifecycle import synthesize_strict_abort, teardown_child
from .guard_loop import GuardState, StrictInspectionAbort

logger = logging.getLogger("mcp_warden.guard")

#: Dedicated exit code for a ``--strict`` abort: an internal inspection error
#: terminated the session fail-CLOSED. DISTINCT from child-natural (0..127),
#: 128+signum, ``GUARD_FATAL_EXIT(2)``, and ``GUARD_TRANSPORT_EXIT(2)`` so an
#: operator can tell "terminated by internal inspection error" from "blocked by
#: policy".
GUARD_STRICT_EXIT = 3

#: Defense-in-depth cap on the rendered ``exc_type`` length. It is already a
#: Python class name (an identifier, so bounded + benign), but capping it bounds
#: the reason string / structured stderr against a pathologically long custom
#: exception class name. Sanitized fields only — never the original message.
_EXC_TYPE_CAP = 64


def _find_strict_abort(exc: BaseException) -> StrictInspectionAbort | None:
    """Unwrap an anyio (Base)ExceptionGroup to find a :class:`StrictInspectionAbort`.

    anyio's task group raises a ``BaseExceptionGroup`` aggregating every task
    failure; a ``StrictInspectionAbort`` (a ``BaseException``) is carried inside
    it (possibly nested). Returns the FIRST abort found in depth-first order, or
    ``None`` if the group holds no strict abort (then the caller re-raises).

    Args:
        exc: The exception (or exception group) raised out of the task group.

    Returns:
        The first :class:`StrictInspectionAbort`, or ``None``.
    """
    if isinstance(exc, StrictInspectionAbort):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            found = _find_strict_abort(sub)
            if found is not None:
                return found
    return None


async def _handle_strict_abort(
    state: GuardState,
    proc: Process,
    client_out,
    client_err,
    client_mode: str,
    abort: StrictInspectionAbort,
) -> int:
    """Fail-CLOSE the session after a strict inspection abort (binding #5 ordering).

    Ordering (exact): the offending frame is ALREADY not forwarded (the pump
    raised before any write of it, binding #2) -> synthesize a ``-32003`` error
    to every in-flight id so the client never hangs -> set ``strict_abort_fired``
    FIRST, then emit exactly ONE structured stderr line (binding #6) built only
    from the sanitized ``{site, tool, exc_type}`` (never the original exception;
    binding #4c) -> graceful ``teardown_child`` (SIGTERM + grace; binding #7,
    NO immediate SIGKILL) -> exit :data:`GUARD_STRICT_EXIT`.

    Args:
        state: The guard state (holds the in-flight id map + the dedup flag).
        proc: The child process to tear down.
        client_out: The client-facing send stream (for the -32003 frames).
        client_err: The client-facing stderr stream (for the structured line).
        client_mode: The client-facing framing mode (``_Channels.client_mode``).
        abort: The unwrapped strict abort carrying sanitized fields only.

    Returns:
        :data:`GUARD_STRICT_EXIT` (3).
    """
    # Double-emission guard (binding #6): if two pumps both aborted, only the
    # first does the work; a second is a no-op (still exits 3). Defense-in-depth:
    # anyio's single-event-loop model makes a SECOND StrictInspectionAbort within
    # one loop iteration effectively impossible (the first abort already cancels
    # the group), but this flag GUARANTEES a single stderr line + single exit 3
    # even if that concurrency assumption ever changes.
    if state.strict_abort_fired:
        logger.debug("guard: strict abort already fired; suppressing duplicate")
        return GUARD_STRICT_EXIT
    state.strict_abort_fired = True

    # In-flight id(s) for the client error frame(s). The offending request's id
    # may already have been popped from `inflight` during result-side inspection,
    # so the abort carries it explicitly: lead with it, then any other still-
    # pending ids (de-duplicated, order-preserving) so NO in-flight call hangs.
    # `seen` is a set for O(1) membership (O(n) overall vs O(n^2) on a list);
    # `pending_ids` preserves first-seen ordering (offending id leads).
    pending_ids: list[Any] = []
    seen: set[Any] = set()
    if abort.rpc_id is not None:
        pending_ids.append(abort.rpc_id)
        seen.add(abort.rpc_id)
    for rid in state.inflight.keys():
        if rid not in seen:
            pending_ids.append(rid)
            seen.add(rid)

    # `exc_type` is already a Python class name (identifier), but cap it as
    # defense-in-depth so neither the reason string nor the structured stderr can
    # be bloated by a pathologically long custom exception class name.
    exc_type = abort.exc_type[:_EXC_TYPE_CAP]

    # Synthesize -32003 to the in-flight id(s) so the client never hangs. The
    # reason is pre-sanitized: site + exception class only, no original repr/str.
    # Site-aware (binding F6): a frame-cap abort is a SIZE-cap termination, not an
    # inspection error, so it gets a distinct (still sanitized) reason string.
    if abort.site.startswith("frame-cap"):
        reason = f"session terminated: frame size cap exceeded at {abort.site} (non-retriable)"
    else:
        reason = f"inspection failed at {abort.site} ({exc_type}); session terminated (non-retriable)"
    await synthesize_strict_abort(state, client_out, client_mode, abort.site, reason, pending_ids)

    # Exactly ONE structured stderr line, built ONLY from sanitized fields
    # (binding #4c). exc_info is irrelevant here (no logging of the original).
    rpc_id = abort.rpc_id if abort.rpc_id is not None else (pending_ids[0] if pending_ids else None)
    line = json.dumps(
        {
            "event": "strict_abort",
            "site": abort.site,
            "tool": abort.tool,
            "exc_type": exc_type,
            "rpc_id": rpc_id,
        },
        ensure_ascii=False,
    )
    try:
        await client_err.send((line + "\n").encode())
    except Exception as exc:  # noqa: BLE001 - stderr may be gone; do not leak original
        # exc_info=False semantics (binding #4b): never format the abort/original.
        logger.debug("guard: could not write strict-abort stderr line: %s", exc)

    # Graceful child teardown (binding #7): reuse the existing SIGTERM+grace path.
    await teardown_child(proc, on_note=state.emit)
    logger.info("guard: strict abort at %s; session terminated, exit %d", abort.site, GUARD_STRICT_EXIT)
    return GUARD_STRICT_EXIT
