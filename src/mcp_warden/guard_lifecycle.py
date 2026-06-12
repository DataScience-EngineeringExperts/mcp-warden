"""Subprocess-lifecycle hardening for ``guard`` (GUARD_PROXY_V3.md §2, §3).

Holds the teardown primitives kept out of ``guard.py`` to respect the LOC budget:

  * ``synthesize_pending_errors`` — on child exit/crash, emit a ``-32002`` transport
    error for EVERY pending request id so the client never hangs (§2.1). Runs on
    Windows too (§3.3.1) — pure JSON-RPC, platform-independent.
  * ``exit_code_for_child`` — translate a child returncode to the client-visible
    exit status (``128 + signum`` on signal, §2.1).
  * ``teardown_child`` — POSIX process-group teardown (TERM -> bounded grace ->
    KILL) on client disconnect/EOF, with a Windows best-effort fallback that logs
    ``WRD-RES-WIN-LIFECYCLE`` and asserts NO orphan-freedom (§2.2, §3.2-§3.3).

All POSIX-only syscalls are guarded by ``os.name == "posix"`` so import and run
never crash on Windows.
"""

from __future__ import annotations

import logging
import os
import signal as _signal
from typing import Any, Iterable

import anyio
from anyio.abc import Process

from . import wire_block
from .framing import serialize_frame
from .result_inspection import ResultFinding

logger = logging.getLogger("mcp_warden.guard")

#: Bounded grace period (seconds) between SIGTERM and SIGKILL on teardown (§2.2).
TERM_GRACE_S = 3.0

_IS_POSIX = os.name == "posix"

#: Dedicated exit code for refusing to run ``guard`` on a non-POSIX platform
#: WITHOUT ``--allow-degraded-platform`` (GUARD_PROXY_V3.md §3.3). A
#: platform-refusal is a config/usage refusal, so it reuses the established
#: config-error code ``2`` (``GUARD_FATAL_EXIT`` / every ``cli_guard`` config
#: ``typer.Exit(code=2)``). It is DISTINCT from confirmed-drift (``check`` exit
#: ``1``) and from the strict / frame-cap abort (``3``, ``GUARD_STRICT_EXIT``),
#: so "exit 1 == confirmed drift" and "exit 3 == strict/frame-cap abort" stay
#: unambiguous.
GUARD_PLATFORM_REFUSE_EXIT = 2

#: The flag that lets an operator knowingly proceed on a degraded (non-POSIX)
#: platform. Affirmative ``--allow-*`` form, matching the sole other affirmative
#: opt-in flag ``--allow-exfil-domain`` (GUARD_PROXY_V3.md §4.2 naming scheme).
ALLOW_DEGRADED_PLATFORM_FLAG = "--allow-degraded-platform"

#: The exact runtime guarantees that are reduced on a non-POSIX platform
#: (GUARD_PROXY_V3.md §3.2). Named precisely so the operator knows what is NOT
#: protected — NOT a vague "experimental" hand-wave.
DEGRADED_GUARANTEES: tuple[str, ...] = (
    "process-group isolation: the child is NOT placed in its own process group "
    "/ job object (no start_new_session)",
    "child teardown: terminate-only on client disconnect/EOF -- NO "
    "SIGTERM->grace->SIGKILL process-group teardown, so orphaned children / "
    "grandchildren are POSSIBLE (orphan-freedom is NOT asserted)",
    "signal forwarding: SIGINT/SIGTERM/SIGHUP are NOT forwarded to the child "
    "process group",
)


def is_degraded_platform() -> bool:
    """Return True when ``guard`` runs with reduced lifecycle guarantees (non-POSIX).

    Pure read of :data:`_IS_POSIX` (itself ``os.name == "posix"``). Tests simulate
    a non-POSIX host by monkeypatching this module's ``_IS_POSIX`` — the same
    ``os.name`` gate every other lifecycle primitive in this module already uses.

    Returns:
        ``True`` on a non-POSIX platform (degraded lifecycle), ``False`` on POSIX.
    """
    return not _IS_POSIX


def _redact_server_identity(command: str, args: list[str]) -> str:
    """Render the server launch argv for a human message WITHOUT leaking secrets.

    Mirrors the redaction contract of :func:`mcp_warden.precommit._redact_server`
    (code-audit binding B3): the server argv may carry API keys/tokens passed as
    CLI args, and the project forbids printing ``server.command`` / ``server.args``
    (cf. ``SAFE_PROVENANCE_FIELDS``). Guard stderr is captured to client logs and
    scrollback, so the platform warning echoes ONLY the executable name
    (``argv[0]``) plus a redacted count of the remaining args -- never the args
    themselves. Kept local (not imported from ``precommit``) so the guard runtime
    has no dependency on the check-only pre-commit module.

    Args:
        command: ``argv[0]`` of the server launch.
        args: The remaining server argv (NEVER rendered; only counted).

    Returns:
        ``command`` alone when there are no args, else
        ``"<command> …(<n> arg(s) redacted)"``.
    """
    if not args:
        return command
    n = len(args)
    return f"{command} …({n} arg{'s' if n != 1 else ''} redacted)"


def platform_refusal_message(command: str, args: list[str]) -> str:
    """Build the LOUD, structured non-POSIX warning naming each reduced guarantee.

    Emitted to stderr at ``guard`` startup on a non-POSIX platform (refuse path
    AND proceed-with-flag path). Names EXACTLY which §3.2 lifecycle guarantees are
    reduced so a user can never falsely believe they have full runtime protection.
    The server identity is rendered ONLY via :func:`_redact_server_identity`
    (argv[0] + redacted arg count) so a secret-bearing argv never reaches stderr
    (binding: redaction).

    Args:
        command: ``argv[0]`` of the server launch (for the redacted identity line).
        args: The remaining server argv (counted + redacted, never rendered).

    Returns:
        A multi-line, all-caps-headed warning string (no trailing newline).
    """
    server = _redact_server_identity(command, args)
    lines = [
        "================================================================",
        "WARNING: mcp-warden guard on a NON-POSIX platform (EXPERIMENTAL).",
        "Runtime process/signal protection is DEGRADED. You do NOT have the",
        "full guard runtime-protection model on this platform. Reduced:",
    ]
    for guarantee in DEGRADED_GUARANTEES:
        lines.append(f"  - {guarantee}")
    lines.append(f"server: {server}")
    lines.append(
        "Frame inspection, default-block posture, secret redaction and the "
        "-32002 pending-id synthesis STILL hold; only the §2 subprocess-"
        "lifecycle guarantees degrade (GUARD_PROXY_V3.md §3)."
    )
    lines.append("================================================================")
    return "\n".join(lines)


def exit_code_for_child(returncode: int | None) -> int:
    """Translate an anyio child returncode to the client-visible exit code.

    anyio/asyncio report a death-by-signal as a negative returncode (``-signum``);
    the conventional shell encoding the client expects is ``128 + signum`` (§2.1).

    Args:
        returncode: ``proc.returncode`` (``None`` if not yet exited -> treated 0).

    Returns:
        The exit code to propagate to the client.
    """
    if returncode is None:
        return 0
    if returncode < 0:
        return 128 + (-returncode)
    return returncode


def win_lifecycle_note(detail: str) -> ResultFinding:
    """Build a low ``WRD-RES-WIN-LIFECYCLE`` degradation note (§3.3.3)."""
    return ResultFinding(
        rule_id="WRD-RES-WIN-LIFECYCLE",
        severity="low",
        tier="note",
        message=f"windows lifecycle (best-effort, orphan-freedom not asserted): {detail}",
        action="passed",
        direction="s2c",
    )


async def synthesize_pending_errors(state, client_out, mode: str, returncode: int | None) -> None:
    """Emit a ``-32002`` transport error for every pending request id (§2.1, §3.3.1).

    Resolves each in-flight client promise so a dead/crashed server never leaves
    the client hanging. Flushed to the client BEFORE the pipes close. Runs
    identically on Windows (pure JSON-RPC). Best-effort per id: a send failure on
    one id (client already gone) does not stop the others.

    Args:
        state: The :class:`~mcp_warden.guard_loop.GuardState` (its ``inflight`` map
            holds the genuinely-pending ids — responded ids were already popped).
        client_out: The client-facing send stream.
        mode: The client-side framing mode for serialization.
        returncode: The child's returncode (for the reason string only; redacted-safe).
    """
    pending: list[Any] = list(state.inflight.keys())
    if not pending:
        return
    code_str = "signal" if (returncode is not None and returncode < 0) else str(returncode)
    reason = f"child exited (code={code_str}) with {len(pending)} request(s) in flight"
    logger.info("guard: child exited with %d request(s) in flight; synthesizing -32002", len(pending))
    for rpc_id in pending:
        err = wire_block.transport_error(rpc_id, reason=reason)
        try:
            await client_out.send(serialize_frame(err, mode))
        except Exception as exc:  # noqa: BLE001 - client may be gone; keep going
            logger.debug("guard: could not deliver -32002 for id=%r: %s", rpc_id, exc)
    state.inflight.clear()
    state.inflight_tool.clear()


async def synthesize_strict_abort(
    state, client_out, mode: str, site: str, reason: str, pending_ids: list[Any]
) -> None:
    """Emit a ``-32003`` strict-abort error for every in-flight id (binding #5).

    Resolves each pending client promise when ``--strict`` terminates the session
    on an internal inspection error, so the client never hangs. Flushed BEFORE the
    pipes close. Best-effort per id: a send failure on one id (client already
    gone) does not stop the others. The ``reason`` MUST be pre-sanitized — no
    original-exception ``repr``/``str``, no result/argument content (binding #4c).

    Args:
        state: The :class:`~mcp_warden.guard_loop.GuardState` (its in-flight maps
            are cleared after synthesis).
        client_out: The client-facing send stream.
        mode: The client-side framing mode for serialization.
        site: The inspection site id (``request-policy`` / ``result-inspect`` /
            ``list-gate``).
        pending_ids: The in-flight request ids to resolve with a -32003 error.
    """
    if not pending_ids:
        return
    logger.info("guard: strict abort at %s; synthesizing -32003 for %d in-flight id(s)", site, len(pending_ids))
    for rpc_id in pending_ids:
        err = wire_block.strict_abort_error(rpc_id, site=site, reason=reason)
        try:
            await client_out.send(serialize_frame(err, mode))
        except Exception as exc:  # noqa: BLE001 - client may be gone; keep going
            logger.debug("guard: could not deliver -32003 for id=%r: %s", rpc_id, exc)
    state.inflight.clear()
    state.inflight_tool.clear()


async def teardown_child(proc: Process, *, on_note=None) -> None:
    """Tear down the child process group on client disconnect/EOF (§2.2, §3.2).

    POSIX: SIGTERM to the child's process group, a bounded grace period, then
    SIGKILL the group if it has not exited — guaranteeing no orphaned children or
    grandchildren. Windows: best-effort ``terminate`` + a ``WRD-RES-WIN-LIFECYCLE``
    note; orphan-freedom is NOT asserted.

    Args:
        proc: The child :class:`~anyio.abc.Process`.
        on_note: Optional callable to receive a degradation note (Windows path).
    """
    if proc.returncode is not None:
        return  # already exited; nothing to tear down
    # Ensure the child sees stdin EOF so a well-behaved server can exit cleanly
    # before any signal escalation (idempotent if the c2s pump already closed it).
    try:
        await proc.stdin.aclose()
    except Exception as exc:  # noqa: BLE001 - best-effort; pump may have closed it
        logger.debug("guard: server stdin already closed: %s", exc)
    if _IS_POSIX:
        await _teardown_posix(proc)
    else:
        _teardown_windows(proc, on_note)


async def _teardown_posix(proc: Process) -> None:
    """POSIX process-group teardown: EOF grace -> TERM -> grace -> KILL (§2.2).

    The child already received stdin EOF (the c2s pump closed server stdin), so a
    well-behaved server exits on its own; we wait a bounded grace for that clean
    exit FIRST and return its natural code. Only an unresponsive child is then
    escalated to SIGTERM, another grace, and finally SIGKILL of the whole group —
    guaranteeing no orphans without clobbering a clean shutdown's exit status.
    """
    with anyio.move_on_after(TERM_GRACE_S):
        await proc.wait()
        return  # clean exit after stdin EOF -> keep the child's natural code
    logger.info("guard: child still running %.0fs after EOF; SIGTERM group", TERM_GRACE_S)
    _signal_group(proc, _signal.SIGTERM)
    with anyio.move_on_after(TERM_GRACE_S):
        await proc.wait()
        return
    if proc.returncode is None:
        logger.info("guard: child did not exit within grace; SIGKILL group", )
        _signal_group(proc, _signal.SIGKILL)
        try:
            await proc.wait()
        except Exception as exc:  # noqa: BLE001
            logger.debug("guard: child wait after SIGKILL failed: %s", exc)


def _signal_group(proc: Process, signum: int) -> None:
    """Send a signal to the child's process group (POSIX, best-effort)."""
    try:
        os.killpg(os.getpgid(proc.pid), signum)
    except (ProcessLookupError, PermissionError, OSError) as exc:
        logger.debug("guard: could not signal child group %s: %s", proc.pid, exc)


def _teardown_windows(proc: Process, on_note) -> None:
    """Windows best-effort teardown; logs the orphan-freedom degradation (§3.3)."""
    try:
        proc.terminate()
    except Exception as exc:  # noqa: BLE001
        logger.debug("guard: windows terminate failed: %s", exc)
    note = win_lifecycle_note("child teardown is terminate-only; a residual child is possible")
    logger.warning("guard: %s", note.message)
    if on_note is not None:
        try:
            on_note(note)
        except Exception:  # noqa: BLE001 - a sink bug must not break teardown
            pass


def forward_signals() -> Iterable[int]:
    """The signals ``guard`` forwards to the child group (POSIX; empty on Windows)."""
    if not _IS_POSIX:
        return ()
    sigs = [_signal.SIGINT, _signal.SIGTERM]
    if hasattr(_signal, "SIGHUP"):
        sigs.append(_signal.SIGHUP)
    return sigs
