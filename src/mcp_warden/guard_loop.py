"""Guard config/state + client->server request handling (GUARD_PROXY.md §2, §4.1, §6.1).

Holds the :class:`GuardConfig`, the single-loop-owned :class:`GuardState` (id->method
correlation, lock/policy/denylists, sinks), the ``WRD-RES-FRAME-ERROR`` note, and the
client->server direction handler (argument-policy enforcement). The server->client
result handling lives in ``guard_result.py``.

Frame discipline (§2.1): pass through UNTOUCHED except a ``tools/call`` request/
response and the ``tools/list_changed`` gate. Enforcement starts at the first
``tools/call`` (§2.2). Pass-through forwards ORIGINAL bytes; only modified frames
are re-serialized. Asymmetric failure (§9): framing/inspection errors fail-OPEN;
policy verdicts fail-CLOSED.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable

from . import res_rules
from .framing import Frame, serialize_frame
from .guard_result import _frame_error_note, handle_s2c  # noqa: F401  (re-exported)
from .policy_eval import evaluate_call, overall_denied
from .policy_model import SHAPE_TO_FLAG, Policy
from .result_inspection import TIER_BLOCK, ResultFinding

logger = logging.getLogger("mcp_warden.guard")


#: Methods that MUST pass through untouched even mid-``tools/call`` (V3 §1):
#: never inspected, blocked, buffered, or reordered, in either direction.
PASSTHROUGH_METHODS = frozenset({"notifications/cancelled", "notifications/progress"})


class StrictInspectionAbort(BaseException):
    """Raised at an inspection site under ``--strict`` to fail-CLOSE the session.

    Subclasses :class:`BaseException` (NOT :class:`Exception`) on purpose: it is
    raised from inside the very ``except Exception`` fail-open handlers it must
    escape, and a ``BaseException`` is not caught by ``except Exception``. That
    guarantees the abort cannot be silently swallowed back into the fail-open
    pass-through (which would downgrade exit 3 -> 2 and drop the stderr line).

    Carries ONLY pre-sanitized fields — NEVER the original exception, its
    message, the result content, or the tool arguments (the original may embed
    secret-bearing result text; see issue #22 B3). The raise site uses
    ``from None`` to sever ``__cause__`` so a traceback cannot print the
    secret-bearing original.

    Attributes:
        site: The inspection site id (``request-policy`` / ``result-inspect`` /
            ``list-gate``).
        tool: The tool name under inspection (or ``"?"`` when unknown).
        exc_type: The class name of the swallowed inspection exception.
        rpc_id: The id of the in-flight request whose inspection failed (carried
            explicitly because a result-side abort has already popped this id
            from the in-flight map, so the loop must synthesize the client error
            for it from here). ``None`` if the frame had no id.
    """

    def __init__(self, *, site: str, tool: str, exc_type: str, rpc_id: Any = None) -> None:
        self.site = site
        self.tool = tool
        self.exc_type = exc_type
        self.rpc_id = rpc_id
        super().__init__(f"strict inspection abort at {site} ({exc_type})")


@dataclass
class GuardConfig:
    """Runtime configuration for ``guard`` (GUARD_PROXY.md §5, GUARD_PROXY_V3.md §4).

    v0.3 posture: the deterministic tier blocks **by default**. Blocking is
    expressed as per-category opt-OUTs (``no_block_*``), not enable flags. The
    ``tools/list_changed`` gate and argument policy are armed simply by supplying
    ``--lock`` / ``--policy`` (``armed_list_changed`` / ``armed_policy``). The
    fuzzy ``WRD-RES-INJECT-PHRASE`` tier NEVER default-blocks — opt-in only via
    ``block_inject_phrase``. ``audit_only`` is highest precedence and disables all
    blocking/mutation (restores full v0.2-style shadow). Precedence (§4.6):
    ``audit_only`` > ``no_block_*`` > default-block / ``block_inject_phrase``.
    """

    no_block_ansi: bool = False
    no_block_secret_echo: bool = False
    no_block_exfil_domain: bool = False
    no_block_exfil_ip_literal: bool = False
    no_block_list_changed: bool = False
    no_block_policy: bool = False
    block_inject_phrase: bool = False
    armed_list_changed: bool = False  # True iff --lock supplied
    armed_policy: bool = False  # True iff --policy supplied
    redact_secret_echo: bool = False
    audit_only: bool = False
    #: Strict fail-CLOSED mode (opt-in, default off). When True, an internal
    #: inspection error (the 3 inspection try/except sites + the nested list-gate
    #: hash error) TERMINATES the session non-zero (exit 3) instead of failing
    #: open. Integrity over availability — see GUARD_PROXY_V3.md strict mode.
    strict: bool = False
    #: Strict frame-cap mode (opt-in, default off; issue #37). When True, a
    #: server->client (s2c) result frame that exceeds ``max_frame_bytes``
    #: TERMINATES the session non-zero (exit 3, reusing the strict-abort
    #: machinery) instead of failing open / passing the over-cap frame through.
    #: Closes T-CAP-PAD (a malicious server padding a tools/call result past the
    #: cap to skip inspection). INDEPENDENT of ``strict`` — either, both, or
    #: neither may be set. s2c ONLY: the client->server direction is UNCHANGED
    #: (fail-open in all modes). See GUARD_PROXY_V3.md strict mode.
    strict_frame_cap: bool = False
    max_frame_bytes: int = 8 * 1024 * 1024
    max_inflight: int = 1024

    #: Maps each default-on deterministic result rule to its opt-out field name.
    _DET_OPTOUT = {
        "WRD-RES-ANSI": "no_block_ansi",
        "WRD-RES-SECRET-ECHO": "no_block_secret_echo",
        "WRD-RES-EXFIL-DOMAIN": "no_block_exfil_domain",
        "WRD-RES-EXFIL-IP-LITERAL": "no_block_exfil_ip_literal",
    }

    def category_enabled(self, rule_id: str) -> bool:
        """Whether blocking is active for a result rule under the v0.3 posture.

        Deterministic rules block by default unless their ``no_block_*`` opt-out
        is set; the fuzzy ``WRD-RES-INJECT-PHRASE`` blocks only with the explicit
        opt-in. ``audit_only`` overrides everything (nothing blocks).

        Args:
            rule_id: The ``WRD-RES-*`` rule id.

        Returns:
            True iff a match in this category should block on the wire.
        """
        if self.audit_only:
            return False
        if rule_id == "WRD-RES-INJECT-PHRASE":
            return self.block_inject_phrase
        optout = self._DET_OPTOUT.get(rule_id)
        if optout is None:
            return False
        return not getattr(self, optout)

    def list_changed_enabled(self) -> bool:
        """Whether the ``tools/list_changed`` drift gate blocks (armed + not opted-out)."""
        return self.armed_list_changed and not self.no_block_list_changed and not self.audit_only

    def policy_block_enabled(self) -> bool:
        """Whether an argument-policy deny blocks (armed + not opted-out)."""
        return self.armed_policy and not self.no_block_policy and not self.audit_only


@dataclass
class GuardState:
    """Mutable, single-loop-owned guard state."""

    config: GuardConfig
    lock: Any = None  # WardenLock | None
    policy: Policy | None = None
    exfil_denylist: tuple[str, ...] = res_rules.SEED_EXFIL_DENYLIST
    inject_phrases: tuple[str, ...] = res_rules.SEED_INJECT_PHRASES
    on_finding: Callable[[ResultFinding], None] | None = None
    record: Callable[[str, dict[str, Any]], None] | None = None
    enforcing: bool = False  # flips True at first tools/call (§2.2)
    inflight: "OrderedDict[Any, str]" = field(default_factory=OrderedDict)
    #: id -> tool name for in-flight tools/call requests (for result correlation).
    inflight_tool: "OrderedDict[Any, str]" = field(default_factory=OrderedDict)
    #: Set by handle_c2s when a request is withheld: error bytes to send to the CLIENT.
    pending_client_error: bytes | None = None
    #: True once a notifications/tools/list_changed was seen; the next tools/list
    #: response is re-checked against the lock (§4.3). Reset after the check runs.
    list_changed_pending: bool = False
    #: Double-emission guard for strict aborts (binding #6): two pumps could both
    #: raise StrictInspectionAbort in one loop iteration. Only the FIRST abort
    #: emits the structured stderr line + drives exit 3; later ones are no-ops.
    #: Defense-in-depth: anyio's single-event-loop model makes a SECOND
    #: StrictInspectionAbort effectively impossible (the first abort cancels the
    #: task group before another pump can raise), but this flag GUARANTEES a single
    #: stderr line + single exit 3 even if that concurrency assumption ever changes.
    strict_abort_fired: bool = False

    def remember_request(self, rpc_id: Any, method: str, tool: str = "") -> None:
        """Record an in-flight request id->method (+tool), bounded LRU (§4.4)."""
        self.inflight[rpc_id] = method
        self.inflight.move_to_end(rpc_id)
        if tool:
            self.inflight_tool[rpc_id] = tool
            self.inflight_tool.move_to_end(rpc_id)
        while len(self.inflight) > self.config.max_inflight:
            old, _ = self.inflight.popitem(last=False)
            self.inflight_tool.pop(old, None)

    def method_for(self, rpc_id: Any) -> str | None:
        """Pop the method for a response id (or None if unknown)."""
        return self.inflight.pop(rpc_id, None)

    def tool_for(self, rpc_id: Any) -> str:
        """Pop the tool name for a response id (or '' if unknown)."""
        return self.inflight_tool.pop(rpc_id, "")

    def emit(self, finding: ResultFinding) -> None:
        """Hand a stamped finding to the sink (best-effort)."""
        if self.on_finding is not None:
            try:
                self.on_finding(finding)
            except Exception as exc:  # a sink bug must not break the session
                logger.error("finding sink raised: %s", exc)


def handle_c2s(state: GuardState, frame: Frame, mode: str) -> bytes:
    """Process one client->server frame; return the bytes to forward to the server (§4.1).

    Pass-through unless a ``tools/call`` request hits a policy deny WITH
    ``--block-policy``, in which case the request is withheld (``b""``) and a
    synthesized client-facing error is stashed on ``state.pending_client_error``.

    Args:
        state: The guard state.
        frame: The parsed/raw client->server frame.
        mode: The client-side framing mode (for re-serialization).

    Returns:
        The bytes to forward server-ward (``b""`` to withhold a blocked request).
    """
    if state.record is not None and frame.json is not None:
        state.record("c2s", frame.json)
    obj = frame.json
    if obj is None:
        state.emit(_frame_error_note("c2s", None, frame.parse_error or "unparseable frame"))
        return frame.raw
    method = obj.get("method")
    if method in PASSTHROUGH_METHODS:
        # Cancellation/progress are control-plane: never inspected/blocked/buffered/
        # reordered, even mid-tools/call (GUARD_PROXY_V3.md §1). Forward original bytes
        # immediately; never withhold (do not touch pending_client_error).
        return frame.raw
    rpc_id = obj.get("id")
    if method is not None and rpc_id is not None:
        tool_name = ""
        if method == "tools/call":
            params = obj.get("params") or {}
            if isinstance(params, dict):
                tool_name = str(params.get("name", ""))
        state.remember_request(rpc_id, str(method), tool_name)
    if method != "tools/call":
        return frame.raw  # pass-through (§2.1)

    state.enforcing = True  # first tools/call starts enforcement (§2.2)
    if state.policy is None:
        return frame.raw  # argument policy inactive
    # Inspection-before-write invariant (binding #2): the policy evaluation below
    # runs BEFORE this request is ever forwarded to the server, so a strict abort
    # here cannot leave a partially-forwarded frame.
    try:
        verdicts, tool = _eval_request_policy(state, obj)
    except StrictInspectionAbort:
        raise  # never swallow the abort (BaseException; would not hit except Exception anyway)
    except Exception as exc:  # inspection error -> fail-open pass-through (§9)
        if state.config.strict:
            # `from None` severs __cause__ so the secret-bearing original cannot
            # print in a traceback (binding #4a). Carry sanitized fields only.
            _tool = _tool_name_from_request(obj)
            raise StrictInspectionAbort(
                site="request-policy", tool=_tool, exc_type=type(exc).__name__, rpc_id=rpc_id
            ) from None
        state.emit(_frame_error_note("c2s", rpc_id, f"policy eval error: {exc}"))
        return frame.raw
    if not overall_denied(verdicts):
        return frame.raw
    deny = next(v for v in verdicts if v.verdict == "deny")
    enabled = state.config.policy_block_enabled()
    state.emit(
        ResultFinding(
            rule_id=deny.constraint,
            severity="high",
            tier=TIER_BLOCK,
            message=f"tools/{tool}: argument policy deny ({deny.reason})",
            action="blocked" if enabled else "shadowed",
            direction="c2s",
            rpc_id=rpc_id,
            tool=tool,
        )
    )
    if not enabled:
        return frame.raw
    err = _error_response(rpc_id, deny.constraint, tool, deny.reason)
    state.pending_client_error = serialize_frame(err, mode)
    return b""  # withhold the request from the server


def _error_response(rpc_id: Any, rule: str, tool: str, reason: str) -> dict[str, Any]:
    """Build a request-stage warden error (delegates to wire_block)."""
    from .wire_block import error_response

    return error_response(rpc_id, stage="request", rule=rule, tool=tool, reason=reason)


def _tool_name_from_request(obj: dict[str, Any]) -> str:
    """Best-effort tool name from a tools/call request (or ``"?"``).

    Used only to label a :class:`StrictInspectionAbort` — never includes
    arguments or any secret-bearing content.
    """
    params = obj.get("params")
    if isinstance(params, dict):
        name = params.get("name")
        if isinstance(name, str) and name:
            return name
    return "?"


def _eval_request_policy(state: GuardState, obj: dict[str, Any]):
    """Evaluate the argument policy for a tools/call request (§6.1)."""
    params = obj.get("params") or {}
    tool = str(params.get("name", ""))
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        arguments = {}
    shapes = _shapes_for_tool(state, tool, arguments)
    return evaluate_call(state.policy, tool, arguments, shapes), tool


def _shapes_for_tool(state: GuardState, tool: str, arguments: dict[str, Any]) -> list[str]:
    """Resolve policy shapes from the lock if present, else infer from arguments."""
    from .policy_model import infer_shapes_from_arguments

    if state.lock is not None:
        flag_to_shape = {v: k for k, v in SHAPE_TO_FLAG.items()}
        for t in state.lock.tools:
            if t.name == tool:
                return sorted(flag_to_shape[f] for f in t.capabilities if f in flag_to_shape)
        return []
    return infer_shapes_from_arguments(arguments)
