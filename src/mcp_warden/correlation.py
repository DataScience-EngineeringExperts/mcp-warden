"""Bounded, session-local correlation of observations from the inspection runners.

Evidence describes an attempted crossing of a policy boundary. It does not
establish causality, authorize a privilege, or change a delivery decision.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import islice

from .content_models import MAX_TAINTS, TAINT_REGISTRY_V1, IngressKindV1, TaintV1
from .correlation_signals import BOUNDARY_ATTEMPT_IDS
from .injection_catalog import INJECTION_RULES

DEFAULT_OBSERVATION_DISTANCE = 32
MAX_OBSERVATION_DISTANCE = 256
_MAX_ORDINAL = (1 << 63) - 1
_TOOL_CALL_OBSERVED = "DSE720-TOOL-CALL-OBSERVED"
_TOOL_SELECTION_IDS = frozenset({"DSE720-SELECT-TOOL", "WRD-RES-INJECT-TOOL-COERCION"})
_INPUT_SIGNAL_IDS = frozenset(rule.rule_id for rule in INJECTION_RULES) | BOUNDARY_ATTEMPT_IDS

# The terminal observation determines which policy boundary the evidence concerns.
_BOUNDARIES = (
    (
        "WRD-RES-CORRELATION-AUTHORITY-GRANT",
        "untrusted-content-to-authority",
        frozenset({"DSE720-GRANT-AUTHORITY"}),
    ),
    (
        "WRD-RES-CORRELATION-PRIVILEGE-REQUEST",
        "untrusted-content-to-privilege",
        frozenset({"DSE720-REQUEST-PRIVILEGE", "WRD-RES-INJECT-SECRET-EXTRACTION"}),
    ),
    (
        "WRD-RES-CORRELATION-POLICY-ALTERATION",
        "untrusted-content-to-policy",
        frozenset({
            "DSE720-ALTER-POLICY",
            "WRD-RES-INJECT-INSTRUCTION-OVERRIDE",
            "WRD-RES-INJECT-POLICY-EVASION",
        }),
    ),
    (
        "WRD-RES-CORRELATION-TOOL-SELECTION",
        "untrusted-content-to-tool-selection",
        _TOOL_SELECTION_IDS,
    ),
)


@dataclass(frozen=True, slots=True)
class CorrelationObservation:
    """Report-safe metadata for one locally ordered observation."""

    ordinal: int
    ingress: IngressKindV1 | None
    signal_ids: tuple[str, ...]
    taints: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CorrelationMatch:
    """A boundary attempt supported by two distinct, ordered observations."""

    rule_id: str
    boundary: str
    evidence: tuple[CorrelationObservation, CorrelationObservation]

    @property
    def taints(self) -> tuple[str, ...]:
        return tuple(sorted({taint for observation in self.evidence for taint in observation.taints}))


def _registered(
    values: Iterable[str], registry: frozenset[str], max_items: int,
) -> frozenset[str]:
    """Consume a bounded number of labels and discard values outside the registry."""
    items = tuple(islice(values, max_items + 1))
    if len(items) > max_items:
        return frozenset()
    max_length = max(map(len, registry))
    return frozenset(
        str(item)
        for item in items
        if (type(item) is str or type(item) is TaintV1)
        and len(item) <= max_length
        and item in registry
    )


def _distinct_antecedent(prior: CorrelationObservation, terminal_ids: frozenset[str]) -> bool:
    """An explicit prior taint or a distinct prior signal supports an attempt."""
    if not prior.signal_ids:
        # A taint-only observation enters history only with AUTHORITY_INJECTION.
        return True
    previous = frozenset(prior.signal_ids)
    if not _TOOL_SELECTION_IDS.isdisjoint(previous):
        # Both catalogs describe the same observed selection directive.
        previous |= _TOOL_SELECTION_IDS
    return not previous.issuperset(terminal_ids)


class CorrelationEngine:
    """One engine per trusted runner session. The runner supplies one observation per frame.

    A prior observation is eligible at an inclusive distance of at most 32
    local observations by default. Every call, including a clean/ignored frame,
    advances this window. There is no wall-clock input; replay in the same order
    produces the same evidence. Only relevant metadata is retained in memory.
    At ordinal exhaustion, the session starts a clean window before reusing ordinals.
    """

    def __init__(self, *, max_observation_distance: int = DEFAULT_OBSERVATION_DISTANCE) -> None:
        if (
            type(max_observation_distance) is not int
            or not 1 <= max_observation_distance <= MAX_OBSERVATION_DISTANCE
        ):
            raise ValueError(f"observation distance must be an integer in [1, {MAX_OBSERVATION_DISTANCE}]")
        self._distance = max_observation_distance
        self._ordinal = 0
        self._last_tool_call = 0
        self._history: deque[CorrelationObservation] = deque(maxlen=max_observation_distance)

    def observe(
        self,
        ingress: IngressKindV1 | None = None,
        *,
        injection_rule_ids: Iterable[str] = (),
        taints: Iterable[str] = (),
        tool_selection: bool = False,
    ) -> tuple[CorrelationMatch, ...]:
        """Record bounded detector labels or a canonical locally observed tool call.

        Supplied content enters only through an explicit ingress kind. Tool-call
        observations carry no content claims and correlate only with tool-selection
        evidence after the last observed call. The engine never uses wire IDs or timestamps.
        """
        if self._ordinal == _MAX_ORDINAL:
            self._history.clear()
            self._ordinal = 0
            self._last_tool_call = 0
        self._ordinal += 1
        while self._history and self._ordinal - self._history[0].ordinal > self._distance:
            self._history.popleft()

        if ingress is None and tool_selection is True:
            return self._observe_tool_selection()
        if type(ingress) is not IngressKindV1:
            return ()

        signals = _registered(injection_rule_ids, _INPUT_SIGNAL_IDS, 64)
        observed_taints = _registered(taints, TAINT_REGISTRY_V1, MAX_TAINTS)
        if not signals and TaintV1.AUTHORITY_INJECTION not in observed_taints:
            return ()

        observed_taints |= {TaintV1.UNTRUSTED.value, TaintV1.AUTHORITY_INJECTION.value}
        current = CorrelationObservation(
            self._ordinal, ingress, tuple(sorted(signals)), tuple(sorted(observed_taints)),
        )
        matches = []
        for rule_id, boundary, boundary_ids in _BOUNDARIES:
            terminal_ids = signals & boundary_ids
            if not terminal_ids:
                continue
            prior = next(
                (item for item in reversed(self._history) if _distinct_antecedent(item, terminal_ids)),
                None,
            )
            if prior is not None:
                matches.append(CorrelationMatch(rule_id, boundary, (prior, current)))
        self._history.append(current)
        return tuple(matches)

    def _observe_tool_selection(self) -> tuple[CorrelationMatch, ...]:
        prior = next(
            (
                item for item in reversed(self._history)
                if item.ordinal > self._last_tool_call
                and not _TOOL_SELECTION_IDS.isdisjoint(item.signal_ids)
            ),
            None,
        )
        self._last_tool_call = self._ordinal
        if prior is None:
            return ()
        current = CorrelationObservation(self._ordinal, None, (_TOOL_CALL_OBSERVED,), ())
        rule_id, boundary, _ = _BOUNDARIES[-1]
        return (CorrelationMatch(rule_id, boundary, (prior, current)),)
