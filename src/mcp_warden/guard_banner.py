"""Startup posture banner for ``guard`` (GUARD_PROXY_V3.md §4, §4.4).

A pure, deterministic renderer for the one-shot stderr banner that ``guard``
emits at startup (after the config is fully resolved, before the child's first
frame) so an operator can see — at a glance, before any traffic flows — exactly
which protections are ENFORCED, which are MONITOR-only, and which are INACTIVE
for this run.

Single source of truth (binding): the banner derives ENTIRELY from a resolved
:class:`~mcp_warden.guard_loop.GuardConfig`. It reads only the public posture
predicates that already encode v0.3 precedence (``audit_only`` > ``no_block_*`` >
default-block / ``block_inject_phrase``):

  * :meth:`GuardConfig.category_enabled` — per result-rule blocking.
  * :meth:`GuardConfig.list_changed_enabled` — ``tools/list_changed`` drift gate.
  * :meth:`GuardConfig.policy_block_enabled` — argument-policy deny.

and the ``armed_*`` / ``strict`` / ``strict_frame_cap`` fields. It NEVER takes the
server ``command``/``args`` — the banner is POSTURE, not server identity, so a
secret-bearing argv can never reach it (redaction invariant).

Deterministic-tier ground truth (RESULT_INSPECTION.md §2): the BLOCKING bucket is
DERIVED from ``result_inspection.BLOCK_RULES`` — the single source of truth for
which deterministic result rules block on the wire — so it tracks whatever the
catalog actually blocks, regardless of how many rules ship. The banner walks a
fixed, ordered label map (``_DET_TIERS``) and keeps only the ids that are both in
``BLOCK_RULES`` AND enabled by config; membership is therefore DYNAMIC (catalog-
driven) while order stays deterministic (map-driven, not frozenset iteration
order). Any ``BLOCK_RULES`` id missing from the map falls back to rendering its
rule id, so a blocking tier is never silently omitted. This reflects ACTUAL
runtime behavior, never aspirational copy.

The returned string is PLAIN TEXT (no ANSI/Rich markup): the CLI prints it via
``err_console.print(..., highlight=False)`` and tests assert on substrings, so it
must carry no embedded color codes — mirroring
:func:`mcp_warden.guard_lifecycle.platform_refusal_message`.
"""

from __future__ import annotations

from .guard_loop import GuardConfig
from .result_inspection import BLOCK_RULES

#: Ordered label map for the deterministic BLOCKING tiers. Order here (NOT the
#: ``BLOCK_RULES`` frozenset iteration order) fixes the banner's tier order, so
#: output stays deterministic for tests + stable for operator reading. The map is
#: a superset that may name rules not yet present in ``BLOCK_RULES`` on a given
#: branch (e.g. the forward-ready IP-literal tier): the BLOCKING bucket is the
#: INTERSECTION of this map with ``result_inspection.BLOCK_RULES``, filtered by
#: per-rule config (``category_enabled``), so it tracks the real catalog at any
#: merge order. Any ``BLOCK_RULES`` id absent from this map still renders (by id)
#: rather than being dropped — a blocking tier is never silently omitted.
_DET_TIERS: tuple[tuple[str, str], ...] = (
    ("WRD-RES-ANSI", "ANSI/control-codepoint scrub"),
    ("WRD-RES-SECRET-ECHO", "secret-echo block"),
    ("WRD-RES-EXFIL-DOMAIN", "exfil/callback-domain block"),
    ("WRD-RES-EXFIL-IP-LITERAL", "exfil/SSRF raw-IP-literal block"),
)

#: Banner delimiter (mirrors the platform-refusal banner width/style).
_RULE = "================================================================"


def render_posture_banner(cfg: GuardConfig) -> str:
    """Render the startup posture banner from a resolved :class:`GuardConfig`.

    Pure, deterministic, no I/O. The banner is grouped into buckets so an operator
    can read the run's enforcement posture before any traffic flows:

      * **BLOCKING (active)** — tiers that block on the wire this run. Under
        ``--audit-only`` this collapses to a single "ALL BLOCKING DISABLED" line
        (nothing is enforced; everything is detect-and-log).
      * **MONITOR-ONLY** — tiers that detect + log but never block: the fuzzy
        ``WRD-RES-INJECT-PHRASE`` tier when ``--block-inject-phrase`` is NOT set,
        plus the §4.4 note that frames with no correlated request id (and
        uninspectable/non-``tools/call`` frames) pass through uninspected.
      * **INACTIVE** — protections that are not armed for this run: the
        ``tools/list_changed`` drift gate without ``--lock`` and the argument
        policy without ``--policy``.
      * **fail-open / strictness** — whether an internal inspection error fails
        OPEN (default) or fails CLOSED (``--strict``), and whether an over-cap
        frame passes through (default) or terminates the session
        (``--strict-frame-cap``).

    Single source of truth: every line is derived from ``cfg``'s public posture
    predicates (``category_enabled`` / ``list_changed_enabled`` /
    ``policy_block_enabled``) and the ``armed_*`` / ``strict`` / ``strict_frame_cap``
    fields. The banner names NO server (no ``command``/``args``), so no argv or
    secret can leak through it.

    Args:
        cfg: The fully-resolved guard configuration (post opt-out / ``--audit-only``
            / arming resolution, exactly as built in ``cli_guard.guard``).

    Returns:
        A multi-line, plain-text banner (no trailing newline, no ANSI/Rich markup).
    """
    lines: list[str] = [
        _RULE,
        "mcp-warden guard posture (v0.3) — enforcement for this run:",
        _RULE,
    ]
    lines.extend(_blocking_lines(cfg))
    lines.extend(_monitor_lines(cfg))
    lines.extend(_inactive_lines(cfg))
    lines.extend(_strictness_lines(cfg))
    lines.append(_RULE)
    return "\n".join(lines)


def _blocking_lines(cfg: GuardConfig) -> list[str]:
    """The BLOCKING (active) bucket — what actually blocks on the wire this run."""
    if cfg.audit_only:
        # Highest-precedence special case: NOTHING is enforced. Be unambiguous so a
        # reader under --audit-only never believes a tier still blocks.
        return [
            "BLOCKING (active):",
            "  ALL BLOCKING DISABLED (audit-only) — detection + logging only; "
            "nothing is enforced on the wire",
        ]

    active: list[str] = []
    # BLOCKING bucket = the ordered label map INTERSECTED with the catalog's
    # single source of truth (result_inspection.BLOCK_RULES), each gated by the
    # run's per-rule config. Ordered-map iteration keeps output deterministic;
    # BLOCK_RULES membership keeps it honest across merge order (e.g. once the
    # IP-literal rule lands in BLOCK_RULES, it appears here with no further edit).
    _labels = dict(_DET_TIERS)
    for rule_id in (rid for rid, _ in _DET_TIERS if rid in BLOCK_RULES):
        if cfg.category_enabled(rule_id):
            active.append(f"  - {_labels[rule_id]} ({rule_id})")
    # Defensive: a blocking rule the label map does not know about must still be
    # rendered (by id) rather than silently omitted — never under-report posture.
    for rule_id in sorted(BLOCK_RULES - set(_labels)):
        if cfg.category_enabled(rule_id):
            active.append(f"  - deterministic block ({rule_id})")
    if cfg.category_enabled("WRD-RES-INJECT-PHRASE"):
        # Opt-in only (--block-inject-phrase); when on it is a real BLOCK tier.
        active.append("  - injection-phrase block (WRD-RES-INJECT-PHRASE, opt-in)")
    elif cfg.block_inject_phrases_subset:
        # Per-phrase opt-in (--block-inject-phrase-only): only NAMED phrases block;
        # all other fuzzy matches stay monitor-only. Report it so posture is honest.
        n = len(cfg.block_inject_phrases_subset)
        active.append(
            f"  - injection-phrase block for {n} named phrase(s) "
            "(WRD-RES-INJECT-PHRASE, --block-inject-phrase-only)"
        )
    if cfg.list_changed_enabled():
        active.append("  - tools/list_changed drift gate (MCP-DRIFT, armed by --lock)")
    if cfg.policy_block_enabled():
        active.append("  - argument policy deny (armed by --policy)")

    if not active:
        # Every default tier was opted out (but not audit-only): say so plainly.
        return [
            "BLOCKING (active):",
            "  (none) — all blocking tiers opted out via --no-block-* flags",
        ]
    return ["BLOCKING (active):", *active]


def _monitor_lines(cfg: GuardConfig) -> list[str]:
    """The MONITOR-ONLY bucket — detect + log, never block."""
    lines = ["MONITOR-ONLY (detect + log, no block):"]
    if not cfg.category_enabled("WRD-RES-INJECT-PHRASE"):
        if cfg.block_inject_phrases_subset and not cfg.audit_only:
            # Per-phrase opt-in: the NAMED phrases block (listed above); every OTHER
            # curated phrase in this tier still only logs.
            lines.append(
                "  - injection-phrase tier (WRD-RES-INJECT-PHRASE) — fuzzy; only the "
                "named phrases block (--block-inject-phrase-only), all others log only"
            )
        else:
            # When NOT opted-in (or under audit-only) the fuzzy tier only logs.
            lines.append(
                "  - injection-phrase tier (WRD-RES-INJECT-PHRASE) — fuzzy; "
                "logs matches, does NOT block (enable: --block-inject-phrase)"
            )
    lines.append(
        "  - uninspectable / non-tools/call / uncorrelated-id frames pass through "
        "uninspected (GUARD_PROXY.md §4.4)"
    )
    return lines


def _inactive_lines(cfg: GuardConfig) -> list[str]:
    """The INACTIVE bucket — protections not armed for this run."""
    lines: list[str] = []
    if not cfg.armed_list_changed:
        lines.append(
            "  - tools/list_changed drift detection: INACTIVE (no --lock) — "
            "mid-session tool-surface swap NOT enforced"
        )
    if not cfg.armed_policy:
        lines.append(
            "  - argument policy: INACTIVE (no --policy) — SSRF/shell/fs/sql "
            "argument enforcement NOT enforced"
        )
    if not lines:
        return []
    return ["INACTIVE (not armed this run):", *lines]


def _strictness_lines(cfg: GuardConfig) -> list[str]:
    """The fail-open / strictness bucket — behavior on inspection error + over-cap."""
    lines = ["on inspection error / over-cap frame:"]
    if cfg.strict:
        lines.append(
            "  - fail-CLOSED: an internal inspection error TERMINATES the session "
            "(exit 3) (--strict)"
        )
    else:
        lines.append(
            "  - fail-open: an internal inspection error passes the frame through "
            "(enable fail-closed: --strict)"
        )
    if cfg.strict_frame_cap:
        lines.append(
            f"  - over-cap frame (> {cfg.max_frame_bytes} bytes): TERMINATES the "
            "session (exit 3) (--strict-frame-cap)"
        )
    else:
        lines.append(
            f"  - over-cap frame (> {cfg.max_frame_bytes} bytes): passes through "
            "uninspected (enable terminate: --strict-frame-cap)"
        )
    return lines
