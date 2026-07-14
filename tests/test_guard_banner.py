"""Startup posture-banner renderer + ``--quiet`` wiring (GUARD_PROXY_V3.md §4).

The banner is a one-shot stderr surface emitted at ``guard`` startup (after the
config resolves, before the child's first frame) so an operator sees the run's
ENFORCED / MONITOR-only / INACTIVE posture before any traffic flows. This module
proves, at two levels:

  * Renderer level (``render_posture_banner``): a PURE function of the resolved
    :class:`~mcp_warden.guard_loop.GuardConfig`. Each test toggles ONE posture
    field and asserts the banner moves the corresponding tier between buckets —
    so a no-op renderer that always lists every tier (or never drops one) FAILS.
  * CLI level: drive the registered ``guard`` command with the SAME harness
    ``test_guard_platform.py`` uses (a ``run_guard`` spy so no child spawns), and
    assert ``--quiet`` suppresses the banner while the default emits it, and that
    a ``--no-block-*`` opt-out flows all the way through cfg -> banner -> stderr.

Ground-truth note (derivation, not enumeration): the banner's BLOCKING bucket is
DERIVED from ``result_inspection.BLOCK_RULES`` — the catalog's single source of
truth for which deterministic result rules block — so it tracks whatever the
catalog actually blocks at any merge order.
``test_banner_blocking_set_equals_enabled_block_rules`` asserts the rendered
blocking-rule set EQUALS the ``BLOCK_RULES`` members enabled under the given
config (so it never fabricates a tier that is NOT in ``BLOCK_RULES``, and never
omits one that is), and ``test_banner_blocking_is_live_to_block_rules`` proves the
derivation is live by extending ``BLOCK_RULES`` with a synthetic rule and showing
the banner picks it up (a hardcoded renderer would fail this).

Redaction invariant: the banner takes ONLY ``cfg`` (never ``command``/``args``),
so a secret-bearing server argv can never reach it.
"""

from __future__ import annotations

import re

import mcp_warden.cli_guard as cli_guard
import mcp_warden.guard_banner as guard_banner
import mcp_warden.guard_lifecycle as guard_lifecycle
import mcp_warden.result_inspection as result_inspection
from mcp_warden.guard_banner import render_posture_banner
from mcp_warden.guard_loop import GuardConfig

# Bucket header literals the banner uses (assert against these, not whole lines).
_BLOCKING_HDR = "BLOCKING (active):"
_AUDIT_LINE = "ALL BLOCKING DISABLED (audit-only)"
_FAIL_OPEN = "fail-open: an internal inspection error passes the frame through"
_FAIL_CLOSED = "fail-CLOSED: an internal inspection error TERMINATES the session"

# Per-tier labels (must match guard_banner._DET_TIERS exactly).
_ANSI = "WRD-RES-ANSI"
_SECRET = "WRD-RES-SECRET-ECHO"
_EXFIL = "WRD-RES-EXFIL-DOMAIN"
_INJECT = "WRD-RES-INJECT-PHRASE"
_DRIFT_INACTIVE = "tools/list_changed drift detection: INACTIVE (no --lock)"
_POLICY_INACTIVE = "argument policy: INACTIVE (no --policy)"


def _blocking_section(banner: str) -> str:
    """Return the slice of the banner from BLOCKING up to the next bucket header.

    Lets a test assert a tier is *in the BLOCKING bucket* (active) rather than
    merely *mentioned somewhere* (it appears in MONITOR/INACTIVE copy too).
    """
    start = banner.index(_BLOCKING_HDR)
    rest = banner[start + len(_BLOCKING_HDR) :]
    end = rest.find("MONITOR-ONLY")
    return rest if end == -1 else rest[:end]


# --- renderer: no flags -> the three default tiers block, gates inactive -------


def test_no_flags_blocks_three_det_tiers_and_marks_gates_inactive():
    banner = render_posture_banner(GuardConfig())
    block = _blocking_section(banner)
    # All THREE shipped deterministic tiers block by default.
    assert _ANSI in block
    assert _SECRET in block
    assert _EXFIL in block
    # The fuzzy tier is MONITOR-only (NOT in the BLOCKING bucket) without opt-in.
    assert _INJECT not in block
    assert _INJECT in banner  # ...but it IS named, in the MONITOR bucket
    # Both gates are INACTIVE without their arming flag.
    assert _DRIFT_INACTIVE in banner
    assert _POLICY_INACTIVE in banner
    # Default strictness is fail-open.
    assert _FAIL_OPEN in banner
    assert _FAIL_CLOSED not in banner


# --- renderer: --lock arms the drift gate (active, not inactive) ---------------


def test_lock_armed_promotes_drift_gate_to_blocking():
    armed = render_posture_banner(GuardConfig(armed_list_changed=True))
    block = _blocking_section(armed)
    # Liveness: armed -> the drift gate is now in BLOCKING and NOT in the INACTIVE
    # bucket (a no-op renderer ignoring armed_list_changed would fail one of these).
    assert "tools/list_changed drift gate" in block
    assert "armed by --lock" in block
    assert _DRIFT_INACTIVE not in armed
    # Unarmed baseline still lists it as inactive (the contrast proves the toggle).
    assert _DRIFT_INACTIVE in render_posture_banner(GuardConfig())


# --- renderer: --policy arms the argument policy (active, not inactive) --------


def test_policy_armed_promotes_argument_policy_to_blocking():
    armed = render_posture_banner(GuardConfig(armed_policy=True))
    block = _blocking_section(armed)
    assert "argument policy deny" in block
    assert "armed by --policy" in block
    assert _POLICY_INACTIVE not in armed
    assert _POLICY_INACTIVE in render_posture_banner(GuardConfig())


# --- renderer: --audit-only disables ALL blocking (special case) ---------------


def test_audit_only_renders_all_blocking_disabled():
    banner = render_posture_banner(GuardConfig(audit_only=True))
    block = _blocking_section(banner)
    # The BLOCKING bucket is the single audit-only line...
    assert _AUDIT_LINE in banner
    # ...and does NOT enumerate any per-tier blocking (nothing is enforced).
    assert _ANSI not in block
    assert _SECRET not in block
    assert _EXFIL not in block
    # Liveness: audit-only must not also claim a tier blocks elsewhere in BLOCKING.
    assert "block (WRD-RES" not in block


# --- renderer: opt-out drops the exfil tier (THE key liveness test) ------------


def test_no_block_exfil_domain_drops_exfil_from_blocking():
    banner = render_posture_banner(GuardConfig(no_block_exfil_domain=True))
    block = _blocking_section(banner)
    # The exfil tier is DEMOTED out of BLOCKING...
    assert _EXFIL not in block
    # ...while the other two deterministic tiers STILL block. A no-op renderer that
    # always lists all tiers would FAIL the first assertion here.
    assert _ANSI in block
    assert _SECRET in block


def _blocking_block_rule_ids(banner: str) -> set[str]:
    """The set of ``result_inspection.BLOCK_RULES`` ids rendered in BLOCKING.

    Parses the deterministic block-rule ids out of the BLOCKING bucket. Filters to
    BLOCK_RULES membership so the non-deterministic tiers that legitimately appear
    in the bucket (``WRD-RES-INJECT-PHRASE`` opt-in, the drift gate, the policy
    deny) do not pollute the comparison against ``BLOCK_RULES``.
    """
    block = _blocking_section(banner)
    ids = set(re.findall(r"WRD-RES-[A-Z0-9-]+", block))
    return ids & set(result_inspection.BLOCK_RULES)


def test_banner_blocking_set_equals_enabled_block_rules():
    # DERIVATION ground truth: the banner's BLOCKING bucket must list EXACTLY the
    # result_inspection.BLOCK_RULES members that are enabled under the given config
    # — derived from BLOCK_RULES, never a hardcoded list. This:
    #   * passes on this branch (BLOCK_RULES=3 -> banner shows 3),
    #   * AUTO-passes once the IP-literal rule lands in BLOCK_RULES (=4 -> 4),
    #   * still catches fabrication (a BLOCK_RULES tier in the banner that is not
    #     actually enabled, or a tier that is not in BLOCK_RULES at all).
    cases = (
        GuardConfig(),  # all deterministic block rules on
        GuardConfig(no_block_exfil_domain=True),  # one opted out
        GuardConfig(no_block_ansi=True, no_block_secret_echo=True),  # two opted out
        GuardConfig(armed_list_changed=True, armed_policy=True),  # gates armed, det unchanged
    )
    for cfg in cases:
        banner = render_posture_banner(cfg)
        expected = {rid for rid in result_inspection.BLOCK_RULES if cfg.category_enabled(rid)}
        assert _blocking_block_rule_ids(banner) == expected, (
            f"BLOCKING bucket must equal the config-enabled subset of BLOCK_RULES for {cfg!r}"
        )


def test_banner_blocking_is_live_to_block_rules(monkeypatch):
    # LIVENESS: prove the BLOCKING bucket is DERIVED from BLOCK_RULES at runtime,
    # not enumerated from a frozen list. Extend BLOCK_RULES + the label map with a
    # synthetic rule and assert the banner picks it up. A hardcoded renderer that
    # ignores BLOCK_RULES would NOT render the synthetic tier -> this test fails it.
    synthetic = "WRD-RES-SYNTHETIC-LIVENESS"
    extended = frozenset(result_inspection.BLOCK_RULES | {synthetic})
    monkeypatch.setattr(result_inspection, "BLOCK_RULES", extended)
    monkeypatch.setattr(guard_banner, "BLOCK_RULES", extended)
    monkeypatch.setattr(
        guard_banner,
        "_DET_TIERS",
        (*guard_banner._DET_TIERS, (synthetic, "synthetic liveness block")),
    )
    # The synthetic rule has no no_block_* opt-out field; category_enabled returns
    # False for unknown ids, so make it enabled by registering an opt-out mapping.
    monkeypatch.setitem(GuardConfig._DET_OPTOUT, synthetic, "no_block_ansi")

    banner = render_posture_banner(GuardConfig())
    block = _blocking_section(banner)
    assert synthetic in block, "derivation is not live: banner ignored an added BLOCK_RULES id"
    # And it shows up in the equality test's derived set too (full consistency).
    assert synthetic in _blocking_block_rule_ids(banner)


def test_banner_renders_unmapped_block_rule_by_id(monkeypatch):
    # DEFENSIVE: a BLOCK_RULES id with NO entry in the label map must still render
    # (by id) rather than be silently dropped — never under-report posture.
    unmapped = "WRD-RES-UNMAPPED-DEFENSE"
    extended = frozenset(result_inspection.BLOCK_RULES | {unmapped})
    monkeypatch.setattr(guard_banner, "BLOCK_RULES", extended)
    monkeypatch.setitem(GuardConfig._DET_OPTOUT, unmapped, "no_block_ansi")

    banner = render_posture_banner(GuardConfig())
    block = _blocking_section(banner)
    assert unmapped in block, "an unmapped BLOCK_RULES id must still render (by id), not vanish"


# --- renderer: --strict flips fail-open -> fail-CLOSED -------------------------


def test_strict_flips_to_fail_closed():
    banner = render_posture_banner(GuardConfig(strict=True))
    assert _FAIL_CLOSED in banner
    assert _FAIL_OPEN not in banner
    # Contrast: the default is fail-open (proves the field is actually read).
    assert _FAIL_OPEN in render_posture_banner(GuardConfig())


def test_strict_frame_cap_flips_over_cap_to_terminate():
    banner = render_posture_banner(GuardConfig(strict_frame_cap=True))
    assert "over-cap frame" in banner
    assert "TERMINATES the session (exit 3) (--strict-frame-cap)" in banner
    # Default: an over-cap frame passes through uninspected.
    assert "passes through uninspected" in render_posture_banner(GuardConfig())


# --- redaction invariant: no server identity / secret can appear ---------------


def test_banner_never_leaks_argv_or_secret():
    # The banner takes ONLY cfg, so a planted secret / fake server arg cannot be in
    # it. Assert it explicitly (the redaction invariant) across postures, and that
    # no --api-key-style argv token appears.
    secret = "PLANTED-BANNER-SECRET-9f3a"
    for cfg in (GuardConfig(), GuardConfig(audit_only=True), GuardConfig(armed_policy=True)):
        banner = render_posture_banner(cfg)
        assert secret not in banner
        assert "--api-key" not in banner
        assert "--token" not in banner
        assert "server.js" not in banner


# --- CLI harness (mirrors test_guard_platform.py exactly) ----------------------


def _spy_run_guard(monkeypatch):
    """Install a run_guard spy so no real child spawns; return the call-log dict."""
    calls: dict = {"invoked": False}

    def _spy(command, args, cfg, **kw):  # noqa: ANN001
        calls["invoked"] = True
        return 0  # pretend a clean child exit

    monkeypatch.setattr(cli_guard, "run_guard", _spy)
    return calls


def _invoke_guard(*args: str):
    from typer.testing import CliRunner

    from mcp_warden.cli import app

    return CliRunner().invoke(app, ["guard", *args])


# --- CLI: --quiet suppresses the banner; default emits it ----------------------


def test_cli_default_emits_banner(monkeypatch):
    # POSIX path (no platform warning). The default run emits the posture banner to
    # stderr before run_guard. Liveness: it reaches run_guard AND the banner shows.
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", True)
    calls = _spy_run_guard(monkeypatch)

    result = _invoke_guard("node", "server.js")

    assert result.exit_code == 0, result.output
    assert calls["invoked"] is True
    assert "guard posture (v0.3)" in result.output
    assert _BLOCKING_HDR in result.output


def test_cli_quiet_suppresses_banner(monkeypatch):
    # WITH --quiet the banner must NOT appear, but the run still proceeds (clean
    # stderr for tooling integrations). Liveness: a no-op flag would still print it.
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", True)
    calls = _spy_run_guard(monkeypatch)

    result = _invoke_guard("--quiet", "node", "server.js")

    assert result.exit_code == 0, result.output
    assert calls["invoked"] is True  # --quiet only mutes the banner, not the run
    assert "guard posture" not in result.output
    assert _BLOCKING_HDR not in result.output


def test_cli_no_banner_alias_suppresses_banner(monkeypatch):
    # --no-banner is an alias of --quiet on the same Option; it must also suppress.
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", True)
    _spy_run_guard(monkeypatch)

    result = _invoke_guard("--no-banner", "node", "server.js")

    assert result.exit_code == 0, result.output
    assert "guard posture" not in result.output


# --- CLI: a --no-block-* opt-out flows cfg -> banner -> stderr end-to-end -------


def test_cli_banner_reflects_exfil_optout_end_to_end(monkeypatch):
    # Drive the REAL command with --no-block-exfil-domain (no --quiet) and assert
    # the emitted banner dropped the exfil tier from BLOCKING while ANSI remains.
    # Proves the cfg->banner->stderr path is wired through the CLI, not just the
    # renderer in isolation.
    monkeypatch.setattr(guard_lifecycle, "_IS_POSIX", True)
    _spy_run_guard(monkeypatch)

    result = _invoke_guard("--no-block-exfil-domain", "node", "server.js")

    assert result.exit_code == 0, result.output
    block = _blocking_section(result.output)
    assert _EXFIL not in block, "opt-out exfil tier leaked into the CLI banner BLOCKING bucket"
    assert _ANSI in block, "ANSI tier should still block end-to-end"


def test_banner_block_inject_phrase_only_reports_named_block():
    """--block-inject-phrase-only surfaces as a NAMED-phrase block in the BLOCKING
    bucket (posture must be honest), while the BLOCK_RULES-equality invariant still
    holds (INJECT-PHRASE is not a deterministic rule) — issue #12."""
    cfg = GuardConfig(block_inject_phrases_subset=frozenset({"you are now"}))
    banner = render_posture_banner(cfg)
    block = _blocking_section(banner)
    assert _INJECT in block and "named phrase" in block
    assert "--block-inject-phrase-only" in block
    # Deterministic-rule equality is unaffected (INJECT-PHRASE filtered out).
    assert _blocking_block_rule_ids(banner) == {
        rid for rid in result_inspection.BLOCK_RULES if cfg.category_enabled(rid)
    }
    # Non-named phrases are still described as monitor-only.
    assert "all others log only" in banner
