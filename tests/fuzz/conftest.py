"""Hypothesis profiles for the fuzz suite (issue #17, binding fix #5).

Two registered profiles, selected by the ``HYPOTHESIS_PROFILE`` env var
(default ``ci``):

``ci`` — the profile that runs inside the normal ``pytest -q`` path and in the
    CI Test-suite job. ``max_examples=1000``, ``deadline=None``,
    ``database=None``. Determinism in CI comes from the pinned
    ``--hypothesis-seed=0`` (see ``make fuzz-ci``), NOT from ``derandomize`` —
    see the B5 note at the profile registration.

    Why 1000 (not hypothesis' default 100): these properties guard a SECURITY
    boundary, not application behavior. A framer/redactor/ANSI bypass is a
    silent fail-open — the worst case in the threat model — so the per-property
    example budget must exercise far more of the constructed-malicious +
    boundary input space than a token smoke-test count. 1000 derandomized
    examples per property keeps the whole suite well under a minute on the CI
    box while giving each soundness/liveness invariant a meaningful sample.
    The pinned CI seed + ``database=None`` make CI replayable from the source
    alone (no dependence on a local ``.hypothesis`` DB); every counterexample
    found in development is additionally frozen as an ``@example`` so it persists
    as a permanent regression even outside the deep ``fuzz`` run.

``fuzz`` — the deep local soak driven by ``make fuzz``. ``max_examples=20000``,
    ``deadline=None``, and the persistent example database (so a freshly found
    counterexample is replayed first on the next local run). Not run in CI.

The default-loaded profile is taken from ``HYPOTHESIS_PROFILE`` (``ci`` if unset),
so ``HYPOTHESIS_PROFILE=fuzz pytest tests/fuzz`` switches to the deep soak.
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, settings
from hypothesis.database import DirectoryBasedExampleDatabase

# @example-FREEZE POLICY (issue #17 audit, enforced by review, not tooling):
# CI runs with database=None, so a counterexample found in one run is NOT carried
# to the next via the Hypothesis example DB. Therefore EVERY counterexample a
# `make fuzz` soak or a CI run surfaces MUST be pinned back into the relevant test
# as an `@example(...)` in the same PR that observes it. That is the only thing that
# makes a found regression permanent across the seed/profile boundary. Do not close
# a fuzz finding without freezing its triggering input as an `@example`.

# Deterministic, fast, source-replayable. Runs in the normal pytest path + CI.
# B5 (issue #17 audit): no ``derandomize=True`` here. CI pins the seed explicitly
# (``make fuzz-ci`` / the CI step pass ``--hypothesis-seed=0``), which already makes
# the run fully deterministic; ``derandomize`` on top of a fixed seed is moot and
# silently changes the example stream vs a local ``pytest`` run that does NOT pass a
# seed (local-vs-CI divergence). Determinism comes from the pinned seed in CI; local
# runs stay randomized for broader coverage, and every counterexample is frozen as an
# ``@example`` so it persists regardless of seed.
settings.register_profile(
    "ci",
    max_examples=1000,
    deadline=None,
    database=None,
    # filter-heavy URL/host strategies can trip the too-much-filtering check on
    # a few examples without indicating a real problem; suppress it for the soak.
    suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.too_slow],
)

# Deep local soak: 20k examples + a persistent DB so found counterexamples replay.
settings.register_profile(
    "fuzz",
    max_examples=20_000,
    deadline=None,
    database=DirectoryBasedExampleDatabase(".hypothesis/examples"),
    suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.too_slow],
)

settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "ci"))
