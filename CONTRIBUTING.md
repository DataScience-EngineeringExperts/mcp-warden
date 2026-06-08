# Contributing to mcp-warden

Thanks for helping harden the MCP supply chain. mcp-warden is a **security tool**,
so contributions are held to a high bar: deterministic behavior, tests green, and
the design specs in `docs/` kept authoritative. This guide gets you set up and
explains the rules that keep the gate trustworthy.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Never
report security vulnerabilities as public issues or PRs — follow
[`SECURITY.md`](SECURITY.md).

---

## Dev setup

mcp-warden requires **Python ≥ 3.11**. Use a project-local virtual environment.

```bash
# from a clone of this repo
uv venv .venv
uv pip install --python .venv/bin/python -e ".[dev]"

# the CLI is then available as:
.venv/bin/mcp-warden --help
```

> **Why a project `.venv` (and why we run tests through it).**
> Run pytest with `.venv/bin/python -m pytest`, not a bare `pytest`. Some
> contributors' *system* Python is polluted by an unrelated global
> `conftest.py` (e.g. a numcodecs-style autouse fixture) that gets imported into
> every collection and breaks or skews unrelated test runs. The repo `.venv` is
> isolated from that global state, so it is the **only supported way to run the
> suite reproducibly**. CI installs into a clean job environment and runs `pytest`
> directly; locally, always go through `.venv`.

`uv` is recommended but not required — `python -m venv .venv && .venv/bin/pip
install -e ".[dev]"` works too.

---

## Running tests

```bash
# full suite (the supported path)
.venv/bin/python -m pytest -q

# a single file or test
.venv/bin/python -m pytest tests/test_hashing.py -q
.venv/bin/python -m pytest tests/test_guard_proxy.py::test_default_block -q
```

The headline tests spawn **real MCP stdio fixture servers** (`pin` → mutate →
`check`, and a live `tools/call` through the `guard` proxy), so the suite takes
~1 minute. That round-trip coverage is intentional — keep it.

A change is not done until `.venv/bin/python -m pytest -q` is fully green.

---

## The specs in `docs/` are the source of truth

The files under `docs/` are the **security contract** — they define every
algorithm; the code merely satisfies them. The mapping from spec to module lives
in [`DOCUMENTATION_INDEX.md`](DOCUMENTATION_INDEX.md). When code and spec disagree,
the spec wins, and your PR must reconcile them.

### Determinism / byte-compatibility contract (read before touching internals)

mcp-warden's core guarantee is **reproducibility**: canonicalization is RFC 8785
(JCS) + SHA-256 (`sha256:<hex>`), so `pin` and `check` agree byte-for-byte, and
`guard` (live) and `inspect` (offline) run the **identical** rule catalog. A change
that silently shifts a hash, a canonical form, or a rule's verdict can break every
committed `warden.lock` in the wild and turn a passing gate into a false negative.

If your change touches **any** of the following, it must preserve byte-compatibility
**and** update the corresponding spec in the same PR:

- **Hashing / canonicalization** — `src/mcp_warden/hashing.py`, the field/entry/
  overall digest construction, or null/ordering handling
  → spec: `docs/WARDEN_LOCK_SCHEMA.md`.
- **The `warden.lock` schema** (including the §11 per-tool inspection policy)
  → spec: `docs/WARDEN_LOCK_SCHEMA.md`.
- **The static-check catalog `WRD-*`** (capability / secret / supply / robustness),
  the shared tokenizer, or redaction → specs: `docs/CHECKS.md`.
- **The result-inspection catalog `WRD-RES-*`** (ANSI allowlist, secret-echo,
  exfil/URL host matching, injection seed phrases, tiers, severities)
  → spec: `docs/RESULT_INSPECTION.md`.
- **Drift semantics** (what counts as added/removed/modified/identity drift and at
  what severity) → spec: `docs/WARDEN_LOCK_SCHEMA.md`.
- **The `guard`/`inspect` block posture, flag scheme, or reserved error codes**
  (`-32001` / `-32002`) → specs: `docs/GUARD_PROXY.md`, `docs/GUARD_PROXY_V3.md`.
- **The policy model** (shapes, fail-closed defaults, SSRF ranges)
  → spec: `docs/POLICY_MODEL.md`.

Practical rules:

- **Do not change a hash without intent.** If a refactor changes a digest of an
  unchanged surface, that is a bug — fix the refactor, don't re-bless the fixtures.
- **`guard` and `inspect` must stay in lockstep.** Any rule change must produce
  identical findings on the same frames (`tests/test_inspect_parity.py` guards
  this). Add to the shared catalog, never to one path only.
- **New behavior gets a new check ID**, never a redefinition of an existing one.
  `ruleId`s are emitted verbatim into SARIF that downstream users key on.

---

## Proposing a new check

New `WRD-*` (static) or `WRD-RES-*` (result-inspection) checks are very welcome.
The path that gets a check merged:

1. **Open an issue first** using the *feature request* template. Describe the
   threat, the MCP surface or tool-result shape it appears in, and why a
   deterministic rule can catch it with a ~0 false-positive rate. Fuzzy/heuristic
   detectors are accepted only in the **monitor (log-only)** tier, never as a
   default block.
2. **Reserve a stable ID** in the right family (`WRD-CAP-*`, `WRD-SEC-*`,
   `WRD-SUP-*`, `WRD-RES-*`). IDs are forever — pick a clear, specific name.
3. **Spec it** in the matching `docs/` file: exact match definition, severity,
   tier (deterministic-block vs fuzzy-monitor), SARIF mapping, and any redaction.
4. **Implement** it in the appropriate module (see `DOCUMENTATION_INDEX.md` for the
   module map) so `guard` and `inspect` share the same evaluator.
5. **Test** it: a positive fixture, a negative/control fixture (no false positive),
   and — for result rules — parity between `guard` and `inspect`.

Detection rules must **never weaken on real secrets** to reduce noise. Tune
precision with allowlists/anchoring, not by dropping coverage.

---

## Regenerating the action lockfiles

The composite action installs hash-locked dependencies from two lock files:

- `action/build-requirements.lock` — hatchling + build backend (installed first)
- `action/requirements.lock` — full runtime dep closure

Both are generated with `uv pip compile` and must be regenerated whenever
`pyproject.toml` dependencies change or a lockfile refresh is needed as part
of a release. The exact command is printed at the top of each lockfile and
reproduced here for convenience:

```bash
# From the repo root — requires uv
uv pip compile --universal --generate-hashes pyproject.toml \
    -o action/requirements.lock

uv pip compile --universal --generate-hashes action/build-requirements.in \
    -o action/build-requirements.lock
```

Lockfile regeneration is a **release gate** — any PR that changes runtime deps
must include updated lockfiles. CI will reject installs whose hashes no longer
match (`pip install --require-hashes` fails on hash mismatch).

---

## Pull request expectations

Before you open a PR, confirm:

- [ ] **Tests pass** via the repo venv: `.venv/bin/python -m pytest -q` is green.
- [ ] **Specs updated.** Any behavior change (hashing, canonicalization, the
      `WRD-*` / `WRD-RES-*` catalogs, drift, block posture, policy) updates the
      corresponding `docs/` spec in the same PR. Determinism / byte-compatibility
      is preserved (or the break is intentional, documented, and version-bumped).
- [ ] **No secrets.** No real credentials anywhere in the tree. Test fixtures use
      obviously-synthetic, clearly-fake placeholders (and the fixture paths are
      already allowlisted in `.gitleaks.toml`).
- [ ] **Docs in sync.** README/CLI reference updated if user-facing behavior or
      flags changed. The 3-core docs and `DOCUMENTATION_INDEX.md` stay accurate.
- [ ] **Scoped commits** with a clear message describing the *why*.

Use the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) — it restates
this checklist. Maintainers may ask for a fixture or spec diff before reviewing
logic; that is normal for a security tool.

Thank you for keeping the gate honest.
