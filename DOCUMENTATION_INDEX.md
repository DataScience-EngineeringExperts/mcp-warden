# Documentation Index — mcp-warden

Master index of every document in this repository. The `docs/` files are the
**security contract and source of truth** for all algorithms; the three core docs
describe and visualize the implementation that satisfies that contract.

---

## Core docs (3-core rule)

| # | Doc | Purpose |
|---|-----|---------|
| 1 | [`README.md`](README.md) | Project overview, install, the pin/check CI demo, CLI reference (incl. v0.3 `lock rotate` + redacted offline `diff` viewer), GitHub Action usage section (Issue #18), **pre-commit hook section (Issue #22)** |
| 2 | [`SYSTEM_CONTEXT_DIAGRAM.md`](SYSTEM_CONTEXT_DIAGRAM.md) | System context + pin/check sequence (mermaid); trust boundary; `conclave` as dev-time reviewer only; composite GitHub Action + **pre-commit hook** as consumer delivery vehicles |
| 3 | [`DOCUMENTATION_INDEX.md`](DOCUMENTATION_INDEX.md) | This file |

## GitHub Action (`action.yml` — Issue #18)

The composite reusable action is the primary delivery vehicle for the `check` gate.
Consumers pin `ernestprovo23/mcp-warden@<tag>` and get a zero-copy-paste integrity
gate with hash-locked supply-chain, SARIF upload, and cross-OS support.

| Artifact | Purpose |
|----------|---------|
| [`action.yml`](action.yml) | Composite action definition — inputs, outputs, injection guard, hash-locked install, exit-code contract |
| [`action/build-requirements.lock`](action/build-requirements.lock) | Hash-locked build backend (hatchling + deps) — regenerate with `pip-compile --generate-hashes` on each release |
| [`action/requirements.lock`](action/requirements.lock) | Hash-locked mcp-warden runtime closure — regenerate with `pip-compile --generate-hashes` on each release |
| [`.github/workflows/action-test.yml`](.github/workflows/action-test.yml) | OS-matrix self-test (ubuntu/macos/windows) + dedicated SARIF-upload job |
| [`tests/test_action_yml.py`](tests/test_action_yml.py) | Structural pytest: composite kind, SHA-pinned `uses:`, version comments, exit-code propagation step, `shell: bash` on every run step |

## pre-commit hook (`.pre-commit-hooks.yaml` — Issue #22)

The local pre-CI gate: runs the same `check` verdict path on every commit so drift
is caught before it reaches CI. A local hook and CI can never disagree on a drift
verdict because both call the shared `check_core.run_check` sequence.

| Artifact | Purpose |
|----------|---------|
| [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml) | Hook definition (`id: mcp-warden-check`, `pass_filenames: false`, `always_run`, `require_serial`) consumers reference from their `.pre-commit-config.yaml` |
| [`src/mcp_warden/precommit.py`](src/mcp_warden/precommit.py) | Wrapper entry point (`mcp-warden-precommit`): `--` server-argv contract, cwd-normalization to git root, non-strict-vs-`--strict` server-unavailability handling; check-only (never writes the lock) |
| [`tests/test_precommit.py`](tests/test_precommit.py) | arg parsing, empty-cmd guidance, clean/drift exit codes, server-unavailable (non-strict 0 / strict 2), cwd normalization, lock write-protection (runtime spy + static import check), `.pre-commit-hooks.yaml` invariants |

## Worked-example gallery (`examples/` — Issue #46)

Copy-paste integration examples, kept green by the `Examples` CI workflow (YAML-lints
the example workflows + re-checks the committed pinned-server locks on every run).

| Artifact | Purpose |
|----------|---------|
| [`examples/README.md`](examples/README.md) | Gallery index; links each example back to the core docs |
| [`examples/github-actions/`](examples/github-actions/) | Four GitHub Action workflows: (a) pin-on-merge + check-on-PR, (b) matrix over multiple servers, (c) SARIF upload, (d) `upload-sarif: false` for private repos |
| [`examples/gitlab-ci/.gitlab-ci.yml`](examples/gitlab-ci/.gitlab-ci.yml) | Equivalent check gate on GitLab CI |
| [`examples/pre-commit/.pre-commit-config.yaml`](examples/pre-commit/.pre-commit-config.yaml) | Minimal + pre-push hook variants (mirror the README hook) |
| [`examples/pinned-servers/`](examples/pinned-servers/) | Three real, openly-available MCP servers (`server-everything`, `server-memory`, `server-sequential-thinking`) each pinned to a committed `warden.lock` via a pinned launcher ref, with a per-server README (exact `pin` argv + sample `check`) |
| [`.github/workflows/examples.yml`](.github/workflows/examples.yml) | CI: yamllint the example workflows + re-run `check` against every committed example lock |

## Documentation site (`docs-site/` — Issues #47 / #48)

Education-first, task-focused guides (mkdocs-material) where mcp-warden is the
implementation detail. Built with `mkdocs build --strict` on every PR and deployed
to GitHub Pages on `main`. The security-contract specs under `docs/` remain the
source of truth; these pages explain and link them. Every page carries a
scope-honesty box and makes no compliance/regulatory claim.

| Artifact | Purpose |
|----------|---------|
| [`mkdocs.yml`](mkdocs.yml) | Site config (material theme, nav, no analytics/tracking) |
| [`docs-site/index.md`](docs-site/index.md) | Home — mental model + where to start |
| [`docs-site/quickstart.md`](docs-site/quickstart.md) | Install → pin → check → Action in under 5 minutes |
| [`docs-site/tool-poisoning.md`](docs-site/tool-poisoning.md) | What is MCP tool poisoning; what mcp-warden does / does-not do |
| [`docs-site/rug-pull.md`](docs-site/rug-pull.md) | What is an MCP rug pull; how the drift gate catches it |
| [`docs-site/pin-in-ci.md`](docs-site/pin-in-ci.md) | Pin MCP servers in CI (GitHub Actions + GitLab); links `examples/` |
| [`docs-site/checklist.md`](docs-site/checklist.md) | Vendor-neutral MCP security checklist; names the tool per layer |
| [`docs-site/lock-format.md`](docs-site/lock-format.md) | The MCP Lock Format; links `docs/SPEC.md` as source of truth |
| [`docs-site/comparison.md`](docs-site/comparison.md) | Honest mcp-warden vs mcp-scan vs gateways — complementary layers (Issue #48) |
| [`.github/workflows/docs.yml`](.github/workflows/docs.yml) | CI: `mkdocs build --strict` PR gate; deploy to Pages on `main` |

## Security contract (`docs/` — source of truth, do not duplicate)

| Doc | Defines |
|-----|---------|
| [`docs/SPEC.md`](docs/SPEC.md) | **MCP Lock Format v1** — the vendor-neutral, self-contained format specification any tool can implement: on-disk `warden.lock` schema, RFC 8785 (JCS) canonicalization, SHA-256 `sha256:<hex>` hashing, `overall_digest` construction, the normative drift class + severity table, the optional per-tool inspection block, and a Conformance section + worked example. `WARDEN_LOCK_SCHEMA.md` is the mcp-warden implementation of this format |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | **(v0.1)** Positioning, trust model (TOFU + `--approve`), assets/actors, the four threat classes (MCP-DRIFT / MCP-CAPSURF / MCP-SECRET / MCP-SUPPLY), explicit out-of-scope limits, deliberate cuts |
| [`docs/THREAT_MODEL_V2.md`](docs/THREAT_MODEL_V2.md) | **(v0.2)** Addendum extending the v0.1 model: T-RESULT vectors, the defends (BLOCK) / monitors (fuzzy) / still-does-NOT-defend (T-BEHAVE) table, runtime trust-model notes, retained + added cuts, shadow-default positioning |
| [`docs/WARDEN_LOCK_SCHEMA.md`](docs/WARDEN_LOCK_SCHEMA.md) | **mcp-warden implementation of [`docs/SPEC.md`](docs/SPEC.md) (MCP Lock Format v1).** `warden.lock` format, RFC 8785 canonicalization + SHA-256 hashing, field/entry/overall digests, the normative drift definition + severities; **§5.1/§6.2 structural schema diff** (normalized per-tool `schema_skeleton`, `schema_version` 2, granular `WRD-DRIFT-SCHEMA-*` taxonomy + severities, v1 fallback); **§8.1/§8.2 (v0.3, #19)** structured out-of-digest provenance (`pinner` / `attestations` / `rotation_count`, `PROVENANCE_VERSION`, B4 `bound_digest` format) + `lock rotate` digest-invariant semantics + the #16 signing implication; **§11 (v0.2)** optional per-tool inspection policy (`expected_output_charset` / `may_return_urls` / `secret_echo_applies`, fail-safe defaults, digest impact) |
| [`docs/WARDEN_LOCK_EXAMPLE.md`](docs/WARDEN_LOCK_EXAMPLE.md) | Illustrative full `warden.lock` + a post-`lock rotate` `pin` block (archived from WARDEN_LOCK_SCHEMA §9 to keep that core doc under the line cap) |
| [`docs/CHECKS.md`](docs/CHECKS.md) | The deterministic `WRD-*` static-check catalog (capability/secret/supply/robustness), the shared tokenizer, severity→SARIF mapping, redaction rule, CUT list. **Reused by v0.2** `WRD-RES-SECRET-ECHO` (the `WRD-SEC-*` patterns + redaction) |
| [`docs/POLICY_MODEL.md`](docs/POLICY_MODEL.md) | Policy schema, the four high-risk shapes, constraint vocabulary, fail-closed defaults, SSRF deny ranges, lint + single-sample eval semantics. **Enforced at runtime by v0.2 `guard`** on live `tools/call` requests |
| [`docs/RESULT_INSPECTION.md`](docs/RESULT_INSPECTION.md) | **(v0.2)** The `WRD-RES-*` result-inspection catalog: deterministic/fuzzy tier partition, per-rule exact match definitions (ANSI allowlist, secret-echo via `WRD-SEC-*`, exfil seed denylist, injection seed phrase list), severities, SARIF mapping, redaction, fail-safe per-tool precision. Run identically by `guard` and `inspect` |
| [`docs/GUARD_PROXY.md`](docs/GUARD_PROXY.md) | **(v0.2 base, updated to v0.3 defaults)** The `guard` transparent stdio proxy + `inspect` offline analyzer contract: frame-handling discipline, single-loop framing (Content-Length + newline), incremental scan, subprocess lifecycle, runtime arg-policy + `tools/list_changed` gate, the **v0.3 default-block posture** + `--no-block-*` opt-outs + `--audit-only`, reserved codes `-32001`/`-32002`, and the exact on-the-wire "block" behavior |
| [`docs/GUARD_PROXY_V3.md`](docs/GUARD_PROXY_V3.md) | **(v0.3)** The proxy-hardening contract: `notifications/cancelled`/`progress` untouched passthrough (§1), subprocess-lifecycle edge cases — server-crash `-32002` synthesis, client-disconnect process-group teardown, truncated/oversized-frame fail-open (§2), Windows experimental degradation (§3), the full v0.3 block-flag scheme + precedence (§4), and **(#21) `--strict` fail-CLOSED mode — terminate on an inspection-layer error, `-32003` non-retriable, exit `3` (§5)** |
| [`docs/SIGNING.md`](docs/SIGNING.md) | **(v0.3, #16)** Sigstore keyless signing + verification of `warden.lock`: the optional `[sigstore]` extra, the deterministic `mcp-warden-lock-digest/v1` statement that binds ONLY `overall_digest` (survives `lock rotate`), `pin --sign` / `check --verify` usage, the **fixed-sidecar** verify contract (pointer field never trusted), the full fail-closed matrix, the TUF-cache/offline caveat, and the two accepted trade-offs (rotate-replay + committed-fixture coverage gap + refresh steps) |

---

## Community & contribution

| Doc | Purpose |
|-----|---------|
| [`LICENSE`](LICENSE) | MIT license |
| [`SECURITY.md`](SECURITY.md) | Private vulnerability-disclosure policy + supported versions (report via GitHub Security Advisories / email — never a public issue) |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Dev setup, the `.venv` test workflow, the determinism / byte-compatibility contract, how to propose a new check |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |
| [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) | Bug report + feature/new-check request forms (security issues routed to `SECURITY.md`) |
| [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) | PR checklist (tests green, specs in sync, determinism preserved, no secrets) |
| [`.gitleaks.toml`](.gitleaks.toml) | Secret-scan config; CI runs gitleaks over full history on every push/PR |

---

## Release engineering

| Doc | Purpose |
|-----|---------|
| [`RELEASING.md`](RELEASING.md) | Operator runbook: one-time PyPI Trusted-Publisher (OIDC) setup, cut-a-release checklist, post-release verification, rollback/yank. PyPI dist name is `mcpwarden`; CLI/repo stay `mcp-warden`. |
| [`CHANGELOG.md`](CHANGELOG.md) | Keep-a-Changelog history (0.3.0 → 1.0.0) with explicit in/out-of-scope. *(Added by the CHANGELOG PR.)* |
| [`.github/workflows/release.yml`](.github/workflows/release.yml) | Publish-on-Release workflow: build sdist+wheel → publish to PyPI via OIDC Trusted Publishing (no stored token) → Sigstore-keyless sign the artifacts and attach bundles to the Release. Inert until a Release is published AND the `mcpwarden` Trusted Publisher exists. |

---

## Source layout

| Module | Responsibility | Spec anchor |
|--------|----------------|-------------|
| `src/mcp_warden/hashing.py` | `canon()` (RFC 8785) + `hash()` + field hashes | WARDEN_LOCK_SCHEMA §3 |
| `src/mcp_warden/tokenizer.py` | Shared tokenizer + capability derivation (single source of truth) | CHECKS §3 / WARDEN_LOCK_SCHEMA §5.4 |
| `src/mcp_warden/capture.py` | MCP stdio capture client (argv array, no shell; timeouts/errors) | THREAT_MODEL §3.3 / WARDEN_LOCK_SCHEMA §4.1 |
| `src/mcp_warden/models.py` | Pydantic models for captured surface + lock (incl. `Pinner`/`Attestation` provenance) | WARDEN_LOCK_SCHEMA §2–§8 |
| `src/mcp_warden/lockfile.py` | Lock builder + reader/writer + overall digest | WARDEN_LOCK_SCHEMA §5–§6, §9 |
| `src/mcp_warden/check_core.py` | **(#22)** Shared check verdict core (`run_check` / `run_check_full`): read_lock→capture→checks→build_lock(in-memory)→compute_drift. Single source of truth for `cli.py:check` AND the pre-commit wrapper | WARDEN_LOCK_SCHEMA §6.2 |
| `src/mcp_warden/provenance.py` | Out-of-digest provenance construction + `rotate_provenance` (pure; note-cap fail-closed) + **(#16)** `make_sigstore_pointer_attestation` | WARDEN_LOCK_SCHEMA §8.1–§8.2 |
| `src/mcp_warden/signing.py` | **(#16)** Sigstore keyless sign/verify primitives (guarded import; `build_statement` / `sign_statement` / `verify_statement` — verify raises on failure, returns None on success) | SIGNING.md |
| `src/mcp_warden/cli_sign.py` | **(#16)** `pin --sign` / `check --verify` CLI control flow: fixed-sidecar verify, atomic bundle write, fail-closed exits | SIGNING.md |
| `src/mcp_warden/drift.py` | Per-class drift/diff engine + severities | WARDEN_LOCK_SCHEMA §6.2 |
| `src/mcp_warden/schema_diff.py` | Deterministic structural `inputSchema` skeleton extractor + per-fact diff classifier (`WRD-DRIFT-SCHEMA-*`; `$ref`/cyclic/malformed-safe) | WARDEN_LOCK_SCHEMA §5.1, §6.2 |
| `src/mcp_warden/checks.py` | Static-check orchestrator (deterministic sort) | CHECKS §4–§5 |
| `src/mcp_warden/checks_secret.py` | `WRD-SEC-*` vendor + entropy + redaction | CHECKS §4.2 |
| `src/mcp_warden/checks_supply.py` | `WRD-SUP-*` launch-command checks | CHECKS §4.3 |
| `src/mcp_warden/redact.py` | `first4 + "…" + (len=N)` secret redaction | CHECKS §8.2 |
| `src/mcp_warden/emitters.py` | SARIF 2.1.0 + JSONL emitters (`ruleId` verbatim) | CHECKS §2 |
| `src/mcp_warden/policy_model.py` | Policy load + lint + fail-closed schema | POLICY_MODEL §3, §4.1 |
| `src/mcp_warden/policy_eval.py` | Single-sample eval + runtime arg eval (fs/shell/http-SSRF/sql) | POLICY_MODEL §2, §4.2, §5 |
| `src/mcp_warden/result_inspection.py` | **(v0.2)** `WRD-RES-*` catalog public entry (`inspect_result`, `ResultFinding`, `InspectionPolicy`) — single source run by guard + inspect | RESULT_INSPECTION §1–§6, §8 |
| `src/mcp_warden/res_catalog.py` | **(v0.2)** per-rule evaluators + content-block text extraction | RESULT_INSPECTION §1, §3–§5 |
| `src/mcp_warden/res_rules.py` · `res_net.py` | **(v0.2)** deterministic primitives: ANSI codepoint scan + inject-phrase normalize (`res_rules`), exfil/URL host matching + seed denylists (`res_net`) | RESULT_INSPECTION §3.1, §3.3, §4.1, §5.1 |
| `src/mcp_warden/guard.py` | **(v0.2/v0.3)** proxy runner: subprocess lifecycle, own pgrp, signal forwarding, single-loop byte pumps, teardown-path decision (client-EOF vs child-exit) | GUARD_PROXY §1, §2.3, §2.6 · V3 §2 |
| `src/mcp_warden/guard_loop.py` · `guard_result.py` | **(v0.2/v0.3)** frame discipline: v0.3 default-block `GuardConfig` + c2s arg-policy + cancel/progress passthrough (`guard_loop`), s2c result inspection + `tools/list_changed` gate + on-wire block decision (`guard_result`) | GUARD_PROXY §2, §4, §7, §9 · V3 §1, §4 |
| `src/mcp_warden/guard_lifecycle.py` | **(v0.3)** lifecycle teardown: `-32002` pending-id synthesis, `128+signum` exit mapping, POSIX process-group TERM→grace→KILL teardown, Windows best-effort + `WRD-RES-WIN-LIFECYCLE`; **(#21)** `-32003` `synthesize_strict_abort` | GUARD_PROXY_V3 §2, §3, §5 |
| `src/mcp_warden/guard_io.py` | **(v0.3)** async stdio adapters (`wrap_recv`/`wrap_send`) bridging blocking stdio to the single-loop framer | GUARD_PROXY §2.3 |
| `src/mcp_warden/guard_list_gate.py` | **(v0.3)** runtime `tools/list` drift gate: hashes the live list vs the lock (reuses `hashing`), fail-open on malformed payloads; **(#21)** `strict=` re-raises the nested hash error instead of swallowing it | GUARD_PROXY §4.3, §7.3 · V3 §5 |
| `src/mcp_warden/framing.py` | **(v0.2)** single-reader stdio framer (Content-Length + newline), original-bytes pass-through, truncation-at-EOF capture | GUARD_PROXY §2.4, §2.5 · V3 §2.3 |
| `src/mcp_warden/wire_block.py` | **(v0.2/v0.3)** on-wire block synthesis: `-32001` error-response + redacted-content (`_meta.warden.modified`); **v0.3** `-32002` `transport_error`; **(#21)** `-32003` `strict_abort_error` (non-retriable) | GUARD_PROXY §7 · V3 §2.6, §5 |
| `src/mcp_warden/inspector.py` | **(v0.2)** offline JSONL analyzer over recorded sessions (same catalog) | GUARD_PROXY §3 |
| `src/mcp_warden/emit_res.py` | **(v0.2)** SARIF 2.1.0 + JSONL emitters for `ResultFinding` (action/direction/tier) | GUARD_PROXY §10 |
| `src/mcp_warden/cli.py` · `cli_guard.py` · `cli_lock.py` · `cli_diff.py` | `typer` CLI (`pin`/`check`/`policy`/`guard`/`inspect`/`lock rotate`/`diff`), exit codes; **`check` delegates its verdict to `check_core.run_check_full` (#22)**; `guard`/`inspect` bodies in `cli_guard`, `lock rotate` + integrity gate in `cli_lock`, **(v0.3) `diff` redacted offline lock viewer (`SAFE_PROVENANCE_FIELDS` allowlist, never reads `server.command`/`args`)** in `cli_diff` | all |
| `src/mcp_warden/precommit.py` | **(#22)** `mcp-warden-precommit` pre-commit entry point — wraps `check_core.run_check`; check-only (never imports `pin`/lock-writer, never opens the lock for write) | README pre-commit section |

## Tests

| File | Covers |
|------|--------|
| `tests/test_hashing.py` | JCS+SHA-256 reproducibility, canonical-form pins, null handling |
| `tests/test_tokenizer.py` | Segment-exact tokenization + capability derivation |
| `tests/test_checks.py` | Capability/secret/supply/robustness checks + redaction |
| `tests/test_drift.py` | Drift per class (added/removed/modified/server-identity/unapproved) |
| `tests/test_schema_diff.py` | Structural skeleton extraction (purity, `$ref`/cyclic/malformed safety) + per-fact diff taxonomy (required/enum/type/constraint/`additionalProperties`) + v1 fallback |
| `tests/test_lockfile.py` | Lock build/write/read, digest exclusions, hashes-not-raw |
| `tests/test_policy.py` | Lint (incl. unknown-key error) + eval (allow/deny/SSRF/fail-closed) |
| `tests/test_emitters.py` | SARIF shape + level mapping + JSONL records |
| `tests/test_e2e_pin_check.py` | **Headline:** real stdio pin→mutate→check round-trip |
| `tests/test_diff.py` | **(v0.3)** `warden diff` renderer: identical→"no differences", tool add/remove + schema change rows, **redaction-leak guard** (secret in `server.args` absent from human/`--json`/`--sarif` incl. parsed-JSONL `detail`), provenance-only section vs empty integrity drift, `--exit-code` (1 on integrity drift / 0 on provenance-only), `--no-provenance` M6 message, fail-closed on missing/invalid lock |
| `tests/test_result_inspection.py` | **(v0.2)** `WRD-RES-*`: ANSI codepoint match (incl. extended/binary-ok), secret-echo reuse + redaction, exfil host/subdomain boundary + path-qualified, injection exact-phrase (no broad-regex FP), URL/uninspectable notes |
| `tests/test_inspection_policy.py` | **(v0.2)** §11 per-tool policy fail-safe defaults, byte-identical-to-v0.1 digest when absent, inspection-policy drift, pin-time validation, reader fallback + LOCK-INVALID |
| `tests/test_wire_block.py` | **(v0.2)** `-32001` error-response shape, block-mode mapping, ANSI strip-in-place `_meta.warden.modified`, secret redact-in-place |
| `tests/test_framing.py` | **(v0.2)** newline + Content-Length framing, chunk-split reads, original-bytes pass-through, malformed-frame parse capture |
| `tests/test_guard_posture.py` | **(v0.2/v0.3)** fail-open (inspector exception/malformed → pass-through) vs fail-closed (policy deny → block under `armed_policy`), audit-only precedence over default-on |
| `tests/test_guard_proxy.py` | **(v0.2/v0.3) Headline:** real `tools/call` through `guard`: v0.3 default-block + `--audit-only` shadow restore, deprecated `--block-*` no-op + stderr note, inject stays monitor, forced framing error survives |
| `tests/test_guard_v3.py` | **(v0.3)** opt-out demotes to shadow (`--no-block-*`/`--allow-exfil-domain`/`--no-block-deterministic`), `tools/list_changed` gate block+shadow, policy deny block+shadow, audit-only override, cancel/progress passthrough, **server-crash → `-32002` for every pending id**, client-disconnect child reap (no orphan), truncated + oversized frame fail-open |
| `tests/test_guard_strict.py` | **(#21)** `--strict` fail-CLOSED: 4 terminate sites (request-policy / result-inspect / list-gate / nested-hash re-raise) → exit `3` + one `strict_abort` stderr line + `-32003` client frame + child reaped; negatives (truncated/over-cap/unparseable/clean) do NOT abort; default `--no-strict` byte-identical fail-open regression; secret-leak redaction; CLI threading; double-emission single line; `StrictInspectionAbort` is `BaseException`-not-`Exception` + anyio `ExceptionGroup` unwrap |
| `tests/test_inspect_parity.py` | **(v0.2)** guard↔inspect finding parity on the same recorded frames + inspect exit codes |
| `tests/fuzz/` (`test_fuzz_framing.py` · `test_fuzz_ansi.py` · `test_fuzz_domain.py` · `test_fuzz_redact.py`) | **(#17)** `hypothesis` property-fuzzing of the live runtime attack surface: framer XOR/never-raise + mode-equivalence + truncation→parse_error + `_parse_content_length` never-negative (Finding A fix) + read_frame never-hang + Content-Length composition consistency; ANSI construction-based liveness/soundness + completeness + idempotence + strip∘redact order-independence; exfil-domain soundness (no invented hits) + URL/bare-host liveness + anchoring/IDN/trailing-dot; redactor format-structure + leak-bound + #38 short-secret contract. `ci`/`fuzz` profiles in `tests/fuzz/conftest.py`; deep soak via `make fuzz` |
| `tests/fixtures/clean_server.py` · `mutated_server.py` | Real MCP SDK stdio fixtures |
| `tests/fixtures/poison_server.py` | **(v0.2)** result-poisoning fixture server (ANSI/secret-echo/exfil/inject/clean tools) |
| `tests/fixtures/crash_server.py` · `listchange_server.py` · `clean_listchange.warden.lock` | **(v0.3)** raw-stdio lifecycle fixtures: crash-mid-call (`-32002`) and `tools/list_changed` rug-pull + its pinned clean lock |
| `tests/fixtures/fault_guard_launcher.py` | **(#21)** test-only launcher that monkeypatches ONE inspection function (`inspect_result` / `evaluate_call` / `diverges_from_lock` / `_hash_live_tools`) to raise inside the spawned guard child, then runs the real CLI — drives the `--strict` terminate-site tests without any test branch in production code; `FAULT_SECRET` plants a secret for the redaction test |
