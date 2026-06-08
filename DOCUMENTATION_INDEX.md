# Documentation Index — mcp-warden

Master index of every document in this repository. The `docs/` files are the
**security contract and source of truth** for all algorithms; the three core docs
describe and visualize the implementation that satisfies that contract.

---

## Core docs (3-core rule)

| # | Doc | Purpose |
|---|-----|---------|
| 1 | [`README.md`](README.md) | Project overview, install, the pin/check CI demo, CLI reference |
| 2 | [`SYSTEM_CONTEXT_DIAGRAM.md`](SYSTEM_CONTEXT_DIAGRAM.md) | System context + pin/check sequence (mermaid); trust boundary; `conclave` as dev-time reviewer only |
| 3 | [`DOCUMENTATION_INDEX.md`](DOCUMENTATION_INDEX.md) | This file |

## Security contract (`docs/` — source of truth, do not duplicate)

| Doc | Defines |
|-----|---------|
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | **(v0.1)** Positioning, trust model (TOFU + `--approve`), assets/actors, the four threat classes (MCP-DRIFT / MCP-CAPSURF / MCP-SECRET / MCP-SUPPLY), explicit out-of-scope limits, deliberate cuts |
| [`docs/THREAT_MODEL_V2.md`](docs/THREAT_MODEL_V2.md) | **(v0.2)** Addendum extending the v0.1 model: T-RESULT vectors, the defends (BLOCK) / monitors (fuzzy) / still-does-NOT-defend (T-BEHAVE) table, runtime trust-model notes, retained + added cuts, shadow-default positioning |
| [`docs/WARDEN_LOCK_SCHEMA.md`](docs/WARDEN_LOCK_SCHEMA.md) | `warden.lock` format, RFC 8785 canonicalization + SHA-256 hashing, field/entry/overall digests, the normative drift definition + severities; **§5.1/§6.2 structural schema diff** (normalized per-tool `schema_skeleton`, `schema_version` 2, granular `WRD-DRIFT-SCHEMA-*` taxonomy + severities, v1 fallback); **§8.1/§8.2 (v0.3, #19)** structured out-of-digest provenance (`pinner` / `attestations` / `rotation_count`, `PROVENANCE_VERSION`, B4 `bound_digest` format) + `lock rotate` digest-invariant semantics + the #16 signing implication; **§11 (v0.2)** optional per-tool inspection policy (`expected_output_charset` / `may_return_urls` / `secret_echo_applies`, fail-safe defaults, digest impact) |
| [`docs/WARDEN_LOCK_EXAMPLE.md`](docs/WARDEN_LOCK_EXAMPLE.md) | Illustrative full `warden.lock` + a post-`lock rotate` `pin` block (archived from WARDEN_LOCK_SCHEMA §9 to keep that core doc under the line cap) |
| [`docs/CHECKS.md`](docs/CHECKS.md) | The deterministic `WRD-*` static-check catalog (capability/secret/supply/robustness), the shared tokenizer, severity→SARIF mapping, redaction rule, CUT list. **Reused by v0.2** `WRD-RES-SECRET-ECHO` (the `WRD-SEC-*` patterns + redaction) |
| [`docs/POLICY_MODEL.md`](docs/POLICY_MODEL.md) | Policy schema, the four high-risk shapes, constraint vocabulary, fail-closed defaults, SSRF deny ranges, lint + single-sample eval semantics. **Enforced at runtime by v0.2 `guard`** on live `tools/call` requests |
| [`docs/RESULT_INSPECTION.md`](docs/RESULT_INSPECTION.md) | **(v0.2)** The `WRD-RES-*` result-inspection catalog: deterministic/fuzzy tier partition, per-rule exact match definitions (ANSI allowlist, secret-echo via `WRD-SEC-*`, exfil seed denylist, injection seed phrase list), severities, SARIF mapping, redaction, fail-safe per-tool precision. Run identically by `guard` and `inspect` |
| [`docs/GUARD_PROXY.md`](docs/GUARD_PROXY.md) | **(v0.2 base, updated to v0.3 defaults)** The `guard` transparent stdio proxy + `inspect` offline analyzer contract: frame-handling discipline, single-loop framing (Content-Length + newline), incremental scan, subprocess lifecycle, runtime arg-policy + `tools/list_changed` gate, the **v0.3 default-block posture** + `--no-block-*` opt-outs + `--audit-only`, reserved codes `-32001`/`-32002`, and the exact on-the-wire "block" behavior |
| [`docs/GUARD_PROXY_V3.md`](docs/GUARD_PROXY_V3.md) | **(v0.3)** The proxy-hardening contract: `notifications/cancelled`/`progress` untouched passthrough (§1), subprocess-lifecycle edge cases — server-crash `-32002` synthesis, client-disconnect process-group teardown, truncated/oversized-frame fail-open (§2), Windows experimental degradation (§3), and the full v0.3 block-flag scheme + precedence (§4) |

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

## Source layout

| Module | Responsibility | Spec anchor |
|--------|----------------|-------------|
| `src/mcp_warden/hashing.py` | `canon()` (RFC 8785) + `hash()` + field hashes | WARDEN_LOCK_SCHEMA §3 |
| `src/mcp_warden/tokenizer.py` | Shared tokenizer + capability derivation (single source of truth) | CHECKS §3 / WARDEN_LOCK_SCHEMA §5.4 |
| `src/mcp_warden/capture.py` | MCP stdio capture client (argv array, no shell; timeouts/errors) | THREAT_MODEL §3.3 / WARDEN_LOCK_SCHEMA §4.1 |
| `src/mcp_warden/models.py` | Pydantic models for captured surface + lock (incl. `Pinner`/`Attestation` provenance) | WARDEN_LOCK_SCHEMA §2–§8 |
| `src/mcp_warden/lockfile.py` | Lock builder + reader/writer + overall digest | WARDEN_LOCK_SCHEMA §5–§6, §9 |
| `src/mcp_warden/provenance.py` | Out-of-digest provenance construction + `rotate_provenance` (pure; note-cap fail-closed) | WARDEN_LOCK_SCHEMA §8.1–§8.2 |
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
| `src/mcp_warden/guard_lifecycle.py` | **(v0.3)** lifecycle teardown: `-32002` pending-id synthesis, `128+signum` exit mapping, POSIX process-group TERM→grace→KILL teardown, Windows best-effort + `WRD-RES-WIN-LIFECYCLE` | GUARD_PROXY_V3 §2, §3 |
| `src/mcp_warden/guard_io.py` | **(v0.3)** async stdio adapters (`wrap_recv`/`wrap_send`) bridging blocking stdio to the single-loop framer | GUARD_PROXY §2.3 |
| `src/mcp_warden/guard_list_gate.py` | **(v0.3)** runtime `tools/list` drift gate: hashes the live list vs the lock (reuses `hashing`), fail-open on malformed payloads | GUARD_PROXY §4.3, §7.3 |
| `src/mcp_warden/framing.py` | **(v0.2)** single-reader stdio framer (Content-Length + newline), original-bytes pass-through, truncation-at-EOF capture | GUARD_PROXY §2.4, §2.5 · V3 §2.3 |
| `src/mcp_warden/wire_block.py` | **(v0.2/v0.3)** on-wire block synthesis: `-32001` error-response + redacted-content (`_meta.warden.modified`); **v0.3** `-32002` `transport_error` | GUARD_PROXY §7 · V3 §2.6 |
| `src/mcp_warden/inspector.py` | **(v0.2)** offline JSONL analyzer over recorded sessions (same catalog) | GUARD_PROXY §3 |
| `src/mcp_warden/emit_res.py` | **(v0.2)** SARIF 2.1.0 + JSONL emitters for `ResultFinding` (action/direction/tier) | GUARD_PROXY §10 |
| `src/mcp_warden/cli.py` · `cli_guard.py` · `cli_lock.py` | `typer` CLI (`pin`/`check`/`policy`/`guard`/`inspect`/`lock rotate`), exit codes; `guard`/`inspect` bodies in `cli_guard`, `lock rotate` + integrity gate in `cli_lock` | all |

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
| `tests/test_result_inspection.py` | **(v0.2)** `WRD-RES-*`: ANSI codepoint match (incl. extended/binary-ok), secret-echo reuse + redaction, exfil host/subdomain boundary + path-qualified, injection exact-phrase (no broad-regex FP), URL/uninspectable notes |
| `tests/test_inspection_policy.py` | **(v0.2)** §11 per-tool policy fail-safe defaults, byte-identical-to-v0.1 digest when absent, inspection-policy drift, pin-time validation, reader fallback + LOCK-INVALID |
| `tests/test_wire_block.py` | **(v0.2)** `-32001` error-response shape, block-mode mapping, ANSI strip-in-place `_meta.warden.modified`, secret redact-in-place |
| `tests/test_framing.py` | **(v0.2)** newline + Content-Length framing, chunk-split reads, original-bytes pass-through, malformed-frame parse capture |
| `tests/test_guard_posture.py` | **(v0.2/v0.3)** fail-open (inspector exception/malformed → pass-through) vs fail-closed (policy deny → block under `armed_policy`), audit-only precedence over default-on |
| `tests/test_guard_proxy.py` | **(v0.2/v0.3) Headline:** real `tools/call` through `guard`: v0.3 default-block + `--audit-only` shadow restore, deprecated `--block-*` no-op + stderr note, inject stays monitor, forced framing error survives |
| `tests/test_guard_v3.py` | **(v0.3)** opt-out demotes to shadow (`--no-block-*`/`--allow-exfil-domain`/`--no-block-deterministic`), `tools/list_changed` gate block+shadow, policy deny block+shadow, audit-only override, cancel/progress passthrough, **server-crash → `-32002` for every pending id**, client-disconnect child reap (no orphan), truncated + oversized frame fail-open |
| `tests/test_inspect_parity.py` | **(v0.2)** guard↔inspect finding parity on the same recorded frames + inspect exit codes |
| `tests/fixtures/clean_server.py` · `mutated_server.py` | Real MCP SDK stdio fixtures |
| `tests/fixtures/poison_server.py` | **(v0.2)** result-poisoning fixture server (ANSI/secret-echo/exfil/inject/clean tools) |
| `tests/fixtures/crash_server.py` · `listchange_server.py` · `clean_listchange.warden.lock` | **(v0.3)** raw-stdio lifecycle fixtures: crash-mid-call (`-32002`) and `tools/list_changed` rug-pull + its pinned clean lock |
