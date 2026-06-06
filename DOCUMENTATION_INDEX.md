# Documentation Index — mcp-warden

Master index of every document in this repository. The four `docs/` files are the
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
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Positioning, trust model (TOFU + `--approve`), assets/actors, the four threat classes (MCP-DRIFT / MCP-CAPSURF / MCP-SECRET / MCP-SUPPLY), explicit out-of-scope limits, deliberate cuts |
| [`docs/WARDEN_LOCK_SCHEMA.md`](docs/WARDEN_LOCK_SCHEMA.md) | `warden.lock` format, RFC 8785 canonicalization + SHA-256 hashing, field/entry/overall digests, the normative drift definition + severities |
| [`docs/CHECKS.md`](docs/CHECKS.md) | The deterministic `WRD-*` static-check catalog (capability/secret/supply/robustness), the shared tokenizer, severity→SARIF mapping, redaction rule, CUT list |
| [`docs/POLICY_MODEL.md`](docs/POLICY_MODEL.md) | Policy schema, the four high-risk shapes, constraint vocabulary, fail-closed defaults, SSRF deny ranges, lint + single-sample eval semantics |

---

## Source layout

| Module | Responsibility | Spec anchor |
|--------|----------------|-------------|
| `src/mcp_warden/hashing.py` | `canon()` (RFC 8785) + `hash()` + field hashes | WARDEN_LOCK_SCHEMA §3 |
| `src/mcp_warden/tokenizer.py` | Shared tokenizer + capability derivation (single source of truth) | CHECKS §3 / WARDEN_LOCK_SCHEMA §5.4 |
| `src/mcp_warden/capture.py` | MCP stdio capture client (argv array, no shell; timeouts/errors) | THREAT_MODEL §3.3 / WARDEN_LOCK_SCHEMA §4.1 |
| `src/mcp_warden/models.py` | Pydantic models for captured surface + lock | WARDEN_LOCK_SCHEMA §2–§8 |
| `src/mcp_warden/lockfile.py` | Lock builder + reader/writer + overall digest | WARDEN_LOCK_SCHEMA §5–§6, §9 |
| `src/mcp_warden/drift.py` | Per-class drift/diff engine + severities | WARDEN_LOCK_SCHEMA §6.2 |
| `src/mcp_warden/checks.py` | Static-check orchestrator (deterministic sort) | CHECKS §4–§5 |
| `src/mcp_warden/checks_secret.py` | `WRD-SEC-*` vendor + entropy + redaction | CHECKS §4.2 |
| `src/mcp_warden/checks_supply.py` | `WRD-SUP-*` launch-command checks | CHECKS §4.3 |
| `src/mcp_warden/redact.py` | `first4 + "…" + (len=N)` secret redaction | CHECKS §8.2 |
| `src/mcp_warden/emitters.py` | SARIF 2.1.0 + JSONL emitters (`ruleId` verbatim) | CHECKS §2 |
| `src/mcp_warden/policy_model.py` | Policy load + lint + fail-closed schema | POLICY_MODEL §3, §4.1 |
| `src/mcp_warden/policy_eval.py` | Single-sample eval (fs/shell/http-SSRF/sql) | POLICY_MODEL §2, §4.2, §5 |
| `src/mcp_warden/cli.py` | `typer` CLI (`pin`/`check`/`policy`), exit codes | all |

## Tests

| File | Covers |
|------|--------|
| `tests/test_hashing.py` | JCS+SHA-256 reproducibility, canonical-form pins, null handling |
| `tests/test_tokenizer.py` | Segment-exact tokenization + capability derivation |
| `tests/test_checks.py` | Capability/secret/supply/robustness checks + redaction |
| `tests/test_drift.py` | Drift per class (added/removed/modified/server-identity/unapproved) |
| `tests/test_lockfile.py` | Lock build/write/read, digest exclusions, hashes-not-raw |
| `tests/test_policy.py` | Lint (incl. unknown-key error) + eval (allow/deny/SSRF/fail-closed) |
| `tests/test_emitters.py` | SARIF shape + level mapping + JSONL records |
| `tests/test_e2e_pin_check.py` | **Headline:** real stdio pin→mutate→check round-trip |
| `tests/fixtures/clean_server.py` · `mutated_server.py` | Real MCP SDK stdio fixtures |
