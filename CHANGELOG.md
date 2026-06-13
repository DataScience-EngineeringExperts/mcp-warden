# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Naming note.** The PyPI **distribution** name is `mcp-warden-cli` — the name
> `mcp-warden` is an unrelated package by a different author, and PyPI rejects
> `mcpwarden` as "too similar" to it (separator-stripping collapses both to the same
> string). The **CLI command** and the GitHub repo stay `mcp-warden`:
> `pip install mcp-warden-cli`, then run `mcp-warden`.

## Scope (v1)

mcp-warden v1 verifies the **declared surface** of **stdio-transport** MCP servers —
the `(name, description, inputSchema)` metadata returned by `tools/list`,
`resources/list`, and `prompts/list` — pinned into a signed `warden.lock` and gated in
CI. The v0.3 `guard` proxy adds deterministic runtime *result* inspection
(ANSI/control escapes, echoed secrets, exfil domains) with default-block.

**Explicitly out of scope in v1 (documented post-1.0 roadmap):**

- **HTTP/SSE transport** — v1 is stdio-only; HTTP/SSE is the headline v1.x item (#9).
- **DNS-name resolution** of exfil-domain matches (raw-IP-literal handling is the D6
  work item) and **prompt-injection default-block** (stays opt-in / MONITOR until
  field false-positive data justifies blocking by default).
- Behavioral-attack defense (`T-BEHAVE`), full agent-firewall mediation, and any
  compliance/regulatory claim. See `docs/THREAT_MODEL.md` for the limits.

## [Unreleased]

_No unreleased changes yet._

## [1.0.0] — 2026-06-12

First stable release. No new core features over 0.3.0 — v1 is the
distribution-hygiene, self-credentialing, and documentation hardening of an already
v1-strong foundation. Highlights of the 0.3.0 → 1.0.0 arc:

### Added

- **Sigstore keyless signing + verification** of `warden.lock` via `pin --sign` and
  `check --verify` (opt-in `mcp-warden-cli[sigstore]` extra). The tool now signs its own
  release artifacts, not just others' locks. (#16)
- **Deterministic structural JSON-Schema diffing** for tool `inputSchema` changes:
  each security-relevant mutation (required dropped, enum widened/removed, type
  broadened, constraint relaxed, `additionalProperties` opened) is classified
  per-fact as `WRD-DRIFT-SCHEMA-*` instead of one opaque change. (#15)
- **In-document `$ref` resolution** in the schema differ, so `$ref` targets are diffed
  structurally instead of reported as an opaque leaf. (#29)
- **Official composite GitHub Action** wrapping `mcp-warden check` with SARIF upload to
  code scanning; all runtime deps hash-locked in `action/requirements.lock`. (#18)
- **pre-commit hook** (`mcp-warden-check`) running the identical drift verdict locally,
  with a `--strict` fail-closed mode and a pre-push variant. (#22)
- **`--strict` fail-closed mode** for the `guard` proxy: an internal inspection error
  terminates the session (exit 3, `-32003`) instead of failing open. (#21)
- **`warden diff`**: offline, redacted, human-readable comparison of two locks over the
  drift engine — never re-captures, never prints raw `server.command`/`args`. (#20)
- **Structured provenance metadata** + `warden lock rotate`: re-attest a baseline's
  provenance without re-capturing the surface (`overall_digest` stays byte-identical).
  (#19)
- **Property-based fuzzing** (Hypothesis) of the guard stdio framer, ANSI stripper,
  exfil-domain matcher, and secret redactor under `tests/fuzz/`. (#17)
- **`--strict-frame-cap`**: fail-closed on over-cap server→client result frames. (#37)
- **Raw-IP-literal exfil/SSRF matching (D6)**: deterministic matching of exfil-domain
  rules against raw IPv4/IPv6 literal hosts, closing the IP-literal bypass of the
  domain matcher. (#54)
- **`guard` startup posture banner** reporting the active enforcement stance
  (active / monitor / inactive, derived from the live `BLOCK_RULES`), plus a
  fail-closed refusal (exit 2) on non-POSIX / degraded platforms unless explicitly
  overridden. (#57)
- Vendor-neutral **MCP Lock Format v1** spec (`docs/SPEC.md`) and an education-first
  docs site with an honest comparison page. (#46, #47, #48, #50)
- **MCP Lock Format v1 compatibility & versioning policy** (`docs/SPEC.md §14`) plus a
  `THREAT_MODEL.md §5.3` self-bypass section (signed-lock replay, SARIF suppression,
  JCS canonicalization edge cases). (#56)
- **Hash-pinned dev/CI lockfile** (`requirements-dev.lock`) and a documented
  dependency-update policy in `SECURITY.md`, so the toolchain that builds a
  supply-chain gate is itself pinned. (#59, closes #14)
- **Release-on-publish GitHub workflow** with OIDC trusted publishing to PyPI and
  self Sigstore signing of the release artifacts, plus a `RELEASING.md` runbook. (#58)

### Changed

- **Distribution name `mcp-warden-cli`.** The PyPI distribution name is `mcp-warden-cli`
  because `mcp-warden` is taken on PyPI by an unrelated package, and PyPI rejects
  `mcpwarden` as "too similar" to it (separator-stripping collapses both to the same
  string). `mcp-warden-cli` normalizes to letters-only `mcpwardencli`, which is
  distinct. The CLI command (`mcp-warden`) and repo are unchanged. (#55)
- README repositioned around the lockfile / CI-gate category claim, with the
  stdio-transport scope surfaced in the opening paragraph and a "Who it's for"
  use-cases section (author-flagship first). (#45, #49, #55)

### Fixed

- `redact_secret` never discloses more than half of a detected secret. (#38)
- Removed the install hazard: every `pip install mcp-warden` snippet (README, docs
  site, example workflows) now installs `mcp-warden-cli`. The README carries a prominent
  impostor-warning banner. (#55)
- Corrected the `SPEC.md` worked-example `schema_version` from `1` to `3` to match the
  live `SCHEMA_VERSION`. (#56)

### Security

- The release pipeline signs its own artifacts (Sigstore / attestation) and publishes a
  pinned-hash lockfile for the install path — the "heal thyself" requirement for a
  supply-chain tool. (#58, #59)

## [0.3.0] — 2026 (in-tree baseline, not released to PyPI)

- Default-block deterministic result-inspection tier + `guard` proxy lifecycle
  hardening (opt-out per category with `--no-block-<category>` / `--audit-only`).
- Public-readiness: OSS community files, MIT license, gitleaks secret-scan CI. (#1)

## [0.2.0]

- Runtime tool-result inspection: `guard` (transparent stdio proxy) + `inspect`
  (offline analyzer) sharing one `WRD-RES-*` catalog.

## [0.1.0]

- Initial CI-first MCP supply-chain integrity gate: `pin` / `check` / `policy` over the
  declared surface, RFC 8785 (JCS) + SHA-256 canonicalization, SARIF output, and a live
  integrity-gate workflow with committed `clean.warden.lock`.

[Unreleased]: https://github.com/ernestprovo23/mcp-warden/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ernestprovo23/mcp-warden/releases/tag/v1.0.0
