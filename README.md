# mcp-warden

[![CI](https://github.com/ernestprovo23/mcp-warden/actions/workflows/integrity-gate.yml/badge.svg)](https://github.com/ernestprovo23/mcp-warden/actions/workflows/integrity-gate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-mcp--warden-2088FF?logo=githubactions&logoColor=white)](https://github.com/ernestprovo23/mcp-warden/blob/main/action.yml)
[![Latest release](https://img.shields.io/github/v/release/ernestprovo23/mcp-warden?display_name=tag&sort=semver)](https://github.com/ernestprovo23/mcp-warden/releases)

**mcp-warden is the lockfile and CI gate for stdio-transport MCP servers: it pins
an MCP server's declared tool/resource/prompt surface into a signed `warden.lock`,
then fails CI when that surface drifts from the approved baseline.** v1 covers
**stdio-transport** servers; HTTP/SSE transport is a documented v1.x roadmap item.

> ⚠️ **Install `mcp-warden-cli`, not `mcp-warden`.** The PyPI name `mcp-warden` is
> an **unrelated package by a different author** — it is not this project. The
> correct install is `pip install mcp-warden-cli` (the CLI command is still
> `mcp-warden`). Or use the [GitHub Action](#github-action-one-step-drop-in) / a
> git-pinned install.

If you already follow the published guidance — *pin versions, hash tool
definitions, alert on drift* — mcp-warden is the deterministic tool that does it.

**The mental model (analogy ladder):**

- **`package-lock.json` / `Cargo.lock`** — a committed, reproducible lock of what
  you depend on. `warden.lock` is that, for an MCP server's *declared surface*.
- **`gitleaks` in CI** — a deterministic, exit-non-zero gate wired into the
  pipeline. `mcp-warden check` is that, for MCP surface drift (and ships the same
  SARIF → code-scanning integration).
- **`Dependabot` / pin-then-review** — a human approves an upstream change before
  it lands. `pin --approve` + the drift gate force a human in the loop on any MCP
  rug-pull.

> **Scope honesty — mcp-warden is an MCP supply-chain integrity gate, not a full
> agent firewall.** It verifies the *declared* surface returned by `tools/list` /
> `resources/list` / `prompts/list`; it does **not** defend behavioral attacks
> (`T-BEHAVE`) and makes no compliance/regulatory claim. The v0.3 `guard` proxy
> adds runtime *result* inspection (ANSI/control escapes, echoed secrets, exfil
> domains — deterministic, default-block), but definition-integrity is the core
> job. Read the limits first:
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
> [`docs/THREAT_MODEL_V2.md`](docs/THREAT_MODEL_V2.md),
> [`docs/GUARD_PROXY_V3.md`](docs/GUARD_PROXY_V3.md).

---

## 60-second quickstart

Copy-paste runnable against the fixtures shipped in this repo. Requires Python ≥ 3.11.

```bash
# 1. Install (from a clone of this repo)
uv venv .venv
uv pip install --python .venv/bin/python -e ".[dev]"

# 2. Pin a server's declared surface and approve it (TOFU baseline) -> writes the lock
.venv/bin/mcp-warden pin python tests/fixtures/clean_server.py \
    --approve --approver you@example.com \
    --lock warden.lock

# 3. Check the same surface against the lock -> exit 0 (no drift)
.venv/bin/mcp-warden check python tests/fixtures/clean_server.py --lock warden.lock

# 4. Prove the gate fires: a rug-pulled server drifts -> DRIFT DETECTED, exit 1
.venv/bin/mcp-warden check python tests/fixtures/mutated_server.py --lock warden.lock
```

Then wire it into CI with the official GitHub Action (point `server-cmd` at *your*
server's launch argv, commit `warden.lock`):

```yaml
# .github/workflows/mcp-integrity.yml
permissions:
  contents: read
  security-events: write   # only needed when upload-sarif: true (the default)

jobs:
  mcp-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ernestprovo23/mcp-warden@v0
        with:
          server-cmd: "node ./build/index.js"
          lock: "warden.lock"
```

The Action runs `check`, fails the build on any drift, and (by default) uploads a
SARIF report to GitHub code scanning. Full input table is in
[GitHub Action](#github-action-one-step-drop-in) below.

---

## Where mcp-warden fits — complements, not substitutes

MCP security splits into three different jobs that run at different times. They are
**complementary layers**; running mcp-warden *alongside* a scanner and/or a gateway
closes gaps none of them cover alone.

| Category | Example | When it runs | What it locks down | Use it when… |
|----------|---------|--------------|--------------------|--------------|
| **Static tool-poisoning scanner** | [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) | pin-time / pre-flight | suspicious *content* in tool definitions (injection-style descriptions, known-bad patterns) | you want to catch a poisoned definition the first time you see it |
| **Runtime gateway / proxy** | ContextForge, Lunar MCPX, TrueFoundry, Docker MCP Gateway | every live request | runtime mediation — auth, rate limits, request/response policy on calls in flight | you need to mediate or police live traffic between agent and server |
| **Lockfile + CI gate** | **mcp-warden** | CI / pre-commit | *drift* — the declared surface changing after a human approved it (rug-pull / silent redefinition) | you want a reproducible, human-approved baseline that fails the build when the surface changes |

mcp-warden does not replace a scanner or a gateway — it adds the missing **drift
gate**: a signed baseline plus a deterministic CI check that the surface you
approved is the surface you still run. For the full, sourced breakdown of how
these layers complement each other and when to use which, see the
[**comparison page**](https://ernestprovo23.github.io/mcp-warden/comparison/)
on the docs site.

---

## Who it's for

Adoption compounds the way `package-lock.json` did — authors adopt, consumers benefit
automatically — so the use cases are sequenced by leverage:

- **MCP server author (flagship).** Pin your *own* server's surface, commit `warden.lock`,
  fail any PR that alters it without re-approval, and ship the signed lock alongside
  releases as a **badge of trust** — you own the server + CI, so no auth/availability friction.
- **Server consumer / app team.** Pin a third-party server you depend on; CI (or the
  pre-commit hook) fails when upstream silently redefines its surface — the core rug-pull defense.
- **Security / platform engineer.** Run the [Action](#github-action-one-step-drop-in)
  across a fleet; SARIF → code scanning; signed locks = auditable human-approval evidence.
- **Incident responder / auditor.** `inspect` an offline trace and `warden diff` a suspect
  lock against a known-good baseline — no live server required.
- **Agent-framework integrator** *(post-launch).* Enforce that only warden-locked servers
  register in a LangGraph-style orchestrator — one integration locks an entire downstream ecosystem.

---

## What it does

mcp-warden operates entirely on **definitions** — the `(name, description,
inputSchema)` metadata returned by `tools/list`, `resources/list`, and
`prompts/list` — never on runtime tool behavior or results.

| Threat class | Control |
|--------------|---------|
| **Definition drift / rug-pull** (`MCP-DRIFT`) | `check` re-captures and diffs the surface vs `warden.lock`; tool `inputSchema` changes are **structurally classified** (required dropped, enum widened/removed, type broadened, constraint relaxed, `additionalProperties` opened → `WRD-DRIFT-SCHEMA-*`) rather than flagged as one opaque change; any drift fails CI |
| **Dangerous capability surface** (`MCP-CAPSURF`) | Deterministic `WRD-CAP-*` static checks (shell/exec, fs-write, fs-read, http, sql) |
| **Secret leakage in definitions** (`MCP-SECRET`) | `WRD-SEC-*` regex + entropy checks; snippets are always redacted |
| **Unpinned supply-chain refs** (`MCP-SUPPLY`) | `WRD-SUP-*` flags unpinned `npx`/`uvx`/`pip`, `latest`, and `curl|sh` launches |
| **Poisoned tool results** (`T-RESULT`, v0.2/v0.3) | `guard`/`inspect` run the `WRD-RES-*` catalog on tool results: ANSI/control escapes, echoed secrets, exfil domains (deterministic BLOCK — **default-on in v0.3**), curated injection phrases (fuzzy MONITOR, opt-in) |

Reproducibility is the core guarantee: canonicalization is **RFC 8785 (JCS)** +
**SHA-256** (`sha256:<hex>`), so `pin` and `check` agree byte-for-byte. The v0.2
result-inspection catalog is defined once and run identically by `guard` (live) and
`inspect` (offline).

---

## Install

Requires Python ≥ 3.11.

> ⚠️ On PyPI the distribution name is **`mcp-warden-cli`**, not `mcp-warden` —
> that name belongs to an unrelated package. The CLI command stays `mcp-warden`.

```bash
# from PyPI (distribution name `mcp-warden-cli`):
pip install mcp-warden-cli

# the CLI is then available as:
mcp-warden --help
```

```bash
# or from a clone of this repo (for development):
uv venv .venv
uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/mcp-warden --help
```

Runtime dependencies: `mcp` (official MCP Python SDK), `rfc8785`, `pydantic`,
`typer`, `rich`, `pyyaml`, `anyio`.

---

## The pin / check CI demo

mcp-warden ships two fixture MCP servers under `tests/fixtures/`: a **clean** one
and a **mutated** (rug-pulled) one. The end-to-end flow:

```bash
# 1. Pin the clean server's surface (TOFU baseline) -> writes warden.lock
.venv/bin/mcp-warden pin python tests/fixtures/clean_server.py \
    --approve --approver ci-bot@example.invalid \
    --sarif pin.sarif

# 2. Later, the upstream server is rug-pulled. Re-run check against it.
#    (Same launch argv would be used in real CI; here we point at the mutated fixture.)
.venv/bin/mcp-warden check python tests/fixtures/mutated_server.py \
    --sarif check.sarif
#  -> prints DRIFT DETECTED, writes SARIF, EXITS NON-ZERO (fails the build)
```

`check` exits **non-zero on any drift** (added/removed/modified tool, capability
change, server-identity change). Tool `inputSchema` changes are **structurally
diffed**: each security-relevant mutation is reported per-fact and deterministically
classified by severity (`docs/WARDEN_LOCK_SCHEMA.md` §6.2). A normalized schema
skeleton is stored in the lock (`schema_version` 2); pre-skeleton (v1) locks fall
back to a single high-severity `schema-modified` until re-pinned. The SARIF report
(`ruleId` == the `WRD-*` / `WRD-DRIFT-*` check ID) uploads straight to GitHub code
scanning.

### GitHub Action (one-step drop-in)

The fastest way to add the integrity gate is the official reusable action:

```yaml
# .github/workflows/mcp-integrity.yml
permissions:
  contents: read
  security-events: write   # only needed when upload-sarif: true (the default)

jobs:
  mcp-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ernestprovo23/mcp-warden@v0
        with:
          server-cmd: "node ./build/index.js"
          lock: "warden.lock"
          # upload-sarif: "false"   # uncomment for private repos without GHAS
```

The action installs mcp-warden from the exact `@ref` you pin, runs `check`,
uploads the SARIF report to GitHub code scanning (optional), and surfaces the
raw exit code (0 = clean / 1 = drift / 2 = error) as an output for downstream
steps. All runtime dependencies are hash-locked in `action/requirements.lock`
so no transitive packages are fetched unpinned.

| Input | Default | Notes |
|-------|---------|-------|
| `server-cmd` | *(required)* | Whitespace-separated argv string (e.g. `node ./build/index.js`). No quoted arguments, no shell metacharacters (`;`, `\|`, `&`, `$`, `` ` ``, `\`, `<`, `>`, `(`, `)`, `{`, `}`, `'`, `"`). The guard step rejects any of these before expansion. |
| `lock` | `warden.lock` | Baseline lock path (relative to `working-directory`) |
| `sarif` | `mcp-warden.sarif` | SARIF output path |
| `upload-sarif` | `true` | Set `false` for repos without GitHub Advanced Security |
| `category` | `mcp-warden` | Code-scanning category; use distinct values per server |
| `python-version` | `3.11` | Python version to use (>= 3.11 required) |
| `timeout` | `30` | Capture timeout (seconds) |
| `working-directory` | `.` | Working directory for the check |

**Outputs:** `exit-code` (0/1/2), `sarif` (resolved absolute path).

> Set `upload-sarif: false` for fork pull requests or private repos without
> GitHub Advanced Security — the `security-events: write` permission is not
> available in those contexts.

### Typical multi-step pattern (manual install)

```yaml
- name: MCP integrity gate
  run: |
    .venv/bin/mcp-warden check node ./build/index.js --sarif warden.sarif
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: warden.sarif
```

---

## CI usage — drop-in gate for your own repo

Three steps to add mcp-warden as a CI integrity gate:

**1. Pin once** (run locally, commit the result):

```bash
pip install mcp-warden-cli    # PyPI dist name is `mcp-warden-cli`; the command is `mcp-warden`
# Pin your server and record an approval
mcp-warden pin node ./build/index.js \
    --approve --approver you@example.com \
    --lock warden.lock
git add warden.lock && git commit -m "chore: pin MCP surface baseline"
```

**2. Add the check step to your workflow** (`.github/workflows/integrity-gate.yml`):

```yaml
- name: Install mcp-warden
  run: pip install mcp-warden-cli       # PyPI dist `mcp-warden-cli`; CLI command `mcp-warden`

- name: MCP integrity gate (pass path — exits 0 when surface matches lock)
  run: |
    mcp-warden check node ./build/index.js \
      --lock warden.lock \
      --sarif warden.sarif

- name: Upload SARIF
  if: always()
  uses: actions/upload-artifact@v6
  with:
    name: mcp-warden-sarif
    path: warden.sarif
```

**3. On any upstream rug-pull**, `mcp-warden check` exits non-zero and the build
fails before the drifted server reaches your agents. Re-pin only after a human
reviews and approves the new surface.

> This repo ships a live demo of this pattern in
> [`.github/workflows/integrity-gate.yml`](.github/workflows/integrity-gate.yml):
> the "pass path" step checks the clean fixture (exits 0) and the "blocking proof"
> step checks the mutated fixture (exits 1, inverted to green) to show both sides
> of the gate on every CI run.

---

## pre-commit hook — the local pre-CI gate

mcp-warden ships a [pre-commit](https://pre-commit.com) hook so the *same* drift
verdict runs locally on every commit, catching a rug-pulled MCP surface before it
ever reaches CI. The hook reuses the identical capture → checks → drift path as
`mcp-warden check`, so a local pass/fail can never disagree with CI.

Add this to your `.pre-commit-config.yaml` (a complete, copy-pasteable example):

```yaml
repos:
  - repo: https://github.com/ernestprovo23/mcp-warden
    rev: v1.0.0                       # pin to a release tag (supply-chain hygiene)
    hooks:
      - id: mcp-warden-check
        # Everything after `--` is your MCP server launch argv.
        # The `--lock` path is resolved relative to your git repo root.
        args: [--lock, warden.lock, --, node, ./build/index.js]
```

Then `pre-commit install` once. The hook will re-capture your server's surface on
every commit and **block the commit on drift** (exit 1) until you review and re-pin.

### The `--` separator (required)

pre-commit is file-triggered, but `mcp-warden check` takes an **MCP server launch
argv**, not staged files (the hook sets `pass_filenames: false`). You tell the hook
where your server command begins with the `--` separator: everything after `--` is
launched as the server. Without it the hook exits 2 with guidance.

### Behavior (clean / drift / server-unavailable)

| Situation | Default (non-strict) | `--strict` |
|-----------|----------------------|------------|
| Surface matches `warden.lock` | exit 0 (commit proceeds) | exit 0 |
| **Drift** vs `warden.lock` | **exit 1 (commit blocked)** | **exit 1 (commit blocked)** |
| `warden.lock` missing / invalid | exit 2 (commit blocked) | exit 2 |
| Server can't spawn / times out | **exit 0 + stderr WARNING (commit proceeds)** | exit 2 (commit blocked) |

The default tolerates a *locally* unspawnable server (a teammate without the right
runtime installed should not be blocked from committing) — **drift always blocks in
both modes**, only infra-failure handling differs. CI stays strict (it can always
spawn the server), so the drift verdict is identical everywhere. Add `--strict` to
`args:` to fail closed locally too.

### Opt-outs for slow servers

Spawning the server on every commit adds latency. Teams that find this too slow can
run the gate only on push:

```yaml
      - id: mcp-warden-check
        stages: [pre-push]            # run on `git push`, not every commit
        args: [--lock, warden.lock, --, node, ./build/index.js]
```

…or skip it ad-hoc for a single commit with `SKIP=mcp-warden-check git commit ...`.

---

## CLI reference

| Command | Purpose | Exit code |
|---------|---------|-----------|
| `mcp-warden pin <server-cmd...> [--approve --approver <id>] [--sign [--identity-token T]] [--sarif F] [--json]` | Capture + write `warden.lock` (TOFU baseline). **(#16)** `--sign` Sigstore-signs `overall_digest` (out-of-digest; needs `mcp-warden[sigstore]`) | 0 on success, 2 on capture/IO error, **1 on signing failure (fail closed, no partial sidecar)** |
| `mcp-warden check <server-cmd...> [--lock F] [--sarif F] [--json]` | Re-capture + diff vs lock | **non-zero on drift**, 2 on error |
| `mcp-warden check --verify --certificate-identity ID --certificate-oidc-issuer ISS [--lock F] [--offline-bundle P]` | **(#16)** Verify the lock's Sigstore signature against a fixed sidecar (`<lockname>.sigstore` next to the lock); no server spawn. See [`docs/SIGNING.md`](docs/SIGNING.md) | **0 only on clean verify**; non-zero on any failure (fail closed) |
| `mcp-warden policy lint <file> [--lock F]` | Lint a policy file (fail closed) | non-zero on lint error |
| `mcp-warden policy eval <file> <sample.json> [--lock F]` | Evaluate one sample call | **non-zero on a deny verdict** (CI assertion) |
| `mcp-warden guard <server-cmd...> [--lock F] [--policy F] [--no-block-* / --allow-exfil-domain] [--block-inject-phrase] [--audit-only] [--strict] [--sarif F] [--record T]` | **(v0.3)** Transparent stdio proxy: inspects `tools/call` results + arguments at runtime. **Deterministic tier blocks by default**; opt out per-category with `--no-block-<category>` or fully with `--audit-only`. `--strict` fails CLOSED on an internal inspection error (exit `3`) | child's exit code; `3` on a `--strict` abort; otherwise never breaks the session |
| `mcp-warden inspect <trace.jsonl> [--lock F] [--sarif F]` | **(v0.2)** Offline analyzer over a recorded JSON-RPC session — same `WRD-RES-*` catalog as `guard` (always report-only) | non-zero on any BLOCK-tier finding; 2 on read error |
| `mcp-warden lock rotate <lock> [--approver ID] [--actor ID] [--note T] [--json]` | **(v0.3)** Re-attest provenance on an existing baseline without re-capturing the surface; `overall_digest` stays **byte-identical** (WARDEN_LOCK_SCHEMA §8.2). Fails closed on a tampered/inconsistent lock | 0 on success, 2 on missing/invalid/tampered lock |
| `mcp-warden diff <lock-a> <lock-b> [--json] [--sarif F] [--no-provenance] [--exit-code]` | **(v0.3)** Offline, **redacted** viewer over the drift engine: renders integrity drift between two existing locks (A=baseline, B=current) + a separate informational provenance section. Never re-captures and never prints raw `server.command`/`args` (secret-safe) | 0 (viewer); with `--exit-code`, 1 on **integrity** drift only; 2 on missing/invalid lock |
| `mcp-warden-precommit [--lock F] [--timeout N] [--strict] -- <server-cmd...>` | **(v0.3)** pre-commit hook entry point (see [pre-commit hook](#pre-commit-hook--the-local-pre-ci-gate)). Runs the same check verdict path; check-only (never pins, never writes the lock) | 0 clean / **1 drift** / 2 config error; server-unavailable → 0+warning (non-strict) or 2 (`--strict`) |

`<server-cmd...>` is passed to the OS as an **argv array, never through a shell.**
Set `WARDEN_LOG_LEVEL=INFO` for diagnostic logging.

### Runtime result inspection (v0.3 — blocks by default)

`guard` sits transparently between an MCP client and server and inspects tool *results*.
**As of v0.3 the deterministic tier blocks out of the box** (council-established field
false-positive rate ~0):

```bash
# Default: ANSI is stripped in place; echoed secrets + exfil domains are error-replaced;
# a mid-session tools/list swap that diverges from warden.lock is blocked (needs --lock);
# an argument-policy deny is blocked (needs --policy). The fuzzy injection tier stays log-only.
mcp-warden guard node ./build/index.js --lock warden.lock --policy policy.yaml --sarif guard.sarif

# Observe-first rollout: --audit-only restores full v0.2 shadow in one flag (detect + log only).
mcp-warden guard node ./build/index.js --lock warden.lock --audit-only

# Opt a single category back to shadow (still detected/logged/SARIF, frame forwarded):
mcp-warden guard node ./build/index.js --no-block-ansi --allow-exfil-domain
# Or shadow the whole deterministic tier + both gates:
mcp-warden guard node ./build/index.js --no-block-deterministic
# Opt INTO the fuzzy injection tier (never default):
mcp-warden guard node ./build/index.js --block-inject-phrase

# Fail-CLOSED (high-security): TERMINATE the session (exit 3, -32003 to the client) if an
# internal inspection (result / argument-policy / tools-list) cannot complete, instead of the
# default fail-open pass-through. Opt-in; integrity over availability.
mcp-warden guard node ./build/index.js --lock warden.lock --policy policy.yaml --strict

# Re-analyze a recorded session offline with the identical rule catalog (always report-only):
mcp-warden inspect session.trace.jsonl --lock warden.lock --sarif inspect.sarif
```

**Flag scheme:** opt-out is canonical `--no-block-<category>`
(`ansi|secret-echo|exfil-domain|list-changed|policy`, plus `--no-block-deterministic` for the
whole tier); `--allow-exfil-domain` is the sole affirmative alias. Precedence:
`--audit-only` > `--no-block-*` > default-block / `--block-inject-phrase`. The v0.2
`--block-*` enable flags are accepted but **inert no-ops** (one-line stderr deprecation note),
so old scripts keep working. **`--strict`** (opt-in, default off) trades availability for
integrity: an internal inspection error at the result / argument-policy / tools-list layer
**terminates the session** (exit `3`, `-32003` non-retriable error to the client) instead of
failing open — framing/EOF/over-cap stay fail-open in all modes (known limitation). Reserved
error codes: **`-32001`** (policy/result block), **`-32002`** (transport/lifecycle), **`-32003`**
(`--strict` abort, non-retriable). See
[`docs/RESULT_INSPECTION.md`](docs/RESULT_INSPECTION.md),
[`docs/GUARD_PROXY.md`](docs/GUARD_PROXY.md), and
[`docs/GUARD_PROXY_V3.md`](docs/GUARD_PROXY_V3.md).

---

## Policy (design-time only)

`policy` **lints** a YAML policy and **evaluates a single provided sample call**.
It does **not** intercept live calls — there is no runtime enforcement in v0.1
(deferred to v0.2). Fail-closed defaults: `shell_exec.allow=false`,
`http_request.deny_private=true` (SSRF ranges), `sql_query.allow_readonly_only=true`,
empty `allow_paths` = deny-all. See [`docs/POLICY_MODEL.md`](docs/POLICY_MODEL.md).

```bash
.venv/bin/mcp-warden policy eval policy.yaml ssrf_sample.json
#  -> deny: host 169.254.169.254 is in deny_private range 169.254.0.0/16  (exit 1)
```

---

## Documentation

See [`DOCUMENTATION_INDEX.md`](DOCUMENTATION_INDEX.md). The security-contract specs
under `docs/` (including [`GUARD_PROXY_V3.md`](docs/GUARD_PROXY_V3.md) for the v0.3
default-block + lifecycle contract) are the source of truth for every algorithm; the
schemas in `warden.lock` and the SARIF output match them byte-for-byte.

## Tests

```bash
.venv/bin/python -m pytest -q
```

The headline test is a real stdio round-trip: spawn the clean fixture → `pin` →
re-run `check` against the mutated fixture → assert non-zero exit + the expected
drift + SARIF finding.

The live runtime attack surface — the stdio JSON-RPC **framer**, the ANSI/control
**stripper**, the exfil-**domain** matcher, and the secret **redactor** — is
additionally **property-fuzzed** with [`hypothesis`](https://hypothesis.works/)
under `tests/fuzz/` (construction-based liveness + soundness properties: a
known-malicious input IS detected, and the parser never invents, leaks, or
misclassifies). The deep soak runs via `make fuzz`; see
[`CONTRIBUTING.md`](CONTRIBUTING.md#fuzzing).

## Contributing & security

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the dev
setup, the determinism contract, and how to propose new checks. By participating
you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

This is a security tool: **do not report vulnerabilities in public issues.** Follow
the responsible-disclosure process in [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE). Copyright (c) 2026 Ernest Provo.
