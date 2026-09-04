# mcp-warden

[![CI](https://github.com/DataScience-EngineeringExperts/mcp-warden/actions/workflows/integrity-gate.yml/badge.svg)](https://github.com/DataScience-EngineeringExperts/mcp-warden/actions/workflows/integrity-gate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-mcp--warden-2088FF?logo=githubactions&logoColor=white)](https://github.com/DataScience-EngineeringExperts/mcp-warden/blob/main/action.yml)
[![Latest release](https://img.shields.io/github/v/release/DataScience-EngineeringExperts/mcp-warden?display_name=tag&sort=semver)](https://github.com/DataScience-EngineeringExperts/mcp-warden/releases)

**mcp-warden is the lockfile and CI gate for MCP servers: it pins a server's declared
tool/resource/prompt surface into a signed `warden.lock`, then fails CI when that surface
drifts.** `pin` and `check` support stdio and Streamable HTTP; `guard` is stdio-only.

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

# 2. Zero-config posture scan of every MCP config already on this machine — Claude Code,
#    Claude Desktop, Cursor, VS Code, Windsurf, Codex. Static: no spawn, no network.
#    Reports weak auth, unpinned npx/uvx launches, and every server with no lock, then
#    prints the exact `pin` command for each. (docs/DOCTOR.md)
.venv/bin/mcp-warden doctor

# 3. Pin a server's declared surface and approve it (TOFU baseline) -> writes the lock
.venv/bin/mcp-warden pin python tests/fixtures/clean_server.py \
    --approve --approver you@example.com \
    --lock warden.lock

# 4. Check the same surface against the lock -> exit 0 (no drift)
.venv/bin/mcp-warden check python tests/fixtures/clean_server.py --lock warden.lock

# 5. Prove the gate fires: a rug-pulled server drifts -> DRIFT DETECTED, exit 1
.venv/bin/mcp-warden check python tests/fixtures/mutated_server.py --lock warden.lock
```

For an already-running Streamable HTTP server, use `--url` instead of a server command:

```bash
.venv/bin/mcp-warden pin --url https://example.com/mcp --approve --approver you@example.com --lock warden.lock
.venv/bin/mcp-warden check --url https://example.com/mcp --lock warden.lock
```

Then wire it into CI with the official GitHub Action (point `server-cmd` at *your* server's launch argv, commit `warden.lock`):

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
      - uses: DataScience-EngineeringExperts/mcp-warden@v0
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
| **Config + deploy gates** | **mcp-warden** (`auth audit`, `deploy-gate`) | CI / pre-commit | *posture* — remote MCP endpoints with no auth or credentials pasted into config; agent deploys whose evals regressed or whose guardrails were switched off | you want the deploy blocked, not just reported, when the declared safety bar isn't met |

mcp-warden does not replace a scanner or a gateway — it adds the missing **drift
gate**: a signed baseline plus a deterministic CI check that the surface you
approved is the surface you still run.

**The common thread across all four commands is that they *block*.** The loudest
complaint about agents in production is that they are insecure by default and
nothing stops a bad configuration or a regressed deploy from shipping — plenty of
tools *report*, very few return a non-zero exit code that a pipeline must answer
for. `check` blocks on surface drift, `auth audit` blocks on weak MCP auth
posture, and `deploy-gate` blocks an agent deploy whose evals, guardrails,
budget, or human approval don't meet the declared bar. All three fail **closed**:
unreadable or missing input is a failure, never a silent pass. See
[`docs/AGENT_GATES.md`](docs/AGENT_GATES.md).

For the full, sourced breakdown of how
these layers complement each other and when to use which, see the
[**comparison page**](https://datascience-engineeringexperts.github.io/mcp-warden/comparison/)
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
  Add `auth audit` to catch MCP endpoints configured without auth or with credentials
  committed into config, and `deploy-gate` to make the agent safety bar a build failure
  rather than a dashboard nobody reads.
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

### TypeScript verifier — `@mcp-warden/lock` (zero dependencies)

The lock **format** is vendor-neutral ([`docs/SPEC.md`](docs/SPEC.md)), and the ecosystem's
servers are mostly Node. [`packages/lock-ts`](packages/lock-ts/README.md) is a verify-only
TypeScript implementation with **no runtime dependencies** and no MCP SDK: hand it a
`warden.lock` and the surface you observed, get back the same drift verdict as the CLI.
Both implementations pass the shared conformance corpus under
[`vectors/`](vectors/README.md) byte-for-byte in CI.

```ts
import { verify } from "@mcp-warden/lock";
const { ok, findings } = verify(lockJson, { command: "node", args: ["./build/index.js"], tools, resources, prompts });
if (!ok) { console.error(findings); process.exit(1); }
```

---

## The pin / check CI demo

mcp-warden ships two fixture MCP servers under `tests/fixtures/` — a **clean** one
and a **mutated** (rug-pulled) one — so the whole gate can be demonstrated end to
end without touching a third-party server:

```bash
# 1. Pin the clean server's surface (TOFU baseline) -> writes warden.lock
.venv/bin/mcp-warden pin python tests/fixtures/clean_server.py \
    --approve --approver ci-bot@example.invalid

# 2. The upstream server is rug-pulled. Re-check against it.
.venv/bin/mcp-warden check python tests/fixtures/mutated_server.py
#  -> DRIFT DETECTED, writes SARIF, EXITS NON-ZERO (fails the build)
```

Full walkthrough — every drift class, the SARIF/JSONL shapes, the structural
`inputSchema` diffing, and the Action wiring — lives in
[`docs/PIN_CHECK_DEMO.md`](docs/PIN_CHECK_DEMO.md).

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
  - repo: https://github.com/DataScience-EngineeringExperts/mcp-warden
    rev: v1.0.1                       # pin to a release tag (supply-chain hygiene)
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
| `mcp-warden pin <server-cmd...> \| --url URL [--approve --approver <id>] [--sign [--identity-token T]] [--sarif F] [--json]` | Capture over stdio or Streamable HTTP + write `warden.lock` (TOFU baseline). **(#16)** `--sign` Sigstore-signs `overall_digest` (out-of-digest; needs `mcp-warden[sigstore]`) | 0 on success, 2 on capture/IO error, **1 on signing failure (fail closed, no partial sidecar)** |
| `mcp-warden check <server-cmd...> \| --url URL [--lock F] [--sarif F] [--json]` | Re-capture over stdio or Streamable HTTP + diff vs lock | **non-zero on drift**, 2 on error |
| `mcp-warden check --verify --certificate-identity ID --certificate-oidc-issuer ISS [--lock F] [--offline-bundle P]` | **(#16)** Verify the lock's Sigstore signature against a fixed sidecar (`<lockname>.sigstore` next to the lock); no server spawn. See [`docs/SIGNING.md`](docs/SIGNING.md) | **0 only on clean verify**; non-zero on any failure (fail closed) |
| `mcp-warden policy lint <file> [--lock F]` | Lint a policy file (fail closed) | non-zero on lint error |
| `mcp-warden policy eval <file> <sample.json> [--lock F]` | Evaluate one sample call | **non-zero on a deny verdict** (CI assertion) |
| `mcp-warden guard <server-cmd...> [--lock F] [--policy F] [--no-block-* / --allow-exfil-domain] [--block-inject-phrase] [--audit-only] [--strict] [--sarif F] [--record T]` | **(v0.3)** Transparent stdio proxy: inspects `tools/call` results + arguments at runtime. **Deterministic tier blocks by default**; opt out per-category with `--no-block-<category>` or fully with `--audit-only`. `--strict` fails CLOSED on an internal inspection error (exit `3`) | child's exit code; `3` on a `--strict` abort; otherwise never breaks the session |
| `mcp-warden inspect <trace.jsonl> [--lock F] [--sarif F]` | **(v0.2)** Offline analyzer over a recorded JSON-RPC session — same `WRD-RES-*` catalog as `guard` (always report-only) | non-zero on any BLOCK-tier finding; 2 on read error |
| `mcp-warden lock rotate <lock> [--approver ID] [--actor ID] [--note T] [--json]` | **(v0.3)** Re-attest provenance on an existing baseline without re-capturing the surface; `overall_digest` stays **byte-identical** (WARDEN_LOCK_SCHEMA §8.2). Fails closed on a tampered/inconsistent lock | 0 on success, 2 on missing/invalid/tampered lock |
| `mcp-warden diff <lock-a> <lock-b> [--json] [--sarif F] [--no-provenance] [--exit-code]` | **(v0.3)** Offline, **redacted** viewer over the drift engine: renders integrity drift between two existing locks (A=baseline, B=current) + a separate informational provenance section. Never re-captures and never prints raw `server.command`/`args` (secret-safe) | 0 (viewer); with `--exit-code`, 1 on **integrity** drift only; 2 on missing/invalid lock |
| `mcp-warden deploy-gate --policy F --evidence F [--json] [--sarif F]` | **(v1.2)** Fail-closed CI gate for agent deployments: verifies declared eval thresholds, required guardrails, a budget/quota, and a human-approval receipt. Adjudicates evidence — it does **not** run evals. See [`docs/AGENT_GATES.md`](docs/AGENT_GATES.md) | 0 only when every control is satisfied; 1 on any gate finding; 2 on unreadable/malformed input (fail closed) |
| `mcp-warden doctor [--config F]... [--no-discover] [--json] [--sarif F] [--pin [--yes]]` | **(v1.2)** Zero-config posture scan: discovers every MCP client config on the machine (Claude Code / Claude Desktop / Cursor / VS Code / Windsurf / Codex), runs `auth audit` + `WRD-SUP-*` launch checks per server, reports servers with no `warden.lock` (`WRD-DOCTOR-NO-LOCK`) and prints the exact `pin` command. Static by default; `--pin` is the opt-in that spawns, and refuses non-interactively without `--yes`. See [`docs/DOCTOR.md`](docs/DOCTOR.md) | 0 clean or no configs; 1 on any finding; 2 on unreadable/malformed config or a `--pin` failure (fail closed) |
| `mcp-warden auth audit <config...> [--json] [--sarif F]` | **(v1.2)** Static MCP auth-posture audit over client/server config: remote endpoints without auth, cleartext `http://`, credential literals committed into config. No server spawn, no network. See [`docs/AGENT_GATES.md`](docs/AGENT_GATES.md) | 0 clean; 1 on any finding; 2 on read/parse error (fail closed) |
| `mcp-warden check <server-cmd...> \| --url URL --against-community --corpus P\|URL --attester ID=IDENTITY@ISSUER… \| --attesters-file F [--corpus-ref SHA] [--coordinate C] [--min-attesters N] [--require-consensus]` | **(DSE-1515, phase 1)** Also compare the captured surface to Sigstore-signed attestations by attesters **you pin** (`--attester`/`--attesters-file` is required — the corpus's own list is discovery, never the trust root). The signature binds identity, `overall_digest` **and** the package coordinate (`npm:`/`pypi:` name@version, inferred from `npx`/`uvx`/`pipx run` argv or given explicitly). Only `https://`/`ssh://`/`git@` corpus URLs; unverifiable/unreachable/unpinnable/unpinned-trust is exit 2, never a skip. See [`docs/COMMUNITY_CORPUS.md`](docs/COMMUNITY_CORPUS.md) | **1 on `WRD-CONSENSUS-MISMATCH`/`-SPLIT`** (composes with drift); 0 on match, `-NOVEL` or `-INSUFFICIENT` (**1** for those two with `--require-consensus`); 2 fail closed |
| `mcp-warden-precommit [--lock F] [--timeout N] [--strict] -- <server-cmd...>` | **(v0.3)** pre-commit hook entry point (see [pre-commit hook](#pre-commit-hook--the-local-pre-ci-gate)). Runs the same check verdict path; check-only (never pins, never writes the lock) | 0 clean / **1 drift** / 2 config error; server-unavailable → 0+warning (non-strict) or 2 (`--strict`) |

For stdio, `<server-cmd...>` is passed to the OS as an **argv array, never through a
shell.** `--url` instead connects to an already-running Streamable HTTP endpoint and
is mutually exclusive with a server command. Set `WARDEN_LOG_LEVEL=INFO` for diagnostics.

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

## Community consensus — `check --against-community` (phase 1)

A single lock is trust-on-first-use: it cannot tell you the surface was poisoned on
day one, or that you are being served a surface nobody else
sees. `--against-community` compares what you just captured with what independent
attesters **you pin** Sigstore-signed for the same package version:

```bash
mcp-warden check npx -y @foo/server@1.2.3 --lock warden.lock \
    --against-community --corpus https://github.com/<org>/mcp-warden-locks.git \
    --corpus-ref <40-hex corpus commit> --attesters-file trusted-attesters.json
#  -> WRD-CONSENSUS-MISMATCH:     observed surface differs from every attested digest … (exit 1)
#  -> WRD-CONSENSUS-SPLIT:        attesters disagree — corpus or upstream may be compromised (exit 1)
#  -> WRD-CONSENSUS-NOVEL:        no trusted attestation exists yet (exit 0)
#  -> WRD-CONSENSUS-INSUFFICIENT: fewer than --min-attesters (default 2) agree (exit 0)
#  add --require-consensus in CI that EXPECTS the package to be attested: NOVEL and
#  INSUFFICIENT then exit 1 — a corpus that withholds an entry cannot turn a MISMATCH into a pass
```

The trust root is yours: the corpus's `attesters.json` is only a discovery list, and
without `--attester`/`--attesters-file` the command exits 2. Each signature binds the
attester identity, the lock digest **and** the package coordinate, so a genuine
signature cannot be relocated under another package. Everything that cannot be
established — an unpinned launch, an unpinned trust root, an undeclared attester, a
missing or failing signature, an unreachable or disallowed corpus URL — is exit 2.
**Consensus attests observation, not safety**; the CLI says so on every verdict. The
default `check` path is unchanged when the flag is absent.

Contract, trust model, layout, and the pending phase-2 live corpus:
[`docs/COMMUNITY_CORPUS.md`](docs/COMMUNITY_CORPUS.md).

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

Agent Trust Kernel development is intentionally isolated from the shipped `guard` path:
DSE-715's content envelope and DSE-716's deterministic PDP/PEP, exact signed adapter/bundle load
gates, frozen handler identity, and fixed-corpus adapter harness are implemented foundations, but
the default evidence gate denies effects. DSE-717 is now in progress: its isolated branch has
the reviewed receipt/recovery design and protected-state contract, but durable signed receipts,
fallback evidence, rollback-resistant state, the recovery latch, and any whole-kernel conformance
claim remain incomplete. See [`docs/POLICY_ENFORCEMENT.md`](docs/POLICY_ENFORCEMENT.md) and
[`docs/AGENT_TRUST_KERNEL.md`](docs/AGENT_TRUST_KERNEL.md).

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
