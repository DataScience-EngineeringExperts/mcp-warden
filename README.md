# mcp-warden

[![CI](https://github.com/ernestprovo23/mcp-warden/actions/workflows/integrity-gate.yml/badge.svg)](https://github.com/ernestprovo23/mcp-warden/actions/workflows/integrity-gate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

**CI-first MCP supply-chain integrity gate.** Pin the *declared* tool / resource /
prompt surface of an [MCP](https://modelcontextprotocol.io) server, then fail CI
when that surface drifts from an approved baseline.

> mcp-warden is an **MCP supply-chain integrity gate, not a full agent firewall.**
> v0.1 verifies that a server's *declared* surface has not changed since a human
> approved it, and flags dangerous capability shapes and leaked secrets in that
> surface. **v0.2 added runtime tool-result inspection** (`guard` proxy + `inspect`
> analyzer): control/ANSI escapes, echoed secrets, configured exfil domains
> (deterministic) plus a curated prompt-injection phrase list (fuzzy, log-only).
> **v0.3 is the first release that actively blocks by default**: the deterministic
> tier (ANSI, secret-echo, exfil-domain, the `tools/list_changed` drift gate when
> `--lock` is supplied, and argument-policy denials when `--policy` is supplied)
> **blocks out of the box**, each individually opt-OUT-able via `--no-block-<category>`
> (and `--audit-only` restores full shadow in one flag); the fuzzy injection tier
> stays opt-in. v0.3 also hardens the proxy lifecycle (cancel/progress passthrough,
> server-crash + client-disconnect teardown). It still does **not** defend behavioral
> attacks (`T-BEHAVE`). See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
> [`docs/THREAT_MODEL_V2.md`](docs/THREAT_MODEL_V2.md), and
> [`docs/GUARD_PROXY_V3.md`](docs/GUARD_PROXY_V3.md).

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

```bash
# from a clone of this repo
uv venv .venv
uv pip install --python .venv/bin/python -e ".[dev]"

# the CLI is then available as:
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
pip install mcp-warden
# Pin your server and record an approval
mcp-warden pin node ./build/index.js \
    --approve --approver you@example.com \
    --lock warden.lock
git add warden.lock && git commit -m "chore: pin MCP surface baseline"
```

**2. Add the check step to your workflow** (`.github/workflows/integrity-gate.yml`):

```yaml
- name: Install mcp-warden
  run: pip install mcp-warden

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
    rev: v0.3.0                       # pin to a release tag (supply-chain hygiene)
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
| `mcp-warden pin <server-cmd...> [--approve --approver <id>] [--sarif F] [--json]` | Capture + write `warden.lock` (TOFU baseline) | 0 on success, 2 on capture/IO error |
| `mcp-warden check <server-cmd...> [--lock F] [--sarif F] [--json]` | Re-capture + diff vs lock | **non-zero on drift**, 2 on error |
| `mcp-warden policy lint <file> [--lock F]` | Lint a policy file (fail closed) | non-zero on lint error |
| `mcp-warden policy eval <file> <sample.json> [--lock F]` | Evaluate one sample call | **non-zero on a deny verdict** (CI assertion) |
| `mcp-warden guard <server-cmd...> [--lock F] [--policy F] [--no-block-* / --allow-exfil-domain] [--block-inject-phrase] [--audit-only] [--sarif F] [--record T]` | **(v0.3)** Transparent stdio proxy: inspects `tools/call` results + arguments at runtime. **Deterministic tier blocks by default**; opt out per-category with `--no-block-<category>` or fully with `--audit-only` | child's exit code; never breaks the session |
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

# Re-analyze a recorded session offline with the identical rule catalog (always report-only):
mcp-warden inspect session.trace.jsonl --lock warden.lock --sarif inspect.sarif
```

**Flag scheme:** opt-out is canonical `--no-block-<category>`
(`ansi|secret-echo|exfil-domain|list-changed|policy`, plus `--no-block-deterministic` for the
whole tier); `--allow-exfil-domain` is the sole affirmative alias. Precedence:
`--audit-only` > `--no-block-*` > default-block / `--block-inject-phrase`. The v0.2
`--block-*` enable flags are accepted but **inert no-ops** (one-line stderr deprecation note),
so old scripts keep working. Reserved error codes: **`-32001`** (policy/result block),
**`-32002`** (transport/lifecycle). See
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

## Contributing & security

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the dev
setup, the determinism contract, and how to propose new checks. By participating
you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

This is a security tool: **do not report vulnerabilities in public issues.** Follow
the responsible-disclosure process in [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE). Copyright (c) 2026 Ernest Provo.
