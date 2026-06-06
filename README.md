# mcp-warden

**CI-first MCP supply-chain integrity gate.** Pin the *declared* tool / resource /
prompt surface of an [MCP](https://modelcontextprotocol.io) server, then fail CI
when that surface drifts from an approved baseline.

> mcp-warden is an **MCP supply-chain integrity gate, not a full agent firewall.**
> v0.1 verifies that a server's *declared* surface has not changed since a human
> approved it, and flags dangerous capability shapes and leaked secrets in that
> surface. **v0.2 adds runtime tool-result inspection** (`guard` proxy + `inspect`
> analyzer): it detects control/ANSI escapes, echoed secrets, and configured exfil
> domains (deterministic, blockable on opt-in) and monitors a narrow curated
> prompt-injection phrase list (fuzzy, log-only) — **shipping shadow-default**. It still
> does **not** defend behavioral attacks (`T-BEHAVE`) or novel result vectors.
> See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and
> [`docs/THREAT_MODEL_V2.md`](docs/THREAT_MODEL_V2.md).

---

## What it does

mcp-warden operates entirely on **definitions** — the `(name, description,
inputSchema)` metadata returned by `tools/list`, `resources/list`, and
`prompts/list` — never on runtime tool behavior or results.

| Threat class | Control |
|--------------|---------|
| **Definition drift / rug-pull** (`MCP-DRIFT`) | `check` re-captures and hash-diffs the surface vs `warden.lock`; any drift fails CI |
| **Dangerous capability surface** (`MCP-CAPSURF`) | Deterministic `WRD-CAP-*` static checks (shell/exec, fs-write, fs-read, http, sql) |
| **Secret leakage in definitions** (`MCP-SECRET`) | `WRD-SEC-*` regex + entropy checks; snippets are always redacted |
| **Unpinned supply-chain refs** (`MCP-SUPPLY`) | `WRD-SUP-*` flags unpinned `npx`/`uvx`/`pip`, `latest`, and `curl|sh` launches |
| **Poisoned tool results** (`T-RESULT`, v0.2) | `guard`/`inspect` run the `WRD-RES-*` catalog on tool results: ANSI/control escapes, echoed secrets, exfil domains (deterministic BLOCK), curated injection phrases (fuzzy MONITOR) — shadow-default |

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

`check` exits **non-zero on any drift** (added/removed/modified tool, schema or
capability change, server-identity change). The SARIF report (`ruleId` ==
the `WRD-*` / `WRD-DRIFT-*` check ID) uploads straight to GitHub code scanning.

### Typical GitHub Actions step

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
  uses: actions/upload-artifact@v4
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

## CLI reference

| Command | Purpose | Exit code |
|---------|---------|-----------|
| `mcp-warden pin <server-cmd...> [--approve --approver <id>] [--sarif F] [--json]` | Capture + write `warden.lock` (TOFU baseline) | 0 on success, 2 on capture/IO error |
| `mcp-warden check <server-cmd...> [--lock F] [--sarif F] [--json]` | Re-capture + diff vs lock | **non-zero on drift**, 2 on error |
| `mcp-warden policy lint <file> [--lock F]` | Lint a policy file (fail closed) | non-zero on lint error |
| `mcp-warden policy eval <file> <sample.json> [--lock F]` | Evaluate one sample call | **non-zero on a deny verdict** (CI assertion) |
| `mcp-warden guard <server-cmd...> [--lock F] [--policy F] [--block-* ...] [--audit-only] [--sarif F] [--record T]` | **(v0.2)** Transparent stdio proxy: inspects `tools/call` results + arguments at runtime. **Shadow-default** (logs, does not block unless a `--block-*` flag is set) | child's exit code; never breaks the session |
| `mcp-warden inspect <trace.jsonl> [--lock F] [--sarif F]` | **(v0.2)** Offline analyzer over a recorded JSON-RPC session — same `WRD-RES-*` catalog as `guard` | non-zero on any BLOCK-tier finding; 2 on read error |

`<server-cmd...>` is passed to the OS as an **argv array, never through a shell.**
Set `WARDEN_LOG_LEVEL=INFO` for diagnostic logging.

### Runtime result inspection (v0.2, shadow-default)

`guard` sits transparently between an MCP client and server and inspects tool *results*:

```bash
# Shadow mode (default): detect + log, never block. Safe to roll out first.
mcp-warden guard node ./build/index.js --lock warden.lock --sarif guard.sarif

# Opt into deterministic blocking once you trust the findings:
mcp-warden guard node ./build/index.js --lock warden.lock --block-deterministic
#  blocks: ANSI/control escapes, echoed secrets, configured exfil domains, and
#  a mid-session tools/list surface swap that diverges from warden.lock.

# Re-analyze a recorded session offline with the identical rule catalog:
mcp-warden inspect session.trace.jsonl --lock warden.lock --sarif inspect.sarif
```

Result rules (`WRD-RES-*`): `WRD-RES-ANSI`, `WRD-RES-SECRET-ECHO`, `WRD-RES-EXFIL-DOMAIN`
(deterministic BLOCK tier) and `WRD-RES-INJECT-PHRASE` (fuzzy MONITOR tier, log-only by
default). `--audit-only` forces every detection to a warning. See
[`docs/RESULT_INSPECTION.md`](docs/RESULT_INSPECTION.md) and
[`docs/GUARD_PROXY.md`](docs/GUARD_PROXY.md).

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

See [`DOCUMENTATION_INDEX.md`](DOCUMENTATION_INDEX.md). The four security-contract
specs under `docs/` are the source of truth for every algorithm; the schemas in
`warden.lock` and the SARIF output match them byte-for-byte.

## Tests

```bash
.venv/bin/python -m pytest -q
```

The headline test is a real stdio round-trip: spawn the clean fixture → `pin` →
re-run `check` against the mutated fixture → assert non-zero exit + the expected
drift + SARIF finding.

## License

Apache-2.0.
