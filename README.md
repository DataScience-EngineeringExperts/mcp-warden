# mcp-warden

**CI-first MCP supply-chain integrity gate.** Pin the *declared* tool / resource /
prompt surface of an [MCP](https://modelcontextprotocol.io) server, then fail CI
when that surface drifts from an approved baseline.

> mcp-warden v0.1 is an **MCP supply-chain integrity gate, not an agent firewall.**
> It verifies that a server's *declared* surface has not changed since a human
> approved it, and flags dangerous capability shapes and leaked secrets in that
> surface. It does **not** (and cannot in v0.1) guarantee that a tool *behaves*
> safely — including poisoned tool results, which is the explicit v0.2 target.
> See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

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

Reproducibility is the core guarantee: canonicalization is **RFC 8785 (JCS)** +
**SHA-256** (`sha256:<hex>`), so `pin` and `check` agree byte-for-byte.

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

## CLI reference

| Command | Purpose | Exit code |
|---------|---------|-----------|
| `mcp-warden pin <server-cmd...> [--approve --approver <id>] [--sarif F] [--json]` | Capture + write `warden.lock` (TOFU baseline) | 0 on success, 2 on capture/IO error |
| `mcp-warden check <server-cmd...> [--lock F] [--sarif F] [--json]` | Re-capture + diff vs lock | **non-zero on drift**, 2 on error |
| `mcp-warden policy lint <file> [--lock F]` | Lint a policy file (fail closed) | non-zero on lint error |
| `mcp-warden policy eval <file> <sample.json> [--lock F]` | Evaluate one sample call | **non-zero on a deny verdict** (CI assertion) |

`<server-cmd...>` is passed to the OS as an **argv array, never through a shell.**
Set `WARDEN_LOG_LEVEL=INFO` for diagnostic logging.

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
