# The pin / check CI demo

The full end-to-end walkthrough, archived out of `README.md` to keep the core
doc under the 500-line limit. Linked from the README's
[pin / check CI demo](../README.md#the-pin--check-ci-demo) pointer.

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
skeleton is stored in the lock (`schema_version` 3); pre-skeleton (v1) locks fall
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
      - uses: DataScience-EngineeringExperts/mcp-warden@v0
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
