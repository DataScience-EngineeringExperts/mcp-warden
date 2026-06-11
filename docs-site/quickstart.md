# Quickstart

Pin an MCP server's declared surface, prove the drift gate fires, and wire it
into CI — in under five minutes. Every command below is copy-paste runnable
against the fixtures shipped in the repository. Requires Python ≥ 3.11.

## 1. Install

From a clone of the repository:

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e ".[dev]"

# the CLI is then available as:
.venv/bin/mcp-warden --help
```

Runtime dependencies are `mcp` (the official MCP Python SDK), `rfc8785`,
`pydantic`, `typer`, `rich`, `pyyaml`, and `anyio`.

## 2. Pin a server's declared surface

`pin` captures the `(name, description, inputSchema)` metadata returned by the
server over `tools/list` / `resources/list` / `prompts/list`, records a
human approval, and writes the signed baseline to `warden.lock`:

```bash
.venv/bin/mcp-warden pin python tests/fixtures/clean_server.py \
    --approve --approver you@example.com \
    --lock warden.lock
```

This is a trust-on-first-use (TOFU) baseline: you are asserting that the surface
you see right now is the surface you approve. Commit `warden.lock`.

## 3. Check the surface against the lock

`check` re-captures the live surface and diffs it against the lock. When nothing
changed, it exits `0`:

```bash
.venv/bin/mcp-warden check python tests/fixtures/clean_server.py --lock warden.lock
```

## 4. Prove the gate fires

Point `check` at a rug-pulled server (the repo ships a mutated fixture). The
declared surface no longer matches the lock, so the check prints
`DRIFT DETECTED` and **exits 1** — which is what fails a build in CI:

```bash
.venv/bin/mcp-warden check python tests/fixtures/mutated_server.py --lock warden.lock
```

`check` exits **non-zero on any drift** (added / removed / modified tool,
capability change, server-identity change), `0` when the surface matches, and
`2` on a capture or I/O error.

## 5. Wire it into CI

Point `server-cmd` at *your* server's launch argv and commit `warden.lock`:

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

The Action runs `check`, fails the build on any drift, and (by default) uploads
a SARIF report to GitHub code scanning. For the full input table, GitLab CI, and
the pin-once / check-on-PR pattern, see
[Pin MCP servers in CI](pin-in-ci.md).

## Next steps

- [What is an MCP rug pull](rug-pull.md) — the exact attack this gate is built to catch.
- [The MCP Lock Format](lock-format.md) — what is inside `warden.lock`.
- [MCP security checklist](checklist.md) — the other layers you still want.

!!! warning "What this does NOT cover"
    The quickstart pins and verifies the **declared** surface only. mcp-warden
    does **not** inspect runtime tool *behavior*, does **not** scan the
    *contents* of tool descriptions for malicious wording (that is a scanner's
    job — see the [comparison](comparison.md)), and makes **no compliance or
    regulatory claim**. Read the limits in the
    [threat model](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/THREAT_MODEL.md).
