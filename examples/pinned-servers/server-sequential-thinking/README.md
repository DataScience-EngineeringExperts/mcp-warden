# Pinned example: `@modelcontextprotocol/server-sequential-thinking`

Sequential-thinking MCP server from the Model Context Protocol project. A single
tool, useful as a minimal npx pin example.

- Package: `@modelcontextprotocol/server-sequential-thinking`
- Launcher: `npx` with the version pinned to `@2025.12.18`
- Surface in this lock: **1 tool, 0 resources, 0 prompts**

The version is pinned in the launch argv (`@2025.12.18`) so
`WRD-SUP-NPX-UNPINNED` does not fire.

## Pin (how `warden.lock` was generated)

```bash
mcp-warden pin \
  --approve --approver "examples@mcp-warden.invalid" \
  --lock warden.lock \
  -- npx -y @modelcontextprotocol/server-sequential-thinking@2025.12.18
```

## Check (what CI re-runs against the committed lock)

```bash
mcp-warden check \
  --lock warden.lock \
  -- npx -y @modelcontextprotocol/server-sequential-thinking@2025.12.18
```

Exit 0 = surface matches the lock. Exit 1 = drift. Exit 2 = capture error.

## Notes

- One static finding is baked into the lock: `WRD-SEC-ENTROPY` on
  `launch/command`. The long scoped package name has high character entropy and
  trips the heuristic; it is not a secret. `check` reproduces it identically, so
  it never registers as drift.
- `command_digest` hashes the literal launch argv, so this lock verifies
  identically on any machine.

The committed example was re-captured at **schema level 4** on 2026-10-02,
including complete tool annotations and output schemas. The approver is an
obviously synthetic example identity; this lock is a reproducible demonstration,
not an authenticated human authorization receipt.
