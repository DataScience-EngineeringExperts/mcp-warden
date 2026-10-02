# Pinned example: `@modelcontextprotocol/server-everything`

Reference MCP server from the Model Context Protocol project. Exercises the full
surface (tools, resources, prompts) which makes it a good end-to-end pin target.

- Package: `@modelcontextprotocol/server-everything`
- Launcher: `npx` with the version pinned to `@2026.1.26`
- Surface in this lock: **13 tools, 7 resources, 4 prompts**

The version is pinned in the launch argv (`@2026.1.26`) so `WRD-SUP-NPX-UNPINNED`
does not fire — the server resolves to a fixed release, not whatever `latest`
points to at run time.

## Pin (how `warden.lock` was generated)

```bash
mcp-warden pin \
  --approve --approver "examples@mcp-warden.invalid" \
  --lock warden.lock \
  -- npx -y @modelcontextprotocol/server-everything@2026.1.26
```

The `--` separator ends mcp-warden's own options; everything after it is the
server launch argv. `-y` tells `npx` to auto-install the pinned version without
an interactive prompt.

## Check (what CI re-runs against the committed lock)

```bash
mcp-warden check \
  --lock warden.lock \
  -- npx -y @modelcontextprotocol/server-everything@2026.1.26
```

Exit 0 = surface matches the lock. Exit 1 = drift. Exit 2 = capture error.

## Notes

- One static finding is baked into the lock: `WRD-CAP-SQL` on the
  `simulate-research-query` tool (the name contains a `query` token). This is a
  capability annotation, not drift — `check` reproduces it identically.
- `command_digest` hashes the literal launch argv (`npx … @2026.1.26`), not the
  resolved binary, so this lock verifies identically on any machine.

The committed example was re-captured at **schema level 4** on 2026-10-02,
including complete tool annotations and output schemas. The approver is an
obviously synthetic example identity; this lock is a reproducible demonstration,
not an authenticated human authorization receipt.
