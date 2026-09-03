# `mcp-warden doctor` — zero-config MCP posture scan (DSE-1516)

**Status:** implemented (v1.2 line). **Purpose:** the one-command, no-argument entry
point. It finds every MCP client config already on the machine, runs the existing
static engines over each configured server, tells you which servers have no
`warden.lock`, and prints the exact `pin` command to fix that. It **composes**
`auth audit` and the `WRD-SUP-*` launch checks — it adds no new detection catalog.

```bash
mcp-warden doctor            # scan; exit 0 clean / 1 findings / 2 unreadable config
mcp-warden doctor --json     # JSONL findings on stdout
mcp-warden doctor --sarif doctor.sarif
mcp-warden doctor --config ./some/mcp.json --no-discover   # explicit paths only
mcp-warden doctor --pin      # OPT-IN: spawn each uncovered server and write <name>.warden.lock
```

---

## 1. Discovery — the documented set

Discovery is a **pure function of `(platform, home, cwd, env)`**. Only the paths
below are ever read. Nothing else on disk is opened unless named with `--config`.

| Client | macOS | Linux | Windows | Key |
|---|---|---|---|---|
| Claude Code (user) | `~/.claude.json` | same | same | top-level `mcpServers` **and** each `projects.<path>.mcpServers` (reported as `~/.claude.json#projects[<path>]`) |
| Claude Code (project) | `.mcp.json` | same | same | `mcpServers` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` | `mcpServers` |
| Cursor | `~/.cursor/mcp.json`, project `.cursor/mcp.json` | same | same | `mcpServers` |
| VS Code | `~/Library/Application Support/Code/User/mcp.json`, project `.vscode/mcp.json` | `~/.config/Code/User/mcp.json`, project `.vscode/mcp.json` | `%APPDATA%\Code\User\mcp.json`, project `.vscode/mcp.json` | `servers` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | same | same | `mcpServers` |
| Codex | `~/.codex/config.toml` | same | same | `[mcp_servers.<name>]` (stdlib `tomllib`) |

**Project-scoped** candidates are found by walking up from `cwd`, stopping after the
home directory (when `cwd` is under it) or at the filesystem root, and never more
than 32 levels. On Windows the two `%APPDATA%` entries are simply absent when
`APPDATA` is unset — the location is never guessed.

Both the `mcpServers` and the VS Code `servers` key are accepted in any JSON file, so
a config copied between clients still scans.

### Symlink rule (path-traversal / escape guard)

A discovered path with a **symlink at any component below its base** (the home
directory for user-level entries, the ancestor directory for project-level entries)
is **skipped with a stderr warning** and its target is never read. A planted link at
a well-known location therefore cannot steer the scan outside the documented set.
An explicit `--config PATH` is trusted as given and may be a symlink.

## 2. What runs per server

| Engine | Rules | Source |
|---|---|---|
| Static auth-posture audit | `WRD-AUTH-*` | `auth_audit.audit_server` — identical verdicts to `mcp-warden auth audit` |
| Supply-chain launch checks | `WRD-SUP-*` (unpinned `npx`/`uvx`/`pip`, `@latest`, `curl \| sh`) | `checks_supply.check_launch_command` over `command` + `args` |
| Lock coverage | `WRD-DOCTOR-NO-LOCK` (low) | see §3 |

Every finding's `target` is `<source label>#<server name>`, e.g.
`~/.cursor/mcp.json#github`, so one report line locates the exact entry.

## 3. Lock coverage

`doctor` looks for `warden.lock` and `*.warden.lock` under `cwd` — at most 4 levels
deep, never following symlinks, never descending into `.git`, `.venv`, `venv`,
`node_modules`, `__pycache__`, `.ruff_cache`, `.tox`. A lock **covers** a server when
its recorded launch is *exactly* the server's launch: `server.url` equality for HTTP
servers, `server.command` + `server.args` equality for stdio. A lock that fails to
parse is ignored with a warning; it never counts as coverage.

An uncovered server yields `WRD-DOCTOR-NO-LOCK` (severity **low**) and an entry in
the **Next steps** block:

```
# ~/.cursor/mcp.json#github
mcp-warden pin npx -y @modelcontextprotocol/server-github --approve --approver you@example.com --lock github.warden.lock
```

The printed argv is shell-quoted and must survive copy-paste, so masking is deliberate
rather than maximal:

- an argument matching a **vendor secret pattern** (`sk-…`, `ghp_…`, `AKIA…`, a JWT,
  a private-key header) is always printed as `<REDACTED>`;
- the **entropy heuristic alone never masks** — `@modelcontextprotocol/server-github`
  is high-entropy and is precisely the token the user needs to copy;
- the value after an **auth-shaped flag** (`--token`, `--api-key`, `-p`, …) or the
  value of an auth-shaped `KEY=value` is masked **unless** it is a `${VAR}` / `$VAR`
  secret reference, which is printed verbatim because it carries nothing;
- a URL embedding userinfo is printed as `<REDACTED: url embeds a credential>`.

The block ends with the GitHub Action snippet.

## 4. Safety contract — static by default

The default path performs **no process spawn, no network I/O, no DNS**. This is
asserted by `tests/test_doctor_cli.py::test_default_path_never_spawns_connects_or_resolves`,
which makes `subprocess.Popen`, `asyncio.create_subprocess_exec`, `socket.socket`
and `socket.getaddrinfo` raise and requires the scan to complete anyway.

Credentials are redacted everywhere a value could surface — terminal, `--json`,
`--sarif`, the Next-steps argv — through the same redactor the rest of warden uses.
`doctor` never edits a config file.

### `--pin` (opt-in)

`--pin` is the only path that launches anything. It runs the same capture + lock
build as `mcp-warden pin` for each **uncovered** server, writes
`<slug>.warden.lock` in `cwd` **unapproved**, and prints the `lock rotate --approver`
command that records the human approval. Contract:

- In a **non-interactive** session (`stdin` is not a TTY) it **refuses** unless
  `--yes` is passed — exit 2, nothing spawned.
- Interactively it prompts once (default **No**) before spawning anything.
- A server that cannot be captured is reported (`pin failed …`) and the rest still
  run; any failure makes the final exit code **2**.

## 5. Exit codes (house contract)

| Exit | Meaning |
|---|---|
| 0 | no configs found (explicit message) **or** every server pinned with no posture findings |
| 1 | at least one finding (including `WRD-DOCTOR-NO-LOCK`) |
| 2 | an unreadable or malformed config, or a `--pin` refusal/capture failure (fail closed) |

## 6. Hidden options

`--home PATH` and `--platform darwin|linux|win32` override discovery inputs. They exist
so the discovery table is testable on any host (the Windows shape is exercised on
Linux CI via injected `APPDATA`) and are hidden from `--help` on purpose.

## 7. Non-goals

- New rule catalogs — `doctor` composes; it does not detect anything `auth audit`
  and `check` do not already detect.
- Editing a config. It reports and prints the command.
- Runtime interception (`guard`).
- Reading any path outside §1 without `--config`.
