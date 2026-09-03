# `mcp-warden doctor` — zero-config MCP posture scan (DSE-1516)

**Status:** implemented (v1.2 line). **Purpose:** the one-command, no-argument entry
point. It finds every MCP client config already on the machine, runs the existing
static engines over each configured server, tells you which servers have no
approved `warden.lock`, and prints the exact `pin` command to fix that. It
**composes** `auth audit` and the `WRD-SUP-*` launch checks — it adds no new
detection catalog.

```bash
mcp-warden doctor            # scan; exit 0 clean / 1 findings or skipped config / 2 unreadable config
mcp-warden doctor --json     # JSONL findings on stdout
mcp-warden doctor --sarif doctor.sarif
mcp-warden doctor --config ./some/mcp.json --no-discover   # explicit paths only
mcp-warden doctor --config ./mcp.json --pin   # OPT-IN: spawn each uncovered --config server, write <name>.warden.lock
```

The threat model is unusual for a scanner: **the input files are attacker-reachable**.
A cloned repository ships `.mcp.json`; `doctor` reads it. Every design rule below
follows from "a config must never drive the operator's terminal or shell".

---

## 1. Discovery — the documented set

Discovery is a function of `(platform, home, cwd, env)` plus two filesystem probes
(`.git` boundaries, file size). Only the paths below are ever read. Nothing else on
disk is opened unless named with `--config`.

| Client | macOS | Linux | Windows | Key / format |
|---|---|---|---|---|
| Claude Code (user) | `~/.claude.json` | same | same | top-level `mcpServers` **and** each `projects.<path>.mcpServers` (reported as `~/.claude.json#projects[<path>]`) |
| Claude Code (project) | `.mcp.json` | same | same | `mcpServers` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` | `mcpServers` |
| Cursor | `~/.cursor/mcp.json`, project `.cursor/mcp.json` | same | same | `mcpServers` |
| VS Code | `~/Library/Application Support/Code/User/mcp.json`, project `.vscode/mcp.json` | `~/.config/Code/User/mcp.json`, project `.vscode/mcp.json` | `%APPDATA%\Code\User\mcp.json`, project `.vscode/mcp.json` | `servers`; **JSONC** (`//` and `/* */` comments, trailing commas) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | same | same | `mcpServers` |
| Codex | `~/.codex/config.toml` | same | same | `[mcp_servers.<name>]` (stdlib `tomllib`) |

Every JSON file is loaded as the **union** of its `mcpServers` and `servers` maps. VS
Code reads `servers`; if a file also carried a benign `mcpServers` and only that map
were audited, a decoy could hide the map the client actually loads. A name present
under both keys with an identical body is loaded once; with *different* bodies both
are audited (the second as `<name>#servers`) and each is flagged
`WRD-DOCTOR-AMBIGUOUS-SERVER` (medium). The JSONC pass (VS Code) is string-aware in
**both** of its stages — comment stripping and trailing-comma removal — so a value
such as `"echo {a, }"` is audited and pinned byte-for-byte as the client launches
it. On Windows the two `%APPDATA%` entries
are simply absent when `APPDATA` is unset — the location is never guessed.

### Project walk-up boundary

Project-scoped candidates are found by walking up from `cwd`. The walk stops at the
**first ancestor containing `.git`** (that directory is still scanned), or at the
**home directory** when `cwd` is under it — whichever comes first — and never more
than 32 levels. When `cwd` is outside home and no `.git` boundary exists, **only
`cwd` itself** is a candidate: an unbounded walk from `/tmp/x` would otherwise read a
world-writable `/tmp/.mcp.json`.

### Symlink rule (path-traversal / escape guard)

A discovered path with a **symlink at any component below its base** (the home
directory for user-level entries, the ancestor directory for project-level entries)
is **skipped with a stderr warning** and its target is never read. An explicit
`--config PATH` is trusted as given and may be a symlink.

### Size cap

A discovered file larger than **8 MiB** is skipped with a warning (`~/.claude.json`
carries session history and can reach tens of MB; a credential-bearing config never
should). `--config` has no cap.

### One bad file does not hide the others

A discovered file that is unreadable or malformed is **warned about and counted as a
hard error**, and the scan continues over every other candidate. The final exit code
is 2 (§5) so the failure is never silent, but the posture of the files that *did*
parse is still reported. `--config` paths keep the hard raise: you named it, so an
unreadable one is an error.

**A skip is never green.** If any discovered file was skipped (symlink, oversized),
the exit code is at least 1 and neither `no MCP configs found` nor `doctor clean` is
printed — something on the machine went unscanned.

## 2. What runs per server

| Engine | Rules | Source |
|---|---|---|
| Static auth-posture audit | `WRD-AUTH-*` | `auth_audit.audit_server` — identical verdicts to `mcp-warden auth audit` |
| Supply-chain launch checks | `WRD-SUP-*` (unpinned `npx`/`uvx`/`pip`, `@latest`, `curl \| sh`) | `checks_supply.check_launch_command` over `command` + `args` |
| Config ambiguity | `WRD-DOCTOR-AMBIGUOUS-SERVER` (medium) | a name declared under both `mcpServers` and `servers` with different bodies (§1) |
| Lock coverage | `WRD-DOCTOR-NO-LOCK` (low), `WRD-DOCTOR-LOCK-UNAPPROVED` (medium) | see §3 |

Every finding's `target` is `<source label>#<server name>`, e.g.
`~/.cursor/mcp.json#github`, so one report line locates the exact entry.

### Rendering is hostile-input safe

Every config-controlled string that reaches the terminal — server name, source
label, config path, the host inside an auth-audit message, warning text — passes
through `safe_text()` **before** any print: every character a terminal or a copy
buffer can be tricked by becomes `U+FFFD` — C0 + DEL (`U+0000`–`U+001F`, `U+007F`),
the C1 range (`U+0080`–`U+009F`; `U+009B` is CSI and `U+009D` is OSC on xterm-family
terminals), NEL, the zero-width and directional marks (`U+200B`–`U+200F`), the line
and paragraph separators (`U+2028`, `U+2029`), and both bidi-override blocks
(`U+202A`–`U+202E`, `U+2066`–`U+2069` — Trojan Source, CVE-2021-42574) — and the
string is capped at 200 characters. Rich markup is then escaped where markup is on, and the JSONL / pin
blocks print with `markup=False`. A server named
`gh\n  mcp-warden pin sh -c '…'` therefore renders as one line with a visible `�`,
never as a second copy-pasteable command; an `\x1b[2K` cannot repaint a row.

## 3. Lock coverage

`doctor` looks for `warden.lock` and `*.warden.lock` under `cwd` — at most 4 levels
deep, never following symlinks, never descending into `.git`, `.venv`, `venv`,
`node_modules`, `__pycache__`, `.ruff_cache`, `.tox`. A lock **matches** a server
when its recorded launch is *exactly* the server's launch: `server.url` equality for
HTTP servers, `server.command` + `server.args` equality for stdio. A lock that fails
to parse is ignored with a warning; it never counts as coverage.

**A lock found in the tree is unauthenticated evidence.** It proves a lock exists,
not that a human approved the surface — a hostile repository can ship a well-formed
lock matching your server. `doctor` therefore reads `pin.approved`:

| State | Finding |
|---|---|
| no matching lock | `WRD-DOCTOR-NO-LOCK` (low) + a **Next steps** entry |
| matching lock, `pin.approved: false` | `WRD-DOCTOR-LOCK-UNAPPROVED` (medium) — includes every lock `--pin` writes |
| matching lock, `pin.approved: true` | covered; no finding |

Whether an *approved* lock is genuine is `mcp-warden check --verify`'s job (Sigstore
signature over `overall_digest`); `doctor` does not attempt it.

### The printed `pin` command

```
# ~/.cursor/mcp.json#github
mcp-warden pin npx -y @modelcontextprotocol/server-github --approve --approver you@example.com --lock github.warden.lock
```

The argv is shell-quoted and must survive copy-paste, so masking is deliberate rather
than maximal — but it is a superset of what `auth audit` recognises, because real
launch lines carry credentials in shapes the config audit never sees:

- an argument matching a **vendor secret pattern** (`sk-…`, `ghp_…`, `AKIA…`, a JWT,
  a private-key header) is always printed as `<REDACTED>`;
- the **entropy heuristic alone never masks** — `@modelcontextprotocol/server-github`
  is high-entropy and is precisely the token the user needs to copy;
- the value after an **auth-shaped flag** is masked. The flag set is doctor-local and
  wider than the config audit's key list: `key`, `api-key`, `apikey`, `token`,
  `secret`, `password`, `passwd`, `pat`, `bearer`, `credential(s)`, `cookie`, `auth`,
  `authorization`, `header`, `-H` (case-insensitive, matched in **both** the raw and
  the `_`→`-` folded spelling, with or without dashes — so `--openai_api_key` masks
  too) — Smithery's `--key <uuid>` and mcp-remote's `--header "Authorization:
  Bearer …"` are both masked. A single-letter `-k` is **not** auth-shaped: its value
  masks only when it hits a vendor pattern;
- an auth-shaped `KEY=value` **or** `Key: value` argument is masked (both separators);
- a JSON-object argument containing an auth-shaped key (`--config '{"apiKey":…}'`) is
  masked whole;
- a `${VAR}` / `$VAR` / `{{ x }}` / `%VAR%` reference is printed verbatim — it carries
  nothing;
- in a URL, userinfo masks the whole URL; an **auth-shaped query parameter**
  (`api_key`, `key`, `token`, `access_token`, `secret`, `sig`, `signature`, `auth`) has
  its value replaced; a **path segment of 20+ characters** that is high-entropy or
  matches a vendor pattern is replaced (`/api/mcp/s/REDACTED/mcp`); a **fragment**
  that is auth-shaped (`#token=…`) or token-like is replaced. Scheme and host stay
  visible. When nothing needs masking the URL is printed **byte-for-byte** as it
  appears in the config — never re-encoded — so the lock the user pins from the
  printed command is the lock `doctor` recognises on the next run.

When two server names slug to the same file (`a/b` and `a-b`), the second gets a
short hash suffix. The block ends with the GitHub Action snippet.

## 4. Safety contract — static by default

The default path performs **no process spawn, no network I/O, no DNS**. This is
asserted by `tests/test_doctor_cli.py::test_default_path_never_spawns_connects_or_resolves`,
which makes `subprocess.Popen`, `asyncio.create_subprocess_exec`, `socket.socket`
and `socket.getaddrinfo` raise and requires the scan to complete anyway.

Credentials are redacted everywhere a value could surface — terminal, `--json`,
`--sarif`, the Next-steps argv — through `redact_secret` (prefix of at most half the
value, exact-or-bucketed length, never a suffix), the same redactor every other
warden command uses. `doctor` never edits a config file.

### `--pin` (opt-in)

`--pin` is the only path that launches anything. Contract:

- **Provenance gate.** It only spawns servers from a file the user named with
  `--config`. A server that came from discovery — including a repo's `.mcp.json` —
  is **refused** with a stderr line naming the server and its source. Without this,
  `doctor --pin --yes` in CI over an untrusted checkout would be remote code
  execution by config file.
- In a **non-interactive** session (`stdin` is not a TTY) it **refuses** unless
  `--yes` is passed — exit 2, nothing spawned.
- Interactively it prints **every argv it is about to run** and prompts once
  (default **No**). That prompt deliberately shows the **raw, unmasked** argv: it is
  informed consent to spawn exactly that process, it is TTY-only, and it is never
  the string the user is told to paste — do not "fix" it into masking.
- The printed `pin` command **omits `env`**. An env-dependent server's secrets belong
  in the shell environment (`export FOO=…` before running the command), never inline
  on a command line that lands in scrollback and shell history.
- It runs the same capture + lock build as `mcp-warden pin`, writes
  `<slug>.warden.lock` in `cwd` **unapproved**, and prints the `lock rotate
  --approver` command that records the human approval. The next `doctor` run reports
  that lock as `WRD-DOCTOR-LOCK-UNAPPROVED` until it is approved.
- It **never overwrites** an existing lock file (refusal, exit 2).
- A server that cannot be captured is reported (`pin failed …`) and the rest still
  run; any failure or refusal makes the final exit code **2**.

## 5. Exit codes (house contract)

| Exit | Meaning |
|---|---|
| 0 | no configs found (explicit message) **or** every server approved-pinned with no posture findings, and nothing skipped |
| 1 | at least one finding (including `WRD-DOCTOR-*`), **or** a discovered config was skipped (symlink / oversized) |
| 2 | a malformed or unreadable config (discovered → after the scan completes; `--config` → immediately), an unwritable `--sarif` path, or a `--pin` refusal / capture failure (fail closed) |

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
- Authenticating a lock. A matching approved lock is trusted as the repository's own
  commitment; signature verification is `check --verify`.
