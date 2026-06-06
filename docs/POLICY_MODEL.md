# mcp-warden — Policy Model (v0.1)

**Status:** v0.1 security contract. Implementation-ready.
**Command:** `mcp-warden policy`

> **Scope boundary (read first):** in v0.1, `policy` only **lints** a policy file and
> **evaluates a single provided sample call** against it. It does **NOT** intercept live
> tool calls. There is no runtime enforcement, no proxy, no agent in the loop. Runtime
> interception is deferred (`THREAT_MODEL.md` T-RUNTIME-PROXY). A policy that passes lint
> and evaluation is a *design-time* artifact, not an active control.

The policy model gives operators an argument-level way to express *which call shapes are
acceptable* for high-risk tools, so they can (a) catch obviously-dangerous declared
shapes at design time, and (b) pre-stage the constraints that v0.2 runtime enforcement
will use.

---

## 1. The four high-risk tool shapes

A policy targets tools by **shape**, derived from the same capability flags as
`WARDEN_LOCK_SCHEMA.md` §5.4 / `CHECKS.md` §3. A tool may match more than one shape.

| Shape | Recognized from the tool def when… | Backed by capability flag |
|-------|------------------------------------|----------------------------|
| **filesystem-write** | tool derives `fs-write` (name tokens write/save/delete/… + a path-like property `path`/`file`/`dest`/`target`) | `fs-write` |
| **shell-exec** | tool derives `shell-exec` (name tokens shell/exec/spawn/… or a `command`/`cmd`/`script`/`shell` string property) | `shell-exec` |
| **http-request** | tool derives `http-request` (a `url`/`uri`/`endpoint`/`host`/`hostname` property or name tokens fetch/http/download/…) | `http-request` |
| **sql-query** | tool derives `sql-query` (a `query`/`sql`/`statement` property or name tokens sql/query/execute/db) | `sql-query` |

Shape recognition is **deterministic** and reuses the §3 tokenizer in `CHECKS.md`. No
fuzzy matching.

---

## 2. Constraint types per shape

Each shape supports a small, fixed constraint vocabulary. Unknown constraint keys are a
**lint error** (fail closed).

### 2.1 filesystem-write

| Constraint | Type | Meaning |
|-----------|------|---------|
| `allow_paths` | list of glob | The path argument MUST match at least one glob (allowlist). |
| `deny_paths` | list of glob | The path argument MUST NOT match any glob (deny overrides allow). |
| `path_arg` | string | Name of the property holding the path (default: auto-detect among `path`,`file`,`filename`,`dest`,`target`). |

- Globs use `**` (any depth), `*` (single segment), `?` (single char). Matching is on the
  **normalized** path: resolve `.`/`..` lexically, no symlink resolution (design-time only).
- **Deny beats allow.** A path matching both is denied.
- Default posture if a `filesystem-write` tool has a policy but no `allow_paths`: **deny
  all** (empty allowlist = nothing permitted).

### 2.2 shell-exec

| Constraint | Type | Meaning |
|-----------|------|---------|
| `allow` | bool | Master switch. **Default `false` (deny-shell-by-default).** |
| `allow_commands` | list of string | If `allow: true`, the resolved command token MUST be in this allowlist. |
| `command_arg` | string | Property holding the command (default: auto-detect `command`/`cmd`/`script`/`shell`). |

- **Deny-shell-by-default is normative.** A `shell-exec` tool with no policy entry, or
  with `allow` unset, evaluates to **deny**.
- `allow_commands` matches the **first token** of the command string (argv[0] after
  whitespace split). v0.1 does not parse full shell grammar — it extracts the leading
  command word; a command string containing shell metacharacters (`;`, `|`, `` ` ``, `$(`,
  `&&`) is **denied regardless of allowlist** (lint emits `POL-SHELL-METACHAR`).

### 2.3 http-request (SSRF constraints)

| Constraint | Type | Meaning |
|-----------|------|---------|
| `allow_hosts` | list of host glob | The destination host MUST match at least one. |
| `deny_cidrs` | list of CIDR/prefix | The resolved host literal MUST NOT fall in a denied range. |
| `deny_private` | bool | Shorthand: deny link-local, loopback, and RFC1918. **Default `true`.** |
| `url_arg` | string | Property holding the URL/host (default: auto-detect `url`/`uri`/`endpoint`/`host`/`hostname`). |

**`deny_private: true` (the default) denies these ranges** (the SSRF blocklist):

| Range | CIDR | Why |
|-------|------|-----|
| Link-local | `169.254.0.0/16` (`169.254.*`) | Cloud metadata (e.g. `169.254.169.254`) — classic SSRF target |
| Loopback | `127.0.0.0/8` (`127.*`) | Localhost services |
| RFC1918 (10) | `10.0.0.0/8` (`10.*`) | Private network |
| RFC1918 (172) | `172.16.0.0/12` (`172.16.*`–`172.31.*`) | Private network |
| RFC1918 (192) | `192.168.0.0/16` (`192.168.*`) | Private network |
| IPv6 loopback | `::1/128` | Localhost |
| IPv6 ULA | `fc00::/7` | Private network |
| IPv6 link-local | `fe80::/10` | Link-local |

Evaluation notes (v0.1, design-time):

- If the sample-call host is an **IP literal**, match it directly against the deny ranges.
- If the sample-call host is a **DNS name**, v0.1 does **NOT** resolve it (no network at
  policy time). It is checked only against `allow_hosts`/`deny` *literal* rules. This is a
  documented limitation: DNS-rebinding / name-to-private-IP resolution is a **v0.2 runtime
  concern** (we cannot safely resolve at lint time and a resolution now ≠ resolution at
  call time). Lint emits `POL-HTTP-DNS-UNRESOLVED` as a `note`.
- `allow_hosts` host globs: `*.example.com` matches one or more left-most labels;
  exact host match otherwise. Port is ignored for matching unless specified as
  `host:port`.

### 2.4 sql-query

| Constraint | Type | Meaning |
|-----------|------|---------|
| `deny_statements` | list of keyword | Leading statement keyword denylist (default: `DROP`,`DELETE`,`TRUNCATE`,`ALTER`,`GRANT`,`REVOKE`,`UPDATE`). |
| `allow_readonly_only` | bool | If `true`, only `SELECT`/`WITH`/`EXPLAIN` leading keywords pass. **Default `true`.** |
| `query_arg` | string | Property holding the query (default: auto-detect `query`/`sql`/`statement`). |

- v0.1 inspects only the **leading SQL keyword** (first non-whitespace word, case-folded).
  It does **not** parse full SQL. A query whose leading keyword is denied → deny. A query
  containing stacked statements (a `;` separating two non-comment statements) is **denied**
  and emits `POL-SQL-STACKED`.

---

## 3. YAML policy schema

```yaml
version: 1                          # integer, policy schema version

defaults:                           # applied to every matching shape unless overridden
  http_request:
    deny_private: true              # SSRF default
  shell_exec:
    allow: false                    # deny-shell-by-default
  sql_query:
    allow_readonly_only: true

tools:                              # per-tool overrides, keyed by exact tool name
  read_config:
    filesystem_write:               # this tool matched fs-write; constrain it
      allow_paths:
        - "/srv/app/cache/**"
      deny_paths:
        - "/srv/app/cache/secrets/**"

  call_api:
    http_request:
      allow_hosts:
        - "api.example.com"
        - "*.internal-allowed.example.com"
      deny_private: true            # explicit (matches default)

  run_report:
    sql_query:
      allow_readonly_only: true

  # shell-exec tool with NO entry here → denied by default (deny-shell-by-default)
```

Schema rules (normative):

- **`version`** required, integer, == `1` for this doc.
- **`defaults`** optional; keys are the four shapes (snake_case). Provide shape-wide
  baselines.
- **`tools`** optional; map of `tool_name -> { <shape>: <constraints> }`. A tool entry may
  declare multiple shapes (a tool can be both `fs-write` and `http-request`).
- Effective constraints for a tool/shape = shape `defaults` deep-merged with the
  per-tool override (per-tool wins).
- **Unknown keys at any level = lint error.** Fail closed. No silent ignore.
- A `shell_exec` shape present on a tool with **no** matching policy and **no** default
  `allow: true` evaluates to **deny**.

---

## 4. `mcp-warden policy` operations (v0.1)

### 4.1 Lint — `policy lint --policy policy.yaml [--lock warden.lock]`

Validates the policy file:

1. Schema validity (version, known keys, correct types). Unknown key → error.
2. Internal consistency: e.g. a path in both `allow_paths` and `deny_paths`; empty
   `allow_paths` on a constrained `filesystem-write` (warns: deny-all).
3. **If `--lock` is supplied:** cross-check that each `tools.<name>` exists in the lock and
   that the declared shape actually matches that tool's derived capabilities. A policy
   entry for a non-existent tool, or for a shape the tool doesn't have, is a `warning`
   (`POL-LINT-ORPHAN` / `POL-LINT-SHAPE-MISMATCH`) — likely a stale or typo'd rule.
4. Emits `POL-SHELL-METACHAR`, `POL-SQL-STACKED` patterns are **evaluation-time** codes,
   not lint; lint codes are `POL-LINT-*`.

Exit: non-zero on any lint **error**; zero on warnings/notes only.

### 4.2 Evaluate a sample call — `policy eval --policy policy.yaml --call call.json`

Evaluates **one** provided sample call against the policy. There is no live tool; the
caller supplies the call shape.

`call.json`:

```json
{
  "tool": "call_api",
  "arguments": { "url": "http://169.254.169.254/latest/meta-data/" }
}
```

Evaluation algorithm:

1. Determine the tool's shape(s) (from `--lock` if provided, else infer from the call's
   argument names using the §3 `CHECKS.md` tokenizer).
2. For each matched shape, pull effective constraints (§3).
3. Apply the shape's constraint checks to the call's arguments.
4. Output a verdict: `allow` or `deny`, with the **specific constraint** that produced a
   deny and a human-readable reason.

Example verdict (the call above):

```json
{
  "tool": "call_api",
  "shape": "http-request",
  "verdict": "deny",
  "reason": "host 169.254.169.254 is in deny_private range 169.254.0.0/16 (link-local)",
  "constraint": "deny_private"
}
```

Exit: **non-zero on a `deny` verdict**, zero on `allow`. (This makes `policy eval` usable
as a CI assertion: "this known-bad sample MUST be denied.")

### 4.3 What `policy` does NOT do in v0.1

- It does **not** sit between an agent and a server. No interception.
- It does **not** resolve DNS, open sockets, or run tools.
- It does **not** evaluate sequences/conversations — exactly one call per `eval`.
- It does **not** modify `warden.lock`.

---

## 5. Evaluation-time finding codes

| Code | Shape | Meaning | Verdict |
|------|-------|---------|---------|
| `POL-FS-DENY` | filesystem-write | path not in `allow_paths` or matched `deny_paths` | deny |
| `POL-SHELL-DENY` | shell-exec | `allow:false` or command not in `allow_commands` | deny |
| `POL-SHELL-METACHAR` | shell-exec | command string contains shell metacharacters | deny |
| `POL-HTTP-SSRF` | http-request | host in a denied/private range | deny |
| `POL-HTTP-HOST-DENY` | http-request | host not in `allow_hosts` | deny |
| `POL-HTTP-DNS-UNRESOLVED` | http-request | host is a DNS name; not resolved at design time | note (allow unless other rule denies) |
| `POL-SQL-DENY` | sql-query | leading keyword denied / not read-only | deny |
| `POL-SQL-STACKED` | sql-query | multiple statements detected | deny |

---

## 6. Implementer must-not-deviate list

1. **Lint + single-sample eval ONLY.** No runtime interception in v0.1.
2. **Fail-closed defaults:** `shell_exec.allow=false`, `http_request.deny_private=true`,
   `sql_query.allow_readonly_only=true`, empty `allow_paths` = deny-all.
3. **Deny overrides allow** in every shape.
4. SSRF deny ranges are the §2.3 table verbatim (incl. `169.254.*`, `127.*`, `10.*`,
   `192.168.*`, `172.16–31.*`, and the IPv6 set).
5. **No DNS resolution** at policy time; DNS-name hosts emit `POL-HTTP-DNS-UNRESOLVED`.
6. Shell/SQL inspection is **leading-token only** + metachar/stacked-statement denial; no
   full grammar parsing.
7. Unknown policy keys = **lint error** (fail closed), never silently ignored.
8. `policy eval` exits **non-zero on deny** so it works as a CI assertion.
9. Shape recognition reuses the `CHECKS.md` §3 tokenizer — one source of truth.
