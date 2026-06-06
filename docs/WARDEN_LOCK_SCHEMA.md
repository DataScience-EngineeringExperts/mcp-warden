# mcp-warden — `warden.lock` Schema (v0.1)

**Status:** v0.1 security contract. Implementation-ready.
**Purpose:** Define the on-disk baseline that `pin` writes and `check` verifies, the
exact canonicalization + hashing so the two are bit-reproducible, and the precise
definition of "drift."

> Reproducibility is non-negotiable. If `pin` and `check` can produce different hashes
> for the same server surface, the gate is worthless. Every algorithm below is fully
> specified so two correct implementations agree byte-for-byte.

---

## 1. File format and location

- **Filename:** `warden.lock` (committed to the consuming repo).
- **Encoding:** UTF-8, JSON, **pretty-printed with 2-space indent** for human/PR review.
  *The pretty-printed file is for humans.* All **hashing** uses the canonical form in §3,
  never the pretty-printed bytes.
- **Trailing newline:** exactly one (`\n`) at end of file.

---

## 2. Top-level schema

```jsonc
{
  "schema_version": 1,                       // integer, this doc = 1
  "warden_version": "0.1.0",                 // semver of the tool that wrote the file
  "server": { ... },                         // §4 server identity
  "tools":     [ { ... } ],                  // §5 per-entry, sorted by name
  "resources": [ { ... } ],                  // §5 per-entry, sorted by uri
  "prompts":   [ { ... } ],                  // §5 per-entry, sorted by name
  "findings":  [ { ... } ],                  // §7 embedded static-check findings
  "overall_digest": "sha256:...",            // §6 digest over the whole surface
  "pin": { ... }                             // §8 pin metadata + optional approver
}
```

Field requiredness: every top-level key is **required**. Empty collections are written as
`[]` (never omitted). `findings` MAY be empty.

---

## 3. Canonicalization + hashing algorithm (THE contract)

This is the part `pin` and `check` MUST implement identically.

### 3.1 Canonical JSON form (`canon()`)

Given any JSON value, produce a deterministic byte string:

1. **Objects:** keys sorted by Unicode code point (lexicographic on UTF-16 code units is
   **not** permitted; sort on Unicode scalar values). No insignificant whitespace.
2. **Arrays:** order preserved **except** where this doc explicitly requires sorting
   (tools by `name`, resources by `uri`, prompts by `name`). Sorting is applied **before**
   canonicalization, by the pinner, so the array order in the file is already canonical.
3. **Strings:** minimal JSON escaping only (`"`, `\`, and control chars U+0000–U+001F via
   `\uXXXX` lowercase hex; all other characters, including non-ASCII, emitted literally as
   UTF-8). No `\/` escaping of solidus.
4. **Numbers:** integers emitted with no decimal point, no leading zeros, no `+`. v0.1
   inputSchemas SHOULD be integer/string-dominant; if a non-integer number appears it is
   emitted via the shortest round-trip decimal (RFC 8785-style). Implementations MUST use
   the JSON Canonicalization Scheme (**JCS, RFC 8785**) number serialization.
5. **Booleans / null:** `true`, `false`, `null`.
6. **No insignificant whitespace** anywhere.

> **Normative reference:** `canon()` is **RFC 8785 (JSON Canonicalization Scheme)**.
> Implementers SHOULD use a vetted JCS library rather than hand-rolling number formatting.

### 3.2 Hash primitive

- Algorithm: **SHA-256**.
- Output encoding in the file: `"sha256:" + lowercase_hex(digest)` (64 hex chars).
- `hash(value) = "sha256:" + hex(SHA256(canon(value)))`.

### 3.3 Field-level hashes

For each tool/resource/prompt entry:

- **`description_hash`** = `hash(description_string_or_empty)`.
  - If `description` is absent/null, hash the **empty string** `""` (so absence is stable
    and distinguishable from a present empty string only if the server distinguishes them
    — we treat null and `""` as identical: both hash `""`).
- **`input_schema_hash`** = `hash(inputSchema_object_or_empty)`.
  - If `inputSchema` is absent/null, hash the empty object `{}`.
  - The **entire** JSON Schema object is hashed via `canon()` — including `type`,
    `properties`, `required`, `enum`, nested schemas, `additionalProperties`, etc.

Hashing the *whole* schema (not a subset) means any schema change at all produces a
different hash. This is intentional: schema is a security-relevant contract.

---

## 4. Server identity

```jsonc
"server": {
  "command": "node",                         // argv[0] of the launch, canonicalized
  "args": ["./server.js", "--flag", "v"],    // remaining argv, order preserved
  "command_digest": "sha256:..."             // hash of {command,args} per §4.1
}
```

### 4.1 Server identity canonicalization

- `command` and `args` are taken **verbatim** from the `<server-cmd...>` passed to
  `pin`/`check`, with one normalization: **no shell expansion is performed by
  mcp-warden** (the args are passed as an argv array to the child process; mcp-warden
  MUST NOT invoke a shell). Environment-variable interpolation is the caller's job before
  invocation.
- `command_digest` = `hash({ "command": command, "args": args })`.
- A change in `command` or `args` is **server-identity drift** (§6, highest severity) —
  it means "you are now pinning a different launch than you approved."

> Note: `command_digest` does **not** hash the *binary contents* of the command. Pinning
> the launch string is MCP-SUPPLY scope; verifying the binary itself is out of scope for
> v0.1 (see `CHECKS.md` `WRD-SUP-*` for the unpinned-ref flag).

---

## 5. Per-entry schema

### 5.1 Tool entry (sorted by `name`)

```jsonc
{
  "name": "read_file",
  "description_hash": "sha256:...",          // §3.3
  "input_schema_hash": "sha256:...",         // §3.3
  "capabilities": ["fs-read"],               // §5.4 derived flags, sorted, deduped
  "entry_digest": "sha256:..."               // §5.3
}
```

The raw `description` and `inputSchema` text are **NOT** stored in the lock — only their
hashes. Rationale: keep the lock small, reviewable, and free of any secret that the static
checks did not catch. (Findings in §7 carry redacted snippets where needed.)

### 5.2 Resource and prompt entries

- **Resource entry** (sorted by `uri`): `{ "uri", "name", "description_hash",
  "mime_type" (or null), "entry_digest" }`. Resources have no `inputSchema`.
- **Prompt entry** (sorted by `name`): `{ "name", "description_hash",
  "arguments_hash", "entry_digest" }`, where `arguments_hash = hash(arguments_array_or_[])`.

### 5.3 Entry digest

`entry_digest = hash(<the entry object WITHOUT its own entry_digest field>)`.

i.e. build the entry with all fields *except* `entry_digest`, run `canon()`, hash it, then
attach `entry_digest`. This makes each entry independently verifiable and makes diffs
localizable to a single tool.

### 5.4 Derived capability flags (`capabilities`)

A small, **deterministic** mapping from the tool definition to coarse capability flags,
used by `CHECKS.md` (`WRD-CAP-*`) and `POLICY_MODEL.md`. Flags are derived from the tool
`name` tokens and `inputSchema` property names/shapes — never from fuzzy description
parsing.

| Flag | Derived when |
|------|--------------|
| `shell-exec` | name token in {`shell`,`exec`,`spawn`,`system`,`subprocess`,`sudo`,`bash`,`sh`,`cmd`,`powershell`} OR a string property named in {`command`,`cmd`,`script`,`shell`} |
| `fs-write` | name token in {`write`,`save`,`create`,`delete`,`rm`,`unlink`,`mkdir`,`chmod`,`mv`,`rename`} with a path-like property, OR a property named in {`path`,`file`,`filename`,`dest`,`target`} alongside a write/content property |
| `fs-read` | name token in {`read`,`cat`,`open`,`load`,`get`,`list`} with a path-like property |
| `http-request` | property named in {`url`,`uri`,`endpoint`,`host`,`hostname`} OR name token in {`fetch`,`http`,`request`,`curl`,`download`,`webhook`} |
| `sql-query` | property named in {`query`,`sql`,`statement`} OR name token in {`sql`,`query`,`execute`,`db`} |

Capability derivation rules are **exactly** these tokens/properties. The full normative
table (including case-folding rules and tokenization) lives in `CHECKS.md` §3 so checks
and lock derivation share one source of truth. Token matching is **case-insensitive** and
operates on `snake_case`/`camelCase`/`kebab-case` segment boundaries.

---

## 6. Overall digest + drift definition

### 6.1 Overall digest

```
overall_digest = hash({
  "schema_version": <int>,
  "server": { "command_digest": <server.command_digest> },
  "tools":     [ <each tool.entry_digest>,     ... sorted ],
  "resources": [ <each resource.entry_digest>, ... sorted ],
  "prompts":   [ <each prompt.entry_digest>,   ... sorted ]
})
```

The overall digest deliberately **excludes** `findings`, `pin`, and `warden_version` so
that re-running an identical tool against an identical surface yields an identical
`overall_digest` regardless of when it ran or who approved it. `--approve` binds to this
digest (see `THREAT_MODEL.md` §2.2).

### 6.2 Drift definition (normative)

`check` re-captures the surface, recomputes everything in §3–§6, and compares to the
stored `warden.lock`. Drift classes and severities:

| Drift class | Condition | Severity | `check` exit |
|-------------|-----------|----------|--------------|
| **Server-identity drift** | `server.command_digest` differs | **critical** | non-zero |
| **Tool added** | a `name` present now, absent in lock | **high** | non-zero |
| **Tool removed** | a `name` present in lock, absent now | **medium** | non-zero |
| **Schema modified** | same `name`, `input_schema_hash` differs | **high** | non-zero |
| **Capability added** | same `name`, a new flag in `capabilities` | **high** | non-zero |
| **Capability removed** | same `name`, a flag dropped from `capabilities` | **medium** | non-zero |
| **Description modified** | same `name`, `description_hash` differs, schema + caps unchanged | **low** | non-zero |
| **Resource/prompt add/remove/modify** | analogous to tools (added=medium, removed=low, modified=low) | as noted | non-zero |
| **No drift** | every entry_digest matches AND `overall_digest` matches | — | **zero** |

Notes:

- **Any** non-empty drift set causes a non-zero exit. Severity drives reporting/SARIF
  level, not the pass/fail decision. (A future `--allow` policy MAY downgrade specific low
  classes; not in v0.1 — v0.1 is strict.)
- "Schema modified" and "Capability added" are **both** high and reported separately even
  if they co-occur (a schema change that introduces a new capability emits two findings).
- Drift is computed **per entry** so the SARIF output points at the exact tool that
  changed. The `overall_digest` is a fast-path: if it matches, there is provably no drift
  and per-entry diffing can be skipped.

---

## 7. Embedded findings

`pin` runs the full static-check catalog (`CHECKS.md`) and embeds the results so the lock
records *what was true at approval time*.

```jsonc
"findings": [
  {
    "rule_id": "WRD-CAP-SHELL",              // matches CHECKS.md
    "severity": "high",                       // critical|high|medium|low
    "target": "tools/run_command",            // entry the finding applies to
    "message": "Tool exposes shell-exec capability",
    "snippet": "command: string (redacted)"   // secrets MUST be redacted, never raw
  }
]
```

- Findings in the lock are **informational at check time** unless they represent *new*
  findings introduced by drift. A *new* finding on a changed entry is reported by `check`;
  pre-existing approved findings are not re-failed (they were accepted at pin).
- **Secret findings MUST store a redacted snippet** (e.g. first 4 + `…` + length), never
  the raw secret. The lock is committed to git; it must never become a secret store.

---

## 8. Pin metadata

```jsonc
"pin": {
  "created_at": "2026-06-06T14:22:05Z",      // RFC 3339, UTC, second precision
  "warden_version": "0.1.0",                  // duplicate of top-level for convenience
  "mcp_protocol_version": "2025-06-18",       // protocolVersion echoed by initialize
  "approved": false,                          // true only when pinned with --approve
  "approver": null,                           // string identity, or null
  "approved_at": null,                        // RFC 3339 UTC, or null
  "approved_digest": null                     // overall_digest the approver attested to
}
```

Rules:

- `created_at` and `mcp_protocol_version` come from the `pin` run; they are **excluded**
  from `overall_digest` (non-deterministic / environmental).
- When `--approve` is used: `approved=true`, `approver` = caller-supplied identity (from
  `--approver <id>` or `WARDEN_APPROVER` env), `approved_at` = now (UTC),
  `approved_digest` = the freshly computed `overall_digest`.
- `check` MAY warn (not fail) if `approved=false` — a CI policy can require
  `approved=true`. Whether that is enforced is a CI configuration choice, not a v0.1
  hard rule.
- `approved_digest` MUST equal `overall_digest` in a freshly pinned-and-approved file;
  if a later edit changes the surface without re-approval, `approved_digest` will
  *disagree* with the recomputed `overall_digest`, which `check` surfaces as an
  **unapproved-change** finding (severity high).

---

## 9. Worked example (illustrative, secrets redacted)

```json
{
  "schema_version": 1,
  "warden_version": "0.1.0",
  "server": {
    "command": "node",
    "args": ["./build/index.js"],
    "command_digest": "sha256:3a7f...e21c"
  },
  "tools": [
    {
      "name": "read_file",
      "description_hash": "sha256:9b12...44aa",
      "input_schema_hash": "sha256:c0de...7788",
      "capabilities": ["fs-read"],
      "entry_digest": "sha256:11ff...0099"
    }
  ],
  "resources": [],
  "prompts": [],
  "findings": [],
  "overall_digest": "sha256:aa00...ff11",
  "pin": {
    "created_at": "2026-06-06T14:22:05Z",
    "warden_version": "0.1.0",
    "mcp_protocol_version": "2025-06-18",
    "approved": true,
    "approver": "ci-bot@example.invalid",
    "approved_at": "2026-06-06T14:22:06Z",
    "approved_digest": "sha256:aa00...ff11"
  }
}
```

---

## 10. Implementer must-not-deviate list

1. `canon()` is **RFC 8785 (JCS)**. SHA-256. `"sha256:"` + lowercase hex. No exceptions.
2. `overall_digest` excludes `findings`, `pin`, and `warden_version`. Including any of
   them breaks reproducibility.
3. The lock stores **hashes, not raw** descriptions/schemas. Secret snippets are
   **redacted**.
4. mcp-warden spawns the server as an **argv array, never via a shell**.
5. Sort: tools by `name`, resources by `uri`, prompts by `name` — *before* hashing.
6. Absent `description`/null → hash `""`; absent `inputSchema`/null → hash `{}`.
7. **Any** drift → non-zero exit. Severity affects reporting only.
