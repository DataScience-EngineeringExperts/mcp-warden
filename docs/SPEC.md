# MCP Lock Format v1

**A vendor-neutral specification for an on-disk integrity baseline of an MCP server's
declared tool, resource, and prompt surface.**

Status: stable v1. This document defines the on-disk file, its canonicalization and
hashing, the construction of the overall digest, and the normative definition of *drift*
in terms that any tool can implement. The reference implementation of this format is
[`docs/WARDEN_LOCK_SCHEMA.md`](WARDEN_LOCK_SCHEMA.md); where the two ever disagree on a
normative rule, that is a defect — both trace to the same algorithm.

The key words **MUST**, **MUST NOT**, **SHOULD**, **MAY**, and **OPTIONAL** are used as
defined in RFC 2119 / RFC 8174.

---

## 1. Scope and non-goals

This format records the **declared surface** of an MCP server — the names, descriptions,
input schemas, and derived capability flags it advertises over the MCP `initialize` /
`tools/list` / `resources/list` / `prompts/list` handshake — and produces a reproducible
digest over that surface. The purpose is to detect a *change* to that declared surface
between an approved baseline and a later observation ("drift").

**In scope:** the byte-reproducible digest of a declared MCP surface, and the
classification of any difference from a stored baseline.

**Out of scope (non-goals).** This format does **not** describe, attest to, or constrain
runtime behavior. It covers declared-surface integrity only. It is **not** a statement
that a server is safe, correct, or trustworthy at execution time; it does not verify the
*contents* of the launched binary; and it makes no claim about what a tool does when
called. A matching digest means only that the declared surface is byte-identical to the
baseline — nothing more.

---

## 2. File format and location

- **Filename:** an implementation MUST write the lock to a single file named `warden.lock`.
- **Encoding:** the file MUST be UTF-8 JSON. For human and code-review legibility it
  SHOULD be pretty-printed with a 2-space indent. The pretty-printed bytes are **never**
  hashed; all hashing uses the canonical form in §4.
- **Trailing newline:** the file MUST end with exactly one `\n`.

---

## 3. Top-level schema

```jsonc
{
  "schema_version": 1,             // integer; this format = 1
  "warden_version": "x.y.z",       // semver of the tool that wrote the file
  "server": { ... },               // §6 server identity
  "tools":     [ { ... } ],        // §7 per-entry, sorted by name
  "resources": [ { ... } ],        // §7 per-entry, sorted by uri
  "prompts":   [ { ... } ],        // §7 per-entry, sorted by name
  "findings":  [ { ... } ],        // §9 embedded informational findings
  "overall_digest": "sha256:...",  // §8 digest over the whole surface
  "pin": { ... }                   // §10 baseline metadata + optional approval
}
```

- `schema_version` MUST be the integer `1` for this format.
- Every top-level key listed above is **required**.
- Empty collections MUST be written as `[]`, never omitted. `findings` MAY be empty.
- `overall_digest` is computed per §8; `tools`/`resources`/`prompts` are sorted per §7.

---

## 4. Canonicalization

To make `pin` (write baseline) and `check` (verify) agree byte-for-byte, every value that
is hashed MUST first be canonicalized.

- **Canonical form:** an implementation MUST serialize JSON values using the **JSON
  Canonicalization Scheme (JCS), RFC 8785**. This fixes object-key ordering (sort by
  Unicode code point), string escaping, number formatting, and the elimination of all
  insignificant whitespace. Implementers SHOULD use a vetted JCS library rather than
  hand-rolling number formatting.
- **Array ordering:** JCS preserves array order. This format additionally requires the
  three top-level entry arrays to be sorted *before* canonicalization (§7); the sort is
  performed by the writer so that the on-disk array order is already canonical.
- **Absent keys:** a key that is absent from a JSON object MUST NOT be emitted by the
  canonicalizer. Therefore an optional field that is simply not present contributes
  nothing to a digest, and a baseline that omits it is byte-identical to one written
  before the field existed.

---

## 5. Hashing

- **Algorithm:** an implementation MUST use **SHA-256**.
- **Digest encoding:** every digest emitted into the file MUST be the string
  `"sha256:" + lowercase_hex(SHA256(canon(value)))` — the literal prefix `sha256:`
  followed by exactly **64 lowercase hexadecimal characters**.
- **Hash primitive:** `hash(value) = "sha256:" + hex(SHA256(canon(value)))`, where
  `canon` is the §4 canonicalization.

### 5.1 Field-level hashes (absence rules)

For each entry the following field hashes are computed. The absence rules below are
normative and MUST be implemented exactly, so that absence is stable and reproducible:

- **`description_hash`** = `hash(description)`. If `description` is absent or `null`, an
  implementation MUST hash the **empty string** `""`. `null` and `""` are treated as
  identical.
- **`input_schema_hash`** = `hash(inputSchema)`. If `inputSchema` is absent or `null`, an
  implementation MUST hash the **empty object** `{}`. The **entire** input-schema object
  is hashed — `type`, `properties`, `required`, `enum`, nested schemas,
  `additionalProperties`, and so on — so that any schema change at all yields a different
  hash.
- **`arguments_hash`** (prompts) = `hash(arguments)`. If `arguments` is absent or `null`,
  an implementation MUST hash the **empty array** `[]`.

---

## 6. Server identity

```jsonc
"server": {
  "command": "node",                       // argv[0] of the launch
  "args": ["./server.js", "--flag", "v"],  // remaining argv, order preserved
  "command_digest": "sha256:..."           // §6.1
}
```

### 6.1 Server identity canonicalization

- `command` and `args` MUST be taken verbatim from the launch invocation. An
  implementation MUST spawn the server as an **argv array and MUST NOT invoke a shell**;
  no shell expansion or environment-variable interpolation is performed by the
  implementation (that is the caller's responsibility before invocation).
- `command_digest` = `hash({ "command": command, "args": args })`.
- A change in `command` or `args` is **server-identity drift** (the highest-severity drift
  class, §8.2): the baseline is now pinning a different launch than was approved.
- `command_digest` does **not** hash the binary contents of the command; it pins the
  launch invocation only.

---

## 7. Per-entry schema

The raw `description` and `inputSchema` text MUST NOT be stored in the lock — only their
hashes. This keeps the file small, reviewable, and free of any secret material.

### 7.1 Tool entry (array sorted by `name`)

```jsonc
{
  "name": "read_file",
  "description_hash": "sha256:...",   // §5.1
  "input_schema_hash": "sha256:...",  // §5.1
  "capabilities": ["fs-read"],        // §7.4 derived flags, sorted, deduped
  "schema_skeleton": { ... },         // §7.5 structural facts, or null
  "inspection": { ... },              // §11 OPTIONAL per-tool inspection block
  "entry_digest": "sha256:..."        // §7.3
}
```

### 7.2 Resource and prompt entries

- **Resource entry** (array sorted by `uri`):
  `{ "uri", "name", "description_hash", "mime_type" (or null), "entry_digest" }`.
  Resources have no `inputSchema`.
- **Prompt entry** (array sorted by `name`):
  `{ "name", "description_hash", "arguments_hash", "entry_digest" }`, where
  `arguments_hash = hash(arguments)` per §5.1.

### 7.3 Entry digest

`entry_digest = hash(<the entry object WITHOUT its own entry_digest field>)`.

An implementation MUST build the entry with all fields *except* `entry_digest`,
canonicalize it (§4), hash it (§5), then attach `entry_digest`. This makes each entry
independently verifiable and localizes any diff to a single entry.

### 7.4 Derived capability flags (`capabilities`)

`capabilities` is a sorted, de-duplicated list of coarse capability flags derived
**deterministically** from a tool's `name` tokens and `inputSchema` property
names/shapes — never from fuzzy description parsing. The defined flags are:

| Flag | Meaning |
|------|---------|
| `shell-exec` | tool can run a shell/exec/spawn/subprocess command |
| `fs-write` | tool can write/create/delete a filesystem path |
| `fs-read` | tool can read a filesystem path |
| `http-request` | tool can issue an outbound HTTP/network request |
| `sql-query` | tool can run a SQL/database query |

An implementation MUST derive these flags by a fixed, documented mapping over tokenized
names and property names (case-insensitive, on `snake_case` / `camelCase` / `kebab-case`
segment boundaries). The exact token and property sets are part of the implementation's
published derivation table; two conformant implementations sharing that table MUST agree.

### 7.5 Structural schema skeleton (`schema_skeleton`)

A tool entry MAY carry a `schema_skeleton`: a deterministic, normalized extraction of the
input schema's *security-relevant* structure — one record per dotted property path,
recursing `properties` and array `items`. Each record keeps `type` (as a sorted tuple),
`required`, `enum`, and constraints (`maxLength`, `minLength`, `minimum`, `maximum`,
`pattern`, `format`, `additionalProperties`); it **drops** cosmetic keys
(`description`, `title`, `examples`, `default`). When `additionalProperties` is absent it
is treated as `true`; a `$ref` is an opaque leaf and MUST NOT be followed; cyclic or
over-deep nodes are recorded as `{"_truncated": true}`. The skeleton lets `check`
classify *what* changed (§8.2). It MAY be `null`; a baseline lacking it falls back to a
blob-level schema-modified classification until re-pinned.

---

## 8. Overall digest and drift

### 8.1 Overall digest

```
overall_digest = hash({
  "schema_version": <int>,
  "server": { "command_digest": <server.command_digest> },
  "tools":     [ <each tool.entry_digest>,     ... sorted ],
  "resources": [ <each resource.entry_digest>, ... sorted ],
  "prompts":   [ <each prompt.entry_digest>,   ... sorted ]
})
```

An implementation MUST compute `overall_digest` over exactly the fields above and MUST
**exclude** `findings`, `pin`, and `warden_version`. Excluding these makes the digest
depend only on the declared surface, so re-running an identical tool against an identical
surface yields an identical `overall_digest` regardless of when it ran or who approved it.

### 8.2 Drift definition (normative)

To verify, an implementation re-captures the surface, recomputes everything in §4–§8, and
compares to the stored lock. Any non-empty set of differences is **drift**, and a verifier
MUST exit non-zero when drift is present. Severity drives reporting only — it never
changes the pass/fail decision.

| Drift class | Condition | Severity |
|-------------|-----------|----------|
| Server-identity drift | `server.command_digest` differs | **critical** |
| Tool added | a `name` present now, absent in baseline | **high** |
| Tool removed | a `name` present in baseline, absent now | **medium** |
| Capability added | same `name`, a new flag in `capabilities` | **high** |
| Capability removed | same `name`, a flag dropped from `capabilities` | **medium** |
| Description modified | same `name`, `description_hash` differs, schema + caps unchanged | **low** |
| Resource/prompt added | analogous to tools | **medium** |
| Resource/prompt removed | analogous to tools | **low** |
| Resource/prompt modified | analogous to tools | **low** |
| Inspection-policy modified | a tool's §11 `inspection` value changed/added/removed | **medium** |
| No drift | every `entry_digest` matches **and** `overall_digest` matches | — |

When `overall_digest` matches the baseline there is provably no drift, and per-entry
diffing MAY be skipped; otherwise an implementation diffs per entry so that a report can
point at the exact entry that changed.

### 8.3 Structural schema drift (when skeletons are present)

When `input_schema_hash` differs **and** both the baseline and current entries carry a
`schema_skeleton`, an implementation classifies the change structurally and emits one item
per changed structural fact (a single property MAY yield more than one item), each with a
compact, non-secret detail. When either side lacks a skeleton, or the change is in an
opaque leaf (`$ref` / truncated), the implementation falls back to a single
`schema-modified` (high). "Unconstrained" means: no enum, no pattern, no maxLength, and
type string/object (or absent).

| `drift_class` | Change | Severity |
|---------------|--------|----------|
| `schema-required-removed` | a required property removed | **high** |
| `schema-property-removed` | an optional property removed | **medium** |
| `schema-required-unconstrained-added` | new required, unconstrained property | **high** |
| `schema-required-added` | new required, constrained property | **medium** |
| `schema-unconstrained-added` | new optional, unconstrained property | **high** |
| `schema-property-added` | new optional, constrained property | **low** |
| `schema-type-broadened` | type set widened (superset) | **high** |
| `schema-type-narrowed` | type set narrowed (subset) | **low** |
| `schema-type-changed` | type set disjoint / otherwise changed | **medium** |
| `schema-enum-widened` | enum widened (superset / new members) | **high** |
| `schema-enum-narrowed` | enum narrowed (subset) | **low** |
| `schema-enum-removed` | enum constraint lost entirely | **high** |
| `schema-enum-added` | enum constraint newly added | **low** |
| `schema-constraint-relaxed` | required→optional, maxLen↑/min↓/max↑, pattern/format removed | **medium** |
| `schema-additional-props-opened` | `additionalProperties` false→true | **high** |
| `schema-constraint-tightened` | any tightening (bounds, pattern/format added) | **low** |
| `schema-cosmetic-modified` | `input_schema_hash` differs but skeleton is identical | **low** |
| `schema-modified` (fallback) | no skeleton, or an opaque-leaf change with no matching rule | **high** |

Because `input_schema_hash` is an input to `entry_digest`, **any** schema byte change —
cosmetic included — changes `entry_digest` and therefore `overall_digest`; the structural
classifier only describes *how* it changed.

---

## 9. Embedded findings

The baseline writer MAY embed informational findings recording what was true at approval
time:

```jsonc
"findings": [
  {
    "rule_id": "...",            // stable identifier for the check that fired
    "severity": "high",          // critical|high|medium|low
    "target": "tools/run_command",
    "message": "Tool exposes shell-exec capability",
    "snippet": "command: string (redacted)"
  }
]
```

- Findings are **informational at verification time** unless a *new* finding is introduced
  by drift on a changed entry; pre-existing approved findings MUST NOT be re-failed.
- Any finding carrying potentially secret material MUST store a **redacted** snippet
  (e.g. first few characters + an elision + a length), never the raw value. The lock is
  committed to source control and MUST NOT become a secret store. `findings` are excluded
  from `overall_digest` (§8.1).

---

## 10. Baseline metadata (`pin`)

```jsonc
"pin": {
  "created_at": "2026-06-06T14:22:05Z",  // RFC 3339, UTC
  "warden_version": "x.y.z",
  "mcp_protocol_version": "2025-06-18",  // protocolVersion echoed by initialize
  "approved": false, "approver": null,
  "approved_at": null,
  "approved_digest": null                // overall_digest the approver attested to
}
```

- All of `pin` is **excluded from `overall_digest`** (§8.1). Adding or changing any field
  inside `pin` MUST NOT change a server's digest.
- When a baseline is approved: `approved` is `true`, `approver` is the caller-supplied
  identity, `approved_at` is the approval time (UTC), and `approved_digest` is the
  freshly computed `overall_digest`.
- `approved_digest` MUST equal `overall_digest` in a freshly approved file. If a later
  surface change is not re-approved, `approved_digest` will disagree with the recomputed
  `overall_digest`; a verifier surfaces this as an unapproved-change finding (high).
- A verifier MAY warn rather than fail when `approved` is `false`; whether approval is
  *required* is a consuming-pipeline configuration choice, not a format rule.

An implementation MAY carry additional metadata (e.g. structured provenance, attestation
records) inside `pin`. Because all of `pin` is excluded from `overall_digest`, such
extensions MUST NOT affect the digest, and an implementation MUST tolerate (ignore)
unknown `pin` fields written by another implementation.

---

## 11. Per-tool inspection block (OPTIONAL)

A tool entry (§7.1) MAY carry an `inspection` object declaring deterministic, reviewed
relaxations of optional result-inspection checks for that one tool:

```jsonc
"inspection": {
  "expected_output_charset": "text",   // "text" | "extended" | "binary-ok"
  "may_return_urls": false,            // bool
  "secret_echo_applies": true          // bool
}
```

| Key | Type | Allowed values | Default when absent |
|-----|------|----------------|----------------------|
| `expected_output_charset` | string | `"text"`, `"extended"`, `"binary-ok"` | `"text"` |
| `may_return_urls` | bool | `true` / `false` | `false` |
| `secret_echo_applies` | bool | `true` / `false` | `true` |

- **Fail-safe principle:** an absent object or key means **maximum protection**; a tool
  only *weakens* a check by an explicit, reviewed declaration. There MUST be no runtime
  override path — these are lock-only, reviewed like any other lock change.
- `expected_output_charset` MUST be one of the three literals; any other value MUST be a
  write-time error. A reader encountering an unknown value MUST fall back to `"text"`.
- An `inspection` object is meaningful only on tool entries; on a resource or prompt entry
  it MUST be ignored.
- **Digest impact:** the `inspection` object **is** part of the tool entry, so it is
  included in that tool's `entry_digest` (§7.3) and in `overall_digest` (§8.1). Changing
  any `inspection` value is therefore **drift** (Inspection-policy modified, medium); a
  relaxation cannot be slipped in without re-pinning. A tool entry with **no**
  `inspection` key hashes exactly as if the key never existed (per §4 absent-key rule).

---

## 12. Conformance

An implementation is **conformant** with MCP Lock Format v1 if and only if:

1. It writes and reads a `warden.lock` matching the top-level schema (§3), with
   `schema_version` `1`.
2. It canonicalizes per RFC 8785 JCS (§4) and hashes per §5, emitting every digest as
   `sha256:` followed by 64 lowercase hex characters.
3. Given the **same declared surface**, it produces a **byte-identical** `overall_digest`
   to any other conformant implementation — this is the core reproducibility requirement.
   Two conformant implementations that capture the same surface MUST agree on
   `overall_digest`, every `entry_digest`, and every field hash.
4. It excludes `findings`, `pin`, and `warden_version` from `overall_digest` (§8.1).
5. It classifies any difference from a stored baseline as drift per §8.2 and exits
   non-zero on any non-empty drift set.
6. It honors the field-absence rules (§5.1), the no-shell launch rule (§6.1), and the
   fail-safe defaults of the optional inspection block (§11).

Conformance is about reproducing the digest over a declared surface. It is **not** any
form of certification, and it makes no claim about runtime behavior or safety.

---

## 13. Minimal worked example

A minimal lock for a single-tool server (digests abbreviated for readability; a real lock
carries full 64-hex digests):

```json
{
  "schema_version": 1,
  "warden_version": "0.3.0",
  "server": {
    "command": "node",
    "args": ["./server.js"],
    "command_digest": "sha256:3f1a...c0de"
  },
  "tools": [
    {
      "name": "read_file",
      "description_hash": "sha256:b2e4...77aa",
      "input_schema_hash": "sha256:9c11...01ff",
      "capabilities": ["fs-read"],
      "schema_skeleton": {
        "props": {
          "$root": { "type": ["object"], "required": false, "enum": null, "constraints": {"additionalProperties": false} },
          "path":  { "type": ["string"], "required": true,  "enum": null, "constraints": {"additionalProperties": true} }
        }
      },
      "entry_digest": "sha256:7d80...4e2b"
    }
  ],
  "resources": [],
  "prompts": [],
  "findings": [],
  "overall_digest": "sha256:a91c...f300",
  "pin": {
    "created_at": "2026-06-06T14:22:05Z",
    "warden_version": "0.3.0",
    "mcp_protocol_version": "2025-06-18",
    "approved": true,
    "approver": "ci-bot",
    "approved_at": "2026-06-06T14:22:05Z",
    "approved_digest": "sha256:a91c...f300"
  }
}
```

To reproduce `overall_digest` here, a verifier hashes
`{"schema_version":1,"server":{"command_digest":"sha256:3f1a...c0de"},"tools":["sha256:7d80...4e2b"],"resources":[],"prompts":[]}`
under §4 canonicalization and §5 hashing. If that value equals the stored
`overall_digest`, there is no drift; otherwise the verifier diffs per entry (§8.2) and
exits non-zero.
