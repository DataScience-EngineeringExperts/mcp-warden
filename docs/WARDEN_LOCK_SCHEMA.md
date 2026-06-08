# mcp-warden — `warden.lock` Schema (v0.1 + v0.2 addendum §11)

**Status:** v0.1 security contract + v0.2 per-tool inspection addendum (§11).
Implementation-ready.
**Purpose:** Define the on-disk baseline that `pin` writes and `check` verifies, the
exact canonicalization + hashing so the two are bit-reproducible, and the precise
definition of "drift." **§11 (v0.2)** adds optional, deterministic per-tool inspection
declarations consumed by `guard`/`inspect` (`RESULT_INSPECTION.md`, `GUARD_PROXY.md`).

> **v0.1 is unchanged.** §1–§10 below are the v0.1 contract verbatim. §11 is a v0.2
> **additive, optional** field block; absence preserves byte-identical v0.1 locks (see
> §11.4 on digest impact).

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
  "input_schema_hash": "sha256:...",         // §3.3 — full-fidelity "did it change" signal
  "capabilities": ["fs-read"],               // §5.4 derived flags, sorted, deduped
  "schema_skeleton": {                        // SCHEMA_VERSION 2 (#15) — structural facts
    "props": {
      "$root": { "type": ["object"], "required": false, "enum": null, "constraints": {"additionalProperties": true} },
      "path":  { "type": ["string"], "required": true,  "enum": null, "constraints": {"additionalProperties": true} }
    }
  },
  "entry_digest": "sha256:..."               // §5.3 — covers schema_skeleton too
}
```

The raw `description` and `inputSchema` text are **NOT** stored in the lock — only their
hashes. Rationale: keep the lock small, reviewable, and free of any secret that the static
checks did not catch. (Findings in §7 carry redacted snippets where needed.)

**`schema_skeleton` (SCHEMA_VERSION 2, #15).** A deterministic, normalized extraction of the
input schema's *security-relevant* structure (one `PropFacts` per dotted property path,
recursing `properties` and array `items`). Keeps `type` (sorted tuple), `required`, `enum`,
and constraints `{maxLength,minLength,minimum,maximum,pattern,format,additionalProperties}`;
**drops** cosmetic keys (`description`,`title`,`examples`,`default`). Absent
`additionalProperties` → `true`; `$ref` is an opaque leaf (never followed); cyclic/over-deep
nodes record `{"_truncated": true}`. Lets `check` classify *what* changed (§6.2). `null` in
v1 locks; a baseline lacking it falls back to blob-level `schema-modified` until re-pinned.

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
| **Capability added** | same `name`, a new flag in `capabilities` | **high** | non-zero |
| **Capability removed** | same `name`, a flag dropped from `capabilities` | **medium** | non-zero |
| **Description modified** | same `name`, `description_hash` differs, schema + caps unchanged | **low** | non-zero |
| **Resource/prompt add/remove/modify** | analogous to tools (added=medium, removed=low, modified=low) | as noted | non-zero |
| **No drift** | every entry_digest matches AND `overall_digest` matches | — | **zero** |

**Schema drift (SCHEMA_VERSION 2, #15).** When `input_schema_hash` differs *and* both the
baseline and current entries carry a `schema_skeleton`, the change is classified
structurally and emitted **per fact** (a single property can yield more than one item).
Each item carries a compact, non-secret `detail` (e.g. `maxLength 64→4096`). "Unconstrained"
= no enum, no pattern, no maxLength, and type string/object (or absent).

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
| `schema-modified` (fallback) | v1 baseline lacks a skeleton, OR an opaque-leaf (`$ref`/truncated) change with no matching rule | **high** |

Migration: `entry_digest` (and `overall_digest`) **changes on ANY schema byte change,
cosmetic included** — `input_schema_hash` is an input, so a cosmetic reword shows
`entry_digest` changed while the skeleton diff reports `schema-cosmetic-modified`. The v1→v2
`entry_digest` formula change (skeleton now hashed in) is a deliberate versioned contract
change: re-pinning a v1 server produces a v2 lock. No signed migration record is written.

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
  "created_at": "2026-06-06T14:22:05Z",  // RFC 3339, UTC, second precision
  "warden_version": "0.1.0",             // duplicate of top-level for convenience
  "mcp_protocol_version": "2025-06-18",  // protocolVersion echoed by initialize
  "approved": false, "approver": null,   // true + identity only when pinned with --approve
  "approved_at": null,                   // RFC 3339 UTC, or null
  "approved_digest": null                // overall_digest the approver attested to
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

### 8.1 Structured provenance (v0.3 addendum, #19)

The `pin` block carries optional structured provenance — **all OUTSIDE `overall_digest`** (it
lives in `pin`, which §6.1 excludes), so adding/changing any of it **cannot** change a server's
digest. All fields are optional with defaults; pre-#19 locks read unchanged (models use
`extra="ignore"`, so future fields are tolerated, not rejected). `PROVENANCE_VERSION = 1` is
in-block, distinct from the digest-bound `schema_version`. New `pin` fields:

- scalars: `provenance_version` (default 1), `rotated_at` (str|null), `rotation_count` (default 0).
- `pinner`: `{tool:"mcp-warden", tool_version:<__version__|"unknown">, actor:str|null, environment:str|null}`.
- `attestations`: the attester **SET** (≤1 today; a list so #16/#23 extend it). Each entry:
  `{actor, role:"approver"|"pinner"|…, method:"manual"|…, created_at, bound_digest, note}`.
- `pinner.actor` / `pinner.environment` are **self-asserted (CRIT-3)** — non-authoritative free
  text, not a trust anchor, not for trust decisions; authenticated identity is #16's job.

**Consistency rule (B2).** The scalar `approved/approver/approved_at/approved_digest` stay the
**canonical** approval record. `--approve` ALSO appends one mirroring
`Attestation(role="approver", method="manual", bound_digest=overall_digest)`; the list is the
forward-compatible superset, the scalars its legacy projection. After a FRESH `pin --approve`
exactly one `role="approver"` attestation exists with `attestations[-1].bound_digest ==
overall_digest`.

**Append-only log (B2 cont.).** `attestations` is an **append-only** audit log — `lock rotate`
APPENDS one entry per rotation and NEVER dedups. So rotating an already-approved lock with
`--approver` appends a SECOND `role="approver"` attestation (intended): the scalar `approved*`
fields remain the single canonical approval, and the **most-recent** `role="approver"`
attestation (`attestations[-1]` after an approver rotation) binds the current `overall_digest`.

**`bound_digest` format (B4).** `bound_digest` equals `overall_digest` **VERBATIM** — i.e.
`sha256:<64 lowercase hex>`, **with** the `sha256:` prefix this repo stores; do NOT strip it on
disk. (For #16: Rekor/in-toto subjects may want the bare hex — strip at signing time only.)

### 8.2 `lock rotate` digest semantics (B3) — and the #16 implication

`warden lock rotate <lock> [--approver ID] [--actor ID] [--note TEXT] [--json]` re-attests
provenance on an existing baseline **without re-capturing the server surface**: it appends one
attestation, stamps `rotated_at`, bumps `rotation_count`, refreshes `pinner`, and (with
`--approver`) re-binds the scalar approval to the lock's *unchanged* `overall_digest`. **It never
recomputes entry digests; `overall_digest` is byte-identical afterward.** Rotate is permitted on
**unapproved** locks (incremental-attestation CI) — NOT gated on approval. It **fails closed
(exit 2, writes nothing)** when the lock is internally inconsistent: it recomputes `overall_digest`
from the lock's OWN stored entries and refuses on mismatch (tampered — re-pin), or when an approved
lock's `approved_digest` no longer binds the surface (stale approval).

> **Implication for #16 (signing).** Rotate mutates the file while leaving `overall_digest`
> unchanged, so **a signature over the whole lock JSON would be invalidated by a later rotate.**
> #16 should sign **`overall_digest` + a canonical attestation subdoc** (not the whole file) —
> the minimum rotate-compatible signing scope.

---

## 9. Worked example (illustrative, secrets redacted)

A full illustrative lock (v0.1 shape) plus a post-`lock rotate` `pin` block lives in
[`WARDEN_LOCK_EXAMPLE.md`](WARDEN_LOCK_EXAMPLE.md) (archived there to keep this core doc under
the 500-line cap). v0.3 `pin` blocks additionally carry the §8.1 provenance fields, all outside
`overall_digest`; pre-#19 locks omit them and read unchanged.

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
8. §8.1 provenance lives in `pin` (excluded from `overall_digest`); `lock rotate` mutates only
   provenance, leaves `overall_digest` **byte-identical**, and fails closed on inconsistency (§8.2).

---

## 11. Per-tool inspection policy (v0.2 addendum)

**Consumed by:** `mcp-warden guard` / `mcp-warden inspect` (`GUARD_PROXY.md`,
`RESULT_INSPECTION.md`; v0.3 default posture in `GUARD_PROXY.md` §5 / `GUARD_PROXY_V3.md` §4).
**Not used by** v0.1 `check` drift logic.

These optional, fully **deterministic** declarations let a pinned tool make the
result-inspection BLOCK-tier checks more precise and cut false positives. **In v0.3 the BLOCK
tier is default-on**, so these per-tool relaxations directly affect what blocks out of the box —
making them, more than ever, security-relevant lock edits that MUST be reviewed (T-LOCK). They are the
*only* way to relax a deterministic result check, and they live in the committed,
reviewed `warden.lock` — never set at runtime (see `THREAT_MODEL_V2.md` §4.3, T-LOCK).

### 11.1 Field block (optional, per tool entry)

A tool entry (§5.1) MAY carry an `inspection` object:

```jsonc
{
  "name": "fetch_url",
  "description_hash": "sha256:...",
  "input_schema_hash": "sha256:...",
  "capabilities": ["http-request"],
  "inspection": {                              // §11 — OPTIONAL
    "expected_output_charset": "text",         // "text" | "binary-ok" | "extended"
    "may_return_urls": true,                   // bool
    "secret_echo_applies": true                // bool
  },
  "entry_digest": "sha256:..."
}
```

### 11.2 Field semantics + fail-safe defaults (when the object or a key is ABSENT)

| Key | Type | Allowed values | Absent default (fail-safe) | Effect |
|-----|------|----------------|----------------------------|--------|
| `expected_output_charset` | string | `"text"`, `"extended"`, `"binary-ok"` | `"text"` | `WRD-RES-ANSI` allowed set. `"text"` = the strict allowlist (`RESULT_INSPECTION.md` §3.1). `"extended"` = also allow C1/`U+2028`/`U+2029` (still **not** ESC/C0). `"binary-ok"` = `WRD-RES-ANSI` is **disabled** for this tool (declare only for tools whose output is legitimately raw bytes). |
| `may_return_urls` | bool | `true` / `false` | `false` | When `false`, `WRD-RES-URL` notes fire for any URL. When `true`, the `WRD-RES-URL` note is suppressed. **`WRD-RES-EXFIL-DOMAIN` always applies regardless** — a tool allowed to return URLs is still not allowed to return a *denylisted exfil* URL. |
| `secret_echo_applies` | bool | `true` / `false` | `true` | When `true`, `WRD-RES-SECRET-ECHO` is BLOCK-tier for this tool. When `false`, it is **demoted to a MONITOR note** for this tool only (e.g. a credential-issuing tool whose job is to return a token to an authorized caller). |

**Fail-safe principle:** absent ⇒ maximum protection. A tool only *weakens* a check by an
explicit, reviewed lock declaration. There is no runtime override path.

### 11.3 Validation (deterministic)

- `expected_output_charset` MUST be one of the three literals; any other value is a
  `pin`-time error (fail closed — the lock is not written). `guard`/`inspect` reading a lock
  with an unknown value treat the tool as `"text"` (fail-safe) and emit a `low`
  `WRD-RES-LOCK-INVALID` note.
- `may_return_urls` / `secret_echo_applies` MUST be JSON booleans; non-bool is a `pin`-time
  error.
- An `inspection` object on a resource or prompt entry is ignored (these are not
  `tools/call` results) and emits a `low` `WRD-RES-LOCK-INVALID` note.

### 11.4 Digest impact (normative — preserves v0.1 reproducibility)

- The `inspection` object **IS** part of the tool entry, therefore it **IS** included in
  that tool's `entry_digest` (§5.3) and consequently in `overall_digest` (§6.1). Changing an
  `inspection` value is therefore **drift** and is caught by `check` like any other entry
  change — a relaxation cannot be slipped in without re-pin/re-approve. This is intentional:
  relaxing a security check must be visible in the gate.
- **Backward compatibility:** a tool entry with **no** `inspection` key hashes **exactly as
  in v0.1** (the key is simply absent from the canonicalized object — `canon()` does not emit
  absent keys). Existing v0.1 locks therefore produce **byte-identical** digests under a
  v0.2 implementation. No re-pin is required to upgrade.
- Drift classification: a changed/added/removed `inspection` value is reported as
  **`Inspection-policy modified`**, severity **medium** (it is a security-relevant
  relaxation/tightening but not a capability or schema change). It contributes to the
  non-zero `check` exit like any drift.

### 11.5 Worked example (illustrative)

A §11 inspection-policy worked example (a secret-echo demotion + a `binary-ok` charset tool) lives in
[`WARDEN_LOCK_EXAMPLE.md`](WARDEN_LOCK_EXAMPLE.md) (archived to keep this core doc under the 500-line cap).

### 11.6 §11 implementer must-not-deviate list

1. `inspection` is **optional**; absent ⇒ fail-safe defaults (§11.2). Absence hashes
   byte-identically to v0.1.
2. `inspection` **is** part of `entry_digest` + `overall_digest`; a change is **drift**
   (medium). Relaxations are never invisible to the gate.
3. `expected_output_charset ∈ {"text","extended","binary-ok"}`; invalid → `pin` fails,
   reader falls back to `"text"` (fail-safe) + `WRD-RES-LOCK-INVALID` note.
4. `may_return_urls: true` suppresses **only** the `WRD-RES-URL` note; it never disables
   `WRD-RES-EXFIL-DOMAIN`.
5. `secret_echo_applies: false` demotes `WRD-RES-SECRET-ECHO` to a **note** for that tool
   only — never globally.
6. No runtime path sets these; they are lock-only, reviewed like any lock change (T-LOCK).
