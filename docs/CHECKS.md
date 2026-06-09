# mcp-warden — Static Check Catalog (v0.1)

**Status:** v0.1 security contract. Implementation-ready.
**Principle:** Every check is **deterministic, explainable, and low-false-positive.**
Fuzzy/NLP "injection-y language" scanning is **CUT** (see §6). Each check has a stable
ID, exact match rules, a severity, a rationale, and a SARIF `ruleId` + `level` mapping.

> Checks run at **both** `pin` (embedded into `warden.lock.findings`) and `check`
> (emitted to SARIF + JSONL). Determinism is required: the same definition input always
> yields the same findings.

---

## 1. Inputs each check operates on

Checks read only the **declared surface** captured over stdio:

- Tool `name`, `description`, `inputSchema` (full JSON Schema).
- Resource `uri`, `name`, `description`, `mimeType`.
- Prompt `name`, `description`, `arguments`.
- The **launch command** (`command` + `args`) for supply-chain checks.

No tool results, no network, no runtime. (See `THREAT_MODEL.md` T-RESULT/T-BEHAVE.)

---

## 2. Severity + SARIF level mapping

| Severity | SARIF `level` | `check` effect |
|----------|---------------|----------------|
| critical | `error` | finding emitted; **does not by itself fail `check`** — `check` fails on **drift** (per `WARDEN_LOCK_SCHEMA.md` §6.2). Static findings inform `pin`/`--approve` decisions. |
| high | `error` | as above |
| medium | `warning` | as above |
| low | `note` | as above |

> **Important distinction:** `check`'s pass/fail is governed by **drift** vs the lock, not
> by static findings. Static checks gate the *human approval* (`pin`/`--approve`) and
> populate SARIF for visibility. A server with high-severity findings can still be a clean
> `check` if a human already approved those findings at pin time. *New* findings on a
> *drifted* entry are reported by `check`.

All findings carry: `rule_id`, `severity`, `target` (e.g. `tools/<name>` or
`launch/command`), `message`, and a **redacted** `snippet`.

### 2.1 Drift rule IDs (`WRD-DRIFT-*`) + the schema-diff family (#15)

Drift items are emitted as SARIF/JSONL results with `ruleId = WRD-DRIFT-<CLASS>` (the
`drift_class` upper-cased). The structural schema-diff classes (`WARDEN_LOCK_SCHEMA.md`
§6.2) surface under this same generic scheme — the `WRD-DRIFT-SCHEMA-*` family:

| `ruleId` | Severity | Meaning |
|----------|----------|---------|
| `WRD-DRIFT-SCHEMA-REQUIRED-REMOVED` | error (high) | required property removed |
| `WRD-DRIFT-SCHEMA-PROPERTY-REMOVED` | warning (medium) | optional property removed |
| `WRD-DRIFT-SCHEMA-REQUIRED-UNCONSTRAINED-ADDED` | error (high) | new required unconstrained param |
| `WRD-DRIFT-SCHEMA-REQUIRED-ADDED` | warning (medium) | new required constrained param |
| `WRD-DRIFT-SCHEMA-UNCONSTRAINED-ADDED` | error (high) | new optional unconstrained param |
| `WRD-DRIFT-SCHEMA-PROPERTY-ADDED` | note (low) | new optional constrained param |
| `WRD-DRIFT-SCHEMA-TYPE-BROADENED` | error (high) | type set widened |
| `WRD-DRIFT-SCHEMA-TYPE-NARROWED` | note (low) | type set narrowed |
| `WRD-DRIFT-SCHEMA-TYPE-CHANGED` | warning (medium) | type set disjoint/changed |
| `WRD-DRIFT-SCHEMA-ENUM-WIDENED` | error (high) | enum widened |
| `WRD-DRIFT-SCHEMA-ENUM-NARROWED` | note (low) | enum narrowed |
| `WRD-DRIFT-SCHEMA-ENUM-REMOVED` | error (high) | enum constraint lost |
| `WRD-DRIFT-SCHEMA-ENUM-ADDED` | note (low) | enum constraint added |
| `WRD-DRIFT-SCHEMA-CONSTRAINT-RELAXED` | warning (medium) | required→optional / bound relaxed / pattern removed |
| `WRD-DRIFT-SCHEMA-ADDITIONAL-PROPS-OPENED` | error (high) | `additionalProperties` false→true |
| `WRD-DRIFT-SCHEMA-CONSTRAINT-TIGHTENED` | note (low) | constraint tightened |
| `WRD-DRIFT-SCHEMA-COSMETIC-MODIFIED` | note (low) | schema bytes differ, structure identical |
| `WRD-DRIFT-SCHEMA-MODIFIED` | error (high) | v1-lock fallback / **unresolvable** opaque-leaf `$ref` change |
| `WRD-DRIFT-SCHEMA-VERSION-MIGRATED` | note (low) | lock schema-format upgrade (v2→v3) moved the digest; advisory only (#29) |

Schema-drift results additionally carry `properties.detail` (a compact, non-secret summary,
e.g. `maxLength 64→4096`) and `properties.schemaPath` (the changed entry, `tools/<name>`).
Items are emitted **per fact** — one property can produce several results.

### 2.2 In-document `$ref` resolution (#29, schema v3)

As of schema **v3**, `extract_skeleton` FOLLOWS an in-document `$ref` into its target
subschema so a constraint relaxation hidden behind a shared definition classifies
GRANULARLY (e.g. `WRD-DRIFT-SCHEMA-CONSTRAINT-RELAXED`) instead of collapsing to the coarse
`WRD-DRIFT-SCHEMA-MODIFIED`. Semantics (binding, never under-report):

- **Resolved** only when `$ref` is the **sole** key of the node (a sibling key such as
  `description` keeps the node opaque), the ref is a **same-document** pointer
  (`#/$defs/...`, `#/definitions/...`, any same-document RFC 6901 JSON pointer), and it
  resolves to a **dict** subschema. The pointer is percent-decoded BEFORE the RFC 6901
  `~1`→`/`, `~0`→`~` unescape; numeric segments index arrays with no list/dict coercion.
- **Stays OPAQUE** (`WRD-DRIFT-SCHEMA-MODIFIED`, high) for: remote refs (`https://…#/…`),
  the bare `#`, an unresolvable pointer, a non-dict target, a non-string ref, a `$ref` with
  sibling keys, or per-path budget exhaustion (`MAX_REFS = 256`).
- **Cyclic** / mutually-recursive refs terminate at the re-entrant position with the
  `_truncated` leaf (also `WRD-DRIFT-SCHEMA-MODIFIED`, high). Extraction is bounded, pure,
  deterministic, and never raises or infinite-loops; a diamond DAG (two refs to one shared
  definition) yields a byte-identical, order-independent skeleton.

### 2.3 v2 → v3 migration note (re-pin required)

Following `$ref` changes the skeleton of any ref-using tool, which changes its `entry_digest`
and the `overall_digest` (which embeds `schema_version`). After upgrading mcp-warden, an
**approved** v2 lock for a ref-using server will report an `unapproved-change` (high) on the
next `check`, accompanied by an additive `schema-version-migrated` (low) advisory explaining
that the digest moved due to the schema-format upgrade (no surface change is implied by the
advisory alone). The advisory NEVER replaces, gates, or downgrades the `unapproved-change`
finding — `overall_digest` guards holistic integrity, so auto-downgrading across the version
boundary would be a laundering bypass. **Action:** review the diff, then **re-pin**
(`mcp-warden pin --approve`) to re-attest the surface under schema v3. Locks for servers that
use no `$ref` keep an identical skeleton; only their `schema_version`/digest changes on re-pin.
When a pre-#29 v2 baseline is diffed under v3, any tool whose schema used `$ref` (and thus held
an opaque leaf in the v2 skeleton) falls back to a coarse `WRD-DRIFT-SCHEMA-MODIFIED` (high) at
the ref-bearing path — granularity-loss by design, never an under-report; re-pin to regain
granular classification.

**Default gate threshold (R9).** `check` exits non-zero on *any* drift (no severity floor
is applied by the CLI today). The intended downstream policy is **medium and above blocks;
low/info does not** — e.g. `schema-cosmetic-modified` and `schema-constraint-tightened`
(both low) inform reviewers but should not, on their own, fail a gate. Surfacing a cosmetic
description reword as a low finding (previously zero signal) is intentional and resolves the
#13 schema/description coupling. This issue changes only *what is emitted*, not the CLI
exit-code logic.

---

## 3. Normative tokenization + capability derivation (shared source of truth)

`WARDEN_LOCK_SCHEMA.md` §5.4 and the `WRD-CAP-*` checks below share this tokenizer.

- **Case-insensitive.** Lowercase everything before matching.
- **Segment splitting:** split identifiers on `snake_case` (`_`), `kebab-case` (`-`),
  `camelCase` boundaries, and dot (`.`). `runShellCommand` → `[run, shell, command]`;
  `fs.write_file` → `[fs, write, file]`.
- A **token match** = an exact segment equals a listed keyword (no substring matching —
  `shelter` must not match `shell`).
- A **property match** = an `inputSchema.properties` key (after the same segment split &
  lowercase) contains a listed keyword as a segment.

Capability flag tokens/properties (the exact lists from `WARDEN_LOCK_SCHEMA.md` §5.4):

| Flag | name tokens | property names |
|------|-------------|----------------|
| `shell-exec` | shell, exec, spawn, system, subprocess, sudo, bash, sh, cmd, powershell | command, cmd, script, shell |
| `fs-write` | write, save, create, delete, rm, unlink, mkdir, chmod, mv, rename | (path-like) path, file, filename, dest, target — *with* a content/write signal |
| `fs-read` | read, cat, open, load, get, list | path, file, filename, src, source |
| `http-request` | fetch, http, request, curl, download, webhook | url, uri, endpoint, host, hostname |
| `sql-query` | sql, query, execute, db | query, sql, statement |

---

## 4. Check catalog

### 4.1 Capability-surface checks (MCP-CAPSURF) — `WRD-CAP-*`

| ID | Matches | Severity | Rationale | SARIF ruleId / level |
|----|---------|----------|-----------|----------------------|
| **WRD-CAP-SHELL** | tool derives `shell-exec` capability (§3) | **critical** | Arbitrary command execution is the highest-impact MCP capability; always warrants explicit human approval | `WRD-CAP-SHELL` / `error` |
| **WRD-CAP-FS-WRITE** | tool derives `fs-write` | **high** | Filesystem mutation can tamper with the host, configs, or other tools' inputs | `WRD-CAP-FS-WRITE` / `error` |
| **WRD-CAP-FS-READ** | tool derives `fs-read` | **medium** | Arbitrary read enables data/secret exfiltration paths; lower than write | `WRD-CAP-FS-READ` / `warning` |
| **WRD-CAP-HTTP** | tool derives `http-request` | **high** | Outbound network = primary exfiltration channel; pairs with policy SSRF constraints | `WRD-CAP-HTTP` / `error` |
| **WRD-CAP-SQL** | tool derives `sql-query` | **high** | Raw query surface enables injection / data exfiltration / destructive statements | `WRD-CAP-SQL` / `error` |

`target` = `tools/<name>`. `message` names the derived capability and the matching token/
property. `snippet` = the matched property line or name token (no secret content).

### 4.2 Secret-leakage checks (MCP-SECRET) — `WRD-SEC-*`

Scanned fields: tool/resource/prompt `name`, `description`, every `inputSchema` string
`default`, every `enum` string value, every `examples` string, resource `uri`. **Not**
property *keys* (a property literally named `api_key` is not a leak; a *value* that looks
like one is).

| ID | Pattern (regex, case-sensitive unless noted) | Severity | Rationale | SARIF ruleId / level |
|----|----------------------------------------------|----------|-----------|----------------------|
| **WRD-SEC-OPENAI** | `\bsk-[A-Za-z0-9]{20,}\b` | **critical** | OpenAI-style API key prefix | `WRD-SEC-OPENAI` / `error` |
| **WRD-SEC-GITHUB** | `\bghp_[A-Za-z0-9]{36}\b` (also `gho_`, `ghu_`, `ghs_`, `ghr_`) | **critical** | GitHub personal/OAuth/app tokens | `WRD-SEC-GITHUB` / `error` |
| **WRD-SEC-AWS-AKID** | `\bAKIA[0-9A-Z]{16}\b` | **critical** | AWS access key ID | `WRD-SEC-AWS-AKID` / `error` |
| **WRD-SEC-SLACK** | `\bxox[baprs]-[A-Za-z0-9-]{10,}\b` | **critical** | Slack token | `WRD-SEC-SLACK` / `error` |
| **WRD-SEC-PRIVKEY** | `-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----` | **critical** | Embedded private key material | `WRD-SEC-PRIVKEY` / `error` |
| **WRD-SEC-JWT** | `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b` | **high** | Bearer JWT — often a live session/identity token | `WRD-SEC-JWT` / `error` |
| **WRD-SEC-ENTROPY** | a token (`[A-Za-z0-9+/_=-]{20,}`, alnum-dominant) with **Shannon entropy ≥ 4.0 bits/char** AND length ≥ 24 | **high** | High-entropy heuristic for unknown-format secrets | `WRD-SEC-ENTROPY` / `error` |

Entropy rule (normative):

- Tokenize the field on whitespace and on characters outside `[A-Za-z0-9+/_=.-]`.
- For each candidate token of length ≥ 24, compute **Shannon entropy** over its character
  distribution: `H = -Σ p_i log2 p_i`.
- Flag if `H ≥ 4.0` **and** the token is alnum-dominant (≥ 80% chars in `[A-Za-z0-9]`).
- **De-dup against the explicit patterns above** — if a token already matched a
  `WRD-SEC-<vendor>` rule, do not *also* emit `WRD-SEC-ENTROPY` for it.
- Threshold `4.0` is the v0.1 constant. It is chosen to avoid flagging hex hashes of
  normal English (≈ 3.5–3.9) while catching random base64/hex secrets (≈ 4.5–6.0).

`message` names the rule and field; `snippet` is **redacted**: emit `first4 + "…" +
"(len=" + N + ")"`. Never the raw match. (The lock and SARIF are committed/shared.)

### 4.3 Supply-chain checks (MCP-SUPPLY) — `WRD-SUP-*`

Operate on the **launch command** (`server.command` + `server.args`), tokenized as argv.

| ID | Matches | Severity | Rationale | SARIF ruleId / level |
|----|---------|----------|-----------|----------------------|
| **WRD-SUP-NPX-UNPINNED** | argv contains `npx` and the package spec target has **no** `@<version>` / no `@sha256:`/digest (e.g. `npx some-server` or `npx -y some-server`) | **high** | `npx pkg` resolves the latest registry version at run — silent upstream code swap | `WRD-SUP-NPX-UNPINNED` / `error` |
| **WRD-SUP-UVX-UNPINNED** | argv contains `uvx` and the package spec has no `==<version>` / no pinned ref | **high** | Same risk for the Python/uv ecosystem | `WRD-SUP-UVX-UNPINNED` / `error` |
| **WRD-SUP-PIP-UNPINNED** | argv contains `pip`/`pip3` + `install` and any target lacks `==<version>` (or `@<git-sha>`/`--require-hashes`) | **high** | Unpinned install = mutable dependency at launch | `WRD-SUP-PIP-UNPINNED` / `error` |
| **WRD-SUP-LATEST-TAG** | a version spec explicitly equals `latest` (`pkg@latest`, `pkg==latest`) | **high** | Explicit floating tag — same risk, made obvious | `WRD-SUP-LATEST-TAG` / `error` |
| **WRD-SUP-CURL-PIPE** | argv reconstructs a `curl ... | sh` / `wget ... | sh` shape, OR command is a remote-fetch piped to an interpreter | **critical** | Remote-fetch-execute at launch is uncontrolled code execution | `WRD-SUP-CURL-PIPE` / `error` |

Pinned-ref recognition (what counts as **pinned**, so it does NOT flag):

- npm: `pkg@1.2.3`, `pkg@1.2.3-rc.1`, or a registry digest.
- uv/pip: `pkg==1.2.3`, `pkg @ git+https://...@<full-40-char-sha>`, or `--require-hashes`
  present anywhere in argv.
- A local path (`./server.js`, `/abs/path`, `file:...`) is **not** a supply-chain ref and
  is **not** flagged.

`target` = `launch/command`. `snippet` = the offending argv token (no secrets present in
launch args is assumed; if a `WRD-SEC-*` pattern also matches a launch arg, emit that too).

---

## 5. Check execution rules

1. **Order is irrelevant to output** — findings are emitted sorted by `(target, rule_id)`
   for deterministic SARIF/JSONL.
2. **One finding per (rule_id, target, match-location).** Duplicate matches at the same
   location collapse to one.
3. **Redaction is mandatory** for all `WRD-SEC-*` snippets, everywhere they appear (lock,
   SARIF, JSONL, stdout).
4. Checks **never** mutate the captured definitions and **never** make network calls.
5. A malformed/unparseable `inputSchema` produces a single `WRD-CAP-*` N/A note and is
   reported as a `low` `WRD-SCHEMA-MALFORMED` finding (schema can't be analyzed) rather
   than crashing.

---

## 6. CUT — explicitly not built (and why)

Per the adversarial council (unanimous). These are **defects if added** in v0.1:

| Cut item | Why |
|----------|-----|
| **Fuzzy / NLP scanning of descriptions for "injection-y" phrasing** (e.g. flagging "ignore previous instructions", "you are now…", "disregard") | Weak signal, high false-positive. Trains operators to ignore warnings. Not deterministic. **CUT — do not implement.** |
| **Semantic/meaning diffing of descriptions** | Hashes catch byte changes; meaning analysis is non-deterministic and unreliable. See `THREAT_MODEL.md` T-SEMANTIC. |
| **Tool-RESULT content scanning** | Out of v0.1 scope; the headline v0.2 gap (T-RESULT). Checks operate on *definitions* only. |
| **Behavioral / sandbox execution of tools** | Definition ≠ behavior (T-BEHAVE). We do not run tools. |
| **Allowlist of "known good" servers / reputation scoring** | Out of scope; TOFU + `--approve` is the v0.1 trust mechanism. |

---

## 7. Full check ID list (the catalog at a glance)

Capability (MCP-CAPSURF):
`WRD-CAP-SHELL` · `WRD-CAP-FS-WRITE` · `WRD-CAP-FS-READ` · `WRD-CAP-HTTP` · `WRD-CAP-SQL`

Secret leakage (MCP-SECRET):
`WRD-SEC-OPENAI` · `WRD-SEC-GITHUB` · `WRD-SEC-AWS-AKID` · `WRD-SEC-SLACK` ·
`WRD-SEC-PRIVKEY` · `WRD-SEC-JWT` · `WRD-SEC-ENTROPY`

Supply chain (MCP-SUPPLY):
`WRD-SUP-NPX-UNPINNED` · `WRD-SUP-UVX-UNPINNED` · `WRD-SUP-PIP-UNPINNED` ·
`WRD-SUP-LATEST-TAG` · `WRD-SUP-CURL-PIPE`

Robustness:
`WRD-SCHEMA-MALFORMED`

---

## 8. Implementer must-not-deviate list

1. **No fuzzy/NLP description scanning.** Deterministic checks only.
2. Secret snippets are **always redacted** (`first4 + "…" + "(len=N)"`).
3. Entropy threshold = **4.0 bits/char**, candidate length ≥ 24, alnum-dominant ≥ 80%,
   de-duped against vendor patterns.
4. Token matching is **segment-exact**, case-insensitive, never substring.
5. `check` pass/fail is driven by **drift** (`WARDEN_LOCK_SCHEMA.md` §6.2), not by static
   findings. Static findings populate SARIF + gate `--approve`.
6. SARIF `ruleId` == the check ID verbatim; `level` per §2.
7. Local paths in launch args are never flagged as supply-chain refs.

> **`warden diff` (v0.3) is an offline VIEWER, not a gate.** `check` is the gate
> (re-captures a live server, fails on drift). `diff <lock-a> <lock-b>` instead
> compares two EXISTING locks offline by reusing the same drift engine
> (`compute_drift`) — it adds no diff logic. It is **redaction-safe**: it renders
> only `DriftItem`s (server-identity drift is the hardcoded "launch changed"
> message; schema `detail` is pre-redacted) plus an explicit allowlist of safe
> provenance fields, and NEVER prints raw `server.command`/`args`. Default exit 0;
> `--exit-code` returns 1 on **integrity** drift only (provenance differences are
> informational and never trip it).
