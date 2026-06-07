# mcp-warden — Guard Proxy Contract (v0.3)

**Status:** v0.3 security contract. Implementation-ready. **Extends — does not replace —** the
v0.2 contract below; v0.2 statements hold except where a `v0.3` note overrides them (default
posture in §5; proxy hardening in [`GUARD_PROXY_V3.md`](GUARD_PROXY_V3.md)).
**Commands:** `mcp-warden guard <server-cmd...>` (live proxy) ·
`mcp-warden inspect <trace.jsonl>` (offline analyzer)

> **What this is.** `guard` is a **transparent stdio proxy** that sits between an MCP
> client and an MCP server, running the result-inspection catalog (`RESULT_INSPECTION.md`)
> on `tools/call` responses and the v0.1 argument policy (`POLICY_MODEL.md`) on `tools/call`
> requests. **As of v0.3 the deterministic tier blocks by default** (`WRD-RES-ANSI`,
> `WRD-RES-SECRET-ECHO`, `WRD-RES-EXFIL-DOMAIN`, the `tools/list_changed` drift gate, and
> argument-policy denials — the council established its field false-positive rate is ~0); the
> fuzzy `WRD-RES-INJECT-PHRASE` tier stays **monitor-only / opt-in**. v0.3 also adds the
> proxy-hardening contract (cancellation/progress passthrough + subprocess-lifecycle edge
> cases) in [`GUARD_PROXY_V3.md`](GUARD_PROXY_V3.md). v0.2 shipped shadow-default (nothing
> blocked without `--block-*`). **v0.3 is the first release that actively blocks by default**;
> the availability/UX risk and the opt-out flags that restore observe-first behavior are
> stated honestly in §5 and `THREAT_MODEL_V2.md` §8.
>
> **What this is not.** It is **not** a full agent firewall. It does not understand model
> behavior, does not correlate across calls, and does not defend `T-BEHAVE`
> (`THREAT_MODEL_V2.md`). It is a narrow, honest, frame-disciplined result/argument
> inspector on the stdio wire.

---

## 1. Topology

```
client (agent / host)  <== stdio ==>  mcp-warden guard  <== stdio ==>  server (child)
        ^                                   |                                  ^
        |  guard's stdin/stdout             |  spawned as argv array           |
        |  ARE the client-facing pipe       |  (NEVER via a shell)             |
```

- The client launches **`mcp-warden guard <server-cmd...>`** exactly where it would have
  launched the server. `guard` spawns `<server-cmd...>` as its child (argv array, no shell —
  same rule as `pin`/`check`, `WARDEN_LOCK_SCHEMA.md` §4.1).
- `guard`'s own **stdin** carries client→server frames; its **stdout** carries
  server→client frames. Two directions, one process.
- `guard`'s child's **stderr** is passed through to `guard`'s stderr untouched (§4.5).

---

## 2. The frame-handling discipline (THE safety contract)

The proxy's safety comes from doing **almost nothing**. Everything below is normative.

### 2.1 Pass every frame through untouched EXCEPT the two it inspects

`guard` parses just enough of each JSON-RPC frame to read its `method` (requests) or to
correlate a `result` to its originating request `id` (responses). It then:

| Frame | Action |
|-------|--------|
| `tools/call` **request** | inspect arguments against the runtime argument policy (§6); pass through (shadow) or block (opt-in) |
| `tools/call` **response** (a `result` whose request was a `tools/call`) | inspect result content against `RESULT_INSPECTION.md`; pass through (shadow) or block (opt-in) |
| `tools/list_changed` **notification** | gated against `warden.lock` (§6.3) |
| **everything else** | **passed through byte-for-byte, unmodified** |

"Everything else" explicitly includes `initialize`, `ping`, `resources/*`, `prompts/*`,
`logging/*`, `completion/*`, `sampling/*`, progress notifications, cancellations, and any
method `guard` does not recognize. Unknown methods are **forwarded verbatim** — `guard`
fails open on methods it does not model.

> **v0.3 (normative):** `notifications/cancelled` and `notifications/progress` MUST pass
> through **untouched — never inspected, blocked, buffered, or reordered, even while a
> `tools/call` is in flight.** The exact interleaving rule vs the single-event-loop frame
> discipline (§2.3) — closing the hole where a result-block on an in-flight call could stall a
> racing cancel/progress frame — is in [`GUARD_PROXY_V3.md`](GUARD_PROXY_V3.md) §1.

### 2.2 NEVER rewrite `initialize` or capabilities — start enforcing only at first `tools/call`

- `guard` MUST forward `initialize` (request and response) and the negotiated capabilities
  **completely untouched.** It MUST NOT add, remove, or alter any capability, protocol
  version, server info, or instructions field. Tampering with the handshake can break the
  session or silently change negotiated behavior — out of scope and forbidden.
- `guard` records the negotiated `protocolVersion` (read-only) for logging and for the
  `tools/list_changed` gate, but does not act on it.
- **Enforcement begins only when the first `tools/call` appears.** Before that, `guard` is a
  pure pass-through. This bounds the proxy's blast radius to exactly the two inspected frame
  types.

### 2.3 Single event loop, one complete frame at a time per direction — NOT multi-threaded reads

- `guard` runs a **single async event loop** (the project already depends on `anyio`).
- Each direction (client→server, server→client) is read by **one** reader that yields **one
  complete JSON-RPC frame at a time.** There is **no** multi-threaded read loop, no
  concurrent partial-frame readers on the same stream. Concurrency is via the event loop's
  two direction-tasks, not threads sharing a buffer.
- Rationale: a multi-threaded reader on a byte stream races on frame boundaries and is the
  classic source of frame-interleaving / smuggling bugs. One reader, one framer, one frame.

### 2.4 Support Content-Length AND newline framing

MCP stdio uses newline-delimited JSON (one JSON object per line). Some transports use
LSP-style `Content-Length:` headers. `guard` MUST support **both**:

- **Newline framing:** read until `\n`; the line (minus the newline) is one JSON-RPC frame.
- **Content-Length framing:** read the header block (CRLF-terminated headers ending in a
  blank line), read exactly `Content-Length` bytes as the body.
- The framing mode is **detected from the first bytes of each stream** (a `Content-Length:`
  header prefix ⇒ header framing; otherwise newline framing) and is **fixed per stream** for
  the session. The two directions are framed independently but in practice match.
- `guard` re-emits frames in the **same framing mode** it received them, so the peer sees
  the framing it expects. When a frame is passed through unmodified, the **original bytes**
  are forwarded (no re-serialization) to avoid canonicalization differences; only an
  **inspected-and-modified** frame (a block result, see §7) is re-serialized.

### 2.5 Incremental scan, never full-buffer

- Result inspection runs **incrementally** over the decoded result text as it is read,
  never by buffering an unbounded result fully in memory first. The deterministic rules
  (`WRD-RES-ANSI`, `WRD-RES-EXFIL-DOMAIN`, `WRD-RES-INJECT-PHRASE`) are streamable: codepoint
  scan, host-token scan, and normalized-substring scan all work over a sliding window.
- A configurable **max-frame cap** (`--max-frame-bytes`, default 8 MiB) bounds memory. A
  frame exceeding the cap is **passed through unmodified** with a `WRD-RES-FRAME-ERROR` note
  (fail-open on resource limits — availability over inspection; `RESULT_INSPECTION.md` §5.3).

### 2.6 Subprocess lifecycle — process groups + explicit signal forwarding

- `guard` spawns the child in its **own process group** (`start_new_session` / `setpgid`).
- Signals received by `guard` (`SIGINT`, `SIGTERM`, `SIGHUP`) are **explicitly forwarded**
  to the child's process group, then `guard` drains in-flight frames and exits.
- On child exit, `guard` flushes any buffered output to the client, closes the client-facing
  pipes cleanly, and exits with the **child's exit code** (so the client sees the real
  server's exit status). A `guard`-internal fatal error exits `2` (consistent with v0.1
  `pin`/`check` IO-error code).
- On client EOF (client closed its end), `guard` forwards EOF to the child and shuts down.
- No orphaned children: the process-group + signal-forwarding discipline guarantees the
  child is reaped on every exit path.

> **v0.3 (normative):** edge cases v0.2 left under-specified — server crash mid-call, client
> disconnect/EOF, partial frame at EOF, oversized frame beyond `--max-frame-bytes` — are
> defined in [`GUARD_PROXY_V3.md`](GUARD_PROXY_V3.md) §2 and supersede any ambiguity here.

### 2.7 Windows = experimental

- The process-group / signal-forwarding model above is POSIX. On Windows, `guard` is
  **experimental**: it uses job objects + `CTRL_BREAK_EVENT` best-effort, and the
  contract's lifecycle guarantees are **not** asserted. v0.2 supports POSIX (Linux/macOS) as
  the contract surface; Windows is documented as experimental and untested for the lifecycle
  guarantees.

> **v0.3 (normative):** Windows remains **EXPLICITLY EXPERIMENTAL** — no POSIX process groups,
> different signal model, no parity claim. Precise degradation + fail-safe in
> [`GUARD_PROXY_V3.md`](GUARD_PROXY_V3.md) §3.

---

## 3. `inspect` — the offline analyzer

`mcp-warden inspect <trace.jsonl>` runs the **same** `RESULT_INSPECTION.md` catalog over a
**recorded** session, with no live processes.

- **Input:** a JSONL trace where each line is one recorded JSON-RPC frame, in observed order.
  A minimal record is the raw JSON-RPC object; an enriched record MAY wrap it as
  `{"direction": "c2s"|"s2c", "ts": <rfc3339>, "frame": <json-rpc>}`. `inspect` accepts both
  (bare frame ⇒ direction inferred from `method`/`result`+`id` correlation).
- `inspect` correlates `result` frames to their `tools/call` requests by `id` exactly as
  `guard` does, then runs the identical catalog. **No blocking** (offline; there is nothing
  to block) — `inspect` is always report-only: SARIF + JSONL + exit code.
- `guard` MAY optionally record its observed frames to a trace (`--record <trace.jsonl>`) so
  a live session can be re-analyzed offline with `inspect` and the two MUST agree.
- **Exit code:** `0` if no BLOCK-tier finding; non-zero if any BLOCK-tier
  (`WRD-RES-ANSI`/`-SECRET-ECHO`/`-EXFIL-DOMAIN`) finding is present (so `inspect` is usable
  as a CI assertion over a captured trace), `2` on read/parse error of the trace file
  itself. MONITOR-tier findings alone do **not** fail `inspect` (they are warnings).
  `--audit-only` forces exit `0` regardless of findings.

---

## 4. Per-frame handling detail

### 4.1 `tools/call` request (argument-side enforcement)

When a `tools/call` request crosses client→server, `guard` runs the **v0.1 argument policy**
(`POLICY_MODEL.md`) against the call's `arguments`, using the **same** shape recognition,
constraint vocabulary, and fail-closed defaults defined there — now applied **at runtime to
the live call**, which `POLICY_MODEL.md` §4.3 / `THREAT_MODEL.md` T-RUNTIME-PROXY named as
the deferred v0.2 work.

- The policy file is supplied via `--policy <file>` (optional; absent ⇒ argument policy
  inactive, result inspection still runs).
- The DNS-name limitation from `POLICY_MODEL.md` §2.3 is **lifted only as far as the literal
  host**: `guard` still does **not** resolve DNS (no network from the proxy). IP-literal
  hosts are matched against SSRF ranges; DNS-name hosts emit `POL-HTTP-DNS-UNRESOLVED`
  (note) exactly as design-time. (Resolution-time SSRF remains a v0.3 concern.)
- A policy **deny** follows the same default posture as the deterministic result rules (§5):
  **in v0.3 a deny blocks by default** (when `--policy` is supplied) per §7; `--no-block-policy`
  demotes it to shadow (logs the deny, passes the call through). (v0.2: shadow + opt-in.)

### 4.2 `tools/call` response (result-side enforcement)

When the correlated `result` crosses server→client, `guard` extracts inspectable text
(`RESULT_INSPECTION.md` §1) and runs the full catalog. Per-tool precision uses the pinned
tool's declarations from `warden.lock` (`--lock <file>`; absent ⇒ fail-safe defaults,
`RESULT_INSPECTION.md` §6).

### 4.3 `tools/list` / `tools/list_changed` gate

- `guard` forwards `tools/list` requests/responses untouched (it does **not** re-pin).
- On a `notifications/tools/list_changed`, **and** on the next `tools/list` response that
  follows it, `guard` recomputes the tool surface digest (reusing `pin`'s capture + hashing,
  `WARDEN_LOCK_SCHEMA.md` §3–§6) and compares to `warden.lock`.
  - If it **matches** the lock ⇒ forward normally.
  - If it **diverges** from the lock ⇒ mid-session drift (`MCP-DRIFT` at runtime), a
    **BLOCK-tier** condition. **In v0.3 the divergent `tools/list` response is blocked by
    default** (§7) so the client never sees the rug-pulled surface; `--no-block-list-changed`
    demotes it to shadow (log + forward). `--lock` required; absent ⇒ monitor-only note. (v0.2:
    shadow + opt-in.)
- This closes `T-TOCTOU-CALL` partially: a server that lists a clean surface to `pin` and
  then swaps it mid-session is caught when it announces or returns the changed list.

### 4.4 Request/response correlation

`guard` maintains an in-memory `id → method` map for in-flight requests so it can tell which
`result` frames belong to `tools/call`. The map is bounded (LRU by `--max-inflight`, default
1024) and entries are dropped on response or on the bound. A `result` with no known request
`id` (or a `result` for a non-`tools/call` method) is **passed through uninspected**.

### 4.5 stderr passthrough

The child's stderr is forwarded to `guard`'s stderr **unmodified and uninspected.** stderr
is the server's diagnostic channel, not the JSON-RPC channel; `guard` never parses or blocks
it. (Operators who want stderr scanned can pipe it to `inspect`-adjacent tooling; that is out
of scope here.)

---

## 5. Default posture, block flags, opt-outs, and `--audit-only`

This is the behavioral contract. It mirrors `RESULT_INSPECTION.md` §8 exactly.

> **The v0.2 → v0.3 posture change (read this first).** v0.2 shipped **shadow-default**
> (nothing blocked without `--block-*`). **v0.3 promotes the deterministic tier to
> block-by-default** (council-established field false-positive rate ~0) — the first mcp-warden
> release that **actively alters or drops frames out of the box.** Honest trade (per
> `THREAT_MODEL_V2.md` §8): a default-block can interrupt a session a shadow build would have
> left alone. Mitigation: every category is **individually opt-OUT-able** (§5.2) and
> `--audit-only` (§5.3) restores full shadow in one flag for observe-first operators.

### 5.1 What blocks by default in v0.3 (the deterministic tier)

The following are **enforced by default** — a match neutralizes the frame on the wire per §7
unless an opt-out (§5.2) is set:

| Default-blocking category | Rule / gate | Wire behavior (§7) |
|---------------------------|-------------|--------------------|
| ANSI / control escapes | `WRD-RES-ANSI` | redacted-content (strip in place) |
| Secret echo | `WRD-RES-SECRET-ECHO` | error-replacement (redact mode opt-in) |
| Exfil domain | `WRD-RES-EXFIL-DOMAIN` | error-replacement |
| Mid-session tool-surface drift | `tools/list_changed` gate (§4.3) | error-replacement — **only when `--lock` is supplied** |
| Argument-policy deny | runtime policy (§4.1) | error-response — **only when `--policy` is supplied** |

- The `tools/list_changed` gate and the argument policy are default-on **only when their
  required input is supplied** (`--lock` / `--policy`) — supplying it arms them; once armed
  they block by default. No separate enable flag exists in v0.3.
- The **fuzzy** `WRD-RES-INJECT-PHRASE` (MONITOR tier) is **NOT** default-on (no field
  false-positive data yet); it stays monitor-only/opt-in (§5.2). **Must-not-deviate: the fuzzy
  tier never becomes default-block in v0.3.**

### 5.2 Flags: opt-out (default-on categories) + opt-in (fuzzy tier)

The full v0.3 flag scheme, naming rule, and worked combinations live in
[`GUARD_PROXY_V3.md`](GUARD_PROXY_V3.md) §4. Summary:
- **Opt-OUT → `--no-block-<category>`** demotes that category to shadow (still
  detects/logs/SARIF, forwards unmodified, `properties.action: "shadowed"`):
  `--no-block-{ansi,secret-echo,exfil-domain,list-changed,policy}` and
  `--no-block-deterministic` (whole tier + both gates). `--allow-exfil-domain` is the sole
  affirmative alias (== `--no-block-exfil-domain`).
- **Opt-IN the fuzzy tier → `--block-inject-phrase`** (`WRD-RES-INJECT-PHRASE`; never default).
- **Deprecated no-ops:** v0.2 enable flags (`--block-ansi` … `--block-deterministic`) are
  accepted but inert (categories already block); a one-line stderr note fires.

### 5.3 `--audit-only` + precedence (normative)

**Precedence:** `--audit-only` > per-category `--no-block-*` opt-out (and
`--allow-exfil-domain`) > **default-block (deterministic tier) / `--block-inject-phrase`
(fuzzy tier)**.

`--audit-only` forces every detection to a warning and **disables all blocking/mutation**
regardless of any other flag (ANSI stripping becomes a warning, not a mutation) — the
single-flag way to restore full v0.2-style shadow ("shadow mode, locked on"). Absent it, each
deterministic category blocks unless its `--no-block-*` opt-out (or `--no-block-deterministic`)
is present; the fuzzy tier blocks only with `--block-inject-phrase`. Contradictory-combo
resolution (e.g. opt-out vs deprecated no-op enable) is spelled out in `GUARD_PROXY_V3.md` §4.

---

## 6. Runtime enforcement specifics

### 6.1 Argument policy at runtime

The v0.1 `POLICY_MODEL.md` constraints (fs-write path allow/deny, shell-exec
deny-by-default + metachar denial, http-request SSRF ranges, sql-query leading-keyword)
evaluate against the **live** `tools/call` arguments. Fail-closed defaults are unchanged and
are **normative**: `shell_exec.allow=false`, `http_request.deny_private=true`,
`sql_query.allow_readonly_only=true`, empty `allow_paths` = deny-all. Deny overrides allow.

### 6.2 Result policy at runtime

`RESULT_INSPECTION.md` rules evaluate against the **live** result. Per-tool precision from
`warden.lock` §11 applies; absent ⇒ fail-safe.

### 6.3 `tools/list_changed` divergence

Defined in §4.3. Requires `--lock`; this is the only runtime check that reuses the full
`pin` capture+hash pipeline.

---

## 7. What "block" sends on the wire (THE decision — normative)

When `guard` blocks, the client MUST receive a **well-formed JSON-RPC frame** so its session
does not hang or crash. The behavior depends on **which side** is blocked.

### 7.1 Blocking a `tools/call` **request** (argument-policy deny — default-on in v0.3 when `--policy` supplied)

`guard` does **not** forward the request to the server. It synthesizes a **JSON-RPC error
response** to the client for that request `id`:

```jsonc
{
  "jsonrpc": "2.0",
  "id": <the request id>,
  "error": {
    "code": -32001,                       // mcp-warden reserved app error (see §7.4)
    "message": "mcp-warden: tools/call blocked by argument policy",
    "data": {
      "warden": true,
      "stage": "request",
      "rule": "POL-HTTP-SSRF",            // the deny code from POLICY_MODEL.md §5
      "tool": "call_api",
      "reason": "host 169.254.169.254 is in deny_private range 169.254.0.0/16 (link-local)"
    }
  }
}
```

The server never sees the call. The client sees a normal error response and can proceed.

### 7.2 Blocking a `tools/call` **response** (result inspection) — two sub-modes

A result is already produced by the server; `guard` chooses **how** to neutralize it. The
mode is per-category:

**(a) Redacted-content mode (default for `WRD-RES-ANSI`, and for `WRD-RES-SECRET-ECHO` when
`--redact-secret-echo` is set):** `guard` forwards a **modified `result`** with the offending
content neutralized in place, preserving the result shape so the agent still gets a usable
(sanitized) answer:

- `WRD-RES-ANSI`: the disallowed codepoints are **stripped** from the text block(s); the
  rest of the result is intact.
- `WRD-RES-SECRET-ECHO` (redact mode): the matched secret substring is replaced with its
  redaction `first4 + "…" + "(len=N)"` (the `CHECKS.md` redaction rule), in place.

The modified result carries a marker so the change is auditable:

```jsonc
{
  "jsonrpc": "2.0",
  "id": <id>,
  "result": {
    "content": [ { "type": "text", "text": "<sanitized text>" } ],
    "isError": false,
    "_meta": { "warden": { "modified": true, "rules": ["WRD-RES-ANSI"] } }
  }
}
```

**(b) Error-replacement mode (default for `WRD-RES-EXFIL-DOMAIN`, and for
`WRD-RES-SECRET-ECHO` unless redact mode is chosen):** `guard` **drops** the original result
and sends a **JSON-RPC error response** for that `id` (same error shape as §7.1, with
`"stage": "response"` and the `WRD-RES-*` rule id). The agent gets an error, not the poisoned
content. This is the safe default for exfil URLs and full secret echoes, where partial
redaction could still leak structure.

> **Default mapping (normative):**
> - `WRD-RES-ANSI` → **redacted-content** (strip control chars; the answer is still useful).
> - `WRD-RES-EXFIL-DOMAIN` → **error-replacement** (do not hand the agent any exfil URL).
> - `WRD-RES-SECRET-ECHO` → **error-replacement** by default; **redacted-content** only if
>   `--redact-secret-echo` is explicitly set.
> - `WRD-RES-INJECT-PHRASE` → never blocks by default (MONITOR, opt-in in v0.2 and v0.3). If
>   opted in via `--block-inject-phrase`, it uses **error-replacement**.

### 7.3 Blocking a divergent `tools/list` response (default-on in v0.3 when `--lock` supplied)

`guard` replaces the divergent `tools/list` **result** with an **error response**
(`"stage": "list_changed"`, `"reason": "tool surface diverged from warden.lock"`), so the
client never ingests the rug-pulled tool surface. (It does **not** synthesize a fake clean
list — fabricating a surface would itself be a tampering risk.)

### 7.4 Reserved error codes + redaction guarantee

- **`-32001`** = policy/result block (this section). **`-32002`** = transport/lifecycle
  synthetic error (server-exit / EOF-teardown, `GUARD_PROXY_V3.md` §2.6). Both are in the
  server-error range `-32000..-32099` and carry `data.warden: true`; `data.stage` + `data.rule`
  make blocks unambiguous to clients and log scrapers.
- **Any secret value referenced in an error `data.reason` MUST be redacted** with the
  `CHECKS.md` rule. An error object explaining a `WRD-RES-SECRET-ECHO` block MUST NOT contain
  the raw secret.

### 7.5 Errors are never blocks

A framing/parse/inspection **error** (`WRD-RES-FRAME-ERROR`) is **not** a block: the frame
passes through unmodified and a note is logged (§9). Only a **policy/result-rule match** in a
category that blocks (default-on deterministic tier, or the opted-in fuzzy tier) produces an
on-the-wire block.

---

## 8. Configuration inputs

| Flag | Purpose | Default |
|------|---------|---------|
| `--lock <file>` | enables per-tool precision (§11 of lock schema) + the `tools/list_changed` gate | absent ⇒ fail-safe defaults, list gate = note-only |
| `--policy <file>` | enables runtime argument policy (`POLICY_MODEL.md`) | absent ⇒ argument policy inactive |
| `--exfil-denylist <file>` | org "never-callback" domains, merged with the seed list | seed list only |
| `--inject-phrases <file>` | org exact injection phrases, merged with the seed list | seed list only |
| `--no-block-*` / `--allow-exfil-domain` / `--no-block-deterministic` (§5.2–§5.3, `GUARD_PROXY_V3.md` §4) | opt a default-blocking category (or the whole tier) back to shadow | off (blocks by default) |
| `--block-inject-phrase` (§5.2) | opt-in block for the fuzzy phrase tier | off (monitor-only) |
| `--block-*` (v0.2 enable flags) | **deprecated no-ops** in v0.3; emit a stderr note | accepted, no effect |
| `--audit-only` | force warnings, disable all blocking (highest precedence) | off |
| `--sarif <file>` / `--json <file>` | report sinks | stderr/log only |
| `--record <trace.jsonl>` | record observed frames for later `inspect` | off |
| `--max-frame-bytes <N>` | per-frame memory cap (pass-through over cap) | 8 MiB |
| `--max-inflight <N>` | request-correlation map bound | 1024 |

All denylist/phrase files are **literal entries** (domains / exact phrases), never regex
(`RESULT_INSPECTION.md` §9).

---

## 9. Failure modes — fail-open for availability (normative)

A bug or malformed input in the **proxy framing / inspection layer MUST NOT kill the
session.** On any framing error, parse error, decode error, inspection exception, or
resource-limit hit: the frame is **forwarded unmodified** (pass-through), a
`WRD-RES-FRAME-ERROR` note is logged + emitted, and the session continues.

This is the deliberate asymmetry stated in `RESULT_INSPECTION.md` §5.3: **policy verdicts are
fail-closed; inspector failures are fail-open.** The user's MCP session is never broken by a
warden defect. In v0.3 the only frames altered/dropped are those that (a) matched a rule **and**
(b) are in a blocking category (default-on deterministic tier unless opted out per §5.3; opt-in
fuzzy tier). An oversized frame beyond `--max-frame-bytes` fails **open** (`GUARD_PROXY_V3.md`
§2.4).

---

## 10. SARIF / JSONL output

`guard` and `inspect` emit the **same** SARIF 2.1.0 + JSONL shape as v0.1 (`CHECKS.md` §2):
`ruleId` == the `WRD-RES-*` / `POL-*` id verbatim, `level` per the severity→level mapping.
Each finding records `direction` (`s2c`/`c2s`), the JSON-RPC `id`, the tool name, the
content-block index (result rules), the tier, and `properties.action`
(`blocked|shadowed|modified|passed`). All secret snippets are redacted (`CHECKS.md` rule).

---

## 11. Implementer must-not-deviate list

1. **Pass everything through untouched except `tools/call` request/response (and the
   `tools/list_changed` gate).** Never rewrite `initialize`/capabilities. Enforcement starts
   only at the first `tools/call`.
2. **Single event loop, one complete frame at a time per direction.** No multi-threaded read
   loops sharing a buffer.
3. **Support both Content-Length and newline framing; pass-through forwards original bytes
   (no re-serialization); only modified frames are re-serialized.**
4. **Incremental scan; bounded by `--max-frame-bytes`; over-cap frames pass through.**
5. **Spawn child as argv array, never via a shell** (same as v0.1). Own process group +
   explicit signal forwarding; exit with the child's exit code.
6. **v0.3 default posture (replaces v0.2 shadow-default).** The **deterministic** tier
   (`WRD-RES-ANSI`, `WRD-RES-SECRET-ECHO`, `WRD-RES-EXFIL-DOMAIN`, the `tools/list_changed`
   gate when `--lock` supplied, argument-policy denials when `--policy` supplied) **blocks by
   default**; each is opt-OUT-able via `--no-block-<category>` (alias `--allow-exfil-domain`)
   and `--no-block-deterministic` shadows the whole tier. The **fuzzy** `WRD-RES-INJECT-PHRASE`
   tier **never** default-blocks (opt-in via `--block-inject-phrase`). `--audit-only` overrides
   all. v0.2 `--block-*` enable flags are accepted no-ops. Full scheme: `GUARD_PROXY_V3.md` §4.
7. **"Block" on the wire is a well-formed JSON-RPC frame:** error-response for blocked
   requests; redacted-content **or** error-replacement for blocked results, per the §7.2
   default mapping; error-response for a blocked divergent `tools/list`. Reserved error code
   `-32001`, `data.warden: true`. Never hang the client.
8. **Framing/inspection errors PASS THROUGH (fail-open); they never block or kill the
   session.** Policy verdicts remain fail-closed.
9. **`guard` and `inspect` run the identical `RESULT_INSPECTION.md` catalog** and MUST agree
   on the same bytes.
10. **Secret redaction (`CHECKS.md` rule) applies to every output and every error `data`
    field.** No raw secrets, ever.
11. **Windows is experimental** (lifecycle guarantees POSIX-only); v0.3 states the precise
    degradation + fail-safe in `GUARD_PROXY_V3.md` §3 and does **not** claim parity.
12. **v0.3 proxy hardening (`GUARD_PROXY_V3.md`) is normative:** `notifications/cancelled` /
    `notifications/progress` pass through untouched even mid-`tools/call` (never inspected,
    blocked, buffered, or reordered); lifecycle edge cases (server crash, client EOF, partial
    frame at EOF, oversized frame → **fail-open** per §9) follow §2 of that doc.
