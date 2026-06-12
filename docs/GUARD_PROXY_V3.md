# mcp-warden — Guard Proxy Hardening Contract (v0.3)

**Status:** v0.3 security contract. Implementation-ready. **Extends — does not replace —**
[`GUARD_PROXY.md`](GUARD_PROXY.md) (v0.2 base) and the v0.3 default-posture change folded into
that doc's §5. This doc specifies the proxy-hardening behavior v0.2 deferred: cancellation /
progress passthrough (§1), subprocess-lifecycle edge cases (§2), Windows degradation (§3), and
the full v0.3 block-flag scheme (§4).

> **All v0.2 non-negotiables hold here unchanged:** one catalog / two runners; the fixed
> deterministic/fuzzy tier partition; the single-event-loop, one-complete-frame-per-direction
> frame discipline (`GUARD_PROXY.md` §2.3); **fail-open on framing/inspection error,
> fail-closed on policy verdict** (`GUARD_PROXY.md` §9, `RESULT_INSPECTION.md` §5.3); secret
> redaction in every output and every error `data` field; per-tool inspection precision from
> `warden.lock` §11. This doc adds hardening rules; it relaxes none of the above.

---

## 1. Cancellation + progress notifications — untouched passthrough (normative)

`notifications/cancelled` and `notifications/progress` are **control-plane** frames in MCP:
the client cancels an in-flight request, or the server streams progress for a long-running one.
`guard` MUST treat them as pure pass-through, even mid-`tools/call`.

### 1.1 The guarantee

For both `notifications/cancelled` and `notifications/progress`, in **either** direction:

1. **Never inspected.** They are not `tools/call` requests or responses; the
   `RESULT_INSPECTION.md` catalog and the argument policy MUST NOT run on them.
2. **Never blocked.** No `--block-*` / default-block path can apply — there is no rule whose
   tier or category covers a notification. A block decision MUST be unreachable for these
   methods.
3. **Never buffered.** They are forwarded **immediately** on read, byte-for-byte (original
   bytes, no re-serialization — `GUARD_PROXY.md` §2.4). `guard` MUST NOT hold them pending the
   completion of any other frame's inspection.
4. **Never reordered.** They are emitted in the **same relative order** they were read on their
   direction's stream. `guard` MUST NOT advance or delay them relative to other frames already
   read on that same stream.

This is a **strengthening** of the v0.2 "everything else passes through" rule
(`GUARD_PROXY.md` §2.1): for these two methods specifically, passthrough is mandatory and
**uninterruptible**, and the no-buffer / no-reorder properties are explicit.

### 1.2 Interleaving with an in-flight `tools/call` (the frame-discipline rule)

The v0.2 frame discipline is: **one reader per direction, one complete frame at a time**
(`GUARD_PROXY.md` §2.3). The hazard v0.3 closes is a `tools/call` **result** that is being
**inspected and possibly blocked** on the server→client (`s2c`) direction while a
`notifications/progress` (also `s2c`) or a `notifications/cancelled` (client→server, `c2s`)
arrives for that same call. Normative interleaving rules:

- **Per-direction sequencing is preserved, never cross-coupled.** Each direction's reader
  pulls complete frames in order and forwards each as soon as its own handling completes. A
  progress notification that arrives **after** a result on the same `s2c` stream is forwarded
  **after** that result; one that arrives **before** is forwarded **before**. Order on the wire
  is the order on the stream — `guard` never reorders within a direction.
- **Inspection of a `tools/call` result MUST NOT stall a later control frame indefinitely.**
  Result inspection is **incremental and bounded** (`GUARD_PROXY.md` §2.5, `--max-frame-bytes`);
  it completes (forward, redact, or error-replace) before the reader pulls the next `s2c`
  frame, so a following progress notification is delayed only by the bounded inspection of the
  one frame ahead of it — never blocked on it. There is **no** unbounded wait.
- **A `c2s` cancellation is independent of `s2c` result inspection.** They are different
  directions, read by different direction-tasks. A cancel on `c2s` is forwarded to the server
  immediately, regardless of whether `guard` is mid-inspection of a result on `s2c`. The two
  tasks share the event loop, not a buffer; neither blocks the other.
- **Blocking a result does not consume or suppress its progress/cancel frames.** If `guard`
  error-replaces a `tools/call` result (§7 of the base doc), any `notifications/progress` for
  that request that were already forwarded stay forwarded, and any `notifications/cancelled`
  the client sends still reaches the server. `guard` neutralizes **only** the one result frame
  it matched; it never retroactively touches the related control frames.

### 1.3 Correlation note (no special-casing the id)

`guard` already keeps a bounded `id → method` map (`GUARD_PROXY.md` §4.4). Progress
notifications carry a `progressToken` and cancellations a request `id`; `guard` **does not**
need to correlate these to gate them — they are forwarded unconditionally by method, before any
id lookup. The correlation map is for `tools/call` result inspection only; it is never a
precondition for forwarding a control frame. (If the map has evicted an id, the control frame
still passes — fail-open on correlation, consistent with §4.4.)

### 1.4 Must-not-deviate (§1)

1. `notifications/cancelled` / `notifications/progress` → **never inspected, blocked,
   buffered, or reordered**, in either direction, even mid-`tools/call`.
2. Forwarded **immediately on read**, original bytes, in per-direction stream order.
3. Result inspection on `s2c` is bounded and never stalls a following control frame; a `c2s`
   cancel is independent of any `s2c` inspection.
4. Blocking a result neutralizes **only** that result frame — related control frames are
   untouched.

---

## 2. Subprocess lifecycle — edge cases (normative)

These extend `GUARD_PROXY.md` §2.6 (POSIX process-group + signal-forwarding). Each case below
has exactly one required behavior. The governing principle is the v0.2 **asymmetric-failure
rule**: a framing/transport/resource failure is **fail-open for availability**; a matched
**policy/result verdict** is fail-closed. None of these edge cases is a policy verdict, so each
resolves toward a **clean, well-formed teardown** — never a hang, never an orphan, never a raw
secret.

### 2.1 Server exits / crashes mid-call

The child process exits (zero or non-zero, or dies on a signal) while one or more `tools/call`
(or any other) requests are **in flight** — i.e. present in the `id → method` correlation map
with no response yet seen.

Required behavior:

1. **Synthesize a JSON-RPC error to the client for every pending request id.** For each id in
   the in-flight map, `guard` emits a well-formed error response so the client's pending
   promises resolve rather than hang:

   ```jsonc
   {
     "jsonrpc": "2.0",
     "id": <pending request id>,
     "error": {
       "code": -32002,                 // mcp-warden transport-error (see §2.6)
       "message": "mcp-warden: server exited before responding",
       "data": { "warden": true, "stage": "lifecycle", "reason": "child exited (code=<N>) with <K> request(s) in flight" }
     }
   }
   ```

   These synthetic errors are **transport** errors, not policy blocks; `code = -32002`
   distinguishes them from the `-32001` block code (`GUARD_PROXY.md` §7.4). `data.warden: true`
   keeps them attributable.
2. **Then close the client-facing pipes cleanly and exit with the child's exit code** (or the
   conventional `128 + signum` when the child died on a signal), preserving the v0.2 rule that
   the client sees the real server's exit status (`GUARD_PROXY.md` §2.6). The synthetic errors
   are flushed **before** the pipes close so the client receives them.
3. **No partial/poisoned result is forwarded.** If the child died mid-frame (a partial result
   was being read), that partial frame is discarded per §2.3 (truncated-frame rule); the id
   gets the §2.1 synthetic error, not a half-frame.

### 2.2 Client disconnects / EOF

The client closes its end (EOF on `guard`'s stdin) or the client-facing pipe breaks (`EPIPE`
/ broken pipe on `guard`'s stdout).

Required behavior:

1. **Tear down the child via its process group** — send `SIGTERM` to the child's process group
   (`GUARD_PROXY.md` §2.6 created it with `start_new_session`), allow a short bounded grace
   period (implementation-defined, e.g. a few seconds), then `SIGKILL` the group if it has not
   exited. This guarantees **no orphaned children** and no orphaned grandchildren the server
   may have spawned.
2. **No synthetic responses are owed to a gone client** — there is no client to receive them;
   `guard` simply drains/abandons in-flight state and reaps the child.
3. **Exit cleanly** with the child's exit code if it exited in grace, else a `guard` transport
   exit (`2`, the v0.1 IO-error code). A broken-pipe on `stdout` is a normal teardown, not a
   crash — `guard` MUST NOT emit a traceback to stderr for it.

### 2.3 Truncated / partial frame at EOF

A stream reaches EOF in the **middle** of a frame: a newline-framed line with no terminating
`\n`, or a `Content-Length`-framed body shorter than the declared length.

Required behavior:

1. **Clean error, never a hang.** `guard` MUST NOT block waiting for bytes that will never
   arrive. On EOF with an incomplete frame buffered, the partial bytes are **discarded** and a
   `WRD-RES-FRAME-ERROR` note is logged (`RESULT_INSPECTION.md` §5.3) — this is a framing error,
   so it is **fail-open**: nothing is blocked, the partial is simply dropped.
2. **Direction-appropriate teardown.** A truncated frame at server EOF is handled as §2.1
   (server-side teardown: synthesize errors for genuinely-pending ids, exit with child code). A
   truncated frame at client EOF is handled as §2.2 (client-side teardown). The truncation
   itself never escalates to a policy block.
3. **Deterministic, bounded.** The partial-frame buffer is bounded by `--max-frame-bytes`
   (§2.4); a never-terminating frame cannot grow memory without bound before EOF or the cap
   trips.

### 2.4 Oversized frame beyond `--max-frame-bytes`

A single frame's length (declared `Content-Length`, or accumulated newline-delimited bytes)
exceeds `--max-frame-bytes` (default 8 MiB, `GUARD_PROXY.md` §2.5).

Required behavior — **defined failure, fail-open** (the asymmetric-failure rule):

1. **The over-cap frame is passed through unmodified** with a `WRD-RES-FRAME-ERROR` note. It is
   **not** buffered fully in memory beyond the cap for inspection, and it is **not** blocked —
   availability over inspection, exactly as `GUARD_PROXY.md` §2.5 / §9 require. Inspection is
   skipped for that frame because it could not be bounded-scanned; the note records the coverage
   gap.
2. **The session continues.** An oversized frame is a resource-limit event, not a policy
   verdict, so it never tears down the session and never blocks. This is the single most
   load-bearing fail-open case: a malicious server MUST NOT be able to break a session (or force
   a fail-closed block) merely by emitting a huge frame (`THREAT_MODEL_V2.md` §3.3, T-AVAIL).
3. **Streaming, not full-buffer.** Implementations forward the over-cap frame by streaming its
   bytes through (within the framing mode's length contract) rather than materializing the whole
   frame; the cap bounds the **inspection** buffer, not the forward path.

> **Why fail-open here and fail-closed on policy:** a frame `guard` cannot fully inspect is an
> *inspector limitation*, and the v0.2 contract chose availability when the inspector cannot
> do its job. A frame `guard` **can** inspect and that **matches a policy/result rule** is a
> *verdict*, and verdicts in a default-blocking category are enforced (v0.3 §5). The two are
> never conflated.

> **Residual risk — the padded-frame inspection bypass (`THREAT_MODEL_V2.md` T-CAP-PAD):**
> because over-cap frames are forwarded un-inspected by default, an attacker controlling the
> **size** of a tool result can **pad a malicious frame above `--max-frame-bytes`** to skip
> inspection. This is fail-OPEN by the deliberate availability-over-inspection choice above (a
> server must not break a session with a huge frame). The opt-in **`--strict-frame-cap`** flag
> (#37, §2.4.1) closes this bypass on the **s2c** direction; the default contract is unchanged.

#### 2.4.1 `--strict-frame-cap` — opt-in fail-CLOSED on an over-cap s2c result (#37)

`--strict-frame-cap` (default OFF, **independent of `--strict`**) makes a server→client (**s2c**)
result frame exceeding `--max-frame-bytes` **terminate the session** (exit 3, reusing the §5
strict-abort machinery) instead of passing it through. It closes **T-CAP-PAD** — a malicious
server padding a `tools/call` result past the cap to skip inspection. Normative scope:

1. **s2c ONLY.** Only the server→client pump changes; the client→server (**c2s**) direction and
   the default mode stay byte-for-byte fail-open. A giant *client* frame is out of scope.
2. **Both over-cap shapes are caught:** **Case B** (newline / accumulated bytes — `len(raw)` >
   cap) and **Case A** (declared `Content-Length` > cap — the framing layer never reads the body
   and stamps a distinct `parse_error` so the pump recognizes it despite a small header-only `raw`).
3. **The offending frame is NEVER forwarded.** The pump emits a **sanitized forensic note**
   (`WRD-RES-FRAME-ERROR`, direction `s2c`, **sizes only** — `raw_length` and, for Case A, the
   declared `Content-Length`; never body/secret bytes) then **raises before any send**.
4. **No client hangs.** The abort carries no rpc_id (the over-cap frame is not partial-parsed for
   its id), so the `-32003` is synthesized to **ALL** in-flight ids. Cost: a deep pipeline
   resolves every in-flight call at once — the trade for a clean teardown over a silent bypass.
5. **Differentiated `-32003` (F6).** A frame-cap abort is a *size-cap* termination, so its
   `data.reason` is distinct (`session terminated: frame size cap exceeded at frame-cap-s2c
   (non-retriable)`) vs. the inspection-error `inspection failed at <site> ...`; the structured
   stderr line carries `site: "frame-cap-s2c"`, `exc_type: "FrameCapExceeded"` (sizes/labels only).

Tuning: a legitimately large result is configuration, not an attack — **raise `--max-frame-bytes`**
to admit it (widens the per-frame memory cap for **all** frames).

### 2.5 Ordering of teardown vs. in-flight inspection

If a lifecycle event (§2.1–§2.4) fires while a `tools/call` result is mid-inspection, the
in-flight inspection is **abandoned** (its frame is discarded, not forwarded half-inspected)
and the lifecycle path takes over. A half-inspected result is never emitted: the relevant id
gets the §2.1 synthetic transport error instead. This preserves "no partial/poisoned result is
ever forwarded."

### 2.6 Reserved transport-error code + redaction

- mcp-warden reserves JSON-RPC error code **`-32002`** for **transport/lifecycle** synthetic
  errors (server-exit, truncation-at-EOF teardown), distinct from `-32001` (policy/result
  blocks, `GUARD_PROXY.md` §7.4). Both carry `data.warden: true`. Both are in the
  implementation-defined server-error range `-32000..-32099`.
- Any secret value that would otherwise appear in a lifecycle `data.reason` MUST be redacted
  per the `CHECKS.md` rule (`first4 + "…" + "(len=N)"`). Lifecycle reasons should not normally
  contain secrets, but the redaction guarantee is unconditional.

### 2.7 Must-not-deviate (§2)

1. **Server crash mid-call →** synthesize a `-32002` error for **every** pending id, flush,
   then exit with the child's code (`128 + signum` on signal). No hung client.
2. **Client EOF/disconnect →** tear down the child via its **process group** (TERM → grace →
   KILL); no orphans; broken-pipe is a clean teardown, not a crash.
3. **Truncated/partial frame at EOF →** discard the partial, `WRD-RES-FRAME-ERROR` (fail-open),
   direction-appropriate teardown; **never hang**.
4. **Oversized frame beyond `--max-frame-bytes` →** pass through unmodified +
   `WRD-RES-FRAME-ERROR`, **fail-open**, session continues; never blocked, never full-buffered.
   EXCEPTION (opt-in, §2.4.1): `--strict-frame-cap` fail-CLOSES on an over-cap **s2c** result
   (exit 3, frame not forwarded); **c2s** + default stay fail-open.
5. A half-inspected result is **never** forwarded; the id gets the `-32002` synthetic error.
6. `-32002` = transport/lifecycle; `-32001` = policy/result block. `data.warden: true` on both.
   Secret redaction is unconditional.

---

## 3. Windows — explicitly EXPERIMENTAL (normative degradation)

Windows has **no POSIX process groups** and a **different signal model** (no `SIGTERM`/`SIGHUP`
to a process group; `CTRL_BREAK_EVENT` / `CTRL_C_EVENT` to a console process group, plus job
objects for tree teardown). v0.3 therefore does **not** claim parity. The frame-discipline,
inspection, and default-block contract (§1, §5 of the base doc) are **transport-agnostic and do
hold** on Windows — what degrades is the **subprocess-lifecycle** guarantees of §2.

### 3.1 What holds on Windows

- All **frame handling** (§2.1–§2.5 of the base doc), the **default-block / opt-out posture**
  (base §5), **result inspection**, **argument policy**, and the **cancellation/progress
  passthrough** (§1 here) are platform-independent and apply on Windows.
- **Reserved error codes** (`-32001` block, `-32002` transport) and **secret redaction** apply
  identically.

### 3.2 What degrades on Windows (no parity claim)

- **Child teardown uses a Job Object**, not a POSIX process group. `guard` SHOULD assign the
  child to a job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` so the child tree is reaped
  when `guard` exits. Where a job object cannot be created, tree-reaping is **best-effort** and
  the orphan-free guarantee of §2.2 is **NOT asserted**.
- **Signal forwarding is approximate.** `guard` translates `SIGINT`/`SIGTERM` to
  `CTRL_BREAK_EVENT` / `CTRL_C_EVENT` to the child's console group on a best-effort basis;
  `SIGHUP` has no Windows analogue. Graceful drain-then-kill (§2.2) reduces to a job-object
  terminate after the bounded grace period.

### 3.3 Fail-safe behavior on Windows (normative)

When a lifecycle guarantee cannot be met on Windows, `guard` degrades **toward the same
client-visible safety** as POSIX, accepting only the orphan-freedom relaxation:

1. **Pending-request synthesis still happens.** On child exit (§2.1), `guard` MUST still emit
   the `-32002` synthetic error for every pending id and flush before closing — this is pure
   JSON-RPC and is platform-independent. A Windows client is **never** left hanging on a dead
   server.
2. **Truncated/oversized-frame handling is identical** (§2.3, §2.4) — fail-open, never hang,
   never block. These do not depend on the signal model.
3. **Teardown is best-effort, and a residual child is possible.** If the job object is
   unavailable, a child may briefly survive `guard`'s exit. `guard` MUST log a `low`
   `WRD-RES-WIN-LIFECYCLE` note recording that orphan-freedom was best-effort, so operators
   know the §2.2 guarantee was degraded on this run. `guard` MUST NOT pretend success.
4. **No silent parity claim.** Any `guard --version` / help text that lists platform support
   MUST mark Windows **experimental**. Docs/marketing implying Windows lifecycle parity are a
   defect (consistent with the v0.1/v0.2 credibility discipline).
5. **Refuse-by-default on a non-POSIX platform (v1.0).** Because the §3.2 degradations are a
   *runtime-protection* gap, `guard` does **not** silently start off-POSIX: at startup it emits a
   LOUD, structured stderr warning naming the reduced §3.2 guarantees, then **exits `2`** (the
   standard `cli_guard` config/usage code, distinct from drift `check` `1` and strict/frame-cap `3`)
   UNLESS `--allow-degraded-platform` is passed — with the flag the same warning prints and `guard`
   proceeds with the best-effort lifecycle. The warning redacts server identity to `argv[0]` + a
   redacted arg count; the POSIX path is unaffected (gate inert, flag a no-op).

### 3.4 Must-not-deviate (§3)

1. Frame discipline, default-block posture, inspection, policy, cancel/progress passthrough,
   error codes, and redaction **all hold** on Windows — only §2 lifecycle guarantees degrade.
2. On child exit, the `-32002` pending-id synthesis **still happens** on Windows (never hang).
3. Child teardown is **job-object best-effort**; orphan-freedom is **NOT asserted** when a job
   object is unavailable — and that degradation is logged (`WRD-RES-WIN-LIFECYCLE`), never hidden.
4. **No parity claim.** Windows is EXPERIMENTAL in code, help text, and docs.
5. **No silent start off-POSIX.** `guard` refuses (exit `2`, distinct from drift `1` /
   strict/frame-cap `3`) without `--allow-degraded-platform`; with the flag it proceeds only after
   the loud, redacted §3.3.5 warning.

---

## 4. v0.3 block-flag scheme (the full reference)

This is the authoritative, single source of truth for the v0.3 flag scheme summarized in
`GUARD_PROXY.md` §5. The base doc's §5 tables and this section MUST agree.

### 4.1 Default-on (deterministic tier) — blocks out of the box

| Category | Rule / gate | Armed by | Wire behavior (`GUARD_PROXY.md` §7) |
|----------|-------------|----------|--------------------------------------|
| ANSI / control escapes | `WRD-RES-ANSI` | always (result inspection) | redacted-content (strip in place) |
| Secret echo | `WRD-RES-SECRET-ECHO` | always | error-replacement (redact mode opt-in via `--redact-secret-echo`) |
| Exfil domain | `WRD-RES-EXFIL-DOMAIN` | always | error-replacement |
| `tools/list_changed` drift | the §4.3 gate | **`--lock` supplied** | error-replacement |
| Argument-policy deny | runtime policy | **`--policy` supplied** | error-response |

The fuzzy `WRD-RES-INJECT-PHRASE` is **not** in this table — it is never default-on (§4.3).

### 4.2 Opt-OUT flags (demote a default-on category to shadow)

| Flag | Demotes to shadow | Affirmative alias |
|------|-------------------|-------------------|
| `--no-block-ansi` | `WRD-RES-ANSI` | — |
| `--no-block-secret-echo` | `WRD-RES-SECRET-ECHO` | — |
| `--no-block-exfil-domain` | `WRD-RES-EXFIL-DOMAIN` | `--allow-exfil-domain` |
| `--no-block-list-changed` | `tools/list_changed` gate | — |
| `--no-block-policy` | argument-policy deny | — |
| `--no-block-deterministic` | the **entire** tier + both gates | — |

**Naming scheme (normative).** The canonical opt-out form is **`--no-block-<category>`** for
every category. Exactly **one** affirmative alias exists — **`--allow-exfil-domain`** (== `--no-block-exfil-domain`)
— because operators reason about exfil domains as an allow/deny list and the affirmative reads
naturally there. No other affirmative aliases exist; do not invent `--allow-ansi` etc. "Demote
to shadow" means the category still **detects, logs, and emits SARIF/JSONL**
(`properties.action: "shadowed"`) but forwards the frame unmodified.

### 4.3 Opt-IN flag (fuzzy tier only)

| Flag | Enables blocking for |
|------|----------------------|
| `--block-inject-phrase` | `WRD-RES-INJECT-PHRASE` (MONITOR — **opt-in only; never default in v0.3**) |

No field false-positive data exists for the fuzzy phrase tier yet, so it stays monitor-only.
An opt-out flag for the fuzzy tier is meaningless (it is already non-blocking) and is **rejected
as an unknown flag**.

### 4.4 Global override

| Flag | Effect |
|------|--------|
| `--audit-only` | force every detection to a warning, **disable all blocking/mutation** (highest precedence) |

### 4.5 Deprecated no-ops (v0.2 enable flags)

`--block-ansi`, `--block-secret-echo`, `--block-exfil-domain`, `--block-list-changed`,
`--block-policy`, and `--block-deterministic` are **accepted but inert** in v0.3 (their
categories already block by default). Each emits a one-line stderr deprecation note and does not
change behavior, so v0.2 scripts keep working.

### 4.6 Precedence (normative, restated)

```
--audit-only
   > --no-block-* opt-out (and --allow-exfil-domain) / --no-block-deterministic
      > default-block (deterministic tier) / --block-inject-phrase (fuzzy tier)
```

- `--audit-only` wins over everything: no frame is blocked or mutated for policy reasons (ANSI
  stripping becomes a warning, not a mutation).
- Absent `--audit-only`, a deterministic category blocks **unless** its `--no-block-*` (or
  `--no-block-deterministic`) is present.
- The fuzzy tier blocks **only** with `--block-inject-phrase`, and `--audit-only` still
  overrides it.
- **Contradictory combo resolution:** an opt-out (`--no-block-ansi`) together with the
  deprecated no-op enable (`--block-ansi`) resolves to **shadow** — the opt-out is higher than
  the inert enable, and the deprecation note for the no-op still fires.

### 4.7 Must-not-deviate (§4)

1. **Deterministic tier blocks by default; fuzzy tier never does.** The partition from
   `RESULT_INSPECTION.md` §2 is the boundary and MUST NOT be blurred.
2. **Opt-out canonical form is `--no-block-<category>`;** `--allow-exfil-domain` is the **only**
   affirmative alias. No other affirmative aliases.
3. **Opt-out demotes to shadow, not silence** — detection/logging/SARIF continue.
4. **`--audit-only` is highest precedence** and restores full v0.2-style shadow in one flag.
5. **v0.2 `--block-*` enable flags are inert no-ops** with a deprecation note; old scripts keep
   working.

---

## 5. `--strict` — fail-CLOSED mode (opt-in, default OFF)

> **Availability trade-off (state it plainly):** strict mode chooses **integrity over
> availability**. By default `guard` fails **OPEN** on an internal inspection error (emits a
> `WRD-RES-FRAME-ERROR` note and passes the frame through, §2.7). `--strict` instead **terminates
> the whole session non-zero** the instant an inspection cannot complete, so an un-inspectable
> message never silently passes. The cost is that an internal inspection bug (or a deliberately
> malformed frame that trips a rule) ends the session rather than degrading to pass-through.
> Default stays fail-open to preserve the current contract.
>
> **What `--strict` terminates on (state it plainly):** strict does NOT only fire on malicious
> inputs. It terminates on *any* inspection that cannot complete — that explicitly includes
> **inspection bugs** (a crash inside `inspect_result()` / `evaluate_call()` / `diverges_from_lock()`)
> and **policy configuration errors** (a malformed or self-contradictory argument policy that makes
> the eval raise). A legitimate session can therefore be killed by a guard-internal bug or a bad
> policy file, not just by a hostile server. That false-positive kill is the deliberate
> integrity-over-availability trade-off: when the analyzer cannot vouch for a frame, strict refuses
> to let it pass rather than guessing. Run default (fail-open) if availability outranks integrity.

### 5.1 The TIGHT scope — exactly the inspection layer (3 + 1 sites)

Strict termination fires **only** when the safety analysis of an *inspected* frame could not
complete. The cardinal risk is false-positive terminations of legitimate sessions, so the trigger
set is deliberately minimal:

| Site id | Where | Trigger |
|---|---|---|
| `request-policy` | `tools/call` **request** | `evaluate_call()` / argument-policy eval raised |
| `result-inspect` | `tools/call` **response** | `inspect_result()` raised |
| `list-gate` | gated `tools/list` **response** | `diverges_from_lock()` raised, **OR** the nested `_hash_live_tools()` hash error (which fails open in default mode by returning *no divergence*) re-raises under strict |

Everything else stays **fail-open in ALL modes** (it is NOT an inspection failure):

- framing / parse errors, including **truncated-at-EOF** (a normal session end, §2.3);
- **over-cap** frames beyond `--max-frame-bytes` (a documented resource limit, §2.4) — `--strict`
  does NOT terminate on an over-cap frame; the **separate** opt-in `--strict-frame-cap` flag
  (§2.4.1, #37) owns that behavior for the **s2c** direction (a distinct `frame-cap-s2c` abort
  site, independent of `--strict`). `--strict` alone still forwards an over-cap result un-inspected;
- finding-sink callback errors (a sink bug must never break the session);
- all stream-closure / signal / lifecycle best-effort paths and every normal protocol event.

### 5.2 Wire contract + exit code

On a strict abort, in this exact order:

1. The offending frame is **not forwarded** (inspection runs *before* any client write of that
   frame — the inspection-before-write invariant; so no partial-forward + error double-delivery).
2. A JSON-RPC error is synthesized to every in-flight request id with reserved code **`-32003`**,
   `stage: "strict_abort"`, and `data.warden: true`, so the client never hangs. `-32003` is
   **NON-RETRIABLE** (distinct from `-32001` policy/result block and `-32002` transport).
3. Exactly **one** structured stderr line is emitted (a session-level dedup flag suppresses a
   second near-simultaneous abort): `{"event":"strict_abort","site":...,"tool":...,"exc_type":...,
   "rpc_id":...}`. It is built **only** from the sanitized `{site, tool, exc_type}` — never the
   original exception's `repr()/str()`, result content, or arguments (a rule exception message can
   echo secret-bearing result text; cf. the `_redact_server` lesson). The raise site uses
   `from None` so a traceback cannot print the secret-bearing original.
4. The child is torn down **gracefully** — the existing SIGTERM-plus-grace `teardown_child` path,
   **not** an immediate SIGKILL (the server may be healthy; the failed inspection is guard-internal).
5. `guard` exits with the dedicated code **`3`** (`GUARD_STRICT_EXIT`), distinct from child-natural
   (`0..127`), `128+signum`, `GUARD_FATAL_EXIT` (`2`), and `GUARD_TRANSPORT_EXIT` (`2`) — so an
   operator can tell "terminated by internal inspection error" from "blocked by policy".

### 5.3 Must-not-deviate (§5)

1. **Default is fail-open** — `--strict` is opt-in; the no-strict path is byte-identical to today.
2. **Only the 3 + 1 inspection sites terminate.** Framing/EOF/over-cap/sink/lifecycle/normal stay
   fail-open in every mode.
3. **`-32003` for strict, exit `3`** — never reuse `-32001`/`-32002` or the fatal/transport codes.
4. **Sanitized fields only** on stderr and in the `-32003` frame — no original exception text.
5. **Graceful teardown**, never immediate SIGKILL.

---

## 6. Related documents

- [`GUARD_PROXY.md`](GUARD_PROXY.md) — v0.2 base proxy contract + the v0.3 default-posture
  change (§5) this doc backs with the full flag scheme (§4).
- [`RESULT_INSPECTION.md`](RESULT_INSPECTION.md) — the `WRD-RES-*` catalog + the
  deterministic/fuzzy tier partition this doc's default-on/opt-in split rests on.
- [`THREAT_MODEL_V2.md`](THREAT_MODEL_V2.md) — the v0.3 defends/monitors table + the honest
  availability/UX-risk posture-change callout (§8) for default-blocking.
- [`WARDEN_LOCK_SCHEMA.md`](WARDEN_LOCK_SCHEMA.md) §11 — per-tool inspection precision that
  refines the default-on deterministic tier.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) / [`CHECKS.md`](CHECKS.md) / [`POLICY_MODEL.md`](POLICY_MODEL.md)
  — v0.1 base (redaction rule, reserved-code conventions, runtime argument policy).
