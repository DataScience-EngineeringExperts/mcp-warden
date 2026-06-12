# mcp-warden — Result Inspection Catalog (v0.2, posture updated in v0.3)

**Status:** v0.2 security contract, catalog unchanged in v0.3. Implementation-ready.
**Principle:** Every rule is **deterministic and explainable** OR **explicitly fuzzy and
monitor-only.** There is no third category. Each rule is partitioned into exactly one of
two tiers and that tier governs whether it MAY ever block.

> **v0.3 posture change (the catalog itself is unchanged).** The tier partition, the rules,
> their match definitions, and their severities are **identical** to v0.2. What changed in
> v0.3 is the **default**: the **BLOCK (deterministic) tier now blocks by default**
> (`GUARD_PROXY.md` §5, `GUARD_PROXY_V3.md` §4), where v0.2 shipped shadow-default. The
> **MONITOR (fuzzy) tier — `WRD-RES-INJECT-PHRASE` — stays monitor-only / opt-in** (no field
> false-positive data exists for it yet). Every "deferred to v0.3" note below now resolves to:
> *deterministic = default-block; fuzzy = still opt-in, NOT default-block.*

> **Single catalog, two runners.** The rules below are defined **once** and applied by
> **both** entrypoints identically:
> - `mcp-warden guard <server-cmd...>` — the live stdio proxy (`GUARD_PROXY.md`).
> - `mcp-warden inspect <trace.jsonl>` — the offline analyzer over a recorded session.
>
> `guard` and `inspect` MUST share one implementation of this catalog (one module, one
> code path). A rule that fires in `inspect` MUST fire identically in `guard` on the same
> bytes, and vice-versa. Divergence between the two is a defect.

> **Reuse, do not redefine.** Secret-echo detection reuses the `WRD-SEC-*` patterns and
> the redaction rule from `CHECKS.md` verbatim. The fail-closed / deny-overrides-allow
> posture is inherited from `POLICY_MODEL.md`. This doc adds **only** result-content rules.

---

## 1. What this catalog inspects

These rules operate on **tool-RESULT content** — the value returned by the server in a
`tools/call` **response**, never on definitions and never on request arguments (request
arguments are handled by the runtime argument policy, `GUARD_PROXY.md` §6).

### 1.1 Extracting inspectable text from a result

A `tools/call` result is the JSON-RPC `result` object. Per MCP, its `content` is an array
of content blocks. The inspector extracts text deterministically:

| Content block `type` | Inspected as |
|----------------------|--------------|
| `text` | the `text` string (inspected in full) |
| `resource` with embedded `text` | the embedded `text` string |
| `resource` with a `uri` field | the `uri` string (URL/exfil rules apply) |
| `image`, `audio`, `blob`, base64 `data` | **NOT** decoded or inspected in v0.2 (see §7) |
| any other / unknown block | the block's JSON-serialized form is **NOT** inspected; a `WRD-RES-UNINSPECTABLE` note is emitted (monitor-only, never blocks) |

Also inspected: the result-level `isError` boolean is **read** (it changes severity
context for some rules — see §3.2) but is never itself a finding.

Text from multiple blocks is inspected **per block** (findings carry the block index), not
concatenated, so a finding points at the exact block. Scanning is **incremental** over the
streamed/decoded text — never requires fully buffering an unbounded result (see
`GUARD_PROXY.md` §5 on incremental scan).

---

## 2. The deterministic / fuzzy partition (THE core decision)

This partition is normative and MUST NOT be blurred. A rule lives in exactly one tier.

| Tier | Property | May block? |
|------|----------|------------|
| **BLOCK (deterministic)** | ~0 false positives. The match is a byte/codepoint fact or a known-pattern fact, not an inference about intent. | **Yes — blocks by DEFAULT in v0.3** (council-established field FP ~0); opt-OUT per category via `--no-block-*` (`GUARD_PROXY.md` §5). v0.2 was shadow-default. |
| **MONITOR (fuzzy)** | Inherently high false-positive. The match is an inference ("this *looks like* an instruction"). | **Never blocks by default**, in v0.2 **or** v0.3. Opt-in block only (`--block-inject-phrase`); default-block is **NOT** adopted in v0.3 (no field FP data yet). |

> **Why the partition exists.** The v0.1 council CUT broad fuzzy "injection-y language"
> scanning because it trains operators to ignore warnings (`CHECKS.md` §6,
> `THREAT_MODEL.md` §6). v0.2 does **not** reopen that decision. It adds runtime result
> inspection where the deterministic tier is the only thing allowed to block, and the one
> fuzzy rule it ships is a **narrow curated exact-phrase denylist**, monitor-only, never
> broad regex.

---

## 3. BLOCK tier (deterministic) — rules

### 3.1 `WRD-RES-ANSI` — control / terminal escape sequences

**Threat:** A tool result containing ANSI/terminal escape sequences can rewrite a
terminal-rendering client's display, hide text, spoof prompts, or trigger
terminal-emulator features. (`T-RESULT` vector: control-escape injection.)

**Match definition (exact, deterministic).** The inspected text is scanned codepoint by
codepoint. A finding fires if **any** codepoint falls **outside the allowed set** below.

**Allowed character set (the allowlist — everything else is a violation):**

| Allowed | Codepoints |
|---------|------------|
| Common whitespace | `U+0009` TAB, `U+000A` LF, `U+000D` CR |
| Printable ASCII | `U+0020`–`U+007E` |
| Printable Unicode | `U+00A0` and above **except** the disallowed ranges below |

**Disallowed (any occurrence = violation):**

| Disallowed class | Codepoints | Why |
|------------------|------------|-----|
| C0 controls (except the 3 allowed whitespace) | `U+0000`–`U+0008`, `U+000B`, `U+000C`, `U+000E`–`U+001F` | Includes `U+001B` ESC (start of all ANSI/CSI/OSC sequences) and `U+0007` BEL |
| DEL | `U+007F` | Control |
| C1 controls | `U+0080`–`U+009F` | Includes the 8-bit CSI `U+009B`; some terminals honor C1 directly |
| Unicode line/para separators | `U+2028`, `U+2029` | Treated as control for terminal-injection purposes |

> `U+001B` ESC is the load-bearing one: every CSI (`ESC [`), OSC (`ESC ]`), and DCS
> sequence begins with it. Because ESC is in the disallowed C0 set, the inspector does
> **not** need an ANSI-grammar parser — **presence of any disallowed codepoint is the
> match.** This keeps the rule deterministic and parser-free.

- **Per-tool override:** if the pinned tool declares `expected_output_charset: "binary-ok"`
  or a wider charset (`WARDEN_LOCK_SCHEMA.md` §11), the allowed set is widened accordingly.
  Default when absent is **fail-safe = the strict allowlist above** (see §6).
- **Tier:** BLOCK-deterministic. **Severity:** `high`.
- **On block (the only deterministic content-mutation case):** the offending codepoints are
  **stripped** (removed) rather than the whole result being replaced, when the proxy is in
  redact-on-block mode; otherwise the result is replaced with an error object. The exact
  wire behavior is defined once in `GUARD_PROXY.md` §7 — this doc does not redefine it.
- **SARIF:** `ruleId: WRD-RES-ANSI`, `level: error`.

### 3.2 `WRD-RES-SECRET-ECHO` — a known secret pattern echoed in a result

**Threat:** A tool result echoes a value matching a known secret pattern. A result that
returns a credential is a credential exposure **regardless of intent** — it may be feeding
the secret into agent context, a downstream log, or an exfil path. (`T-RESULT` vector:
secret echo.)

**Match definition (exact, deterministic).** Apply the **`WRD-SEC-*` patterns from
`CHECKS.md` §4.2 verbatim** — `WRD-SEC-OPENAI`, `WRD-SEC-GITHUB`, `WRD-SEC-AWS-AKID`,
`WRD-SEC-SLACK`, `WRD-SEC-PRIVKEY`, `WRD-SEC-JWT`, and the `WRD-SEC-ENTROPY` heuristic
(threshold 4.0 bits/char, length ≥ 24, alnum-dominant ≥ 80%, de-duped against vendor
patterns) — to the **result text** instead of the definition text.

- **One source of truth.** The pattern set, the entropy constants, and the vendor/entropy
  de-dup rule are **imported from `CHECKS.md`**, not re-stated here. If `CHECKS.md` adds a
  `WRD-SEC-*` pattern, this rule inherits it automatically.
- **Per-tool override:** if the pinned tool declares `secret_echo_applies: false`
  (`WARDEN_LOCK_SCHEMA.md` §11) — e.g. a tool whose *job* is to return a token to an
  authorized caller — this rule is **demoted to MONITOR (note)** for that tool only. Default
  when absent is **fail-safe = applies, BLOCK tier** (see §6).
- **Tier:** BLOCK-deterministic (unless demoted per-tool). **Severity:** mirrors the
  underlying `WRD-SEC-*` severity (`critical` for OPENAI/GITHUB/AWS-AKID/SLACK/PRIVKEY;
  `high` for JWT/ENTROPY).
- **Redaction is mandatory.** The matched secret is **never** emitted raw. The snippet uses
  the existing rule from `CHECKS.md` §4.2 / §8.2 verbatim: `first4 + "…" + "(len=" + N +
  ")"`. This applies in SARIF, JSONL, stdout, and any error object sent on the wire.
- **SARIF:** `ruleId: WRD-RES-SECRET-ECHO` (the underlying `WRD-SEC-*` id is carried in the
  finding's `message`/`properties`, not as the SARIF `ruleId`, so the result-echo class is
  countable distinctly), `level: error`.

### 3.3 `WRD-RES-EXFIL-DOMAIN` — a configured exfil/callback domain in a result

**Threat:** A tool result contains a URL pointing at a known data-exfiltration or
out-of-band callback service. An agent that follows or relays such a URL leaks data.
(`T-RESULT` vector: exfil URL.)

**Match definition (exact, deterministic — NOT "looks like a URL").** The inspected text
is scanned for **host literals** belonging to the **exfil denylist**. Matching is on the
**registrable domain (eTLD+1) and its subdomains**, host-anchored, case-insensitive:

1. Extract candidate hosts deterministically: a host is the authority component of a
   substring matching `scheme://host[:port]/...` for `scheme ∈ {http, https, ftp, ws,
   wss}`, **and** any bare `host` token that exactly equals or is a subdomain of a denylist
   entry. (No heuristic "this might be a URL" — only `scheme://` authorities and exact
   host/subdomain token matches.)
2. A host **matches** the denylist if it equals a denylist domain `D` or ends with `"." +
   D` (subdomain match). e.g. denylist `ngrok.io` matches `ngrok.io` and
   `abc123.ngrok.io`, but **not** `myngrok.io` (no leading-dot boundary).

**Seed exfil denylist (v0.2 ships these; org-extensible — see below):**

| Domain | Class |
|--------|-------|
| `ngrok.io`, `ngrok-free.app`, `ngrok.app` | tunnel / callback |
| `pastebin.com`, `paste.ee`, `dpaste.com`, `hastebin.com`, `ghostbin.com` | paste / dump |
| `transfer.sh`, `file.io`, `0x0.st`, `temp.sh`, `oshi.at` | anonymous file drop |
| `requestbin.com`, `requestbin.net`, `pipedream.net`, `webhook.site`, `beeceptor.com`, `hookbin.com` | request-capture / callback |
| `burpcollaborator.net`, `oast.fun`, `oast.live`, `oast.pro`, `oast.site`, `interact.sh`, `canarytokens.com` | OOB interaction / canary |
| `serveo.net`, `localhost.run`, `localtunnel.me`, `loca.lt` | tunnel |
| `discord.com/api/webhooks`, `discordapp.com/api/webhooks` | webhook callback (path-qualified — see note) |

> Path-qualified entries (`discord.com/api/webhooks`) match only when the
> `scheme://host/path...` prefix matches host **and** the path begins with the listed path.
> Bare-host matching does not apply to path-qualified entries (so normal `discord.com`
> links are not flagged).

- **Org configuration:** operators add **"never-callback" domains** via the proxy config
  (`GUARD_PROXY.md` §8, `--exfil-denylist <file>`), merged with the seed list. The merged
  list is deterministic; entries are exact domains, never regex.
- **Per-tool override:** if the pinned tool declares `may_return_urls: true`
  (`WARDEN_LOCK_SCHEMA.md` §11), exfil-domain matching still applies (a tool being *allowed*
  to return URLs does not make it allowed to return a **denylisted exfil** URL); the override
  affects only the broader monitor-only URL note (`WRD-RES-URL`, §4.2). Default when absent:
  `may_return_urls: false` (fail-safe — see §6).
- **Tier:** BLOCK-deterministic. **Severity:** `high`.
- **SARIF:** `ruleId: WRD-RES-EXFIL-DOMAIN`, `level: error`.

### 3.4 `WRD-RES-EXFIL-IP-LITERAL` — a private/loopback/metadata IP literal in a result

**Threat:** A tool result names a raw IP literal pointing at an internal, loopback, or cloud
metadata address (e.g. `http://10.0.0.5/collect`, `https://169.254.169.254/…`). This is the
evasion where an exfil/callback destination is given as a **raw IP** instead of a denylisted
**hostname**, so `WRD-RES-EXFIL-DOMAIN` (host-string match) does not see it. (`T-RESULT`
vector: exfil/SSRF IP.)

**Match definition (exact, deterministic — NO DNS).** IP literals are extracted
deterministically from three sources and parsed by `ipaddress`:

1. `scheme://host[:port]/…` authorities (IPv4 + bracketed/scoped IPv6);
2. bare dotted IPv4 tokens (`10.0.0.5`);
3. bare and bracketed IPv6 tokens (`::1`, `[::1]`, `fc00::1`, `fe80::1`) — which the dotted
   bare-host scan does not catch.

Each candidate is handed to `ipaddress.ip_address`; non-IP candidates are dropped (no
hand-rolled IP validity). A parsed IP **matches** if it falls in any `SSRF_NETWORKS` deny
range (the same `POLICY_MODEL.md` §2.3 table the argument policy uses): the
loopback / RFC1918 / link-local / IPv6 loopback-ULA-link-local ranges. The cloud-metadata IP
`169.254.169.254` is covered by `169.254.0.0/16` (link-local) — no special case. **Public,
routable IPs do not match** (no false positive on a legitimate result that cites a public
address). The match is **pure** (no network, no resolution) and the finding lists the matched
IP(s) and range label(s) **plainly** (IPs are not secrets).

- **No DNS, ever.** This rule matches **raw IP literals only**. A hostname that *resolves* to
  a private IP is **not** caught here — DNS-name resolution of result-borne hosts remains out
  of scope (see §7), tracked as a residual (issue #11 PR-2).
- **Tier:** BLOCK-deterministic. **Severity:** `high`.
- **SARIF:** `ruleId: WRD-RES-EXFIL-IP-LITERAL`, `level: error`.

---

## 4. MONITOR tier (fuzzy) — rules

> **These NEVER block by default — in v0.2 or v0.3.** They log + emit findings only. v0.3
> **deliberately does NOT** promote the fuzzy tier to default-block: no field false-positive
> data exists for it yet, so default-blocking it would risk the alert-fatigue / availability
> problem the partition exists to avoid. They MAY be promoted to blocking only via the explicit
> opt-in flag `--block-inject-phrase` (`GUARD_PROXY.md` §5, `GUARD_PROXY_V3.md` §4.3).
> `--audit-only` forces them (and everything) to warnings.

### 4.1 `WRD-RES-INJECT-PHRASE` — curated exact-phrase prompt-injection denylist

**Threat:** A tool result contains text crafted to be interpreted by the agent as an
instruction ("ignore previous instructions", "you are now…"). This is the canonical
prompt-injection-via-result attack. (`T-RESULT` vector: injection string.)

**Match definition (narrow, exact-phrase — broad regex is FORBIDDEN).** Matching is a
**case-insensitive, whitespace-normalized, exact substring** match against a **small
curated phrase denylist.** Normalization before matching:

- Lowercase (Unicode simple case fold).
- Collapse any run of ASCII whitespace (`\t\n\r ` and the Unicode separators already
  flagged by `WRD-RES-ANSI`) to a single space.
- No stemming, no fuzzy/edit-distance, no regex wildcards, no token-gap allowance. A phrase
  matches only if it appears as a contiguous normalized substring.

**Seed injection-phrase denylist (v0.2 — narrow and curated, org-extensible):**

```
ignore previous instructions
ignore all previous instructions
disregard previous instructions
disregard all previous instructions
ignore the above instructions
forget previous instructions
forget all prior instructions
you are now
from now on you are
new instructions:
system prompt:
override your instructions
disregard your system prompt
do not tell the user
do not mention this to the user
without telling the user
reveal your system prompt
print your system prompt
exfiltrate
send the following to
```

> This list is intentionally short and high-precision. **Broad regex (e.g. matching any
> sentence containing "ignore" near "instructions") is explicitly forbidden** — that is the
> exact CUT the council made in v0.1 and v0.2 does not undo it. Operators extend the list
> with their own **exact phrases** via `--inject-phrases <file>`; entries are literal
> phrases, never regex.

- **Per-tool override:** none. (Phrase matching is not refined per-tool in v0.2; the tool's
  charset/url/secret declarations do not affect it.)
- **Tier:** MONITOR-fuzzy. **Severity:** `medium` (so SARIF level is `warning`, never
  `error`, reflecting its monitor status).
- **Default behavior:** log + SARIF/JSONL only. **Does not block** unless
  `--block-inject-phrase` is explicitly set (opt-in in v0.2 **and** v0.3; v0.3 does **not**
  make it default-block).
- **SARIF:** `ruleId: WRD-RES-INJECT-PHRASE`, `level: warning`.

---

## 5. Robustness / monitor-only auxiliary rules

These exist so the inspector degrades safely and surfaces context. None ever block.

### 5.1 `WRD-RES-URL` — a non-denylisted URL appeared (note)

A `scheme://host/...` whose host is **not** on the exfil denylist. Emitted as a `note` only
when the pinned tool declares `may_return_urls: false` (or absent → false). Purpose: give
operators visibility into URL-returning tools without flagging exfil. **Never blocks.**
Suppressed entirely when the tool declares `may_return_urls: true`. SARIF `level: note`.

### 5.2 `WRD-RES-UNINSPECTABLE` — a content block could not be inspected (note)

An `image`/`audio`/`blob`/base64 or unknown content block was present and not decoded (§1).
Records that inspection coverage was incomplete for that block. **Never blocks.** SARIF
`level: note`.

### 5.3 `WRD-RES-FRAME-ERROR` — inspection or framing error (note, PASS-THROUGH)

The inspector (or the proxy's framing layer) raised an error on a frame (malformed JSON,
truncated frame, decode failure). Per the fail-**open-on-error** rule for availability, the
frame **passes through unmodified** and a `note` is logged. **A framing/inspection error
MUST NEVER kill the session or block the frame** (`GUARD_PROXY.md` §9). SARIF `level: note`.

> Note the deliberate asymmetry: the *policy* posture is fail-**closed** (deny-by-default
> for argument constraints, inherited from `POLICY_MODEL.md`), but the *proxy framing /
> inspection error* posture is fail-**open / pass-through** for availability. A bug in the
> inspector must not break the user's MCP session. These two postures do not conflict: one
> governs *policy verdicts*, the other governs *inspector failure modes*.

---

## 6. Per-tool precision — fail-safe defaults

Per-tool declarations (`WARDEN_LOCK_SCHEMA.md` §11) make the deterministic checks more
precise and cut false positives. When a declaration is **absent**, the inspector uses the
**fail-safe** default (the stricter, more-protective interpretation):

| Declaration | Absent default (fail-safe) | Effect on rules |
|-------------|----------------------------|-----------------|
| `expected_output_charset` | `"text"` (the §3.1 strict allowlist) | `WRD-RES-ANSI` uses the strict allowlist |
| `may_return_urls` | `false` | `WRD-RES-URL` note fires for any URL; exfil rule unaffected (always on) |
| `secret_echo_applies` | `true` | `WRD-RES-SECRET-ECHO` is BLOCK-tier for the tool |

Fail-safe means: **absent declaration → maximum protection.** A tool only *relaxes* a check
by explicitly declaring it in `warden.lock`, which is a committed, reviewed, approved
artifact. There is no way to relax a check at runtime without a lock edit.

---

## 7. Out of scope for v0.2 (do NOT build)

| Item | Why |
|------|-----|
| Decoding/scanning image/audio/blob/base64 content | Unbounded cost + new parsers = new attack surface. Surface coverage gap via `WRD-RES-UNINSPECTABLE` instead. |
| Broad/fuzzy injection regex, NLP intent classification | The v0.1 CUT stands. Only the narrow exact-phrase denylist ships (monitor-only). |
| DNS resolution of result-borne **hostnames** | No network from the inspector. Exfil-domain match is on the **literal host string**, not a resolved IP. (Mirrors `POLICY_MODEL.md` §2.3 no-DNS rule.) NOTE: raw **IP literals** in results ARE now matched deterministically against the SSRF deny ranges (`WRD-RES-EXFIL-IP-LITERAL`, §3.4) — no DNS needed for those. Resolving a *hostname* to its IP stays out of scope (issue #11 PR-2). |
| Cross-call / conversational correlation ("this result + that later call = exfil chain") | Stateful behavioral reasoning = `T-BEHAVE`, out of scope (`THREAT_MODEL_V2.md`). |
| Blocking by default for the MONITOR (fuzzy) tier | **Still NOT adopted in v0.3.** No field false-positive data exists for `WRD-RES-INJECT-PHRASE`, so it remains monitor-only / opt-in. (Only the **deterministic** tier became default-block in v0.3.) |

---

## 8. Full `WRD-RES-*` rule list (the catalog at a glance)

| Rule ID | Tier | Severity | SARIF level | Default-block in v0.3? | Opt-out / opt-in flag |
|---------|------|----------|-------------|------------------------|------------------------|
| `WRD-RES-ANSI` | BLOCK-deterministic | high | error | **YES (default-on)** | opt-OUT `--no-block-ansi` |
| `WRD-RES-SECRET-ECHO` | BLOCK-deterministic | critical/high (mirrors `WRD-SEC-*`) | error | **YES (default-on)** | opt-OUT `--no-block-secret-echo` |
| `WRD-RES-EXFIL-DOMAIN` | BLOCK-deterministic | high | error | **YES (default-on)** | opt-OUT `--no-block-exfil-domain` / `--allow-exfil-domain` |
| `WRD-RES-EXFIL-IP-LITERAL` | BLOCK-deterministic | high | error | **YES (default-on)** | opt-OUT `--no-block-exfil-ip-literal` |
| `WRD-RES-INJECT-PHRASE` | MONITOR-fuzzy | medium | warning | **NO — monitor-only / opt-in** | opt-IN `--block-inject-phrase` |
| `WRD-RES-URL` | MONITOR (note) | low | note | no (never blocks) | — |
| `WRD-RES-UNINSPECTABLE` | MONITOR (note) | low | note | no (never blocks) | — |
| `WRD-RES-FRAME-ERROR` | MONITOR (note) | low | note | no (pass-through, fail-open) | — |

> The `tools/list_changed` drift gate and argument-policy denials (defined in `GUARD_PROXY.md`,
> not this catalog) are likewise **default-block in v0.3** when `--lock` / `--policy` are
> supplied, opt-OUT via `--no-block-list-changed` / `--no-block-policy`.

---

## 9. Implementer must-not-deviate list

1. **One catalog, two runners.** `guard` and `inspect` import and run the **identical**
   rule implementation. No rule may exist in one and not the other.
2. **The tier partition is fixed.** BLOCK-deterministic ∈ {`WRD-RES-ANSI`,
   `WRD-RES-SECRET-ECHO`, `WRD-RES-EXFIL-DOMAIN`, `WRD-RES-EXFIL-IP-LITERAL`}.
   MONITOR-fuzzy = {`WRD-RES-INJECT-PHRASE`}. Notes never block. Do not move a rule between
   tiers.
3. **`WRD-RES-SECRET-ECHO` reuses `CHECKS.md` `WRD-SEC-*` patterns + the `first4 + "…" +
   (len=N)` redaction verbatim.** No re-defining secret patterns or redaction here.
4. **`WRD-RES-ANSI` is parser-free:** any disallowed codepoint (§3.1) is the match. ESC
   (`U+001B`) being disallowed is what makes an ANSI grammar unnecessary.
5. **`WRD-RES-EXFIL-DOMAIN` is exact host/subdomain matching, host-anchored, never "looks
   like a URL"** and never regex. The seed list + org list are literal domains.
6. **`WRD-RES-INJECT-PHRASE` is narrow exact-phrase, case-insensitive, whitespace-normalized
   substring only. Broad regex is FORBIDDEN** (the v0.1 CUT stands).
7. **Default posture (v0.3):** the **BLOCK (deterministic) tier blocks by default**; each
   category is opt-OUT-able via `--no-block-*` (`GUARD_PROXY.md` §5). The **MONITOR (fuzzy)
   tier never default-blocks** in v0.2 or v0.3 — it is opt-in via `--block-inject-phrase` only.
   `--audit-only` forces everything to warnings (no blocking at all). (v0.2 was shadow-default
   for all tiers.)
8. **Fail-safe per-tool defaults:** absent declaration → maximum protection (§6).
9. **Inspection/framing errors PASS THROUGH** (`WRD-RES-FRAME-ERROR`, never block, never
   kill the session).
10. **SARIF `ruleId` == the `WRD-RES-*` id verbatim; `level` per §8.** Severity→level
    mapping matches `CHECKS.md` §2 (critical/high→error, medium→warning, low→note).
