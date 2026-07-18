# mcp-warden — Threat Model (v0.1)

**Status:** v0.1 security contract. Implementation-ready.
**Scope:** CI-first integrity gate for MCP (Model Context Protocol) servers.
**Document owner:** Security. Changes here require a threat-model review.

---

## 1. Positioning statement (read this first)

> **mcp-warden v0.1 is an MCP supply-chain integrity gate. It is NOT an agent firewall.**

mcp-warden pins and verifies the **declared tool/resource/prompt surface** of an MCP
server, then fails CI when that declared surface drifts from an approved baseline.
It operates entirely on **definitions** — the `(name, description, inputSchema)`
metadata returned by `tools/list`, `resources/list`, and `prompts/list` — never on
runtime tool **behavior** or tool **results**.

> **Forward contract:** [`AGENT_TRUST_KERNEL.md`](AGENT_TRUST_KERNEL.md) defines a separate,
> future non-bypassable reference-monitor contract. It does not retroactively change this
> v0.1 contract or imply that the current product is ATK-conformant.

This distinction is the single most important thing in this document. An earlier
"runtime firewall" design was critiqued by a 4-model adversarial council. The
council's central finding was that **definition integrity is not behavioral
integrity**, and that overclaiming behavioral protection is the fastest way to lose
credibility. v0.1 therefore makes a narrow, honest, *verifiable* claim:

- We detect when a server's **declared capability surface changes** (rug-pull / silent
  redefinition).
- We flag **dangerous capability shapes** and **secret leakage** in the definitions at
  pin time.
- We make the approved surface **reproducibly hashable** so a diff is meaningful in CI.

We do **not** claim to stop a tool from doing something malicious *while honoring its
declared schema*. That is out of scope and is stated plainly below.

---

## 2. Trust model

### 2.1 Trust On First Use (TOFU)

The first successful `pin` of a server establishes the baseline of record. mcp-warden
has no out-of-band notion of "what this server *should* declare" — it trusts what the
server declares **at the moment of pinning** and records it in `warden.lock`.

Consequences the operator must accept:

- **A server that is already compromised at first pin will be pinned as "clean."**
  TOFU defends against *future* drift, not a *pre-existing* malicious baseline.
- The integrity guarantee is **"the surface has not changed since a human pinned it,"**
  not **"the surface is safe."** Static checks (see `CHECKS.md`) partially mitigate the
  first-pin blind spot but do not eliminate it.

### 2.2 Optional `--approve` attestation (anti-TOFU mitigation)

`pin --approve` records a lightweight human attestation in `warden.lock`:

- An **approver identity** string (e.g. `ernest@thedataexperts.us`, a CI principal, or a
  service account id) supplied by the caller / CI environment.
- A **timestamp** (`approved_at`, RFC 3339 UTC).
- The **overall digest** the human is attesting to (binds the approval to exact bytes).

`--approve` does **not** add cryptographic non-repudiation in v0.1. It is an *audit
record*: "a named principal looked at this surface and accepted it." Cryptographic
signing (SLSA / in-toto / sigstore) is explicitly deferred to a later version. The
attestation is meaningful only to the degree the `warden.lock` file itself is protected
by the surrounding system (code review, branch protection, CI provenance).

### 2.3 Integrity of `warden.lock` itself

`warden.lock` is the root of trust for `check`. mcp-warden does not protect the lock
file from tampering on disk — that is delegated to the host repository's controls:

- The lock file MUST be committed to version control and changes reviewed via PR.
- Branch protection / required reviews are the mechanism that makes `--approve`
  meaningful.
- An attacker who can silently rewrite `warden.lock` in the repo defeats the gate; this
  is an accepted, documented boundary (see §5, T-LOCK).

---

## 3. Assets and actors

### 3.1 Assets we protect

| ID | Asset | Why it matters |
|----|-------|----------------|
| A1 | The approved MCP tool/resource/prompt surface | The agent acts on these definitions; silent change = silent capability change |
| A2 | `warden.lock` baseline integrity | Root of trust for every `check` |
| A3 | Secrets that might be embedded in definitions | Tokens leaked in descriptions/defaults are credential exposure |
| A4 | Supply-chain provenance of server launch refs | Unpinned `npx`/`uvx`/`pip` = silent code swap upstream |

### 3.2 Actors / threat sources

| ID | Actor | Capability assumed |
|----|-------|--------------------|
| TS1 | Malicious/compromised MCP server author (upstream) | Can change what the server declares between versions ("rug-pull") |
| TS2 | Compromised dependency of the server | Can alter declared surface or inject capabilities at install time |
| TS3 | Adaptive server that fingerprints the caller | Can return a benign surface to the pinner and a hostile surface to the real client |
| TS4 | Repo-local attacker | Can edit files in the consuming repo, incl. `warden.lock` |

### 3.3 Trust boundary

mcp-warden runs in CI (or locally) and spawns the MCP server **over stdio** as a child
process. The boundary is the stdio channel between mcp-warden and the server. Everything
on the server side of that pipe is **untrusted**. mcp-warden itself, the Node/Python
runtime it runs in, and the lock file in the repo are **trusted** (delegated to host
controls).

---

## 4. MCP threat taxonomy addressed by v0.1

v0.1 addresses exactly four named threat classes. Anything not on this list is out of
scope.

| Tax. ID | Name | Definition | Primary control |
|---------|------|-----------|-----------------|
| **MCP-DRIFT** | Definition drift / rug-pull | A previously-pinned server later declares a changed surface (added/removed/modified tool, changed description or schema) without re-approval | `check` hash-diff vs `warden.lock` (see `WARDEN_LOCK_SCHEMA.md` §6) |
| **MCP-CAPSURF** | Dangerous capability surface | A tool declares a high-risk shape — shell/exec, filesystem write, network egress, raw SQL — that warrants explicit human review | Deterministic static checks `WRD-CAP-*` + policy shapes (see `CHECKS.md`, `POLICY_MODEL.md`) |
| **MCP-SECRET** | Secret leakage in definitions | A token/key/credential is embedded in a tool name, description, default value, or example | Static secret checks `WRD-SEC-*` (see `CHECKS.md`) |
| **MCP-SUPPLY** | Unpinned supply-chain refs | The server is launched via a mutable upstream ref (`npx pkg`, `uvx pkg`, `pip install pkg` without a version/digest) | Launch-command static check `WRD-SUP-*` (see `CHECKS.md`) |

---

## 5. Defends against / Does NOT defend against

This table is the contract. It is deliberately conservative. Each "does not" row names
*why*, grounded in the council findings.

### 5.1 Defends against (in scope)

| ID | Threat | How v0.1 addresses it | Residual gap |
|----|--------|-----------------------|--------------|
| D1 | Rug-pull: server silently changes a tool's schema or description after approval (MCP-DRIFT) | `check` re-captures and diffs canonical hashes; any change exits non-zero | Only catches change *between pin and check*; a hostile *first* pin passes (TOFU) |
| D2 | New dangerous tool appears in a previously-clean server (MCP-DRIFT + MCP-CAPSURF) | Added-tool drift = high severity; capability checks fire on the new tool | Detection, not prevention; relies on CI failing the build |
| D3 | Token/key pasted into a tool description or default (MCP-SECRET) | `WRD-SEC-*` regex + entropy checks at pin and check time | Custom/short secret formats may evade patterns; entropy threshold is a heuristic |
| D4 | Server launched via mutable upstream ref (MCP-SUPPLY) | `WRD-SUP-*` flags unpinned `npx`/`uvx`/`pip` in the launch command | Flags the ref; does not itself pin or vendor the dependency |
| D5 | Dangerous capability shape merits human sign-off (MCP-CAPSURF) | Capability flags surfaced in lock + findings; `--approve` forces a human in the loop | A shape can be "approved" and still be misused at runtime |

### 5.2 Does NOT defend against (out of scope) — and why

| ID | Threat | Why v0.1 cannot defend (council finding) | Disposition |
|----|--------|------------------------------------------|-------------|
| **T-BEHAVE** | A clean-pinned tool exfiltrates data or takes hostile action *while fully honoring its declared schema* | **Architectural TOCTOU: definition ≠ behavior.** Hashing `(name, description, inputSchema)` gives **zero** behavioral guarantee. The declared surface and the runtime conduct are independent. | **Explicit v0.1 limitation.** Not a defended threat. Requires runtime mediation we do not build. |
| **T-RESULT** | Tool **result** is poisoned to inject instructions into the agent (prompt injection via returned content) | v0.1 never inspects tool results — only definitions. This is the **dominant real-world MCP attack class.** | **OUT of scope in v0.1. Named headline v0.2 gap → now ADDRESSED in v0.2** (deterministic block tier + fuzzy monitor tier, shadow-default). See `THREAT_MODEL_V2.md`, `RESULT_INSPECTION.md`, `GUARD_PROXY.md`. |
| **T-SEMANTIC** | Semantic drift with an **identical hash** (e.g. description reworded to invert meaning while canonical bytes collide — or, more realistically, meaning changes that the operator considers benign-looking) | Hash equality is byte equality after canonicalization; it cannot reason about *meaning*. Any change that alters canonical bytes *is* caught; any change that does not is, by definition, invisible. | Accepted limitation. We do **not** add fuzzy/NLP description analysis (cut — see §6). |
| **T-FINGERPRINT** | Adaptive server returns benign defs to the pinner (TS3) and hostile defs to the real client | mcp-warden is a *different client/session* than the production agent. A server that fingerprints clients can serve us a clean surface and the agent a dirty one. Per-client / per-session definition variance is real in MCP. | Accepted limitation. Partial mitigation: run `check` in the same environment as the agent where feasible. |
| **T-TOCTOU-CALL** | Drift *between* `tools/list` and an actual `tools/call` in the same session | v0.1 verifies the *listed* surface; it does not sit between the agent and live calls. The set verified at list-time can differ from what is honored at call-time. | Accepted limitation. Runtime interception deferred. |
| **T-LOCK** | Attacker rewrites `warden.lock` in the repo to launder a malicious surface (TS4) | mcp-warden does not protect its own baseline file; that is the host repo's job (PR review, branch protection). | Boundary delegated to host controls (see §2.3). |
| **T-RUNTIME-PROXY** | Transparent runtime enforcement of policy on live calls | Not built in v0.1 — `policy` only lints and evaluates a *provided sample call*. | Deferred to v0.2+. |
| **T-TRANSPORT** | HTTP/SSE-transported servers | v0.1 supports **stdio only**. | Deferred. |

---

## 5.3 Self-threat / tool-integrity bypasses (physician, heal thyself)

A v1.0 tool that claims supply-chain integrity must document **its own** residual
bypasses, not just the threats it gates for downstream consumers. The three surfaces
below were named in the v1 adversarial review. Each was verified against the actual
implementation before a verdict was assigned — this section asserts **no defense that
the code does not actually provide.** Verdicts use the same vocabulary as §5:
**DEFENDED** (a mechanism prevents it), **PARTIALLY-DEFENDED** (a mechanism narrows it
but a residual remains), **ACCEPTED LIMITATION** (no mechanism; documented boundary).

| ID | Self-threat | Verdict | Mechanism / residual |
|----|-------------|---------|----------------------|
| **T-SELF-REPLAY** | A validly-signed `warden.lock` is presented for server **B** when it was pinned + signed for server **A** | **PARTIALLY-DEFENDED** | See §5.3.1 |
| **T-SELF-SARIF** | An attacker suppresses or rewrites the SARIF report so a real drift finding is ignored by a consumer | **DEFENDED** (exit code is the gate; SARIF is advisory) | See §5.3.2 |
| **T-SELF-JCS** | Two semantically-different surfaces canonicalize to the same bytes, or canonicalization is made non-deterministic | **PARTIALLY-DEFENDED** (collision DEFENDED; semantic-equivalence is an ACCEPTED LIMITATION = T-SEMANTIC) | See §5.3.3 |

### 5.3.1 T-SELF-REPLAY — signed-lock replay against a different server

**Verdict: PARTIALLY-DEFENDED.**

What actually binds the lock to a server. The lock's server identity
(`models.py:ServerIdentity`, SPEC §6) is **only** the launch invocation: `command`,
`args`, and `command_digest = hash({command, args})`. There is **no capture of the
server's self-declared `serverInfo.name` / `serverInfo.version`** from the `initialize`
response anywhere in `src/` — verified by absence. The Sigstore signature
(`signing.py`) binds a single statement `{"_type":"mcp-warden-lock-digest/v1","digest":
<overall_digest>}`, and `overall_digest` (`lockfile.py:compute_overall_digest`) embeds
`server.command_digest` plus the sorted per-entry digests. The signed statement carries
**no repository, filename, or path binding** (`SIGNING.md` "No repository/filename
binding"), so two CI runs signing the same `overall_digest` produce **interchangeable**
bundles.

What this defends. A replay against a server with a *different launch command or a
different declared surface* fails: its recomputed `command_digest` (or its per-entry
digests) differ, so its `overall_digest` differs, so the signed statement does not match
and `check --verify` fails closed. Run isolation comes from the verify-time identity
policy (`--certificate-identity` / `--certificate-oidc-issuer`), which pins *who* signed
the digest.

Residual risk (why only PARTIAL). Because identity is the launch invocation and the
declared surface — **not** the server's network/process identity — two servers that are
launched with a **byte-identical `command`+`args`** *and* expose a **byte-identical
declared surface** produce the **same `overall_digest`**, and a bundle signed for one
verifies for the other. Concretely: a lock signed for `python ./server.py` is valid for
**any** `python ./server.py` whose surface matches, regardless of which directory,
container, or host it runs in (the spec deliberately does not hash binary contents —
SPEC §6.1). An operator who relies on the signature alone to prove "this is *the* server
I approved" is over-trusting it; the signature proves "this *launch + surface* was
approved by this identity," nothing more.

Mitigations available to the operator: (1) make `command`/`args` carry the disambiguating
identity (a pinned absolute path, a content-addressed image ref) so the launch invocation
*is* the server identity; (2) enforce per-repo/workflow isolation through the verify-time
`--certificate-identity` policy. This is the same residual as T-FINGERPRINT's cousin: the
lock attests a *declared surface under a launch*, not a *running process*.

### 5.3.2 T-SELF-SARIF — SARIF-output suppression / manipulation

**Verdict: DEFENDED — because the exit code, not the SARIF, is the gate.**

Source of truth. On the `check` path (`cli.py:check`), the verdict is the **drift set**
returned by the shared `run_check_full` core (`check_core.py`). The SARIF file, when
`--sarif PATH` is given, is written as a pure **side effect** (`cli.py:177`) and is read
back by **nothing** in the verdict path. The exit code is then set **solely** by whether
the drift set is non-empty: `if drift: raise typer.Exit(code=1)` (`cli.py:184-185`). A
clean run exits 0; any drift exits 1; a capture/lock error exits 2. SARIF emission cannot
change any of these.

Why suppression does not bypass the gate. An attacker who deletes, truncates, or rewrites
the SARIF file changes **only** an advisory report consumed by code-scanning dashboards —
it does **not** change the process exit code that CI gates on. A CI job that does
`mcp-warden check ... && deploy` (or that treats a non-zero exit as a hard failure) is
**unaffected** by SARIF tampering, because drift already forced exit 1 before any
dashboard saw the report.

Failure mode if a consumer relies on SARIF alone. The defense holds **only** for
pipelines that gate on the exit code. A pipeline that runs `mcp-warden check ... ; true`
(swallowing the exit) or `... --sarif report.json` and then gates **purely** on
GitHub code-scanning alerts derived from the SARIF has moved the trust boundary onto an
advisory artifact. In that configuration a suppressed SARIF *can* hide a real finding.
**This is a consumer misconfiguration, not a tool bypass** — but it is the one way to
turn T-SELF-SARIF into a real exposure, so it is documented here and the rule for
downstream docs is explicit: **the exit code is the authoritative gate; SARIF is advisory
output only.** Never gate solely on the SARIF.

### 5.3.3 T-SELF-JCS — canonicalization attack surface

**Verdict: PARTIALLY-DEFENDED.** Engineered byte-collision is DEFENDED;
semantic-but-byte-identical change is an ACCEPTED LIMITATION (this is exactly
**T-SEMANTIC**, §5.2).

What JCS guarantees here. Canonicalization is delegated to the vetted `rfc8785` library
(`hashing.py:canon`), RFC 8785 JCS: object keys sorted by Unicode code point, fixed string
escaping, fixed number formatting, all insignificant whitespace eliminated. Hashing is
SHA-256 over those canonical bytes. The entire declared surface flows through this one
function, so:

- **Determinism is DEFENDED.** For a given JSON value, JCS produces one and only one byte
  string; two conformant implementations capturing the same surface MUST produce the same
  `overall_digest` (SPEC §12). There is no caller-influenceable knob (locale, key order,
  whitespace) that makes canonicalization non-deterministic — JCS exists precisely to
  remove those. A malformed value that JCS cannot serialize raises `ValueError`
  (`hashing.py:44-46`) and fails closed, rather than silently hashing a partial value.
- **Engineered collision is DEFENDED to SHA-256 strength.** Producing two *different*
  canonical byte strings that hash to the same `overall_digest` is a SHA-256 preimage/
  collision, not a canonicalization weakness. JCS does not widen this surface.

What JCS does NOT do (the accepted limitation). Hash equality is **byte equality after
canonicalization** — it is not semantic equality. Any change that alters the canonical
bytes *is* caught (the structural classifier in SPEC §8.3 only describes *how* it
changed); any change that does **not** alter canonical bytes is, by construction,
invisible. Two surfaces are "the same" to mcp-warden **iff** their JCS bytes are identical.
A description reworded to invert its meaning *will* change bytes and *will* be caught (as a
`description-modified`/low drift); the genuinely invisible case is a change the operator
already considers benign-looking AND that leaves canonical bytes identical (e.g. a cosmetic
key the skeleton drops — `description`, `title`, `examples`, `default` are extracted *out*
of `schema_skeleton`, SPEC §7.5, though they still feed `input_schema_hash` so a raw schema
text change is still caught at the blob level). mcp-warden deliberately does **not** add
fuzzy/NLP description analysis to close this (§6, cut #1): it is a net-negative,
high-false-positive signal. This residual is tracked as **T-SEMANTIC** and is an
**ACCEPTED LIMITATION**, not a defect.

---

## 6. Deliberate cuts (what we will NOT build, by design)

The council was unanimous that these *weaken* the product. They are out of scope not
because of time, but because they are net-negative:

1. **Fuzzy / NLP "injection-y language" scanning of descriptions.** Weak signal, high
   false-positive rate. A description containing "ignore previous instructions" is not
   reliably malicious, and flagging it trains operators to ignore warnings. **CUT.** Only
   deterministic, explainable static checks ship (see `CHECKS.md`).
2. **Any claim of behavioral / runtime protection.** See T-BEHAVE, T-RESULT. Marketing or
   docs that imply mcp-warden stops a tool from "doing bad things" are a defect.
3. **Tool-result inspection.** The real attack surface, deliberately deferred *in v0.1* so
   it ships an honest, scoped guarantee rather than a leaky broad one. **Delivered in v0.2**
   (`THREAT_MODEL_V2.md`) as a deterministic block tier + a narrow fuzzy monitor tier,
   shadow-default — the broad fuzzy injection cut (item 1) is **retained** there.

---

## 7. Honest one-line summary for downstream docs

> "mcp-warden verifies that an MCP server's *declared* tool surface has not changed since
> a human approved it, and flags dangerous shapes and leaked secrets in that surface. It
> does not, and cannot in v0.1, guarantee that a tool *behaves* safely — including the
> dominant attack of poisoned tool results, which is the explicit v0.2 target."

---

## 8. Related documents

- `AGENT_TRUST_KERNEL.md` — **DSE-714 design contract:** future deterministic reference-monitor
  invariants and downstream bindings; implementation conformance is pending DSE-715–717.
- `WARDEN_LOCK_SCHEMA.md` — baseline format, canonicalization, hashing, drift definition.
- `CHECKS.md` — the deterministic static-check catalog (IDs, rules, severities, SARIF).
- `POLICY_MODEL.md` — argument-level policy shapes, constraints, lint + sample evaluation.
- `THREAT_MODEL_V2.md` — **v0.2 addendum (v0.3 posture):** T-RESULT vectors, the
  defends/monitors/does-not table, the runtime result-inspection scope, and the v0.3
  default-block posture change + honest availability/UX risk (extends this doc; v0.1 unchanged).
- `RESULT_INSPECTION.md` — **v0.2:** the `WRD-RES-*` result-inspection catalog (v0.3: defaults
  updated, catalog unchanged).
- `GUARD_PROXY.md` — **v0.2/v0.3:** the `guard` proxy + `inspect` analyzer contract.
- `GUARD_PROXY_V3.md` — **v0.3:** proxy hardening (cancellation/progress passthrough, subprocess
  lifecycle, Windows) + the full v0.3 block-flag scheme.
- `SIGNING.md` — Sigstore keyless signing/verify contract; the basis for the
  T-SELF-REPLAY analysis (§5.3.1): what `overall_digest` binds and what it does not.
- `SPEC.md` — MCP Lock Format v1 + the compatibility & versioning policy; the basis for
  the T-SELF-JCS canonicalization analysis (§5.3.3) and the digest-binding facts (§5.3.1).
