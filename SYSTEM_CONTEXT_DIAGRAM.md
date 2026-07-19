# mcp-warden — System Context Diagram

Where mcp-warden sits, what it talks to, and where its outputs go. The **definition-only
path introduced in v0.1** (`pin`/`check`/`policy`) is read-only: it captures the
*declared* surface and writes a baseline + machine reports — no proxy, no runtime
interception. **As of v1.1**, `pin` and `check` either spawn a target over stdio or
connect to an already-running Streamable HTTP endpoint. The **v0.2** path added a
transparent stdio
**proxy** (`guard`) and an **offline analyzer** (`inspect`) that inspect tool *results*
at runtime; see C3 below. **v0.3** promotes the deterministic tier to **block by default**
(opt-OUT per category via `--no-block-<category>`; `--audit-only` restores full shadow) and
hardens the proxy lifecycle (cancel/progress passthrough, server-crash + client-disconnect
teardown, reserved transport code `-32002`); see `docs/GUARD_PROXY_V3.md`. **v0.3** also adds
`lock rotate` — a lifecycle verb that re-attests an existing baseline's structured provenance
(`pinner`/`attestations`) **without re-capturing the surface**, leaving `overall_digest`
byte-identical and failing closed on a tampered lock (`docs/WARDEN_LOCK_SCHEMA.md` §8.1–§8.2).
**v0.3** further adds `diff <lock-a> <lock-b>` — an **offline, redacted viewer** that renders
integrity drift between two EXISTING locks by reusing `compute_drift` (no capture, no new diff
logic) plus a separate informational provenance section. It never prints raw
`server.command`/`args` (secret-safe); default exit 0, `--exit-code` → 1 on integrity drift only.

> **Agent Trust Kernel status (DSE-714):** [`docs/AGENT_TRUST_KERNEL.md`](docs/AGENT_TRUST_KERNEL.md)
> is the normative contract for a future deterministic reference monitor. It is **design-only**
> until DSE-715 through DSE-717 implement provenance/taint, PDP/PEP complete mediation, and
> signed evidence-before-effect. The current `guard` path is not represented as ATK-conformant.
> In C1, the dashed ATK edge and `Future Agent Trust Kernel runtime` node are conceptual
> documentation scope only—not a deployed component, shipped data flow, or implementation claim.

> `conclave` (the 4-model adversarial council referenced in `docs/THREAT_MODEL.md`)
> is a **dev-time design reviewer** that shaped this contract. It is **NOT** a
> runtime dependency and is never invoked by `pin`/`check`/`policy`.

> **`action.yml` (Issue #18)** is the primary consumer delivery vehicle for the `check`
> gate. Consumers pin `DataScience-EngineeringExperts/mcp-warden@<tag>` in their workflow; the composite
> action wraps the C2 sequence (steps 1–5 of the pin/check sequence above) behind a
> single `uses:` step with hash-locked supply-chain, injection guard, SARIF upload, and
> cross-OS support. See `action/requirements.lock` and `README.md` §GitHub Action.

> **`.pre-commit-hooks.yaml` (Issue #22)** is the **local pre-CI gate** delivery vehicle.
> The `mcp-warden-precommit` wrapper runs the SAME `check` verdict via `check_core.run_check`
> (read_lock→capture→build_lock(in-memory)→compute_drift) so a local hook and CI can never
> disagree on drift. It is check-only: it never pins, never writes `warden.lock`. Drift always
> exits 1 in both modes; a *locally* unspawnable server is non-blocking by default (exit 0 +
> warning) and fail-closed under `--strict` (exit 2) — CI stays strict. The wrapper normalizes
> cwd to the git repo root before capturing. See `README.md` §pre-commit hook.

> **`pin --sign` / `check --verify` (Issue #16)** add optional **Sigstore keyless** signing of
> the lock: `--sign` writes a `<lockname>.sigstore` bundle binding `overall_digest` (survives
> `lock rotate`); `--verify` recomputes + verifies **fail-closed** (`docs/SIGNING.md`). The
> release pipeline (`.github/workflows/release.yml`) signs mcp-warden's OWN published artifacts
> the same way ("heal thyself"). Signing is the optional `mcp-warden-cli[sigstore]` extra — the
> core gate has no crypto dependency.

---

## C1 — System context

```mermaid
flowchart TB
    subgraph dev["Dev-time (design review only)"]
        conclave["conclave\n4-model adversarial council\n(NOT a runtime dependency)"]
        specs["docs/ security contract\nTHREAT_MODEL · WARDEN_LOCK_SCHEMA\nCHECKS · POLICY_MODEL"]
        atk["AGENT_TRUST_KERNEL\nDSE-714 design contract"]
        conclave -. "critiques / shapes" .-> specs
        conclave -. "security review" .-> atk
    end

    future["Future Agent Trust Kernel runtime\nDSE-715–717 · NOT IMPLEMENTED"]
    atk -. "governs future conformance" .-> future

    subgraph ci["CI pipeline (GitHub Actions / local)"]
        warden["mcp-warden CLI\npin · check · policy · lock rotate · diff"]
    end

    subgraph target["Untrusted boundary"]
        server["Target MCP server\nstdio child (argv, no shell) OR\nalready-running Streamable HTTP endpoint"]
    end

    repo[("warden.lock\ncommitted baseline\n(root of trust)")]
    sarif["SARIF 2.1.0\n(code scanning)"]
    jsonl["JSONL\n(machine log)"]

    specs -. "implemented by" .-> warden

    warden -- "1. stdio: spawn; HTTP: connect\n2. initialize + tools/list\nresources/list / prompts/list" --> server
    server -- "3. declared surface\n(definitions only)" --> warden

    warden -- "pin: write baseline" --> repo
    repo -- "check: read baseline" --> warden
    warden -- "check: drift + findings" --> sarif
    warden -- "check: drift + findings" --> jsonl

    sarif --> gate{"drift?"}
    gate -- "yes → exit≠0" --> failci["CI build FAILS"]
    gate -- "no → exit 0" --> passci["CI build passes"]
```

---

## C2 — `pin` then `check` sequence

```mermaid
sequenceDiagram
    autonumber
    participant CI as CI / operator
    participant W as mcp-warden
    participant S as MCP server (stdio child or HTTP endpoint)
    participant L as warden.lock

    Note over CI,L: pin (TOFU baseline)
    CI->>W: pin <server-cmd...> OR pin --url <endpoint>
    alt stdio command
        W->>S: spawn (argv array, no shell)
    else --url
        W->>S: connect (Streamable HTTP)
    end
    W->>S: initialize
    S-->>W: protocolVersion
    W->>S: tools/list · resources/list · prompts/list
    S-->>W: declared surface (definitions)
    W->>W: canonicalize (RFC 8785) + SHA-256, derive caps, run WRD-* checks
    W->>L: write warden.lock (hashes, redacted findings, approved_digest)

    Note over CI,L: check (later, in CI)
    CI->>W: check <server-cmd...> OR check --url <endpoint>
    W->>L: read baseline
    W->>S: spawn or connect + initialize + list (same transport as pin)
    S-->>W: declared surface (possibly rug-pulled)
    W->>W: recompute digests, compute_drift(baseline, current)
    alt drift detected
        W-->>CI: SARIF/JSONL + exit 1 (build fails)
    else no drift
        W-->>CI: exit 0 (build passes)
    end
```

> `compute_drift` structurally classifies tool `inputSchema` changes via the normalized
> `schema_skeleton` stored in the lock (`schema_version` 3 — skeleton added at v2, in-document
> `$ref` resolution at v3, #29): each security-relevant mutation is a per-fact
> `WRD-DRIFT-SCHEMA-*` item (`docs/WARDEN_LOCK_SCHEMA.md` §6.2). v1 locks fall
> back to a single high-severity `schema-modified` until re-pinned.

---

## C3 — `guard` runtime proxy + `inspect` offline analyzer (v0.2)

```mermaid
flowchart LR
    subgraph live["Live session (v0.2 guard)"]
        client["MCP client\n(agent / host)"]
        guard["mcp-warden guard\n(transparent stdio proxy)\nv0.3: deterministic tier\nblocks by default"]
        server2["Target MCP server\n(child, argv array,\nNEVER via a shell)"]
        client <-- "c2s frames" --> guard
        guard <-- "s2c frames" --> server2
    end

    lock[("warden.lock\n+ §11 per-tool\ninspection policy")]
    cat["WRD-RES-* catalog\n(RESULT_INSPECTION.md)\nANSI · secret-echo · exfil-domain\n· inject-phrase (monitor)"]
    trace[("trace.jsonl\nrecorded frames")]

    subgraph offline["Offline (v0.2 inspect)"]
        inspect["mcp-warden inspect"]
    end

    lock -. "per-tool precision" .-> guard
    cat -. "applied by BOTH (identical rules)" .-> guard
    cat -. "applied by BOTH (identical rules)" .-> inspect
    guard -- "--record" --> trace
    trace --> inspect

    guard --> sarif2["SARIF / JSONL\n(action: shadowed|blocked|modified)"]
    inspect --> sarif2

    guard -- "on block (opt-in): JSON-RPC error\nOR redacted-content result" --> client
```

- `guard` passes **every frame through untouched EXCEPT** `tools/call` request/response
  (+ the `tools/list_changed` gate vs the lock). `initialize`/capabilities are never
  rewritten; enforcement begins only at the first `tools/call` (`GUARD_PROXY.md` §2).
- A framing/inspection **error fails open** by default — the frame passes through and the session
  is never killed (`GUARD_PROXY.md` §9). Oversized frames (> `--max-frame-bytes`) and truncated
  frames at EOF also fail open (`GUARD_PROXY_V3.md` §2.3–§2.4). **(#21)** The opt-in `--strict`
  flag fails CLOSED instead, but only for the inspection layer: an error at the result /
  argument-policy / tools-list inspection sites **terminates** the session (`-32003` non-retriable
  to the client, exit `3`); framing/EOF/over-cap stay fail-open in all modes (`GUARD_PROXY_V3.md` §5).
- "Block" on the wire is a **well-formed JSON-RPC frame**: an error response (`-32001`) for
  blocked requests/exfil/secret-echo results, or a redacted-content result for ANSI stripping
  (`GUARD_PROXY.md` §7).
- **v0.3 lifecycle:** `notifications/cancelled` + `notifications/progress` pass through
  untouched even mid-`tools/call`; a server crash mid-call synthesizes a `-32002` transport
  error for every pending id (client never hangs); a client disconnect reaps the child via its
  process group (no orphan) (`GUARD_PROXY_V3.md` §1–§2).

---

## Trust boundary (from `docs/THREAT_MODEL.md` §3.3)

- **Trusted:** mcp-warden, the Python runtime it runs in, and `warden.lock` in
  the repo (delegated to host controls — PR review, branch protection).
- **Untrusted:** the target server and everything beyond its transport boundary.
- The boundary is the **stdio channel** to a spawned child or the network channel to the
  configured Streamable HTTP endpoint. Runtime `guard` interception remains stdio-only.

## What is explicitly NOT in this picture

**v0.1 (`pin`/`check`/`policy`):**
- No runtime proxy / no agent-in-the-loop (`policy` is design-time only).
- No tool-result inspection (the headline gap, `T-RESULT` — addressed by v0.2 `guard`).

**Still NOT in scope, even with v0.2 `guard`/`inspect`:**
- No behavioral defense (`T-BEHAVE`) — content is inspected, side effects are not.
- No cross-call/conversational correlation; each frame is inspected independently.
- No decoding of image/audio/blob/base64 result content (coverage gap recorded as
  `WRD-RES-UNINSPECTABLE`).
- No network calls / no DNS resolution by checks, policy, or the proxy. Exfil + SSRF match
  on literal host strings **and (#54, D6) raw IP literals** in result text/args against the
  SSRF/exfil address ranges (`net_rules`) — deterministic, still no DNS-name resolution.
- No HTTP/SSE runtime proxy: `guard` remains stdio-only. Streamable HTTP support is limited
  to definition capture by `pin` and `check` via `--url`.
- The fuzzy `WRD-RES-INJECT-PHRASE` MONITOR tier is **never default-block**, even in v0.3
  (opt-in only via `--block-inject-phrase`).
- Windows lifecycle guarantees are **experimental** in v0.3 — job-object best-effort teardown,
  no orphan-freedom claim (the `-32002` pending-id synthesis still runs); see
  `docs/GUARD_PROXY_V3.md` §3.
