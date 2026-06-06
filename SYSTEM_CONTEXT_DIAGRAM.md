# mcp-warden — System Context Diagram

Where mcp-warden sits, what it talks to, and where its outputs go. mcp-warden is
a **read-only, definition-only** gate: it spawns the target MCP server over
stdio, captures the *declared* surface, and writes a baseline + machine reports.
There is no proxy and no runtime interception in v0.1.

> `conclave` (the 4-model adversarial council referenced in `docs/THREAT_MODEL.md`)
> is a **dev-time design reviewer** that shaped this contract. It is **NOT** a
> runtime dependency and is never invoked by `pin`/`check`/`policy`.

---

## C1 — System context

```mermaid
flowchart TB
    subgraph dev["Dev-time (design review only)"]
        conclave["conclave\n4-model adversarial council\n(NOT a runtime dependency)"]
        specs["docs/ security contract\nTHREAT_MODEL · WARDEN_LOCK_SCHEMA\nCHECKS · POLICY_MODEL"]
        conclave -. "critiques / shapes" .-> specs
    end

    subgraph ci["CI pipeline (GitHub Actions / local)"]
        warden["mcp-warden CLI\npin · check · policy"]
    end

    subgraph target["Untrusted boundary"]
        server["Target MCP server\n(spawned as argv array,\nNEVER via a shell)"]
    end

    repo[("warden.lock\ncommitted baseline\n(root of trust)")]
    sarif["SARIF 2.1.0\n(code scanning)"]
    jsonl["JSONL\n(machine log)"]

    specs -. "implemented by" .-> warden

    warden -- "1. spawn + initialize\n+ tools/list / resources/list\n/ prompts/list  (stdio)" --> server
    server -- "2. declared surface\n(definitions only)" --> warden

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
    participant S as MCP server (stdio child)
    participant L as warden.lock

    Note over CI,L: pin (TOFU baseline)
    CI->>W: pin <server-cmd...> --approve --approver <id>
    W->>S: spawn (argv array, no shell)
    W->>S: initialize
    S-->>W: protocolVersion
    W->>S: tools/list · resources/list · prompts/list
    S-->>W: declared surface (definitions)
    W->>W: canonicalize (RFC 8785) + SHA-256, derive caps, run WRD-* checks
    W->>L: write warden.lock (hashes, redacted findings, approved_digest)

    Note over CI,L: check (later, in CI)
    CI->>W: check <server-cmd...>
    W->>L: read baseline
    W->>S: spawn + initialize + list (same as pin)
    S-->>W: declared surface (possibly rug-pulled)
    W->>W: recompute digests, compute_drift(baseline, current)
    alt drift detected
        W-->>CI: SARIF/JSONL + exit 1 (build fails)
    else no drift
        W-->>CI: exit 0 (build passes)
    end
```

---

## Trust boundary (from `docs/THREAT_MODEL.md` §3.3)

- **Trusted:** mcp-warden, the Python runtime it runs in, and `warden.lock` in
  the repo (delegated to host controls — PR review, branch protection).
- **Untrusted:** everything on the server side of the stdio pipe.
- The boundary is the **stdio channel** between mcp-warden and the spawned server.

## What is explicitly NOT in this picture (v0.1)

- No runtime proxy / no agent-in-the-loop (`policy` is design-time only).
- No tool-result inspection (the headline v0.2 gap, `T-RESULT`).
- No network calls by the checks; no DNS resolution at policy time.
- stdio transport only (HTTP/SSE deferred).
