# mcp-warden vs mcp-scan vs MCP gateways

People evaluating MCP security tooling often conflate three different jobs and
assume they are substitutes — then pick one and leave gaps. They are not
substitutes. They are **complementary layers** that run at different times and
lock down different things. The right answer for a production deployment is
usually **all three**.

## The three jobs

1. **Static tool-poisoning scanning** — read the tool *definitions* (and
   results/flows) and judge whether the *content* looks malicious: injection-style
   descriptions, known-bad patterns, toxic data flows. Runs at pin-time /
   pre-flight, before you trust a server.
   Representative tool:
   [`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan) (Invariant Labs).

2. **Runtime mediation** — sit in front of live MCP traffic and police it: auth,
   rate limits, request/response policy, isolation, observability on calls in
   flight. Runs at *runtime*, on every request.
   Representative tools (gateways):
   [ContextForge](https://github.com/IBM/mcp-context-forge) (IBM),
   [Lunar MCPX](https://www.lunar.dev/),
   [TrueFoundry MCP Gateway](https://www.truefoundry.com/),
   [Docker MCP Gateway](https://docs.docker.com/ai/mcp-gateway/).

3. **Surface pinning + drift CI gating** — pin the human-approved declared surface
   into a reproducible, signed lock and **fail CI when that surface drifts** from
   the baseline (a rug-pull / silent redefinition). Runs in CI / pre-commit.
   Tool: **mcp-warden**.

These three answer different questions: *"is this definition malicious right
now?"* (scanner), *"is this live call allowed?"* (gateway), and *"did the surface
change from what a human approved?"* (mcp-warden).

## At a glance

| Tool / category | When it runs | What it locks down | What it does NOT do |
|-----------------|--------------|--------------------|----------------------|
| **mcp-scan** (static tool-poisoning scanner) | pin-time / pre-flight | suspicious *content* in tool definitions and resources — prompt-injection wording, known-bad patterns, toxic flows | it is not a runtime traffic mediator, and it is not a reproducible CI baseline that fails a build on any surface change |
| **Gateways** (ContextForge, Lunar MCPX, TrueFoundry, Docker MCP Gateway) | runtime — every live request | live traffic: auth, rate limits, request/response policy, isolation, observability | they do not provide a committed, human-approved *definition* baseline diffed in CI before deploy |
| **mcp-warden** (lockfile + drift CI gate) | CI / pre-commit | *drift* — the declared tool/resource/prompt surface changing after a human approved it (rug-pull / silent redefinition) | it does not judge whether a brand-new definition is malicious, and it does not mediate or inspect live runtime behavior as its core job |

## When to use which

### Use mcp-scan when…

…you are seeing a server (or a new tool definition) for the **first time** and
want to know whether its descriptions, schemas, or flows look malicious before
you ever approve them. A scanner answers *"is this content dangerous?"* — a
question a drift gate deliberately does not answer.

### Use a gateway when…

…you need to **mediate live traffic** between agents and servers: enforce auth,
apply rate limits and request/response policy, isolate servers, or get runtime
observability. A gateway is the only layer that sees and can act on calls *in
flight*.

### Use mcp-warden when…

…you want a **reproducible, human-approved baseline that fails the build when the
surface changes**. mcp-warden pins the declared `(name, description, inputSchema)`
surface into a signed `warden.lock` (RFC 8785 JCS + SHA-256) and exits non-zero in
CI on any drift — the rug-pull gate that keeps a *previously approved* surface
honest over time. See the [quickstart](quickstart.md) and
[how to pin in CI](pin-in-ci.md).

## Run them together

These layers cover different gaps, so the recommendation is to **run mcp-warden
alongside a scanner and/or a gateway**, not instead of them:

- **Scanner + mcp-warden** — the scanner vets a surface the first time; mcp-warden
  freezes the approved surface and fails CI if it ever changes without review.
  Note that mcp-scan also offers tool-change detection; mcp-warden's distinct
  contribution is a *committed, reproducible, signed* baseline that gates the
  build deterministically and emits SARIF to code scanning.
- **Gateway + mcp-warden** — the gateway polices runtime traffic; mcp-warden
  ensures the *definitions* that reach the gateway are the ones a human approved.
- **All three** — scan on first sight, gate drift in CI, mediate at runtime. No
  single layer covers the others' gaps.

mcp-warden does **not** replace mcp-scan or any gateway, and makes no claim to.
Each tool above is good at its own job; pick the layers you need and combine them.

!!! warning "What this does NOT cover"
    mcp-warden owns the pin-and-drift layer only. It does **not** statically
    classify new definitions (use a scanner), does **not** mediate runtime traffic
    as its core job (use a gateway), and makes **no compliance or regulatory
    claim**. Read the limits in the
    [threat model](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/THREAT_MODEL.md).

---

*Sources: [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan),
[ContextForge](https://github.com/IBM/mcp-context-forge),
[Lunar MCPX](https://www.lunar.dev/),
[TrueFoundry](https://www.truefoundry.com/),
[Docker MCP Gateway](https://docs.docker.com/ai/mcp-gateway/). Descriptions reflect
each tool's stated scope; no performance claims about other tools are made here.*
