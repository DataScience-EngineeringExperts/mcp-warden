# MCP security checklist

A practical, vendor-neutral checklist for teams adopting MCP servers in
production. It mirrors the published guidance (Invariant, OWASP, NSA, OWASP MCP
Top 10) — *pin versions, hash tool definitions, alert on drift, review before
re-pin, scan results at runtime*. Each item links the mcp-warden command that
does it where one applies, and **names a complementary tool where mcp-warden is
not the right layer.** No single tool covers this list — that is the point.

## Before you trust a server

- [ ] **Pin the server to a specific version/ref, never a floating tag.** Launch
      via a pinned version (`@1.2.3`), not `latest` or an unpinned `npx`/`uvx`/`pip`
      install. mcp-warden flags unpinned supply-chain refs (`WRD-SUP-*`) at pin
      time, but the actual pinning happens in *your* launch argv and lockfiles —
      pair this with your package manager's lockfile (`package-lock.json`,
      `uv.lock`, etc.).
- [ ] **Statically scan the tool definitions on first sight.** Before you ever
      approve a surface, check the descriptions and schemas for injection-style
      content and known-bad patterns. mcp-warden does **not** judge whether a
      brand-new definition is malicious — use a static scanner such as
      [`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan) for this. See the
      [comparison](comparison.md).
- [ ] **Review the declared capability surface.** Understand what each tool can do
      (shell/exec, filesystem read/write, outbound HTTP, SQL) before approving.
      mcp-warden surfaces dangerous capability shapes deterministically
      (`WRD-CAP-*`) at pin time so they are explicit in the review.
- [ ] **Check for secrets leaked into definitions.** Tokens or keys baked into a
      tool description or default are a finding. mcp-warden runs regex + entropy
      checks (`WRD-SEC-*`) and always redacts the snippet it reports.

## Establish and protect the baseline

- [ ] **Hash the approved tool definitions into a committed lock.** Capture the
      `(name, description, inputSchema)` surface into a reproducible, signed
      baseline. mcp-warden:
      `mcp-warden pin <server argv> --approve --approver you@example.com --lock warden.lock`,
      then commit `warden.lock`.
- [ ] **Require a human approval on the baseline.** The lock records *who*
      approved the surface and *when*. mcp-warden's `pin --approve --approver`
      captures that provenance; re-attest without re-capturing via
      `mcp-warden lock rotate`.

## Alert on drift, continuously

- [ ] **Fail CI when the declared surface drifts from the approved baseline.**
      This is the rug-pull gate. mcp-warden:
      `mcp-warden check <server argv> --lock warden.lock --sarif warden.sarif`
      exits non-zero on any drift. Wire it into [CI](pin-in-ci.md).
- [ ] **Run the same verdict locally before CI.** Catch drift at commit time, not
      in the pipeline. mcp-warden ships a pre-commit hook
      ([example config](https://github.com/ernestprovo23/mcp-warden/blob/main/examples/pre-commit/.pre-commit-config.yaml))
      that reuses the identical drift path as `check`.
- [ ] **Surface findings where your team already looks.** mcp-warden emits SARIF
      (`--sarif`) that uploads straight to GitHub code scanning, so drift shows up
      as a code-scanning alert rather than buried CI logs.

## Review before re-pinning

- [ ] **Never re-pin a drifted surface automatically.** When `check` fails, a
      human reviews the diff and decides. mcp-warden classifies each change
      (schema loosening, capability change, added/removed tool, identity change)
      with a severity so the review is concrete, then you re-pin deliberately.

## At runtime

- [ ] **Scan / mediate tool results and live traffic at runtime.** Definition
      integrity is not behavioral integrity. For runtime mediation — auth, rate
      limits, request/response policy on live calls — use a **runtime gateway**
      (ContextForge, Lunar MCPX, TrueFoundry, Docker MCP Gateway). See the
      [comparison](comparison.md).
- [ ] **Inspect suspicious tool *results* for exfil / control-sequence tricks.**
      mcp-warden's optional `guard` proxy and offline `inspect` run a deterministic
      result-inspection catalog (`WRD-RES-*`: ANSI/control escapes, echoed secrets,
      exfil domains) — useful, but it is *result* inspection, not a behavioral
      firewall, and a dedicated gateway is the broader runtime layer.

## What no tool on this list gives you

- [ ] **A guarantee of runtime behavior.** Every layer above works on
      definitions, results, or traffic — none of them certifies what a tool
      *actually does* internally when called.
- [ ] **A compliance attestation.** Nothing here "meets" or "certifies" any
      regulation. Treat any tool claiming otherwise with skepticism.

!!! warning "What this does NOT cover"
    This checklist combines several tools across several layers; mcp-warden owns
    only the pin-and-drift items. mcp-warden does **not** defend behavioral /
    runtime attacks, does **not** statically classify new definitions, and makes
    **no compliance or regulatory claim**. Read the limits in the
    [threat model](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/THREAT_MODEL.md).
