# mcp-warden documentation

**mcp-warden is the lockfile and CI gate for MCP servers.** It pins an MCP
server's declared tool / resource / prompt surface into a signed `warden.lock`,
then fails CI when that surface drifts from a human-approved baseline.

If you already follow the published guidance — *pin versions, hash tool
definitions, alert on drift* — mcp-warden is the deterministic tool that does it.

## The mental model

| Familiar primitive | mcp-warden equivalent |
|--------------------|------------------------|
| `package-lock.json` / `Cargo.lock` — a committed, reproducible lock of what you depend on | `warden.lock` — the same, for an MCP server's *declared surface* |
| `gitleaks` in CI — a deterministic, exit-non-zero gate | `mcp-warden check` — the same, for MCP surface drift (with SARIF → code scanning) |
| `Dependabot` / pin-then-review — a human approves an upstream change before it lands | `pin --approve` + the drift gate force a human in the loop on any MCP rug-pull |

## Where to start

- **[Quickstart](quickstart.md)** — install → pin → check → wire the GitHub Action, in under 5 minutes.
- **[What is MCP tool poisoning](tool-poisoning.md)** — the attack, and the narrow slice of it mcp-warden addresses.
- **[What is an MCP rug pull](rug-pull.md)** — a silent surface change after approval, and how the drift gate catches it.
- **[Pin MCP servers in CI](pin-in-ci.md)** — GitHub Actions + GitLab CI, the pin-once / check-on-PR pattern.
- **[MCP security checklist](checklist.md)** — a vendor-neutral checklist with the tool for each layer.
- **[The MCP Lock Format](lock-format.md)** — the vendor-neutral on-disk format any tool can implement.
- **[Comparison vs scanners & gateways](comparison.md)** — how mcp-warden, mcp-scan, and gateways are complementary layers.

!!! warning "What this does NOT cover"
    mcp-warden is an MCP supply-chain integrity gate, **not a full agent
    firewall**. It verifies the *declared* surface returned by `tools/list` /
    `resources/list` / `prompts/list`; it does **not** defend against behavioral
    attacks at runtime and makes **no compliance or regulatory claim** of any
    kind. Read the limits first in the
    [threat model](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/THREAT_MODEL.md).
