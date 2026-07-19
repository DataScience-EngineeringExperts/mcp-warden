# Agent Trust Kernel Contract Implementation Plan

> **Status:** Non-normative execution record. The binding security requirements live in
> `docs/AGENT_TRUST_KERNEL.md`.

**Goal:** Define the non-bypassable, deterministic security contract that DSE-715,
DSE-716, and DSE-717 must implement.

**Architecture:** Add one normative umbrella contract for the future Agent Trust Kernel
without rewriting MCP-Warden's shipped v0.1-v1.1 security contracts. Cross-link the new
contract from the documentation index, system context, and existing threat models, and
state clearly that the current runtime is not yet kernel-conformant.

**Tech Stack:** Markdown security contracts, Mermaid system context, repository link and
consistency checks.

---

## Validated design

Three approaches were considered:

1. **New normative umbrella contract (selected).** Keeps the kernel's fail-closed,
   non-bypassable rules separate from the current product's intentional opt-outs and
   fail-open paths. This is the only approach that avoids overstating shipped behavior.
2. **Extend `THREAT_MODEL_V2.md`.** Rejected because that document is a historical MCP
   result-inspection contract and deliberately permits behavior that the kernel forbids.
3. **Implement schemas/APIs first.** Rejected because DSE-715 through DSE-717 would otherwise
   encode incompatible assumptions before the governing invariants exist.

The new contract will define twelve stable `ATK-*` invariants, the trusted computing base,
untrusted inputs, attacker capabilities, fail-closed outcomes, non-overridable critical
classes, offline evaluation, explicit cuts, residual risks, and downstream ticket mappings.
It is a design contract only; conformance remains pending DSE-715 through DSE-717.

### Task 1: Add the normative Agent Trust Kernel contract

**Files:**
- Create: `docs/AGENT_TRUST_KERNEL.md`

**Step 1:** Define status, scope, normative language, and current nonconformance warning.

**Step 2:** Add `ATK-01` through `ATK-12` with unique, testable requirements.

**Step 3:** Add exhaustive trust boundaries, trusted-time ownership, attacker model,
structurally enforced mediation, fail-closed and evidence-degraded recovery matrices,
critical classes, provenance authority, offline contract, explicit cuts, and residual risks.

**Step 4:** Assign one primary owner and secondary bindings to every invariant, record the
DSE-715 → DSE-716 → DSE-717 dependency order, and gate DSE-717 completion on ATK-04.

**Step 5:** Define mechanically executable conformance around authoritative finite adapter
manifests with handler/sink bijection, an instrumented PEP/sink harness, a fixed malformed
corpus, and planted-secret byte scans.

### Task 2: Integrate the contract without rewriting shipped guarantees

**Files:**
- Modify: `DOCUMENTATION_INDEX.md`
- Modify: `SYSTEM_CONTEXT_DIAGRAM.md`
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/THREAT_MODEL_V2.md`

**Step 1:** Add the new contract to the security-contract index.

**Step 2:** Add a dashed, design-only kernel boundary to the system context.

**Step 3:** Add short relationship notes to both threat models that preserve their existing
scope and point forward to the kernel contract.

### Task 3: Verify the contract

**Files:**
- Verify: `docs/AGENT_TRUST_KERNEL.md`
- Verify: `DOCUMENTATION_INDEX.md`
- Verify: `SYSTEM_CONTEXT_DIAGRAM.md`
- Verify: `docs/THREAT_MODEL.md`
- Verify: `docs/THREAT_MODEL_V2.md`

**Step 1:** Run an invariant/mapping scan.

Run: `rg -n 'ATK-(0[1-9]|1[0-2])|DSE-71[5-7]' docs/AGENT_TRUST_KERNEL.md`

Expected: all twelve invariant IDs and all three downstream ticket IDs are present.

**Step 2:** Validate changed Markdown links and Mermaid diagrams explicitly.

Run: a local-link validator across the six changed Markdown files, then:
`mmdc -i docs/AGENT_TRUST_KERNEL.md -o /private/tmp/mcp-warden-dse714-atk.md` and
`mmdc -i SYSTEM_CONTEXT_DIAGRAM.md -o /private/tmp/mcp-warden-dse714-system.md`.

Expected: every relative link resolves to an existing file and Mermaid CLI renders every
diagram without a syntax error.

**Step 3:** Run documentation and whitespace checks.

Run: `/private/tmp/mcp-warden-docs-dse714/bin/mkdocs build --strict --site-dir /private/tmp/mcp-warden-dse714-site && git diff --check`

Expected: both commands exit 0.

**Step 4:** Run the full repository suite.

Run: `PYTHONPATH=src /Users/ernestprovo/dev/mcp-warden/.venv/bin/python -m pytest -q`

Expected: zero failures.

### Task 4: Publish for review

**Step 1:** Stage only the five contract/integration files plus this plan.

**Step 2:** Commit as `docs: define Agent Trust Kernel contract (DSE-714)`.

**Step 3:** Push `codex/dse-714-agent-trust-kernel` and open a draft PR to `main`.

**Step 4:** Add the PR link and verification evidence to DSE-714, then move the ticket to
`In Review`; do not mark it Done before review/merge.
