# What is MCP tool poisoning?

**Tool poisoning** is an attack on the *definitions* an MCP server advertises.
An MCP server tells a client what tools it offers by returning, for each tool, a
`name`, a `description`, and an `inputSchema`. The agent's model reads those
descriptions to decide when and how to call a tool. A poisoned tool definition
hides instructions or capability changes in that metadata so the model behaves
in ways the user never intended.

## How the attack works

Invariant Labs first documented this class as **Tool Poisoning Attacks**: an
attacker embeds instructions inside a tool's `description` field that are visible
to the language model but easy for a human to miss in a UI that only shows a tool
name. The model treats the hidden text as authoritative and acts on it — for
example, exfiltrating files, reading secrets it was told to "include for context,"
or routing output to an attacker-controlled destination.

The publicly disclosed **WhatsApp MCP exfiltration** case showed the practical
impact: a malicious or compromised MCP server redefined a tool so that, once
trusted, it could siphon a user's WhatsApp message history out to an attacker.
The damage came from the agent acting on a *changed* tool surface that no human
re-reviewed.

Tool poisoning shows up in two forms:

1. **Poisoned at first sight** — the very first definition you ever see already
   contains the malicious content.
2. **Poisoned later (a "rug pull")** — a server you already approved silently
   changes a tool definition afterward. That second form has its own page:
   [What is an MCP rug pull](rug-pull.md).

## What mcp-warden does about it

mcp-warden addresses the **definition-drift** slice of this problem. It pins the
exact declared surface — every tool's `name`, `description`, and `inputSchema` —
into a signed `warden.lock`, then fails CI when any of that metadata changes from
the human-approved baseline:

- A tool gains a new, dangerous capability shape (shell/exec, filesystem write,
  outbound HTTP) → flagged as a capability change.
- A tool's `inputSchema` is loosened (a required field dropped, an enum widened,
  a type broadened, `additionalProperties` opened) → structurally classified and
  failed, not waved through as one opaque change.
- A tool's `description` is rewritten after approval → drift, build fails until a
  human reviews and re-pins.

See the [quickstart](quickstart.md) to run this end to end, and
[Pin MCP servers in CI](pin-in-ci.md) to wire it into a pipeline.

## What mcp-warden does NOT do about it

This is the honest, narrow part. mcp-warden does **not**:

- **Judge whether a definition is malicious.** It detects that the definition
  *changed* from what you approved. Deciding that a brand-new, never-before-seen
  description contains an injection is the job of a static scanner — see
  [`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan) and the
  [comparison page](comparison.md).
- **Inspect runtime behavior.** A poisoned tool that keeps the *same* declared
  definition but misbehaves when called is outside the definition-integrity model.
- **Read injection-y wording.** Fuzzy natural-language detection of "injection
  style" descriptions is deliberately out of scope for the lock.

In short: mcp-warden guarantees the declared surface you run is byte-for-byte the
surface a human approved. It does not certify that the approved surface was benign
in the first place — pair it with a scanner for that.

!!! warning "What this does NOT cover"
    This page covers definition-level integrity only. mcp-warden does **not**
    defend against behavioral / runtime attacks, does **not** statically classify
    new descriptions as malicious, and makes **no compliance or regulatory
    claim**. Read the limits in the
    [threat model](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/THREAT_MODEL.md).
