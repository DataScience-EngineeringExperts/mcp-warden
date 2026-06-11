# The MCP Lock Format

`warden.lock` is not a private mcp-warden file format — it is an instance of a
**vendor-neutral specification, the MCP Lock Format v1**, that any tool may
implement. Owning the *format* (not just the tool) is what lets the drift gate
become a shared standard rather than one project's internal contract.

## What the format is

The MCP Lock Format v1 records the **declared surface** of an MCP server — the
names, descriptions, input schemas, and derived capability flags it advertises
over the `initialize` / `tools/list` / `resources/list` / `prompts/list`
handshake — and produces a **reproducible digest** over that surface so that any
later change ("drift") is detectable deterministically.

It is defined in normative, implementation-independent terms:

- **Canonicalization** — RFC 8785 JSON Canonicalization Scheme (JCS).
- **Hashing** — SHA-256, written as `sha256:<hex>`.
- **Digests** — per-field, per-entry, and an `overall_digest` over the whole
  surface, so a single byte change anywhere produces a different overall digest.
- **Drift definition** — a normative classification of *how* a surface differs
  from a stored baseline (added / removed / modified entries, schema loosening,
  capability change, identity change), with severities.

Two tools that implement the format correctly will compute the **same digest over
the same declared surface** — that byte-reproducibility is the conformance bar.

## Read the full specification

The complete, normative specification is the source of truth and lives in the
repository:

- **[MCP Lock Format v1 — `docs/SPEC.md`](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/SPEC.md)**

It covers the file format and location, server identity, the per-entry schema
(tool / resource / prompt), field / entry / overall digest construction, the
drift class and severity table, the optional per-tool inspection block, a
conformance section, and a minimal worked-example lock.

The mcp-warden-specific implementation details (how *this* tool realizes the
format) are documented separately in
[`docs/WARDEN_LOCK_SCHEMA.md`](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/WARDEN_LOCK_SCHEMA.md),
which references `SPEC.md` as the format source of truth. A short, concrete
example lock is in
[`docs/WARDEN_LOCK_EXAMPLE.md`](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/WARDEN_LOCK_EXAMPLE.md).

## What the format is for — and is not

The format records *declared-surface integrity* only. A matching digest means the
declared surface is byte-identical to the approved baseline — **nothing more**. It
is explicitly **not**:

- a description, attestation, or constraint on runtime behavior;
- a statement that a server is safe, correct, or trustworthy at execution time;
- a verification of the *contents* of the launched binary;
- a compliance or regulatory artifact.

!!! warning "What this does NOT cover"
    The lock format covers declared-surface integrity only. It does **not** attest
    runtime behavior, does **not** judge whether a surface is benign, and makes
    **no compliance or regulatory claim**. Read the limits in the
    [threat model](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/THREAT_MODEL.md).
