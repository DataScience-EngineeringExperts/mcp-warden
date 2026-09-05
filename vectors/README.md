# MCP Lock Format v1 — conformance vectors

This directory is the **language-neutral definition of a conforming implementation**
of [MCP Lock Format v1](../docs/SPEC.md). An implementation conforms **if and only if**
it reproduces every vector here (SPEC.md §12). Two implementations ship in this repo and
both run this corpus in CI: the Python reference (`src/mcp_warden`, via
`tests/test_spec_vectors.py`) and the zero-dependency TypeScript verifier
(`packages/lock-ts`).

The corpus is **generated from the Python reference**, not hand-written:

```bash
.venv/bin/python vectors/tools/generate.py
```

Regenerate deliberately and review the diff — a changed expected value means a hashed
derivation changed, which is a `schema_version` bump per SPEC.md §14.2, never a silent
edit.

## Layout

```
vectors/
  manifest.json        # index: {format, schema_version, count, vectors:[{id, kind, file}]}
  cases/<kind>-<id>.json
  tools/generate.py    # regenerates everything above from the reference implementation
```

Every case file is self-contained: `{"id", "kind", "description", ...inputs, "expect"}`.

## Vector kinds

| kind | inputs | `expect` | what it pins |
|------|--------|----------|--------------|
| `canonical` | `input` — any JSON value | `{jcs, sha256}` — the RFC 8785 text and `sha256:<hex>` of its UTF-8 bytes | SPEC.md §4–§5: UTF-16 key order, ES6 number formatting, escaping rules, the three absence digests |
| `digest` | `surface` — a declared surface (below) | `{server.command_digest, tools[], resources[], prompts[], overall_digest}` — the full hashed entries exactly as a lock stores them | §5.1 absence rules, §6 server identity, §7 entry digests incl. `capabilities` + `schema_skeleton`, §7 sorting, §8.1 overall digest |
| `drift` | `lock` — a complete baseline lock document; `surface` — the observed surface | ordered list of `{drift_class, severity, target, detail}` | §8.2 / §8.3: every drift class, severities, per-fact emission, `(target, drift_class)` ordering, detail redaction |
| `malformed` | `lock` (a JSON document) or `lock_text` (raw text) — **or** `input_json` (the JSON text of a value for the canonicalizer) | `{"error": true}` | a conforming reader MUST reject the lock (fail closed); with `input_json`, the canonicalizer MUST refuse the value (unpaired surrogates, excessive nesting) rather than produce a digest |

`drift` compares only the four fields above; human-readable messages are implementation
wording and are not part of the contract.

## The surface document

Vectors describe an observed surface with **MCP wire naming**, so no implementation's
internal model leaks into the corpus:

```jsonc
{
  "command": "node", "args": ["./server.js"],   // OR  "url": "https://host/mcp"
  "tools":     [ { "name", "description"?, "inputSchema"? } ],
  "resources": [ { "uri", "name"?, "description"?, "mimeType"? } ],
  "prompts":   [ { "name", "description"?, "arguments"? } ]
}
```

A missing key means "absent" and triggers the §5.1 absence rule for that field.

## Consuming the corpus from a third implementation

1. Read `manifest.json`; iterate `vectors`, loading each `file`.
2. For each kind, compute the value(s) described above and compare to `expect`
   **byte-for-byte** (digests are lowercase hex; `jcs` is compared as a UTF-8 string).
3. Treat any mismatch as non-conformance. Do not "fix" a vector to match your output —
   open an issue against the reference instead.
4. Run the `digest`, `drift` and `malformed` vectors through your **public verify entry
   point**, not only the primitives — the reference harnesses do (`verify()` in
   `packages/lock-ts`), because a duck-typed shortcut in the public API is exactly the
   defect a corpus exists to catch. A `malformed` lock MUST make verification fail
   closed (throw / non-zero), never yield "no drift".

Both shipped harnesses honour `MCP_LOCK_VECTORS_DIR=<dir>` to point at another copy of
the corpus; the CI `conformance` job uses that to prove a single flipped hex character
fails **both** implementations.

## Known scope boundaries

- **Integers beyond ±(2^53 − 1) are outside the interoperable subset.** The Python
  reference refuses them (`rfc8785` raises "exceeds safe integer domain"); JavaScript
  cannot even represent them exactly (`2**63` parses to `9223372036854776000`). Vectors
  never contain such integers; a surface that does is not portable and the reference
  will not digest it. Integer-valued *floats* such as `1e21` are fine and are pinned.
- **Nesting is bounded at 512 — normative (SPEC.md §4).** Depth counts enclosing
  arrays/objects with the root at 0. `canonical/depth-512-accepted` MUST canonicalize and
  `malformed/depth-513-rejected` MUST be refused; both the Python reference (`canon()`,
  `read_lock()`) and the TypeScript verifier enforce the same explicit bound.
  `malformed/deep-nesting-2000` remains as the coarse guard. An implementation that only
  relies on its runtime's recursion limit is not conformant.

- Enum ordering inside `schema_skeleton` keys on Python's `json.dumps` text of each value.
  JavaScript cannot distinguish `1.0` from `1`, so vectors never put integer-valued
  floats in an `enum`; a third implementation in a language with that distinction
  should follow the Python rule (`1.0` serialises as `1.0`).
- Capability tokenization splits on `[_\-.\s]` and camelCase boundaries; `\s` is the
  implementation language's Unicode whitespace class. Vectors use ASCII identifiers.
- The `$ref` resolver percent-decodes the fragment before RFC 6901 unescaping; vectors
  use well-formed percent-escapes only.
