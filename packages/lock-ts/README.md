# @mcp-warden/lock

Zero-dependency **verifier** for [MCP Lock Format v1](../../docs/SPEC.md) — the
`warden.lock` baseline that [mcp-warden](https://github.com/DataScience-EngineeringExperts/mcp-warden)
pins an MCP server's declared tool/resource/prompt surface into.

It is verify-only by design: no server spawn, no network, no MCP SDK. Give it a lock
document and the surface you observed over `tools/list` / `resources/list` /
`prompts/list`, and it returns the same drift items — rule ids, severities, ordering,
redacted detail — as the Python reference. Both implementations pass the shared
conformance corpus under [`vectors/`](../../vectors/README.md) in CI, byte-for-byte.

Requires Node ≥ 20. Runtime dependencies: **none**.

```ts
import { readFileSync } from "node:fs";
import { verify, digest } from "@mcp-warden/lock";

const lock = JSON.parse(readFileSync("warden.lock", "utf8"));

// Whatever you captured from the server — MCP wire naming (inputSchema, mimeType).
const surface = {
  command: "node", args: ["./build/index.js"],
  tools: [{ name: "read_file", description: "Read a file.", inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } }],
  resources: [], prompts: [],
};

const result = verify(lock, surface);
if (!result.ok) {
  for (const d of result.findings) console.error(`WRD-DRIFT-${d.drift_class.toUpperCase()} [${d.severity}] ${d.target}: ${d.message}`);
  process.exit(1);
}
console.log("surface matches baseline", digest(surface));
```

## API

| export | purpose |
|--------|---------|
| `verify(lock, surface) → { ok, findings, observed_digest }` | drift between a baseline lock document and an observed surface; always runs the strict reader first and throws `LockFormatError` — and only `LockFormatError` — on a malformed lock, one at a newer `schema_version`, or an observed surface it cannot canonicalize (unpaired surrogate, nesting past 512); it can never return `ok` for a document a conforming reader must reject |
| `digest(surface) → "sha256:…"` | the `overall_digest` a conforming writer would store for that surface |
| `parseLock(doc)` | strict structural reader; throws `LockFormatError` (fail closed) |
| `buildFromSurface(surface)` | the hashed entries (`entry_digest`, `capabilities`, `schema_skeleton`) for a surface |
| `computeDrift(lock, built)`, `diffSkeletons(a, b)` | the classifier, exposed for tooling |
| `canonicalize(value)`, `hashValue(value)` | RFC 8785 text and `sha256:` digest of any JSON value |
| `extractSkeleton(inputSchema)`, `deriveCapabilities(name, inputSchema)` | the §7.4 / §7.5 derivations |

Any non-empty `findings` means a verifier **must** fail (SPEC.md §8.2). Severity is for
reporting only.

## Scope

This package covers the **format**: canonicalization, hashing, entry digests, drift
classification. Capturing a surface from a live server, Sigstore signature
verification, result inspection (`guard`) and the CI gates stay in the Python CLI.

## Development

```bash
npm ci
npm test        # tsc build + node --test over ../../vectors
```

MIT — see the repository `LICENSE`.
