/**
 * @mcp-warden/lock — zero-dependency verifier for MCP Lock Format v1.
 *
 * Verify-only by design: this package never spawns a server, never touches the
 * network, and needs no MCP SDK. Feed it a `warden.lock` document and the surface
 * you observed (`tools/list` / `resources/list` / `prompts/list`), and it tells you
 * whether the surface still matches the approved baseline and, if not, exactly
 * what drifted — with the same rule ids, severities and ordering as the Python
 * reference. Conformance is defined by the corpus under `vectors/`.
 *
 * Fail-closed contract: `verify()` ALWAYS runs the strict reader (`parseLock`) on
 * the lock it is given — a document a conforming reader must reject (missing
 * `overall_digest`, a `schema_version` above the level this package implements,
 * malformed entries, excessive nesting) throws `LockFormatError` and can never
 * produce `ok: true`. There is no duck-typed "already parsed" shortcut.
 */

import { computeDrift, type DriftItem } from "./drift.js";
import { buildFromSurface, parseLock, type Surface } from "./lock.js";

export { canonicalize, hasUnpairedSurrogate, JcsError } from "./jcs.js";
export { canon, hashArguments, hashDescription, hashInputSchema, hashValue, SHA256_PREFIX } from "./digest.js";
export { deriveCapabilities, tokenize } from "./capabilities.js";
export { extractSkeleton, ROOT_PATH, type PropFacts, type Skeleton } from "./skeleton.js";
export { computeDrift, diffSkeletons, type DriftItem, type SchemaChange } from "./drift.js";
export { deepEqual, DepthError, MAX_JSON_DEPTH } from "./py.js";
export {
  buildFromSurface,
  LockFormatError,
  overallDigest,
  parseLock,
  SCHEMA_VERSION,
  type BuiltLock,
  type BuiltTool,
  type Lock,
  type LockPromptEntry,
  type LockResourceEntry,
  type LockToolEntry,
  type Surface,
} from "./lock.js";

export interface VerifyResult {
  /** `true` when the observed surface is byte-identical to the baseline (no drift). */
  ok: boolean;
  /** Ordered drift items; empty when `ok`. Any non-empty set means a verifier MUST fail. */
  findings: DriftItem[];
  /** The `overall_digest` recomputed from the observed surface. */
  observed_digest: string;
}

/** The `overall_digest` an implementation would write for this surface (SPEC.md §8.1). */
export function digest(surface: Surface): string {
  return buildFromSurface(surface).overall_digest;
}

/**
 * Compare an observed surface against a baseline lock document.
 *
 * `lock` is the raw JSON document (or a `Lock` previously returned by `parseLock`,
 * which re-validates identically). Throws `LockFormatError` if the document is not
 * a structurally valid lock at a level this package implements — fail closed.
 */
export function verify(lock: unknown, surface: Surface): VerifyResult {
  const baseline = parseLock(lock);
  const current = buildFromSurface(surface);
  const findings = computeDrift(baseline, current);
  return { ok: findings.length === 0, findings, observed_digest: current.overall_digest };
}
