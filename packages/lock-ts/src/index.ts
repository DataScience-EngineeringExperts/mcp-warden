/**
 * @mcp-warden/lock — zero-dependency verifier for MCP Lock Format v1.
 *
 * Verify-only by design: this package never spawns a server, never touches the
 * network, and needs no MCP SDK. Feed it a `warden.lock` document and the surface
 * you observed (`tools/list` / `resources/list` / `prompts/list`), and it tells you
 * whether the surface still matches the approved baseline and, if not, exactly
 * what drifted — with the same rule ids, severities and ordering as the Python
 * reference. Conformance is defined by the corpus under `vectors/`.
 */

import { computeDrift, type DriftItem } from "./drift.js";
import { buildFromSurface, parseLock, type Lock, type Surface } from "./lock.js";

export { canonicalize, JcsError } from "./jcs.js";
export { canon, hashArguments, hashDescription, hashInputSchema, hashValue, SHA256_PREFIX } from "./digest.js";
export { deriveCapabilities, tokenize } from "./capabilities.js";
export { extractSkeleton, ROOT_PATH, type PropFacts, type Skeleton } from "./skeleton.js";
export { computeDrift, diffSkeletons, type DriftItem, type SchemaChange } from "./drift.js";
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

/** Compare an observed surface against a baseline lock (a parsed `Lock` or the raw JSON document). */
export function verify(lock: Lock | unknown, surface: Surface): VerifyResult {
  const baseline = isParsed(lock) ? lock : parseLock(lock);
  const current = buildFromSurface(surface);
  const findings = computeDrift(baseline, current);
  return { ok: findings.length === 0, findings, observed_digest: current.overall_digest };
}

function isParsed(v: unknown): v is Lock {
  return (
    typeof v === "object" &&
    v !== null &&
    "tools" in v &&
    Array.isArray((v as Lock).tools) &&
    (v as Lock).tools.every((t) => t !== null && typeof t === "object" && "schema_skeleton" in t && (t.schema_skeleton === null || "props" in (t.schema_skeleton as object))) &&
    "pin" in v &&
    typeof (v as Lock).pin === "object" &&
    "approved_digest" in (v as Lock).pin
  );
}
