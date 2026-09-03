/**
 * Drift classification — SPEC.md §8.2 / §8.3. A faithful port of
 * `mcp_warden/schema_diff.diff_skeletons` and `mcp_warden/drift.compute_drift`,
 * including emission order, the final `(target, drift_class)` sort, and the
 * secret-redaction rule for `detail`.
 */

import type { Lock, LockPromptEntry, LockResourceEntry, LockToolEntry, BuiltLock, BuiltTool } from "./lock.js";
import { cmpCodepoint, deepEqual, pyJsonDumps, pyRepr, pyStr } from "./py.js";
import type { PropFacts, Skeleton } from "./skeleton.js";

export interface SchemaChange {
  path: string;
  change_class: string;
  severity: string;
  detail: string;
}

export interface DriftItem {
  drift_class: string;
  severity: string;
  target: string;
  message: string;
  detail: string | null;
}

const SECRET_HINTS = ["secret", "token", "password", "apikey", "api_key", "key", "bearer"];
const RELAX_WHEN_HIGHER = ["maxLength", "maximum"];
const RELAX_WHEN_LOWER = ["minLength", "minimum"];
const RELAX_WHEN_REMOVED = ["pattern", "format"];
const RELAX = "schema-constraint-relaxed";
const TIGHTEN = "schema-constraint-tightened";

function looksSecret(value: unknown): boolean {
  const s = pyStr(value).toLowerCase();
  return SECRET_HINTS.some((h) => s.includes(h));
}

function safe(value: unknown, limit = 40): string {
  if (looksSecret(value)) return "<redacted>";
  const s = pyStr(value);
  const cps = Array.from(s);
  return cps.length > limit ? cps.slice(0, limit).join("") + "…" : s;
}

function isUnconstrained(f: PropFacts): boolean {
  if (f.enum && f.enum.length) return false;
  const c = f.constraints;
  if ((c["pattern"] ?? null) !== null || (c["maxLength"] ?? null) !== null) return false;
  if (f.type === null) return true;
  return f.type.every((t) => t === "string" || t === "object");
}

function change(path: string, cls: string, severity: string, detail: string): SchemaChange {
  return { path, change_class: cls, severity, detail };
}

function diffType(path: string, b: PropFacts, c: PropFacts): SchemaChange[] {
  const bt = new Set(b.type ?? []);
  const ct = new Set(c.type ?? []);
  if (bt.size === ct.size && [...bt].every((t) => ct.has(t))) return [];
  const show = (s: Set<string>) => (s.size ? pyRepr([...s].sort(cmpCodepoint)) : "any");
  const detail = `type ${show(bt)}→${show(ct)}`;
  if (!bt.size || !ct.size) {
    if (!bt.size && ct.size) return [change(path, "schema-type-narrowed", "low", detail)];
    return [change(path, "schema-type-broadened", "high", detail)];
  }
  const bSub = [...bt].every((t) => ct.has(t));
  const cSub = [...ct].every((t) => bt.has(t));
  if (bSub && bt.size < ct.size) return [change(path, "schema-type-broadened", "high", detail)];
  if (cSub && ct.size < bt.size) return [change(path, "schema-type-narrowed", "low", detail)];
  return [change(path, "schema-type-changed", "medium", detail)];
}

// Membership uses Python's `json.dumps(v, sort_keys=True)` text, exactly like the reference.
function enumKeySet(values: unknown[]): Set<string> {
  return new Set(values.map((v) => pyJsonDumps(v)));
}

function diffEnum(path: string, b: PropFacts, c: PropFacts): SchemaChange[] {
  const be = b.enum;
  const ce = c.enum;
  if (deepEqual(be, ce)) return [];
  if (be !== null && ce === null) return [change(path, "schema-enum-removed", "high", "enum removed")];
  if (be === null && ce !== null) return [change(path, "schema-enum-added", "low", "enum added")];
  const bs = enumKeySet(be ?? []);
  const cs = enumKeySet(ce ?? []);
  const detail = `enum ${(be ?? []).length}→${(ce ?? []).length} values`;
  const bSub = [...bs].every((k) => cs.has(k));
  const cSub = [...cs].every((k) => bs.has(k));
  if (bSub && bs.size < cs.size) return [change(path, "schema-enum-widened", "high", detail)];
  if (cSub && cs.size < bs.size) return [change(path, "schema-enum-narrowed", "low", detail)];
  return [change(path, "schema-enum-widened", "high", detail)];
}

function num(value: unknown): number | null {
  return typeof value === "number" ? value : null;
}

function diffNumeric(path: string, key: string, bv: number | null, cv: number | null, relaxUp: boolean): SchemaChange[] {
  if (bv === null && cv === null) return [];
  if (bv === null) return [change(path, TIGHTEN, "low", `${key} added ${safe(cv)}`)];
  if (cv === null) return [change(path, RELAX, "medium", `${key} removed`)];
  if (cv === bv) return [];
  const relaxed = relaxUp ? cv > bv : cv < bv;
  return relaxed ? [change(path, RELAX, "medium", `${key} ${safe(bv)}→${safe(cv)}`)] : [change(path, TIGHTEN, "low", `${key} ${safe(bv)}→${safe(cv)}`)];
}

function diffConstraints(path: string, b: PropFacts, c: PropFacts): SchemaChange[] {
  const out: SchemaChange[] = [];
  const bc = b.constraints;
  const cc = c.constraints;

  for (const marker of ["$ref", "_truncated"]) {
    const bv = bc[marker] ?? null;
    const cv = cc[marker] ?? null;
    if (!deepEqual(bv, cv)) out.push(change(path, "schema-modified", "high", `${marker} ${safe(bv)}→${safe(cv)}`));
  }

  const bAp = "additionalProperties" in bc ? bc["additionalProperties"] : true;
  const cAp = "additionalProperties" in cc ? cc["additionalProperties"] : true;
  const bOpen = bAp !== false;
  const cOpen = cAp !== false;
  if (!bOpen && cOpen) out.push(change(path, "schema-additional-props-opened", "high", `additionalProperties ${safe(bAp)}→${safe(cAp)}`));
  else if (bOpen && !cOpen) out.push(change(path, TIGHTEN, "low", `additionalProperties ${safe(bAp)}→${safe(cAp)}`));

  for (const key of RELAX_WHEN_HIGHER) out.push(...diffNumeric(path, key, num(bc[key]), num(cc[key]), true));
  for (const key of RELAX_WHEN_LOWER) out.push(...diffNumeric(path, key, num(bc[key]), num(cc[key]), false));

  for (const key of RELAX_WHEN_REMOVED) {
    const bv = bc[key] ?? null;
    const cv = cc[key] ?? null;
    if (deepEqual(bv, cv)) continue;
    if (bv !== null && cv === null) out.push(change(path, RELAX, "medium", `${key} removed`));
    else if (bv === null) out.push(change(path, TIGHTEN, "low", `${key} added`));
    else out.push(change(path, TIGHTEN, "low", `${key} changed`));
  }
  return out;
}

function classifyAdded(path: string, f: PropFacts): SchemaChange {
  if (f.required) {
    if (isUnconstrained(f)) return change(path, "schema-required-unconstrained-added", "high", "new required unconstrained");
    return change(path, "schema-required-added", "medium", "new required constrained");
  }
  if (isUnconstrained(f)) return change(path, "schema-unconstrained-added", "high", "new optional unconstrained");
  return change(path, "schema-property-added", "low", "new optional constrained");
}

/** Per-fact structural diff of two skeletons, sorted by (path, change_class). */
export function diffSkeletons(base: Skeleton, cur: Skeleton): SchemaChange[] {
  const out: SchemaChange[] = [];
  const bpaths = base.props;
  const cpaths = cur.props;

  for (const path of Object.keys(cpaths)) if (!(path in bpaths)) out.push(classifyAdded(path, cpaths[path]));
  for (const path of Object.keys(bpaths)) {
    if (path in cpaths) continue;
    const f = bpaths[path];
    out.push(
      f.required
        ? change(path, "schema-required-removed", "high", "required property removed")
        : change(path, "schema-property-removed", "medium", "optional property removed"),
    );
  }

  for (const path of Object.keys(bpaths)) {
    if (!(path in cpaths)) continue;
    const b = bpaths[path];
    const c = cpaths[path];
    if (b.required && !c.required) out.push(change(path, RELAX, "medium", "required→optional"));
    else if (!b.required && c.required) {
      out.push(
        isUnconstrained(c)
          ? change(path, "schema-required-unconstrained-added", "high", "optional→required unconstrained")
          : change(path, "schema-required-added", "medium", "optional→required"),
      );
    }
    out.push(...diffType(path, b, c));
    out.push(...diffEnum(path, b, c));
    out.push(...diffConstraints(path, b, c));
  }

  out.sort((x, y) => cmpCodepoint(x.path, y.path) || cmpCodepoint(x.change_class, y.change_class));
  return out;
}

function item(drift_class: string, severity: string, target: string, message: string, detail: string | null = null): DriftItem {
  return { drift_class, severity, target, message, detail };
}

function indexBy<T>(entries: T[], key: (e: T) => string): Map<string, T> {
  const m = new Map<string, T>();
  for (const e of entries) m.set(key(e), e);
  return m;
}

function sortedKeys(m: Map<string, unknown>): string[] {
  return [...m.keys()].sort(cmpCodepoint);
}

function diffToolSchema(name: string, target: string, b: LockToolEntry, c: BuiltTool): DriftItem[] {
  if (b.schema_skeleton === null || c.schema_skeleton === null) {
    return [item("schema-modified", "high", target, `Tool '${name}' inputSchema changed`)];
  }
  const changes = diffSkeletons(b.schema_skeleton, c.schema_skeleton);
  if (!changes.length) {
    return [item("schema-cosmetic-modified", "low", target, `Tool '${name}' inputSchema changed cosmetically (no structural change)`)];
  }
  return changes.map((ch) => item(ch.change_class, ch.severity, target, `Tool '${name}' schema ${ch.change_class} at '${ch.path}'`, ch.detail));
}

function diffTools(baseline: LockToolEntry[], current: BuiltTool[]): DriftItem[] {
  const items: DriftItem[] = [];
  const base = indexBy(baseline, (t) => t.name);
  const cur = indexBy(current, (t) => t.name);

  for (const name of sortedKeys(cur)) if (!base.has(name)) items.push(item("tool-added", "high", `tools/${name}`, `Tool '${name}' added since pin`));
  for (const name of sortedKeys(base)) if (!cur.has(name)) items.push(item("tool-removed", "medium", `tools/${name}`, `Tool '${name}' removed since pin`));

  for (const name of sortedKeys(base)) {
    const c = cur.get(name);
    if (!c) continue;
    const b = base.get(name) as LockToolEntry;
    const target = `tools/${name}`;

    const schemaChanged = b.input_schema_hash !== c.input_schema_hash;
    if (schemaChanged) items.push(...diffToolSchema(name, target, b, c));

    const bCaps = new Set(b.capabilities);
    const cCaps = new Set(c.capabilities);
    const addedCaps = [...cCaps].filter((x) => !bCaps.has(x)).sort(cmpCodepoint);
    const removedCaps = [...bCaps].filter((x) => !cCaps.has(x)).sort(cmpCodepoint);
    for (const cap of addedCaps) items.push(item("capability-added", "high", target, `Tool '${name}' gained capability '${cap}'`));
    for (const cap of removedCaps) items.push(item("capability-removed", "medium", target, `Tool '${name}' lost capability '${cap}'`));

    // The current side is built from a live surface and never carries an inspection block.
    if (b.inspection !== null) {
      items.push(item("inspection-policy-modified", "medium", target, `Tool '${name}' inspection policy changed (security-relevant relaxation/tightening)`));
    }

    if (b.description_hash !== c.description_hash && !schemaChanged && !addedCaps.length && !removedCaps.length) {
      items.push(item("description-modified", "low", target, `Tool '${name}' description changed`));
    }
  }
  return items;
}

function diffResources(baseline: LockResourceEntry[], current: LockResourceEntry[]): DriftItem[] {
  const items: DriftItem[] = [];
  const base = indexBy(baseline, (r) => r.uri);
  const cur = indexBy(current, (r) => r.uri);
  for (const uri of sortedKeys(cur)) if (!base.has(uri)) items.push(item("resource-added", "medium", `resources/${uri}`, `Resource '${uri}' added`));
  for (const uri of sortedKeys(base)) if (!cur.has(uri)) items.push(item("resource-removed", "low", `resources/${uri}`, `Resource '${uri}' removed`));
  for (const uri of sortedKeys(base)) {
    const c = cur.get(uri);
    if (c && (base.get(uri) as LockResourceEntry).entry_digest !== c.entry_digest) {
      items.push(item("resource-modified", "low", `resources/${uri}`, `Resource '${uri}' modified`));
    }
  }
  return items;
}

function diffPrompts(baseline: LockPromptEntry[], current: LockPromptEntry[]): DriftItem[] {
  const items: DriftItem[] = [];
  const base = indexBy(baseline, (p) => p.name);
  const cur = indexBy(current, (p) => p.name);
  for (const name of sortedKeys(cur)) if (!base.has(name)) items.push(item("prompt-added", "medium", `prompts/${name}`, `Prompt '${name}' added`));
  for (const name of sortedKeys(base)) if (!cur.has(name)) items.push(item("prompt-removed", "low", `prompts/${name}`, `Prompt '${name}' removed`));
  for (const name of sortedKeys(base)) {
    const c = cur.get(name);
    if (c && (base.get(name) as LockPromptEntry).entry_digest !== c.entry_digest) {
      items.push(item("prompt-modified", "low", `prompts/${name}`, `Prompt '${name}' modified`));
    }
  }
  return items;
}

/** The full drift set between a stored baseline and a lock built from the observed surface. */
export function computeDrift(baseline: Lock, current: BuiltLock): DriftItem[] {
  if (baseline.overall_digest === current.overall_digest) return [];

  const items: DriftItem[] = [];
  if (baseline.server.command_digest !== current.server.command_digest) {
    items.push(item("server-identity", "critical", "launch/command", "Server launch command/args changed since pin (you are pinning a different launch)"));
  }
  items.push(...diffTools(baseline.tools, current.tools));
  items.push(...diffResources(baseline.resources, current.resources));
  items.push(...diffPrompts(baseline.prompts, current.prompts));

  const approvedDigest = baseline.pin.approved_digest;
  if (baseline.pin.approved && approvedDigest !== null && approvedDigest !== current.overall_digest) {
    items.push(item("unapproved-change", "high", "pin/approved_digest", "Surface changed since approval; approved_digest no longer matches the current surface"));
    if (current.schema_version > baseline.schema_version) {
      items.push(
        item(
          "schema-version-migrated",
          "low",
          "pin/approved_digest",
          `Lock schema version migrated v${baseline.schema_version}→v${current.schema_version}; the approved_digest changed because the lock's schema-format upgraded. This advisory does NOT excuse or downgrade the accompanying 'unapproved-change' finding: review and re-pin to re-attest the surface under schema v${current.schema_version}.`,
        ),
      );
    }
  }

  items.sort((x, y) => cmpCodepoint(x.target, y.target) || cmpCodepoint(x.drift_class, y.drift_class));
  return items;
}
