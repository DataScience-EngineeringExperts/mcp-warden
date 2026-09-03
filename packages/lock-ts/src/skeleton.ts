/**
 * Structural schema skeleton — SPEC.md §7.5. A faithful port of
 * `mcp_warden/schema_diff.extract_skeleton` (schema_version 3: in-document `$ref`
 * is followed; remote / sibling-keyed / cyclic refs degrade to opaque leaves).
 *
 * Invariants preserved from the reference:
 *   - pure and order-independent (everything sorted by code point);
 *   - absent `additionalProperties` normalizes to `true`;
 *   - never throws on cyclic / malformed / non-object input.
 */

import { cmpCodepoint, isPlainObject, pyJsonDumps, pyRepr, pyStr, pyTypeName, pyUnquote } from "./py.js";

export interface PropFacts {
  type: string[] | null;
  required: boolean;
  enum: unknown[] | null;
  constraints: Record<string, unknown>;
}

export interface Skeleton {
  props: Record<string, PropFacts>;
}

export const MAX_DEPTH = 64;
export const MAX_REFS = 256;
export const ROOT_PATH = "$root";

const CONSTRAINT_KEYS = ["maxLength", "minLength", "minimum", "maximum", "pattern", "format", "additionalProperties"] as const;

const OPAQUE = Symbol("opaque");
const CYCLE = Symbol("cycle");

function normalizeType(raw: unknown): string[] | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "string") return [raw];
  if (Array.isArray(raw)) {
    const names = [...new Set(raw.filter((t): t is string => typeof t === "string"))].sort(cmpCodepoint);
    return names.length ? names : null;
  }
  return null;
}

function enumKey(v: unknown): string {
  try {
    return pyJsonDumps(v);
  } catch {
    return pyRepr(v);
  }
}

function normalizeEnum(raw: unknown): unknown[] | null {
  if (!Array.isArray(raw)) return null;
  return [...raw].sort((a, b) => cmpCodepoint(pyTypeName(a), pyTypeName(b)) || cmpCodepoint(enumKey(a), enumKey(b)));
}

function extractConstraints(schema: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of CONSTRAINT_KEYS) {
    if (Object.prototype.hasOwnProperty.call(schema, key)) out[key] = schema[key];
  }
  if (!("additionalProperties" in out)) out["additionalProperties"] = true;
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => cmpCodepoint(a, b)));
}

function resolveInDocRef(ref: string, root: unknown, refPath: ReadonlySet<string>): Record<string, unknown> | typeof OPAQUE | typeof CYCLE {
  try {
    if (!isPlainObject(root)) return OPAQUE;
    if (!ref.startsWith("#") || ref === "#") return OPAQUE;
    if (refPath.has(ref)) return CYCLE;
    if (refPath.size >= MAX_REFS) return OPAQUE;
    const frag = pyUnquote(ref.slice(1));
    if (frag === "") return OPAQUE;
    const raw = frag.split("/");
    if (raw[0] !== "") return OPAQUE;
    const segments = raw.slice(1).map((s) => s.replaceAll("~1", "/").replaceAll("~0", "~"));
    let cur: unknown = root;
    for (const seg of segments) {
      if (isPlainObject(cur)) {
        if (Object.prototype.hasOwnProperty.call(cur, seg)) cur = cur[seg];
        else return OPAQUE;
      } else if (Array.isArray(cur)) {
        if (/^[0-9]+$/.test(seg) && (seg === "0" || !seg.startsWith("0")) && Number(seg) < cur.length) cur = cur[Number(seg)];
        else return OPAQUE;
      } else {
        return OPAQUE;
      }
    }
    return isPlainObject(cur) ? cur : OPAQUE;
  } catch {
    return OPAQUE;
  }
}

function leaf(required: boolean, constraints: Record<string, unknown>): PropFacts {
  return { type: null, required, enum: null, constraints };
}

function walk(
  schema: unknown,
  path: string,
  required: boolean,
  props: Record<string, PropFacts>,
  visited: ReadonlySet<object>,
  depth: number,
  root: Record<string, unknown> | null,
  refPath: ReadonlySet<string>,
): void {
  const nodeKey = path || ROOT_PATH;

  if (!isPlainObject(schema)) {
    if (path) props[path] = { type: null, required: false, enum: null, constraints: { additionalProperties: true } };
    return;
  }

  if ("$ref" in schema) {
    if (Object.keys(schema).length !== 1) {
      props[nodeKey] = leaf(required, { $ref: pyStr(schema["$ref"]) });
      return;
    }
    const ref = schema["$ref"];
    if (typeof ref !== "string") {
      props[nodeKey] = leaf(required, { $ref: pyStr(ref) });
      return;
    }
    const resolved = resolveInDocRef(ref, root, refPath);
    if (resolved === OPAQUE) {
      props[nodeKey] = leaf(required, { $ref: ref });
      return;
    }
    if (resolved === CYCLE) {
      props[nodeKey] = leaf(required, { _truncated: true });
      return;
    }
    walk(resolved, path, required, props, visited, depth + 1, root, new Set([...refPath, ref]));
    return;
  }

  if (depth > MAX_DEPTH || visited.has(schema)) {
    props[nodeKey] = leaf(required, { _truncated: true });
    return;
  }
  const seen = new Set(visited);
  seen.add(schema);

  props[nodeKey] = {
    type: normalizeType(schema["type"]),
    required,
    enum: normalizeEnum(schema["enum"]),
    constraints: extractConstraints(schema),
  };

  const properties = schema["properties"];
  if (isPlainObject(properties)) {
    const reqRaw = schema["required"];
    const reqSet = new Set(Array.isArray(reqRaw) ? reqRaw.filter((r): r is string => typeof r === "string") : []);
    for (const key of Object.keys(properties).sort(cmpCodepoint)) {
      walk(properties[key], path ? `${path}.${key}` : key, reqSet.has(key), props, seen, depth + 1, root, refPath);
    }
  }

  const items = schema["items"];
  if (isPlainObject(items)) {
    walk(items, path ? `${path}[]` : "[]", false, props, seen, depth + 1, root, refPath);
  }
}

/** Extract the normalized structural skeleton of a tool inputSchema (never throws). */
export function extractSkeleton(inputSchema: unknown): Skeleton {
  const props: Record<string, PropFacts> = {};
  const root = isPlainObject(inputSchema) ? inputSchema : null;
  try {
    walk(inputSchema, "", false, props, new Set(), 0, root, new Set());
  } catch {
    // never propagate — degrade to a partial skeleton
  }
  const ordered: Record<string, PropFacts> = {};
  for (const p of Object.keys(props).sort(cmpCodepoint)) ordered[p] = props[p];
  return { props: ordered };
}

/** Normalize a skeleton read from a lock file (pydantic defaults for absent fields). */
export function skeletonFromJson(raw: unknown): Skeleton | null {
  if (raw === null || raw === undefined) return null;
  if (!isPlainObject(raw)) throw new TypeError("schema_skeleton must be an object or null");
  const rawProps = raw["props"];
  const props: Record<string, PropFacts> = {};
  if (rawProps !== undefined) {
    if (!isPlainObject(rawProps)) throw new TypeError("schema_skeleton.props must be an object");
    for (const [path, f] of Object.entries(rawProps)) {
      if (!isPlainObject(f)) throw new TypeError(`schema_skeleton.props.${path} must be an object`);
      const type = f["type"];
      const en = f["enum"];
      const constraints = f["constraints"];
      props[path] = {
        type: type === undefined || type === null ? null : (type as string[]),
        required: f["required"] === undefined ? false : Boolean(f["required"]),
        enum: en === undefined || en === null ? null : (en as unknown[]),
        constraints: constraints === undefined ? {} : (constraints as Record<string, unknown>),
      };
    }
  }
  return { props };
}
