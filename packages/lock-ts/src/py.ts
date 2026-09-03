/**
 * Small shims that reproduce Python semantics the reference implementation
 * leans on — string ordering, `json.dumps`, `str()`/`repr()` — so this verifier
 * agrees with `src/mcp_warden` byte-for-byte on the conformance corpus.
 *
 * Only the subset the lock format actually exercises is implemented; every
 * function here is pure and total on JSON-shaped input within `MAX_JSON_DEPTH`;
 * `deepEqual` throws `DepthError` beyond it (security review of #99).
 */

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A JSON object proper: a plain object whose prototype is `Object.prototype` or `null`.
 *  `Date`, `Map`, `Buffer` and class instances are NOT JSON and must never canonicalize. */
export function isJsonObject(v: unknown): v is Record<string, unknown> {
  if (!isPlainObject(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** Maximum nesting any JSON value may have before the verifier refuses it (fail closed). */
export const MAX_JSON_DEPTH = 512;

export class DepthError extends Error {}

/** Throw `DepthError` if `v` nests deeper than `MAX_JSON_DEPTH`. */
export function checkDepth(v: unknown, where: string, depth = 0): void {
  if (depth > MAX_JSON_DEPTH) throw new DepthError(`${where}: nesting deeper than ${MAX_JSON_DEPTH} levels`);
  if (Array.isArray(v)) {
    for (const el of v) checkDepth(el, where, depth + 1);
  } else if (isPlainObject(v)) {
    for (const k of Object.keys(v)) checkDepth(v[k], where, depth + 1);
  }
}

/** Python `str` ordering: compare by Unicode code point (NOT UTF-16 code unit). */
export function cmpCodepoint(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const x = ia.next();
    const y = ib.next();
    if (x.done && y.done) return 0;
    if (x.done) return -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0) as number;
    const cy = y.value.codePointAt(0) as number;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

/** RFC 8785 key ordering: compare by UTF-16 code unit (JavaScript's native `<`). */
export function cmpUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** `type(v).__name__` for a JSON value parsed by Python's `json` module. */
export function pyTypeName(v: unknown): string {
  if (v === null || v === undefined) return "NoneType";
  switch (typeof v) {
    case "boolean":
      return "bool";
    case "number":
      // JSON `1.0` is indistinguishable from `1` here; see vectors/README.md.
      return Number.isInteger(v) ? "int" : "float";
    case "string":
      return "str";
    default:
      return Array.isArray(v) ? "list" : "dict";
  }
}

function pyNumber(v: number): string {
  if (Object.is(v, -0)) return "-0.0";
  return String(v);
}

/** `json.dumps(v, sort_keys=True, ensure_ascii=False)` with Python's default separators. */
export function pyJsonDumps(v: unknown): string {
  if (v === null || v === undefined) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      return pyNumber(v);
    case "string":
      return JSON.stringify(v);
    default:
      if (Array.isArray(v)) return "[" + v.map(pyJsonDumps).join(", ") + "]";
      if (isPlainObject(v)) {
        const keys = Object.keys(v).sort(cmpCodepoint);
        return "{" + keys.map((k) => JSON.stringify(k) + ": " + pyJsonDumps(v[k])).join(", ") + "}";
      }
      return JSON.stringify(String(v));
  }
}

function pyStrRepr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    const cp = ch.codePointAt(0) as number;
    if (ch === "\\") out += "\\\\";
    else if (ch === quote) out += "\\" + quote;
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (cp < 0x20 || cp === 0x7f) out += "\\x" + cp.toString(16).padStart(2, "0");
    else out += ch;
  }
  return out + quote;
}

/** Python `repr()` of a JSON value. */
export function pyRepr(v: unknown): string {
  if (v === null || v === undefined) return "None";
  switch (typeof v) {
    case "boolean":
      return v ? "True" : "False";
    case "number":
      return pyNumber(v);
    case "string":
      return pyStrRepr(v);
    default:
      if (Array.isArray(v)) return "[" + v.map(pyRepr).join(", ") + "]";
      if (isPlainObject(v)) {
        return "{" + Object.keys(v).map((k) => pyStrRepr(k) + ": " + pyRepr(v[k])).join(", ") + "}";
      }
      return String(v);
  }
}

/** Python `str()`: identity for str, `True`/`False` for bool, number text, else `repr()`. */
export function pyStr(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return v ? "True" : "False";
  if (typeof v === "number") return pyNumber(v);
  return pyRepr(v);
}

/** Structural equality for JSON values, treating `undefined` as `null`. */
export function deepEqual(a: unknown, b: unknown, depth = 0): boolean {
  if (depth > MAX_JSON_DEPTH) throw new DepthError(`deepEqual: nesting deeper than ${MAX_JSON_DEPTH} levels`);
  const x = a === undefined ? null : a;
  const y = b === undefined ? null : b;
  if (x === y) return true;
  if (typeof x !== typeof y) return false;
  if (Array.isArray(x)) {
    if (!Array.isArray(y) || x.length !== y.length) return false;
    return x.every((el, i) => deepEqual(el, y[i], depth + 1));
  }
  if (isPlainObject(x) && isPlainObject(y)) {
    const kx = Object.keys(x).sort();
    const ky = Object.keys(y).sort();
    if (kx.length !== ky.length || kx.some((k, i) => k !== ky[i])) return false;
    return kx.every((k) => deepEqual(x[k], y[k], depth + 1));
  }
  return false;
}

/** `urllib.parse.unquote`: decode %XX runs as UTF-8, replacing malformed bytes; leave stray `%` alone. */
export function pyUnquote(s: string): string {
  return s.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    const bytes = Buffer.from(run.replace(/%/g, ""), "hex");
    return bytes.toString("utf8");
  });
}
