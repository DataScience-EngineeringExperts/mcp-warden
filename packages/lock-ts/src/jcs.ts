/**
 * RFC 8785 — JSON Canonicalization Scheme (JCS), hand-written and dependency-free.
 *
 * Rules (RFC 8785 §3):
 *   - object keys sorted by UTF-16 code units (JavaScript's native string order);
 *   - arrays keep their order; no insignificant whitespace anywhere;
 *   - numbers serialize exactly as ES6 `Number.prototype.toString` (`1e21` -> `1e+21`,
 *     `1.0` -> `1`, `-0` -> `0`); non-finite numbers are not JSON and are rejected;
 *   - strings escape only `"` `\` and the controls U+0000–U+001F (short forms for
 *     \b \f \n \r \t, `\u00xx` lowercase otherwise) — everything else, including
 *     non-ASCII, DEL and U+2028/2029, is emitted literally. This is precisely what
 *     `JSON.stringify` does for a string, so it is reused for that one job.
 *
 * `undefined` object values are treated as absent (never emitted), matching the
 * SPEC.md §4 absent-key rule.
 */

import { cmpUtf16, isPlainObject } from "./py.js";

export class JcsError extends Error {}

function serialize(v: unknown): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new JcsError("non-finite number is not JSON");
      if (Object.is(v, -0)) return "0";
      return String(v);
    case "string":
      return JSON.stringify(v);
    case "object": {
      if (Array.isArray(v)) return "[" + v.map((el) => serialize(el === undefined ? null : el)).join(",") + "]";
      if (isPlainObject(v)) {
        const keys = Object.keys(v)
          .filter((k) => v[k] !== undefined)
          .sort(cmpUtf16);
        return "{" + keys.map((k) => JSON.stringify(k) + ":" + serialize(v[k])).join(",") + "}";
      }
      throw new JcsError(`unsupported object ${Object.prototype.toString.call(v)}`);
    }
    default:
      throw new JcsError(`unsupported type ${typeof v}`);
  }
}

/** Return the RFC 8785 canonical text of a JSON value. */
export function canonicalize(value: unknown): string {
  return serialize(value);
}
