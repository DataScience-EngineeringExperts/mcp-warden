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
 *     `JSON.stringify` does for a well-formed string, so it is reused for that job.
 *
 * `undefined` object values are treated as absent (never emitted), matching the
 * SPEC.md §4 absent-key rule.
 *
 * Fail-closed rules (security review of #99). The digest is a security contract, so
 * anything the reference would refuse must be refused here too — never turned into
 * a plausible-looking digest the reference can never agree with:
 *   - only JSON-shaped input serializes: arrays and plain objects (prototype
 *     `Object.prototype` or `null`). `Date`, `Map`, `Buffer` and class instances
 *     throw `JcsError` instead of silently canonicalizing to `{}` or a byte table;
 *   - an unpaired UTF-16 surrogate throws `JcsError`. It has no UTF-8 encoding, the
 *     reference (`rfc8785`) rejects it, and `JSON.stringify` would otherwise emit
 *     `\ud800` — valid JSON text, wrong digest;
 *   - nesting deeper than `MAX_JSON_DEPTH` throws `JcsError`, bounding the recursion
 *     an attacker-supplied surface can drive (the reference raises at a similar depth).
 */

import { cmpUtf16, isJsonObject, MAX_JSON_DEPTH } from "./py.js";

export class JcsError extends Error {}

/** True when `s` contains a high surrogate not followed by a low one, or a stray low one. */
export function hasUnpairedSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d < 0xdc00 || d > 0xdfff) return true;
      i++; // well-formed pair: skip the low surrogate
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function jsonString(s: string): string {
  if (hasUnpairedSurrogate(s)) throw new JcsError("unpaired UTF-16 surrogate is not Unicode text");
  return JSON.stringify(s);
}

function serialize(v: unknown, depth: number): string {
  if (depth > MAX_JSON_DEPTH) throw new JcsError(`nesting deeper than ${MAX_JSON_DEPTH} levels`);
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new JcsError("non-finite number is not JSON");
      if (Object.is(v, -0)) return "0";
      return String(v);
    case "string":
      return jsonString(v);
    case "object": {
      if (Array.isArray(v)) {
        return "[" + v.map((el) => serialize(el === undefined ? null : el, depth + 1)).join(",") + "]";
      }
      if (isJsonObject(v)) {
        const keys = Object.keys(v)
          .filter((k) => v[k] !== undefined)
          .sort(cmpUtf16);
        return "{" + keys.map((k) => jsonString(k) + ":" + serialize(v[k], depth + 1)).join(",") + "}";
      }
      throw new JcsError(`unsupported object ${Object.prototype.toString.call(v)}`);
    }
    default:
      throw new JcsError(`unsupported type ${typeof v}`);
  }
}

/** Return the RFC 8785 canonical text of a JSON value; throws `JcsError` on anything that is not one. */
export function canonicalize(value: unknown): string {
  return serialize(value, 0);
}
