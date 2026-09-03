/**
 * Hashing — SPEC.md §5: `"sha256:" + lowercase_hex(SHA256(canon(value)))`, plus
 * the §5.1 absence rules (absent description -> "", inputSchema -> {}, arguments -> []).
 */

import { createHash } from "node:crypto";
import { canonicalize } from "./jcs.js";

export const SHA256_PREFIX = "sha256:";

/** Return the canonical UTF-8 bytes of a JSON value. */
export function canon(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), "utf8");
}

/** `sha256:<64 lowercase hex>` over the canonical form of `value`. */
export function hashValue(value: unknown): string {
  return SHA256_PREFIX + createHash("sha256").update(canon(value)).digest("hex");
}

export function hashDescription(description: string | null | undefined): string {
  return hashValue(description ?? "");
}

export function hashInputSchema(inputSchema: Record<string, unknown> | null | undefined): string {
  return hashValue(inputSchema ?? {});
}

export function hashArguments(args: unknown[] | null | undefined): string {
  return hashValue(args ?? []);
}
