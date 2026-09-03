/**
 * Capability derivation — SPEC.md §7.4 / CHECKS.md §3. Mirrors
 * `mcp_warden/tokenizer.py`: segment-exact, case-insensitive, never substring.
 */

import { isPlainObject } from "./py.js";

export const CAP_NAME_TOKENS: Record<string, ReadonlySet<string>> = {
  "shell-exec": new Set(["shell", "exec", "spawn", "system", "subprocess", "sudo", "bash", "sh", "cmd", "powershell"]),
  "fs-write": new Set(["write", "save", "create", "delete", "rm", "unlink", "mkdir", "chmod", "mv", "rename"]),
  "fs-read": new Set(["read", "cat", "open", "load", "get", "list"]),
  "http-request": new Set(["fetch", "http", "request", "curl", "download", "webhook"]),
  "sql-query": new Set(["sql", "query", "execute", "db"]),
};

export const CAP_PROP_TOKENS: Record<string, ReadonlySet<string>> = {
  "shell-exec": new Set(["command", "cmd", "script", "shell"]),
  "fs-write": new Set(["path", "file", "filename", "dest", "target"]),
  "fs-read": new Set(["path", "file", "filename", "src", "source"]),
  "http-request": new Set(["url", "uri", "endpoint", "host", "hostname"]),
  "sql-query": new Set(["query", "sql", "statement"]),
};

export const FS_WRITE_CONTENT_TOKENS: ReadonlySet<string> = new Set(["content", "data", "body", "text", "bytes", "payload"]);

// Explicit delimiters, then camelCase (lower/digit -> Upper) and acronym (HTTPServer -> HTTP, Server) boundaries.
const SEGMENT_SPLIT = /[_\-.\s]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/;

/** Split an identifier into lowercase segments. */
export function tokenize(identifier: string): string[] {
  if (!identifier) return [];
  return identifier
    .split(SEGMENT_SPLIT)
    .filter((p) => p.length > 0)
    .map((p) => p.toLowerCase());
}

export function hasToken(identifier: string, keywords: ReadonlySet<string>): boolean {
  return tokenize(identifier).some((t) => keywords.has(t));
}

function schemaPropertyNames(inputSchema: unknown): string[] {
  if (!isPlainObject(inputSchema)) return [];
  const props = inputSchema["properties"];
  if (!isPlainObject(props)) return [];
  return Object.keys(props);
}

function hasProperty(propNames: string[], keywords: ReadonlySet<string>): boolean {
  return propNames.some((n) => hasToken(n, keywords));
}

/** Sorted, de-duplicated capability flags for a tool (name tokens + inputSchema property names). */
export function deriveCapabilities(name: string, inputSchema: Record<string, unknown> | null | undefined): string[] {
  const propNames = schemaPropertyNames(inputSchema);
  const flags = new Set<string>();

  if (hasToken(name, CAP_NAME_TOKENS["shell-exec"]) || hasProperty(propNames, CAP_PROP_TOKENS["shell-exec"])) {
    flags.add("shell-exec");
  }

  const nameHasWrite = hasToken(name, CAP_NAME_TOKENS["fs-write"]);
  const hasPathProp = hasProperty(propNames, CAP_PROP_TOKENS["fs-write"]);
  const hasContentProp = hasProperty(propNames, FS_WRITE_CONTENT_TOKENS);
  if ((nameHasWrite && hasPathProp) || (hasPathProp && hasContentProp)) flags.add("fs-write");

  if (hasToken(name, CAP_NAME_TOKENS["fs-read"]) && hasProperty(propNames, CAP_PROP_TOKENS["fs-read"])) {
    flags.add("fs-read");
  }

  if (hasToken(name, CAP_NAME_TOKENS["http-request"]) || hasProperty(propNames, CAP_PROP_TOKENS["http-request"])) {
    flags.add("http-request");
  }

  if (hasToken(name, CAP_NAME_TOKENS["sql-query"]) || hasProperty(propNames, CAP_PROP_TOKENS["sql-query"])) {
    flags.add("sql-query");
  }

  return [...flags].sort();
}
