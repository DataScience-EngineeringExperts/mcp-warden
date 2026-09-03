/**
 * Lock document model — SPEC.md §3, §6, §7, §8.1 — plus a strict reader and the
 * surface -> hashed-entries builder that `verify` compares against a baseline.
 */

import { deriveCapabilities } from "./capabilities.js";
import { hashArguments, hashDescription, hashInputSchema, hashValue } from "./digest.js";
import { cmpCodepoint, isPlainObject } from "./py.js";
import { extractSkeleton, skeletonFromJson, type Skeleton } from "./skeleton.js";

/** The format level this verifier implements (SPEC.md §14). */
export const SCHEMA_VERSION = 3;

export class LockFormatError extends Error {}

export interface LockToolEntry {
  name: string;
  description_hash: string;
  input_schema_hash: string;
  capabilities: string[];
  inspection: Record<string, unknown> | null;
  schema_skeleton: Skeleton | null;
  entry_digest: string;
}

export interface LockResourceEntry {
  uri: string;
  name: string | null;
  description_hash: string;
  mime_type: string | null;
  entry_digest: string;
}

export interface LockPromptEntry {
  name: string;
  description_hash: string;
  arguments_hash: string;
  entry_digest: string;
}

export interface Lock {
  schema_version: number;
  warden_version: string;
  server: { command: string; args: string[]; url: string | null; command_digest: string };
  tools: LockToolEntry[];
  resources: LockResourceEntry[];
  prompts: LockPromptEntry[];
  findings: unknown[];
  overall_digest: string;
  pin: { approved: boolean; approved_digest: string | null; [k: string]: unknown };
}

/** An observed declared surface, in MCP wire naming (see vectors/README.md). */
export interface Surface {
  command?: string;
  args?: string[];
  url?: string | null;
  tools?: Array<{ name: string; description?: string | null; inputSchema?: unknown }>;
  resources?: Array<{ uri: string; name?: string | null; description?: string | null; mimeType?: string | null }>;
  prompts?: Array<{ name: string; description?: string | null; arguments?: unknown[] | null }>;
}

/** A tool entry built from a live surface (never carries an inspection block). */
export interface BuiltTool {
  name: string;
  description_hash: string;
  input_schema_hash: string;
  capabilities: string[];
  schema_skeleton: Skeleton;
  entry_digest: string;
}

export interface BuiltLock {
  schema_version: number;
  server: { command_digest: string };
  tools: BuiltTool[];
  resources: LockResourceEntry[];
  prompts: LockPromptEntry[];
  overall_digest: string;
}

// --- strict reader -----------------------------------------------------------

function fail(msg: string): never {
  throw new LockFormatError(msg);
}

function str(o: Record<string, unknown>, key: string, where: string): string {
  const v = o[key];
  if (typeof v !== "string") fail(`${where}.${key} must be a string`);
  return v;
}

function strOrNull(o: Record<string, unknown>, key: string, where: string): string | null {
  if (!(key in o)) fail(`${where}.${key} is required (may be null)`);
  const v = o[key];
  if (v === null) return null;
  if (typeof v !== "string") fail(`${where}.${key} must be a string or null`);
  return v;
}

function arr(o: Record<string, unknown>, key: string, where: string): unknown[] {
  const v = o[key];
  if (!Array.isArray(v)) fail(`${where}.${key} must be an array`);
  return v;
}

function obj(v: unknown, where: string): Record<string, unknown> {
  if (!isPlainObject(v)) fail(`${where} must be an object`);
  return v;
}

function toolEntry(raw: unknown, i: number): LockToolEntry {
  const o = obj(raw, `tools[${i}]`);
  const w = `tools[${i}]`;
  const caps = arr(o, "capabilities", w);
  if (!caps.every((c) => typeof c === "string")) fail(`${w}.capabilities must be strings`);
  const inspection = o["inspection"];
  if (inspection !== undefined && inspection !== null && !isPlainObject(inspection)) fail(`${w}.inspection must be an object or null`);
  let skeleton: Skeleton | null;
  try {
    skeleton = skeletonFromJson(o["schema_skeleton"]);
  } catch (e) {
    fail(`${w}.schema_skeleton: ${(e as Error).message}`);
  }
  return {
    name: str(o, "name", w),
    description_hash: str(o, "description_hash", w),
    input_schema_hash: str(o, "input_schema_hash", w),
    capabilities: caps as string[],
    inspection: inspection === undefined || inspection === null ? null : inspection,
    schema_skeleton: skeleton,
    entry_digest: str(o, "entry_digest", w),
  };
}

function resourceEntry(raw: unknown, i: number): LockResourceEntry {
  const w = `resources[${i}]`;
  const o = obj(raw, w);
  return {
    uri: str(o, "uri", w),
    name: strOrNull(o, "name", w),
    description_hash: str(o, "description_hash", w),
    mime_type: strOrNull(o, "mime_type", w),
    entry_digest: str(o, "entry_digest", w),
  };
}

function promptEntry(raw: unknown, i: number): LockPromptEntry {
  const w = `prompts[${i}]`;
  const o = obj(raw, w);
  return {
    name: str(o, "name", w),
    description_hash: str(o, "description_hash", w),
    arguments_hash: str(o, "arguments_hash", w),
    entry_digest: str(o, "entry_digest", w),
  };
}

/** Parse and structurally validate a lock document; throws `LockFormatError` (fail closed). */
export function parseLock(doc: unknown): Lock {
  const o = obj(doc, "lock");
  const sv = o["schema_version"];
  if (typeof sv !== "number" || !Number.isInteger(sv) || sv < 1) fail("schema_version must be a positive integer");
  const server = obj(o["server"], "server");
  const args = server["args"] === undefined ? [] : arr(server, "args", "server");
  if (!args.every((a) => typeof a === "string")) fail("server.args must be strings");
  const url = server["url"];
  if (url !== undefined && url !== null && typeof url !== "string") fail("server.url must be a string or null");
  const pin = obj(o["pin"], "pin");
  for (const key of ["created_at", "warden_version", "mcp_protocol_version"]) str(pin, key, "pin");
  const approved = pin["approved"] === undefined ? false : pin["approved"];
  if (typeof approved !== "boolean") fail("pin.approved must be a boolean");
  const approvedDigest = pin["approved_digest"] === undefined ? null : pin["approved_digest"];
  if (approvedDigest !== null && typeof approvedDigest !== "string") fail("pin.approved_digest must be a string or null");

  return {
    schema_version: sv,
    warden_version: str(o, "warden_version", "lock"),
    server: {
      command: server["command"] === undefined ? "" : str(server, "command", "server"),
      args: args as string[],
      url: url === undefined ? null : url,
      command_digest: str(server, "command_digest", "server"),
    },
    tools: arr(o, "tools", "lock").map(toolEntry),
    resources: arr(o, "resources", "lock").map(resourceEntry),
    prompts: arr(o, "prompts", "lock").map(promptEntry),
    findings: arr(o, "findings", "lock"),
    overall_digest: str(o, "overall_digest", "lock"),
    pin: { ...pin, approved, approved_digest: approvedDigest },
  };
}

// --- builder -----------------------------------------------------------------

/** SPEC.md §8.1: the overall digest over server identity + the sorted entry digests. */
export function overallDigest(
  schemaVersion: number,
  commandDigest: string,
  tools: Array<{ entry_digest: string }>,
  resources: Array<{ entry_digest: string }>,
  prompts: Array<{ entry_digest: string }>,
): string {
  return hashValue({
    schema_version: schemaVersion,
    server: { command_digest: commandDigest },
    tools: tools.map((t) => t.entry_digest),
    resources: resources.map((r) => r.entry_digest),
    prompts: prompts.map((p) => p.entry_digest),
  });
}

/** Hash an observed surface into the entries a lock would store (SPEC.md §6–§8). */
export function buildFromSurface(surface: Surface): BuiltLock {
  const commandDigest = surface.url
    ? hashValue({ url: surface.url })
    : hashValue({ command: surface.command ?? "", args: surface.args ?? [] });

  const tools: BuiltTool[] = (surface.tools ?? [])
    .map((t) => {
      const schema = isPlainObject(t.inputSchema) ? t.inputSchema : null;
      const body = {
        name: t.name,
        description_hash: hashDescription(t.description),
        input_schema_hash: hashInputSchema(schema),
        capabilities: deriveCapabilities(t.name, schema),
        schema_skeleton: extractSkeleton(t.inputSchema),
      };
      return { ...body, entry_digest: hashValue(body) };
    })
    .sort((a, b) => cmpCodepoint(a.name, b.name));

  const resources: LockResourceEntry[] = (surface.resources ?? [])
    .map((r) => {
      const body = {
        uri: r.uri,
        name: r.name ?? null,
        description_hash: hashDescription(r.description),
        mime_type: r.mimeType ?? null,
      };
      return { ...body, entry_digest: hashValue(body) };
    })
    .sort((a, b) => cmpCodepoint(a.uri, b.uri));

  const prompts: LockPromptEntry[] = (surface.prompts ?? [])
    .map((p) => {
      const body = {
        name: p.name,
        description_hash: hashDescription(p.description),
        arguments_hash: hashArguments(p.arguments),
      };
      return { ...body, entry_digest: hashValue(body) };
    })
    .sort((a, b) => cmpCodepoint(a.name, b.name));

  return {
    schema_version: SCHEMA_VERSION,
    server: { command_digest: commandDigest },
    tools,
    resources,
    prompts,
    overall_digest: overallDigest(SCHEMA_VERSION, commandDigest, tools, resources, prompts),
  };
}
