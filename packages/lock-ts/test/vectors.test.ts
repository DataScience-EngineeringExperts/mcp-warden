/**
 * Run the language-neutral conformance corpus (`vectors/`) against this package.
 * `MCP_LOCK_VECTORS_DIR` overrides the corpus location (the CI mutation proof
 * points it at a copy with one flipped digest and expects this file to fail).
 *
 * Every `digest`, `drift` and `malformed` vector is asserted through the public
 * `verify()` entry point as well as through the lower-level primitives, so the
 * API consumers actually call has full corpus coverage (security review of #99).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildFromSurface,
  canonicalize,
  computeDrift,
  deepEqual,
  DepthError,
  hashValue,
  JcsError,
  LockFormatError,
  MAX_JSON_DEPTH,
  parseLock,
  SCHEMA_VERSION,
  verify,
  type Surface,
} from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = process.env["MCP_LOCK_VECTORS_DIR"] ?? path.resolve(here, "../../../../vectors");

interface Entry {
  id: string;
  kind: "canonical" | "digest" | "drift" | "malformed";
  file: string;
}

type Doc = Record<string, unknown>;

const manifest = JSON.parse(readFileSync(path.join(VECTORS, "manifest.json"), "utf8")) as {
  format: string;
  count: number;
  vectors: Entry[];
};

function load(entry: Entry): Doc {
  return JSON.parse(readFileSync(path.join(VECTORS, entry.file), "utf8")) as Doc;
}

/** Assemble the lock document a producer would have written for a `digest` vector. */
function lockFromDigestVector(v: Doc): Doc {
  const surface = v["surface"] as Surface;
  const expect = v["expect"] as Doc;
  return {
    schema_version: SCHEMA_VERSION,
    warden_version: "0.0.0",
    server: {
      command: surface.command ?? "",
      args: surface.args ?? [],
      url: surface.url ?? null,
      command_digest: (expect["server"] as Doc)["command_digest"],
    },
    tools: expect["tools"],
    resources: expect["resources"],
    prompts: expect["prompts"],
    findings: [],
    overall_digest: expect["overall_digest"],
    pin: {
      created_at: "2026-01-01T00:00:00Z",
      warden_version: "0.0.0",
      mcp_protocol_version: "2025-06-18",
      approved: false,
      approved_digest: null,
    },
  };
}

function driftShape(items: ReturnType<typeof computeDrift>): Doc[] {
  return items.map((d) => ({ drift_class: d.drift_class, severity: d.severity, target: d.target, detail: d.detail }));
}

test("manifest shape", () => {
  assert.equal(manifest.format, "mcp-lock-v1");
  assert.equal(manifest.count, manifest.vectors.length);
  assert.ok(manifest.vectors.length >= 25);
  assert.equal(new Set(manifest.vectors.map((v) => v.id)).size, manifest.vectors.length);
});

for (const entry of manifest.vectors) {
  test(entry.id, () => {
    const v = load(entry);
    const expect = v["expect"] as Doc;
    switch (entry.kind) {
      case "canonical": {
        assert.equal(canonicalize(v["input"]), expect["jcs"]);
        assert.equal(hashValue(v["input"]), expect["sha256"]);
        break;
      }
      case "digest": {
        const surface = v["surface"] as Surface;
        const built = JSON.parse(JSON.stringify(buildFromSurface(surface))) as Doc;
        assert.deepEqual((built["server"] as Doc)["command_digest"], (expect["server"] as Doc)["command_digest"]);
        assert.deepEqual(built["tools"], expect["tools"]);
        assert.deepEqual(built["resources"], expect["resources"]);
        assert.deepEqual(built["prompts"], expect["prompts"]);
        assert.equal(built["overall_digest"], expect["overall_digest"]);
        // Public API: the lock a producer writes for this surface verifies clean.
        const r = verify(lockFromDigestVector(v), surface);
        assert.equal(r.ok, true);
        assert.deepEqual(r.findings, []);
        assert.equal(r.observed_digest, expect["overall_digest"]);
        break;
      }
      case "drift": {
        const surface = v["surface"] as Surface;
        const lock = parseLock(v["lock"]);
        assert.deepEqual(driftShape(computeDrift(lock, buildFromSurface(surface))), v["expect"]);
        // Public API: same ordered set, and `ok` iff the set is empty.
        const r = verify(v["lock"], surface);
        assert.deepEqual(driftShape(r.findings), v["expect"]);
        assert.equal(r.ok, (v["expect"] as unknown[]).length === 0);
        break;
      }
      case "malformed": {
        assert.deepEqual(expect, { error: true });
        if ("input_json" in v) {
          // A JSON value the canonicalizer MUST reject (it parses, but is not Unicode
          // text / is too deep) — the reference raises on the same input.
          assert.throws(() => canonicalize(JSON.parse(v["input_json"] as string)), JcsError);
          break;
        }
        let doc: unknown;
        if ("lock_text" in v) {
          try {
            doc = JSON.parse(v["lock_text"] as string);
          } catch (e) {
            assert.ok(e instanceof SyntaxError, "non-JSON lock text must be a parse failure");
            break;
          }
        } else {
          doc = v["lock"];
        }
        assert.throws(() => parseLock(doc), LockFormatError);
        // The public entry point must fail identically — no duck-typed shortcut.
        assert.throws(() => verify(doc, {}), LockFormatError);
        break;
      }
      default:
        assert.fail(`unknown vector kind ${String(entry.kind)}`);
    }
  });
}

// --- fail-closed unit tests (security review of #99) ---------------------------

const validLock = (): Doc => {
  const first = manifest.vectors.find((e) => e.kind === "drift");
  assert.ok(first, "corpus has at least one drift vector");
  return JSON.parse(JSON.stringify(load(first)["lock"])) as Doc;
};

test("F1: verify() rejects a lock missing overall_digest even when it duck-types as parsed", () => {
  const lock = validLock();
  delete lock["overall_digest"];
  assert.throws(() => verify(lock, {}), LockFormatError);
});

test("F1: verify() re-validates an already-parsed Lock identically", () => {
  const raw = validLock();
  const parsed = parseLock(raw);
  assert.deepEqual(verify(parsed, {}).findings, verify(raw, {}).findings);
});

test("F1: a non-object schema_skeleton is a LockFormatError, not a TypeError", () => {
  const lock = validLock();
  ((lock["tools"] as Doc[])[0] as Doc)["schema_skeleton"] = 42;
  assert.throws(() => verify(lock, {}), LockFormatError);
});

test("F2: a lock at a schema_version above the implemented level is rejected", () => {
  const lock = validLock();
  lock["schema_version"] = SCHEMA_VERSION + 1;
  assert.throws(() => parseLock(lock), LockFormatError);
  assert.throws(() => verify(lock, {}), LockFormatError);
});

test("F3: only JSON-shaped objects canonicalize", () => {
  class Thing {
    x = 1;
  }
  for (const bad of [new Date(0), new Map([["a", 1]]), Buffer.from("x"), new Thing(), new Set([1])]) {
    assert.throws(() => canonicalize(bad), JcsError, Object.prototype.toString.call(bad));
    assert.throws(() => canonicalize({ k: bad }), JcsError);
  }
  assert.equal(canonicalize(Object.create(null)), "{}");
  assert.equal(canonicalize({ b: 1, a: [2] }), '{"a":[2],"b":1}');
});

test("F4: unpaired surrogates are rejected; well-formed pairs are not", () => {
  for (const bad of ["\ud800", "a\udc00b", "\ud83d", "x\ud800\ud800"]) {
    assert.throws(() => canonicalize(bad), JcsError, JSON.stringify(bad));
    assert.throws(() => canonicalize({ [bad]: 1 }), JcsError, "as a key");
  }
  assert.equal(canonicalize("😀"), '"😀"');
});

test("depth: canonicalize, deepEqual and parseLock are bounded", () => {
  const deep = (n: number): unknown => {
    let v: unknown = [];
    for (let i = 0; i < n; i++) v = [v];
    return v;
  };
  assert.doesNotThrow(() => canonicalize(deep(MAX_JSON_DEPTH - 1)));
  assert.throws(() => canonicalize(deep(MAX_JSON_DEPTH + 2)), JcsError);
  assert.throws(() => deepEqual(deep(MAX_JSON_DEPTH + 2), deep(MAX_JSON_DEPTH + 2)), DepthError);
  const lock = validLock();
  ((lock["tools"] as Doc[])[0] as Doc)["schema_skeleton"] = { props: { p: { constraints: { deep: deep(MAX_JSON_DEPTH + 2) } } } };
  assert.throws(() => verify(lock, {}), LockFormatError);
});

// --- DSE-1527: normative nesting bound + verify() error contract -----------------

const nestedArrays = (n: number): unknown => {
  // n enclosing arrays around an empty array: the innermost `[]` sits at depth n.
  let v: unknown = [];
  for (let i = 0; i < n; i++) v = [v];
  return v;
};

test("DSE-1527: the canonicalizer bound is exactly 512 (root = 0)", () => {
  assert.equal(MAX_JSON_DEPTH, 512);
  assert.doesNotThrow(() => canonicalize(nestedArrays(MAX_JSON_DEPTH)));
  assert.throws(() => canonicalize(nestedArrays(MAX_JSON_DEPTH + 1)), JcsError);
  // A leaf counts, and objects count like arrays.
  let obj: unknown = { k: "leaf" };
  for (let i = 0; i < MAX_JSON_DEPTH; i++) obj = { k: obj };
  assert.throws(() => canonicalize(obj), JcsError);
});

test("DSE-1527: verify() throws only LockFormatError, even when the observed surface is unverifiable", () => {
  const lock = validLock();
  const surface = { tools: [{ name: "t", inputSchema: { deep: nestedArrays(MAX_JSON_DEPTH + 5) } }] } as unknown as Surface;
  let caught: unknown;
  try {
    verify(lock, surface);
  } catch (e) {
    caught = e;
  }
  assert.ok(caught instanceof LockFormatError, `expected LockFormatError, got ${String(caught)}`);
  assert.ok(!(caught instanceof JcsError) && !(caught instanceof DepthError), "underlying error type must not leak");
  assert.match((caught as Error).message, /observed surface is not verifiable/);
  // Unpaired surrogate on the observed side takes the same path.
  const bad = { tools: [{ name: "t", inputSchema: { d: "\ud800" } }] } as unknown as Surface;
  assert.throws(() => verify(lock, bad), LockFormatError);
});
