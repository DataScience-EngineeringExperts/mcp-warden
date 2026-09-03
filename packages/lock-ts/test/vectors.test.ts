/**
 * Run the language-neutral conformance corpus (`vectors/`) against this package.
 * `MCP_LOCK_VECTORS_DIR` overrides the corpus location (the CI mutation proof
 * points it at a copy with one flipped digest and expects this file to fail).
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildFromSurface, canonicalize, computeDrift, hashValue, parseLock } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = process.env["MCP_LOCK_VECTORS_DIR"] ?? path.resolve(here, "../../../../vectors");

interface Entry {
  id: string;
  kind: "canonical" | "digest" | "drift" | "malformed";
  file: string;
}

const manifest = JSON.parse(readFileSync(path.join(VECTORS, "manifest.json"), "utf8")) as {
  format: string;
  count: number;
  vectors: Entry[];
};

function load(entry: Entry): Record<string, unknown> {
  return JSON.parse(readFileSync(path.join(VECTORS, entry.file), "utf8")) as Record<string, unknown>;
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
    const expect = v["expect"] as Record<string, unknown>;
    switch (entry.kind) {
      case "canonical": {
        assert.equal(canonicalize(v["input"]), expect["jcs"]);
        assert.equal(hashValue(v["input"]), expect["sha256"]);
        break;
      }
      case "digest": {
        const built = JSON.parse(JSON.stringify(buildFromSurface(v["surface"] as never))) as Record<string, unknown>;
        assert.deepEqual((built["server"] as Record<string, unknown>)["command_digest"], (expect["server"] as Record<string, unknown>)["command_digest"]);
        assert.deepEqual(built["tools"], expect["tools"]);
        assert.deepEqual(built["resources"], expect["resources"]);
        assert.deepEqual(built["prompts"], expect["prompts"]);
        assert.equal(built["overall_digest"], expect["overall_digest"]);
        break;
      }
      case "drift": {
        const lock = parseLock(v["lock"]);
        const got = computeDrift(lock, buildFromSurface(v["surface"] as never)).map((d) => ({
          drift_class: d.drift_class,
          severity: d.severity,
          target: d.target,
          detail: d.detail,
        }));
        assert.deepEqual(got, v["expect"]);
        break;
      }
      case "malformed": {
        assert.deepEqual(expect, { error: true });
        assert.throws(() => {
          const doc = "lock_text" in v ? JSON.parse(v["lock_text"] as string) : v["lock"];
          parseLock(doc);
        });
        break;
      }
      default:
        assert.fail(`unknown vector kind ${String(entry.kind)}`);
    }
  });
}
