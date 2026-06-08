# `warden.lock` — worked example (illustrative)

Companion to `WARDEN_LOCK_SCHEMA.md` (kept here to keep the schema doc under the
500-line core-doc cap). Illustrative only; digests are truncated and secrets are
redacted. Normative field definitions live in `WARDEN_LOCK_SCHEMA.md` §4–§8.

```json
{
  "schema_version": 1, "warden_version": "0.1.0",
  "server": { "command": "node", "args": ["./build/index.js"], "command_digest": "sha256:3a7f...e21c" },
  "tools": [ { "name": "read_file", "description_hash": "sha256:9b12...44aa",
      "input_schema_hash": "sha256:c0de...7788", "capabilities": ["fs-read"], "entry_digest": "sha256:11ff...0099" } ],
  "resources": [], "prompts": [], "findings": [], "overall_digest": "sha256:aa00...ff11",
  "pin": { "created_at": "2026-06-06T14:22:05Z", "warden_version": "0.1.0", "mcp_protocol_version": "2025-06-18",
    "approved": true, "approver": "ci-bot@example.invalid", "approved_at": "2026-06-06T14:22:06Z",
    "approved_digest": "sha256:aa00...ff11" }
}
```

v0.3 `pin` blocks additionally carry the §8.1 structured-provenance fields
(`provenance_version`, `pinner`, `attestations`, `rotated_at`, `rotation_count`),
all outside `overall_digest`. Pre-#19 locks omit them and read unchanged. A
post-`lock rotate` `pin` block (same `overall_digest`, `rotation_count` bumped):

```json
"pin": {
  "created_at": "2026-06-06T14:22:05Z", "warden_version": "0.3.0",
  "mcp_protocol_version": "2025-06-18", "approved": true,
  "approver": "boss@example.invalid", "approved_at": "2026-06-08T09:00:00Z",
  "approved_digest": "sha256:aa00...ff11",
  "provenance_version": 1,
  "pinner": { "tool": "mcp-warden", "tool_version": "0.3.0", "actor": null, "environment": null },
  "attestations": [
    { "actor": "ci-bot@example.invalid", "role": "approver", "method": "manual",
      "created_at": "2026-06-06T14:22:06Z", "bound_digest": "sha256:aa00...ff11", "note": null },
    { "actor": "boss@example.invalid", "role": "approver", "method": "manual",
      "created_at": "2026-06-08T09:00:00Z", "bound_digest": "sha256:aa00...ff11", "note": "q2 re-attest" }
  ],
  "rotated_at": "2026-06-08T09:00:00Z", "rotation_count": 1
}
```
