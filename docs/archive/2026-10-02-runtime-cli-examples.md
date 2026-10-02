# Runtime CLI examples

Moved from README on 2026-10-02 to keep the core overview within 500 lines.

### Runtime result inspection (v0.3 — blocks by default)

`guard` sits transparently between an MCP client and server and inspects tool *results*.
**As of v0.3 the deterministic tier blocks out of the box** (council-established field
false-positive rate ~0):

```bash
# Default: ANSI is stripped in place; echoed secrets + exfil domains are error-replaced;
# a mid-session tools/list swap that diverges from warden.lock is blocked (needs --lock);
# an argument-policy deny is blocked (needs --policy). The fuzzy injection tier stays log-only.
mcp-warden guard node ./build/index.js --lock warden.lock --policy policy.yaml --sarif guard.sarif

# Observe-first rollout: --audit-only restores full v0.2 shadow in one flag (detect + log only).
mcp-warden guard node ./build/index.js --lock warden.lock --audit-only

# Opt a single category back to shadow (still detected/logged/SARIF, frame forwarded):
mcp-warden guard node ./build/index.js --no-block-ansi --allow-exfil-domain
# Or shadow the whole deterministic tier + both gates:
mcp-warden guard node ./build/index.js --no-block-deterministic
# Opt INTO the fuzzy injection tier (never default):
mcp-warden guard node ./build/index.js --block-inject-phrase

# Fail-CLOSED (high-security): TERMINATE the session (exit 3, -32003 to the client) if an
# internal inspection (result / argument-policy / tools-list) cannot complete, instead of the
# default fail-open pass-through. Opt-in; integrity over availability.
mcp-warden guard node ./build/index.js --lock warden.lock --policy policy.yaml --strict

# Re-analyze a recorded session offline with the identical rule catalog (always report-only):
mcp-warden inspect session.trace.jsonl --lock warden.lock --sarif inspect.sarif
```

**Flag scheme:** opt-out is canonical `--no-block-<category>`
(`ansi|secret-echo|exfil-domain|list-changed|policy`, plus `--no-block-deterministic` for the
whole tier); `--allow-exfil-domain` is the sole affirmative alias. Precedence:
`--audit-only` > `--no-block-*` > default-block / `--block-inject-phrase`. The v0.2
`--block-*` enable flags are accepted but **inert no-ops** (one-line stderr deprecation note),
so old scripts keep working. **`--strict`** (opt-in, default off) trades availability for
integrity: an internal inspection error at the result / argument-policy / tools-list layer
**terminates the session** (exit `3`, `-32003` non-retriable error to the client) instead of
failing open — framing/EOF/over-cap stay fail-open in all modes (known limitation). Reserved
error codes: **`-32001`** (policy/result block), **`-32002`** (transport/lifecycle), **`-32003`**
(`--strict` abort, non-retriable). See
[`docs/RESULT_INSPECTION.md`](../RESULT_INSPECTION.md),
[`docs/GUARD_PROXY.md`](../GUARD_PROXY.md), and
[`docs/GUARD_PROXY_V3.md`](../GUARD_PROXY_V3.md).

---
