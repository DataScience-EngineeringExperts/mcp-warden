# Agent gates — runnable examples

Two fail-closed CI gates. Full contract: [`docs/AGENT_GATES.md`](../../docs/AGENT_GATES.md).

## `auth audit` — static MCP auth posture

```bash
mcp-warden auth audit examples/agent-gates/mcp-config-audit-demo.json
```

The demo config has six servers. **Four are flagged, two must not be** — the
non-flags matter as much as the findings, because a gate that cries wolf on
correct configuration gets disabled.

| Server | Verdict |
|--------|---------|
| `filesystem-local` | clean — local stdio server, no auth posture to audit |
| `loopback-dev` | clean — loopback is not remotely reachable |
| `good-citizen` | clean — `${VENDOR_TOKEN}` is a reference, not a literal |
| `internal-http` | `WRD-AUTH-PLAINTEXT-HTTP` (high) + `WRD-AUTH-NOAUTH` (medium) |
| `vendor-api` | `WRD-AUTH-TOKEN-IN-CONFIG` (high) + `WRD-SEC-ENTROPY` (high) |
| `legacy` | `WRD-AUTH-URL-CREDENTIAL` (high) + `WRD-AUTH-NOAUTH` (medium) |

Exits `1` with six findings. Every credential is redacted in output and SARIF.

Static only: no server is spawned, no DNS is resolved, no network is touched.

## `deploy-gate` — release control for agent deploys

```bash
mcp-warden deploy-gate \
  --policy examples/agent-gates/gate-policy.json \
  --evidence examples/agent-gates/evidence-pass.json      # exit 0

mcp-warden deploy-gate \
  --policy examples/agent-gates/gate-policy.json \
  --evidence examples/agent-gates/evidence-fail.json      # exit 1
```

`evidence-fail.json` trips four controls at once: the safety eval regressed
below threshold, a required guardrail was switched off, the budget has no
positive limit, and the approval receipt is unattributed.

The gate **adjudicates evidence — it does not run evals.** Your pipeline runs
them and writes the evidence file; the gate decides deterministically whether
the deploy may proceed. Missing or malformed evidence is a failure, never a
pass.

## In CI

```yaml
- name: MCP auth posture
  run: mcp-warden auth audit .mcp.json --sarif auth.sarif

- name: Agent deploy gate
  run: mcp-warden deploy-gate --policy gate-policy.json --evidence evidence.json --sarif gate.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: auth.sarif
```
