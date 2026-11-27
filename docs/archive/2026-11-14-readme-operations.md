# README operator examples archived 2026-11-14

Preserved from the README to keep its overview bounded. Run the commands below
from the repository root.

## Policy (design-time only)

`policy` **lints** a YAML policy and **evaluates a single provided sample call**.
It does **not** intercept live calls — there is no runtime enforcement in v0.1
(deferred to v0.2). Fail-closed defaults: `shell_exec.allow=false`,
`http_request.deny_private=true` (SSRF ranges), `sql_query.allow_readonly_only=true`,
empty `allow_paths` = deny-all. See [`docs/POLICY_MODEL.md`](../POLICY_MODEL.md).

```bash
.venv/bin/mcp-warden policy eval policy.yaml ssrf_sample.json
#  -> deny: host 169.254.169.254 is in deny_private range 169.254.0.0/16  (exit 1)
```

---

## Tests

```bash
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python -m pytest -q
```

The headline test is a real stdio round-trip: spawn the clean fixture → `pin` →
re-run `check` against the mutated fixture → assert non-zero exit + the expected
drift + SARIF finding.

The live runtime attack surface — the stdio JSON-RPC **framer**, the ANSI/control
**stripper**, the exfil-**domain** matcher, and the secret **redactor** — is
additionally **property-fuzzed** with [`hypothesis`](https://hypothesis.works/)
under `tests/fuzz/` (construction-based liveness + soundness properties: a
known-malicious input IS detected, and the parser never invents, leaks, or
misclassifies). The deep soak runs via `make fuzz`; see
[`CONTRIBUTING.md`](../../CONTRIBUTING.md#fuzzing).

