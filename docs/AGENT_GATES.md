# Agent Gates — `deploy-gate` and `auth audit`

Two fail-closed gates that extend mcp-warden past MCP-surface integrity into the
two adjacent controls that agent deployments actually lack in CI: **did the
deploy meet its declared safety bar** (`deploy-gate`, DSE-1257) and **is the MCP
auth posture sound** (`auth audit`, DSE-1258).

Both follow the same contract as `check`:

| Exit | Meaning |
|------|---------|
| `0` | Every declared control satisfied |
| `1` | At least one finding — the gate blocks |
| `2` | Unreadable/malformed input — **fail closed**, never a pass |

Both emit `--json` (JSONL findings) and `--sarif` (code-scanning upload), reusing
the same emitters as `check`, so an existing SARIF pipeline needs no changes.

---

## 1. `deploy-gate` — release control for agent deployments

**The gap.** Agent frameworks ship evals, guardrails, and budgets as libraries,
but nothing *blocks a deploy* when the evals regress or a guardrail is switched
off. Teams write bespoke shell in CI, or skip the check.

**The design decision that matters: the gate does not run evals.** It verifies
*evidence* that they ran and passed. Running evals is the pipeline's job and is
framework-specific; adjudicating them is a deterministic, portable control. This
keeps the gate free of every eval framework's dependency tree, makes verdicts
reproducible from two JSON files, and means a missing or malformed evidence file
is unambiguously a **failure** rather than a silent skip.

### Policy schema

```json
{
  "required_evals": [{ "suite": "safety", "min_score": 0.9 }],
  "required_guardrails": ["prompt-injection", "pii-redaction"],
  "require_budget": true,
  "require_approval": true
}
```

### Evidence schema

Produced by the deploy pipeline:

```json
{
  "evals":      { "safety": { "score": 0.95 } },
  "guardrails": ["prompt-injection", "pii-redaction"],
  "budget":     { "limit": 100 },
  "approval":   { "approved": true, "approver": "release-manager@example.com" }
}
```

### Rules

| Rule ID | Severity | Fires when |
|---------|----------|-----------|
| `WRD-GATE-EVAL-MISSING` | high | A required suite has no result in evidence |
| `WRD-GATE-EVAL-MALFORMED` | high | A suite reported no numeric score |
| `WRD-GATE-EVAL-THRESHOLD` | high | A suite scored below its `min_score` |
| `WRD-GATE-EVAL-EVIDENCE` | high | The `evals` block is not an object |
| `WRD-GATE-GUARDRAIL-MISSING` | high | A required guardrail is not active |
| `WRD-GATE-BUDGET-MISSING` | medium | `require_budget` set, no budget declared |
| `WRD-GATE-BUDGET-INVALID` | medium | Budget has no positive limit |
| `WRD-GATE-APPROVAL-MISSING` | critical | `require_approval` set, no receipt |
| `WRD-GATE-APPROVAL-INVALID` | critical | Receipt is not affirmative and attributed |

### Usage

```bash
mcp-warden deploy-gate --policy gate-policy.json --evidence deploy-evidence.json
```

```yaml
- name: Agent deploy gate
  run: mcp-warden deploy-gate --policy gate-policy.json --evidence evidence.json --sarif gate.sarif
```

### Scope honesty

`deploy-gate` adjudicates **declared evidence**. It does not verify that the
evidence is truthful — a pipeline that fabricates a score passes. Bind evidence
to a trusted producer (signed CI artifact, restricted branch) when that matters.
It is a release control, not an attestation system; the signed-decision path
lives in [`POLICY_ENFORCEMENT.md`](POLICY_ENFORCEMENT.md).

---

## 2. `auth audit` — static MCP auth-posture audit

**The gap.** MCP configs routinely point at remote endpoints with no
authentication, over cleartext `http://`, with bearer tokens pasted directly
into the committed config. None of that requires exploitation to find — it is
declared in the file.

**The design decision that matters: static only.** No server is spawned, no DNS
is resolved, no network is touched. The audit reasons purely about what the
config declares. That makes it safe to run against any config in CI, and — this
is the load-bearing part — it keeps the feature **immune to churn in the MCP
auth specification**. Runtime capability brokering is deliberately out of scope
and tracked separately (DSE-725).

### Rules

| Rule ID | Severity | Fires when |
|---------|----------|-----------|
| `WRD-AUTH-NOAUTH` | medium | A remote endpoint declares no auth material |
| `WRD-AUTH-PLAINTEXT-HTTP` | high | A remote endpoint uses `http://` |
| `WRD-AUTH-TOKEN-IN-CONFIG` | high | An auth-bearing key holds a literal credential |
| `WRD-AUTH-PLACEHOLDER-SECRET` | low | An auth-bearing key holds an obvious template fill-me-in (`<your-api-key>`, `YOUR KEY GOES HERE`, `changeme`, `xxx`) — a config that cannot work, not a committed credential |
| `WRD-AUTH-URL-CREDENTIAL` | high | The endpoint URL embeds a `user:pass@` userinfo credential |
| `WRD-SEC-*` | varies | Vendor secret patterns found in any config value (shared with `check`) |

### What it deliberately does not flag

Precision matters more than recall for a gate that blocks CI:

- **Loopback servers** (`localhost`, `127.0.0.1`, `::1`) — not remotely
  reachable, so missing auth is not an exposure.
- **Secret references, including embedded ones** — `${TOKEN}`, `$TOKEN`,
  `${TOKEN:-default}` / `${TOKEN:?msg}` (shell expansion forms), `%TOKEN%`
  (Windows), `{{ secret }}`, secret-manager URIs (`op://`, `vault://`,
  `awssm://`, `gcpsm://`, `azkv://`, `secretref://`, `keyring://`, `pass://`) and
  paths to a credential file (`~/.config/app/keys.json`, `/etc/app/secrets/token`)
  are the correct pattern and are never flagged as literals, and
  that holds when the reference sits *inside* a larger value. **`Bearer ${TOKEN}`
  is correct configuration and is not a finding** — it is the most common shape
  an Authorization header takes, and flagging it was a real false positive found
  by dogfooding (fixed in #94).

  This is not a hole. A reference must be present, and once every reference is
  removed, whatever remains may only be a short alphabetic auth-scheme word
  (`Bearer`, `Token`, `Basic`, `ApiKey`). So `Bearer sk-abc… ${TOKEN}` — a real
  literal sitting beside a reference — is still flagged.
- **Local stdio servers** — a `command`/`args` entry with no URL and no remote
  transport has no auth posture to audit.

### Placeholders are a separate, low-severity rule

Running the audit over a 463-config public corpus showed that **74 % of
`WRD-AUTH-TOKEN-IN-CONFIG` hits were template fill-me-ins** — `<your-api-key>`,
`YOUR KEY GOES HERE`, `changeme`, `xxx`. Calling those committed credentials is
false, and false highs are what get a gate switched off. They are now
`WRD-AUTH-PLACEHOLDER-SECRET` (low): a shipped config that cannot work is still a
finding, just not a leak.

The downgrade is built so it cannot hide a real secret:

- **Vendor scan first.** Any value the `WRD-SEC-*` vendor patterns or the entropy
  heuristic recognise is reported as a credential regardless of what else it
  contains — a `ghp_…` token that happens to spell `example` stays high.
- **Whole-token matching.** Placeholder words match whole tokens of the value
  (split on non-alphanumerics), never substrings: `adherenceTokenValue` is not
  `here`, `fillmoreStreetPass` is not `fill`.
- **Short bare words only.** The "scheme/type word" rule (`admin`, `basic`,
  `api-key`) accepts at most 11 purely alphabetic characters plus `-`/`_`. A digit
  or any other punctuation (`hunter2!`, `p@ssword`) disqualifies the value.
- **Bracketed slots must stand alone.** `Bearer <token>` is a template;
  `Bearer <token> aB3x…` — a literal sitting beside the slot — is a credential.

### Usage

```bash
mcp-warden auth audit ~/.claude/claude_desktop_config.json .mcp.json
mcp-warden auth audit .mcp.json --sarif auth.sarif
```

Every credential literal is redacted in findings, snippets, and SARIF output —
the audit never widens exposure of the thing it is reporting.
