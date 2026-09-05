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

**The bound, stated honestly.** The downgrade is guaranteed not to hide a value
the `WRD-SEC-*` vendor patterns match, or one the entropy heuristic catches
(**24+ characters at >= 4.0 bits/char, >= 80 % alphanumeric**) — those are
reported as credentials before the placeholder logic runs. A *shorter* or
*low-entropy* secret (a lowercase hex key, a passphrase) is outside that guard,
and for those the placeholder heuristic is the only line. It is bounded as
follows, each bound pinned by a test with a sub-threshold bypass string:

- **Whole-token matching, every token accounted for.** A value is a placeholder
  only if at least one *strong* placeholder token (`your`, `example`, `changeme`,
  `xxx`, …) is present as a whole token **and every other token is filler**
  (`key`, `token`, `goes`, a vendor name). One placeholder word does not launder
  the rest: `example-9f8e7d6c5b4a` is a credential. Hard floor: unless every
  token is placeholder/filler, a value of 16+ characters containing a digit is
  never downgraded (`YOUR_API_KEY_1234567890` is all filler and stays low).
- **Closed scheme set.** Only `Bearer`, `Token`, `Basic`, `ApiKey`, `Negotiate`,
  `Digest` may sit beside a reference or a `<slot>` — `correcthorse ${TOKEN}` is
  a literal.
- **`${VAR:-default}` / `${VAR:=default}` is a reference only when the default is
  empty, itself a reference (recursively), or itself a placeholder.**
  `${TOKEN:-9f8e7d6c5b4a}` and `${T:-${U:-hunter2!}}` are committed credentials
  wearing a reference; `${VAR:?msg}` stays a reference.
- **Locators need >= 2 segments and no token-shaped segment.** Token-shaped is
  an alphanumeric-only segment that is 20+ characters, or 16+ at >= 3.5 bits/char,
  or 16+ mixed-case (`Passw0rdPassw0rd`). Segments with dots, underscores or
  hyphens are file names. A URI fragment or a `${VAR:?msg}` message is checked
  the same way: `#key` and `:?required` are fine, `#9f8e…` and `:?9f8e…` are
  literals. `op://Private/GitHub/token`, `~/.config/app/keys.json` and
  `~/.config/gcloud/application_default_credentials.json` are references;
  `op://9f8e…`, `~/9f8e…`, `~/.config/9f8e7d6c5b4a3e2d1c0b9a8f`,
  `~/.config/GHSAT0AAAAAABCDEFGHIJ`, `/etc/Passw0rdPassw0rd` and `/9j/4AAQ…` are
  literals. **Known residual:** a token that itself contains a separator
  (`9f8e-7d6c-5b4a-…`) reads as a file name and is not caught by this rule —
  tracked as a follow-up.
- **Short bare words are an allowlist, not a heuristic.** Only `basic`, `bearer`,
  `token`, `apikey`/`api-key`, `digest`, `negotiate`, `oauth`, `none` are treated
  as scheme/type slots. Everything else — `admin`, `password`, `letmein`,
  `qwerty`, `welcome`, `hunter2!` — is a working secret and stays high.
- **`...` is anchored** — the whole value, or the tail of a short stub (`sk-...`)
  or an all-filler value (`your-key...`); never a substring, never behind a real
  token.

### Usage

```bash
mcp-warden auth audit ~/.claude/claude_desktop_config.json .mcp.json
mcp-warden auth audit .mcp.json --sarif auth.sarif
```

Every credential literal is redacted in findings, snippets, and SARIF output —
the audit never widens exposure of the thing it is reporting.
