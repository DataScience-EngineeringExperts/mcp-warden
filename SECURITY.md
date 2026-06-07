# Security Policy

mcp-warden is itself a security tool — a supply-chain integrity gate and runtime
tool-result inspector for Model Context Protocol (MCP) servers. A weakness in
mcp-warden can silently let drift, poisoned results, or leaked secrets through a
gate that downstream users trust. We treat vulnerability reports accordingly.

## Reporting a vulnerability

**Do not open a public GitHub issue, pull request, or discussion for a security
vulnerability.** Public disclosure before a fix is available puts every downstream
user at risk.

Report privately through **either** channel (GitHub Security Advisories is
preferred because it keeps the report, the fix, and the CVE in one place):

1. **GitHub Security Advisories** — go to the repository's **Security** tab and
   click **"Report a vulnerability"**
   (<https://github.com/ernestprovo23/mcp-warden/security/advisories/new>). This
   opens a private advisory visible only to you and the maintainers.
2. **Email** — `ernest@thedataexperts.us`. Use a clear subject line such as
   `[mcp-warden security]`. If you want to encrypt, say so in a first plaintext
   email and we will arrange a key.

### What to include

A good report lets us reproduce and triage fast:

- The mcp-warden version (`mcp-warden --version`) or commit SHA.
- The command and surface involved (`pin` / `check` / `policy` / `guard` /
  `inspect`), and the relevant flags.
- A minimal MCP server fixture, `warden.lock`, policy file, or recorded
  `trace.jsonl` that reproduces the issue. Strip or fake any real secrets first.
- The expected vs. actual behavior, and the security impact (e.g. "a poisoned
  tool result bypasses the deterministic block tier", "drift is not detected for
  X", "a real secret is emitted unredacted in SARIF").

Reports that demonstrate a **bypass of a control we claim to enforce** are the
highest priority. The controls in scope are defined in `docs/THREAT_MODEL.md`,
`docs/THREAT_MODEL_V2.md`, `docs/RESULT_INSPECTION.md`, `docs/GUARD_PROXY.md`, and
`docs/GUARD_PROXY_V3.md`. Behaviors documented there as **explicitly out of scope**
(notably behavioral attacks, `T-BEHAVE`) are not vulnerabilities, but reports that
sharpen those boundaries are still welcome.

## Supported versions

Security fixes are issued for the latest minor series. Older series are not
patched — upgrade to a supported release.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :x:                |
| 0.1.x   | :x:                |
| < 0.1   | :x:                |

> Pre-1.0 note: the public surface is still evolving. The supported series will
> advance with each minor release; only the most recent `0.x` minor receives
> security patches.

## Response window

We aim to:

- **Acknowledge** your report within **3 business days**.
- Provide an **initial assessment** (accepted / needs-info / not-a-vuln, with a
  severity estimate) within **7 business days**.
- Ship a fix or a documented mitigation for accepted, validated reports within
  **30 days** of acknowledgement for high/critical severity, and on a best-effort
  basis for lower severities.

These are targets for a small maintainer team, not contractual SLAs. If a report
stalls, a polite nudge to `ernest@thedataexperts.us` is welcome.

## Disclosure & credit

We follow coordinated disclosure. We will work with you on a disclosure timeline,
publish a GitHub Security Advisory (and request a CVE where warranted) once a fix
is available, and credit you in the advisory unless you ask to remain anonymous.

## Scope notes for this repository

- The files under `tests/fixtures/` intentionally contain **synthetic,
  clearly-fake secret-shaped strings** (e.g. fake `ghp_`/`AKIA...EXAMPLE`/`sk-`
  placeholders) used to exercise mcp-warden's own detectors. These are not real
  credentials and are allowlisted in `.gitleaks.toml`. Finding one of these is not
  a vulnerability; finding a path where mcp-warden **fails to redact a real
  secret** is.
- Reports about dependencies (the MCP SDK, pydantic, typer, etc.) are best filed
  upstream, but tell us too if mcp-warden's use of them is exploitable.
