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
   (<https://github.com/DataScience-EngineeringExperts/mcp-warden/security/advisories/new>). This
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

## Dependency-update policy

mcp-warden is a supply-chain integrity gate, so its own dependencies are part of
its attack surface. We hold our updates to the standard we ask of users.

**Pinning.** Our dev/CI dependency closure is locked to exact versions with
SHA-256 artifact hashes in `requirements-dev.lock` (runtime + the `[dev]`
extras), regenerated with `uv pip compile --universal --generate-hashes`. The
published GitHub Action already ships its own hash-locked closure in
`action/requirements.lock` and `action/build-requirements.lock`. The published
*library* declares minimum-version floors in `pyproject.toml` (a library pins
floors, not exact versions); the lockfile is what makes *our* development and CI
reproducible and hash-verified.

**No auto-merge.** Every dependency bump — including Dependabot PRs — requires
human review before merge. We never bulk-merge or auto-merge dependency updates.
A compromised or malicious release reaches us only through a bump, so each one is
inspected individually.

**Cool-down.** We do not merge a brand-new upstream release the moment it lands.
We prefer a short soak (a few days) so a yanked or compromised release has time
to surface before it enters our locked set. Security-critical fixes are the
exception and are fast-tracked with extra scrutiny.

**What a reviewer checks on every bump:**

- The upstream changelog / release notes and the diff for the bump range, with
  attention to anything touching capture, JCS+SHA-256 canonicalization, proxy
  framing, redaction, or the block posture.
- `requirements-dev.lock` has been **regenerated and committed** as part of the
  bump (an accepted bump that does not update the lockfile is incomplete).
- CI is fully green, including the `deps-locked` job (hash-verified
  `--require-hashes` install + lockfile-in-sync check) and the gitleaks
  secret-scan.
- For large version jumps or runtime-critical packages (e.g. `mcp`, `typer`,
  `pydantic`): no API breakage across `pin` / `check` / `policy` / `guard` /
  `inspect`.
- For GitHub Actions bumps: the action is still pinned to a full 40-char commit
  SHA with a version comment (enforced by `tests/test_workflow_pins.py`).

Regenerating the lockfile (run from the repo root, requires `uv`):

```bash
uv pip compile --universal --generate-hashes --python-version 3.11 \
    --extra dev pyproject.toml -o requirements-dev.lock
```

See `CONTRIBUTING.md` for regenerating the Action's `action/*.lock` files.
