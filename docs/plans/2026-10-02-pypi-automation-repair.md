# PyPI automation repair implementation plan

> **For Claude:** Execute the bounded tasks below in the existing repair worktree.

**Goal:** Restore verified production Trusted Publishing where authenticated access permits, and give operators a safe authentication-only check without creating a release or uploading packages.

**Architecture:** Preserve `release.yml`, its current GitHub identity, pinned actions, job permissions, and OIDC-only publication. Add a manually selected `verify-pypi` path that exchanges the workflow's short-lived identity without building, uploading, signing, or storing credentials. PyPI publisher administration remains an authenticated project-owner browser operation; do not substitute the existing upload token for that authority.

**Tech Stack:** GitHub Actions, Python 3.11 standard library HTTPS/JSON, pytest, MkDocs.

---

## Task 1: Establish the configuration boundary

- Inspect the failed release's sanitized claim summary and GitHub environments.
- Read PyPI's official publisher documentation and management implementation.
- Inspect the production settings page when authenticated admin access is available; otherwise request its four publisher fields from the owner once.
- Evidence already obtained: the management page redirects this builder to login; GitHub has only `github-pages`; the release job declares no environment. Do not infer which PyPI-side field is wrong.

## Task 2: Implement a non-uploading verification path

**Files:** `.github/workflows/release.yml`, `scripts/verify_pypi_oidc.py`, `tests/test_release_oidc.py`.

- Add `verify-pypi` to the existing manual choices; skip build and publish jobs for it.
- Run the standard-library script in a job with the existing `id-token: write` and `contents: read` permissions. Both job and script require reviewed `main`; the script requires an explicit owner publisher-inspection acknowledgment before requesting tokens.
- Validate the GitHub request endpoint, audience and current workflow/repository claims; reject redirects and unexpected claims before PyPI exchange.
- Send secrets only as HTTPS headers/bodies. Never log tokens, response bodies, or uncontrolled server error descriptions; retain only fixed failure codes and status.
- Require a valid, short-lived successful PyPI exchange response. Clearly label success as authentication, not proof of package/project upload authorization.
- Inspect a normal existing-project publisher and absence of matching pending publishers visible in the owning account before dispatch. PyPI minting checks pending publishers first and can mutate their records; the account check cannot establish universal absence. No live probe is authorized by a guessed inspection acknowledgment.
- Test both routes' separation, safe exchange, identity mismatch, malicious redirects, invalid/malformed responses, bounded network errors and log non-disclosure.

## Task 3: Correct and sync release documentation

**Files:** `RELEASING.md`, `README.md`, `SYSTEM_CONTEXT_DIAGRAM.md`, `DOCUMENTATION_INDEX.md`, `CHANGELOG.md`.

- Lead existing-project instructions with the exact production project publishing URL and expected fields.
- Correct the false claim that a pending publisher reserves a project name.
- Record 2.0.0's verified manual recovery and the outstanding OIDC mismatch without claiming it is repaired.
- Document `verify-pypi`, its boundary and a failed-job-only rerun using the existing artifacts after publisher alignment.
- Re-read and validate all three core docs, their links and the 500-line cap.

## Task 4: Evaluate, deliver and verify

- Run focused probe/workflow tests, Ruff, strict docs build and rendered desktop/mobile QA for changed public docs.
- Obtain the required independent security review of the concrete head; deliver through a PR with required CI and the existing merge helper.
- Run the production authentication-only path. A red exchange remains a failure, never a skip/disabled gate presented as success.
- If the owner aligns the publisher, rerun only the old release's failed PyPI job; confirm authentication, duplicate handling and unchanged public hashes.

## Task 5: Session wrap

- Preserve release URLs, exact repair commit/PR, test results, actual publisher/probe status and the one remaining action, if any.
- Save a bounded Codex memory note and attempt the authorized Notion mirror; report the builder's iCloud discovery refresh as skipped.
- Do not close DSE-1539 while its pagination acceptance is incomplete or mutate another agent's started issue.
