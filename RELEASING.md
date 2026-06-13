# Releasing mcp-warden

This is the operator runbook for cutting a release of **mcp-warden**.

Two names matter and they are deliberately different:

| Thing | Value |
|-------|-------|
| PyPI distribution name (what `pip install` uses) | `mcp-warden-cli` |
| CLI command (what users type) | `mcp-warden` |
| GitHub repository | `ernestprovo23/mcp-warden` |

Install is therefore `pip install mcp-warden-cli`, but the command stays `mcp-warden`.
The PyPI name `mcp-warden` is an unrelated package by another author. PyPI rejects
`mcpwarden` as "too similar" to it — PyPI's anti-typosquat guard strips separators,
so `mcpwarden` and `mcp-warden` collapse to the same string. `mcp-warden-cli`
normalizes to letters-only `mcpwardencli`, which is distinct, so it is accepted and
does not collide.

The publish + signing automation lives in
[`.github/workflows/release.yml`](.github/workflows/release.yml). That workflow is
**inert until configured**: it only fires when a GitHub *Release* is published, and
publishing only succeeds once the one-time PyPI Trusted Publisher below exists.

---

## 0. One-time PyPI setup (do this ONCE, before the first release)

The workflow publishes via **OIDC Trusted Publishing** — there is no API token and
no secret stored in GitHub. Instead, PyPI is told to trust releases that come from
this exact repo + workflow. Configure the publisher *before* the first release so
the very first upload is already OIDC-published.

### Recommended path — "pending publisher" (zero prior upload required)

1. Log in to <https://pypi.org> as the account that will own `mcp-warden-cli`.
2. Go to **Account → Publishing** (<https://pypi.org/manage/account/publishing/>).
3. Under **Add a new pending publisher**, fill in **exactly**:
   - **PyPI Project Name**: `mcp-warden-cli`
   - **Owner**: `ernestprovo23`
   - **Repository name**: `mcp-warden`
   - **Workflow name**: `release.yml`
   - **Environment name**: *(leave blank — the workflow does not use a GitHub
     deployment environment; if you later add one, set it here and add
     `environment:` to the `pypi-publish` job)*
4. Save. PyPI now holds the project name `mcp-warden-cli` and will create it on the
   first successful OIDC upload from `release.yml`.

A "pending publisher" reserves the name and lets the FIRST release be OIDC-published
— no manual upload, no token ever.

### Alternative path — manual first upload, then configure

If you would rather seed the project manually first:

1. Build locally: `python -m build` (produces `dist/*.tar.gz` + `dist/*.whl`).
2. `twine upload dist/*` with a temporary PyPI API token (creates `mcp-warden-cli`).
3. Then go to **Manage project → Publishing** on the new `mcp-warden-cli` project and add
   the Trusted Publisher with the same owner/repo/workflow values as above.
4. Revoke the temporary token.

> Prefer the pending-publisher path. It avoids ever minting a long-lived token and
> keeps the entire supply chain OIDC-only from release #1.

### (Optional) TestPyPI dry-run publisher

The workflow has a manual `workflow_dispatch` path that publishes to TestPyPI for a
dry run. To use it, repeat step 2–4 above on <https://test.pypi.org> (separate
account + separate pending publisher for `mcp-warden-cli`). This is optional and only
needed if you want to rehearse the publish without touching production PyPI.

---

## 1. Cut a release

Do this on a clean checkout of `main` with all v1 PRs merged.

1. **Update the changelog.** In [`CHANGELOG.md`](CHANGELOG.md), move the
   `## [Unreleased]` entries under a new `## [1.0.0] - <YYYY-MM-DD>` heading with
   today's date. Leave a fresh empty `## [Unreleased]` section above it.

2. **Bump the version.** In [`pyproject.toml`](pyproject.toml), set
   `[project] version = "1.0.0"`.

3. **Commit.**
   ```bash
   git add CHANGELOG.md pyproject.toml
   git commit -m "release: v1.0.0"
   git push origin main
   ```

4. **Tag and push the tag.** (A tag alone does NOT publish anything — it only marks
   the commit. The Release in the next step is what triggers the workflow.)
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

5. **Create the GitHub Release.** This is the trigger.
   ```bash
   gh release create v1.0.0 \
     --title "v1.0.0" \
     --notes-file <(awk '/## \[1.0.0\]/{f=1} /## \[0\./{if(f)exit} f' CHANGELOG.md)
   ```
   or use the GitHub UI: **Releases → Draft a new release → choose tag `v1.0.0` →
   Publish release**.

   Publishing the Release fires `release.yml`, which:
   - **build** — builds the sdist + wheel and uploads them as workflow artifacts;
   - **pypi-publish** — publishes those artifacts to PyPI via OIDC (no token);
   - **sign** — signs the sdist + wheel with Sigstore keyless and attaches the
     `.sigstore` bundle(s) to the Release assets.

---

## 2. Post-release verification

1. **Install from PyPI** (give the CDN a minute):
   ```bash
   pip install mcp-warden-cli
   mcp-warden --version
   ```
   The version must print `1.0.0`. Note the install name is `mcp-warden-cli`, the
   command is `mcp-warden`.

2. **Verify the Sigstore bundle.** On the GitHub Release page, confirm there is a
   `.sigstore` (bundle) asset next to each `.tar.gz`/`.whl`. The `sign` job already
   self-verified against this workflow's own identity before attaching, but you can
   re-verify any artifact locally:
   ```bash
   pip install sigstore
   sigstore verify identity dist/mcp_warden_cli-1.0.0-py3-none-any.whl \
     --bundle mcp_warden_cli-1.0.0-py3-none-any.whl.sigstore \
     --cert-identity \
       "https://github.com/ernestprovo23/mcp-warden/.github/workflows/release.yml@refs/tags/v1.0.0" \
     --cert-oidc-issuer "https://token.actions.githubusercontent.com"
   ```
   (Download the `.whl` and its `.sigstore` bundle from the Release assets first.)

3. **Confirm the PyPI page.** Visit <https://pypi.org/project/mcp-warden-cli/> and check:
   - version `1.0.0` is listed;
   - the project URLs (homepage / repository) point at `ernestprovo23/mcp-warden`;
   - "Publisher" shows the Trusted Publisher (OIDC), not a token upload.

4. **Smoke-test the gate** in a throwaway dir to confirm the published wheel works:
   ```bash
   mcp-warden --help
   ```

---

## 3. Rollback / yank

PyPI uploads are **immutable** — you cannot overwrite a published version. If a
release is broken:

- **Yank** the bad version (keeps existing pins working, hides it from new
  installs): on <https://pypi.org/project/mcp-warden-cli/> → **Manage → Releases →
  Options → Yank**. Yanking is reversible.
- **Ship a fix-forward release** (`1.0.1`) following section 1 again. This is the
  preferred remedy — never try to re-upload `1.0.0`.
- **GitHub Release**: you may delete or edit the GitHub Release and its assets
  freely; that does not affect what is already on PyPI. Re-running the workflow
  against the same version will fail the PyPI publish (duplicate filename), which is
  the correct fail-closed behavior — bump the version instead.

---

## Why this design

- **No stored secret.** OIDC Trusted Publishing means GitHub never holds a PyPI
  token; PyPI trusts the workflow identity directly. Same trust model as the repo's
  existing keyless Sigstore signing.
- **Heal thyself.** mcp-warden signs everyone else's locks; from v1.0.0 it signs its
  own release artifacts too (the `sign` job), so consumers can verify the wheel they
  install came from this repo's release workflow.
- **Explicit gesture.** A pushed tag does nothing; only *publishing a Release* ships.
  That keeps accidental tags from triggering a publish.
