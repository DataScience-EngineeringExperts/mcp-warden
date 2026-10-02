# Releasing mcp-warden

This is the operator runbook for cutting a release of **mcp-warden**.

Two names matter and they are deliberately different:

| Thing | Value |
|-------|-------|
| PyPI distribution name (what `pip install` uses) | `mcp-warden-cli` |
| CLI command (what users type) | `mcp-warden` |
| GitHub repository | `DataScience-EngineeringExperts/mcp-warden` |

Install is therefore `pip install mcp-warden-cli`, but the command stays `mcp-warden`.
The PyPI name `mcp-warden` is an unrelated package by another author. PyPI rejects
`mcpwarden` as "too similar" to it — PyPI's anti-typosquat guard strips separators,
so `mcpwarden` and `mcp-warden` collapse to the same string. `mcp-warden-cli`
normalizes to letters-only `mcpwardencli`, which is distinct, so it is accepted and
does not collide.

The publish + signing automation lives in
[`.github/workflows/release.yml`](.github/workflows/release.yml). That workflow is
publishes production packages only on a published GitHub Release. Manual modes
are TestPyPI upload, build-only, and production authentication verification without
uploading. Production authentication needs a matching PyPI Trusted Publisher.

---

## 0. Configure the production publisher

The production project already exists. Its publisher is managed at
[PyPI → mcp-warden-cli → Publishing](https://pypi.org/manage/project/mcp-warden-cli/settings/publishing/)
by a logged-in project owner. An upload API token is not a publisher-admin browser session.

For the existing workflow, the GitHub publisher fields are:

| Field | Expected value |
|-------|----------------|
| Owner | `DataScience-EngineeringExperts` |
| Repository name | `mcp-warden` |
| Workflow name | `release.yml` |
| Environment name | blank: the current publishing job has no deployment environment |

Inspect the current publisher before changing it. An existing environment restriction
must be deliberately aligned on both sides, preserving any required reviewer gate.
A repository transfer can also change the immutable owner ID PyPI records; a matching
display name alone does not prove identity alignment. See
[PyPI troubleshooting](https://docs.pypi.org/trusted-publishers/troubleshooting/).

The workflow uses **OIDC Trusted Publishing**, without a stored GitHub upload token.
The repo variable `PYPI_TRUSTED_PUBLISHER=true` permits an attempt; it does not prove
that a matching PyPI publisher exists. Verify the exchange before cutting a new release.

### New projects only — pending publisher

1. Log in to <https://pypi.org> as the account that will own `mcp-warden-cli`.
2. Go to **Account → Publishing** (<https://pypi.org/manage/account/publishing/>).
3. Under **Add a new pending publisher**, fill in **exactly**:
   - **PyPI Project Name**: `mcp-warden-cli`
   - **Owner**: `DataScience-EngineeringExperts`
   - **Repository name**: `mcp-warden`
   - **Workflow name**: `release.yml`
   - **Environment name**: *(leave blank — the workflow does not use a GitHub
     deployment environment; if you later add one, set it here and add
     `environment:` to the `pypi-publish` job)*
4. Save the pending configuration. A successful authorized OIDC flow can create
   the new project if the name remains available; saving does not reserve it.

A pending publisher does **not** reserve a name or create a project. It is not the
setup path for the already-existing `mcp-warden-cli` project. See
[PyPI pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

### New projects only — manual first upload, then configure

If you would rather seed the project manually first:

1. Build locally: `python -m build` (produces `dist/*.tar.gz` + `dist/*.whl`).
2. `twine upload dist/*` with a temporary PyPI API token (creates `mcp-warden-cli`).
3. Then go to **Manage project → Publishing** on the new `mcp-warden-cli` project and add
   the Trusted Publisher with the same owner/repo/workflow values as above.
4. Revoke the temporary token.

> Prefer the pending-publisher path. It avoids ever minting a long-lived token and
> keeps the entire supply chain OIDC-only from release #1.

### Enable OIDC publishing (the `PYPI_TRUSTED_PUBLISHER` gate)

The `pypi-publish` job in `release.yml` is gated behind the repo variable
`PYPI_TRUSTED_PUBLISHER` and only runs when it equals `true`. This lets you publish
a GitHub Release that **builds + Sigstore-signs + attaches `.sigstore` bundles**
without the publish job failing red before the Trusted Publisher exists.

- **While the variable is unset** (or any value other than `true`): publishing a
  GitHub Release builds the sdist + wheel, Sigstore-signs them, and attaches the
  bundles to the Release — but the `pypi-publish` job is **SKIPPED** (gray, not red)
  and nothing is uploaded to PyPI. Use this to cut signed GitHub Releases for
  historical versions already published by token (e.g. `1.0.0`, `1.0.1`).
- **After you have configured the Trusted Publisher above** (project
  `mcp-warden-cli`, owner `DataScience-EngineeringExperts`, repo `mcp-warden`, workflow
  `release.yml`), enable OIDC publishing for future releases by setting the
  variable:
  ```bash
  gh variable set PYPI_TRUSTED_PUBLISHER --body true
  ```
  or in the GitHub UI: **Settings → Secrets and variables → Actions → Variables →
  New repository variable**, name `PYPI_TRUSTED_PUBLISHER`, value `true`.

The publish action must authenticate **before** `skip-existing: true` can handle
duplicate files. A previously uploaded version does not bypass a broken publisher.

### Verify production authentication without uploading

From the repository, dispatch the existing release workflow on reviewed `main`:

```bash
gh workflow run release.yml --ref main --field publish-target=verify-pypi
gh run list --workflow release.yml --event workflow_dispatch --limit 1
gh run view <run-id> --log
```

Only **Verify PyPI OIDC (no upload)** runs. Build, signing and upload jobs are
skipped; the script uses Python's standard library and preserves the release
workflow's repository/owner/workflow identity and current environment contract.
It validates the GitHub request host, refuses redirects, limits response sizes
and suppresses credentials and arbitrary server error text. The minted short-lived
credential remains only in memory and is discarded without being used.

**Pass:** the exchange job succeeds and reports that PyPI accepted the workflow
identity. This confirms authentication, not project-specific upload permission or
package safety. Confirm the normal publisher is attached to `mcp-warden-cli` in
the project settings; a pending publisher is not the intended verification target.
**Fail:** any failed/malformed exchange, identity mismatch or missing permission
exits nonzero. A skipped publication job is not proof of working authentication.

For `invalid-publisher`, compare the existing project's four fields above and the
immutable owner identity with the current workflow. Do not copy tokens into logs,
add a workflow token fallback, disable the gate to hide the failure, or remove a
reviewer/environment restriction to make the check pass.

### 2.0.0 recovery and retry boundary

[Release run 36960647544](https://github.com/DataScience-EngineeringExperts/mcp-warden/actions/runs/36960647544)
built and signed the release but failed PyPI's exchange with `invalid-publisher`.
The same exchange error occurred on the prior 1.2.0 release. The authorized manual
2.0.0 upload used the exact signed GitHub wheel/sdist; their SHA-256 hashes match
[PyPI 2.0.0](https://pypi.org/project/mcp-warden-cli/2.0.0/). That recovery proves
publication, not that OIDC automation was repaired.

After the publisher is aligned and authentication succeeds, rerun only the failed
job from the original release run, using its retained build artifacts:

```bash
gh run rerun 36960647544 --failed
```

Do not rebuild/re-sign/replace the released assets as a repair attempt. If the
original artifacts expired, stop and plan a fix-forward release. Success means
OIDC authentication passes and the existing immutable files are handled by
`skip-existing`; verify the public wheel/sdist hashes remain unchanged.

### (Optional) TestPyPI dry-run publisher

The workflow has a manual `workflow_dispatch` path that publishes to TestPyPI for a
dry run. To use it, repeat step 2–4 above on <https://test.pypi.org> (separate
account + separate pending publisher for `mcp-warden-cli`). This is optional and only
needed if you want to rehearse the publish without touching production PyPI.

---

## 1. Cut a release

Do this on a clean checkout of `main` with the intended changes merged through a reviewed PR.
The commands below use `2.0.1` as an example next version, not a published release.

1. **Update the changelog.** In [`CHANGELOG.md`](CHANGELOG.md), move the
   `## [Unreleased]` entries under a new `## [2.0.1] - <YYYY-MM-DD>` heading with
   today's date. Leave a fresh empty `## [Unreleased]` section above it.

2. **Bump both Python versions.** In [`pyproject.toml`](pyproject.toml), set
   `[project] version = "2.0.1"`; update `__version__` in
   [`src/mcp_warden/__init__.py`](src/mcp_warden/__init__.py) to match.

3. **Commit.**
   ```bash
   git add CHANGELOG.md pyproject.toml src/mcp_warden/__init__.py
   git commit -m "release: v2.0.1"
   # Push a release branch and merge its reviewed PR; do not push directly to main.
   ```

4. **Refresh the merged `main`, then tag and push the tag.** Required CI must be
   green at the reviewed release commit. A tag alone does not publish packages;
   the Release in the next step triggers the workflow.
   ```bash
   git tag v2.0.1
   git push origin v2.0.1
   ```

5. **Create the GitHub Release.** This is the trigger.
   ```bash
   gh release create v2.0.1 --verify-tag \
     --title "v2.0.1" \
     --notes-file /tmp/release-notes.md
   ```
   or use the GitHub UI: **Releases → Draft a new release → choose tag `v2.0.1` →
   Publish release**.

   Publishing the Release fires `release.yml`, which:
   - **build** — builds the sdist + wheel and uploads them as workflow artifacts;
   - **pypi-publish** — publishes those artifacts to PyPI via OIDC (no token).
     **Skipped unless** the repo variable `PYPI_TRUSTED_PUBLISHER` is `true`
     (see "Enable OIDC publishing" in section 0). Previously published files still
     require valid authentication; do not hide an exchange failure;
   - **sign** — signs the sdist + wheel with Sigstore keyless and attaches the
     `.sigstore.json` bundle(s) to the Release assets (runs regardless of the gate).

---

## TypeScript release artifact

The build job also runs the shared TypeScript conformance suite and `npm pack`.
The npm-installable `.tgz` and `SHA256SUMS` are downloaded only by the signing job;
PyPI receives only the Python distribution artifact. The existing release identity
signs and attaches the TypeScript tarball and checksums alongside Python artifacts.
No npm registry token or publisher is configured by this workflow.

Verify the tarball bundle against the same release workflow identity, then install
the exact GitHub asset into a fresh consumer and import `@mcp-warden/lock`.

## 2. Post-release verification

1. **Install from PyPI** (give the CDN a minute):
   ```bash
   pip install mcp-warden-cli==2.0.1
   mcp-warden --version
   ```
   The version must print `2.0.1`. Note the install name is `mcp-warden-cli`, the
   command is `mcp-warden`.

2. **Verify the Sigstore bundle.** On the GitHub Release page, confirm there is a
   `.sigstore.json` (bundle) asset next to each `.tar.gz`/`.whl`. The `sign` job already
   self-verified against this workflow's own identity before attaching, but you can
   re-verify any artifact locally:
   ```bash
   pip install sigstore
   sigstore verify identity dist/mcp_warden_cli-2.0.1-py3-none-any.whl \
     --bundle mcp_warden_cli-2.0.1-py3-none-any.whl.sigstore.json \
     --cert-identity \
       "https://github.com/DataScience-EngineeringExperts/mcp-warden/.github/workflows/release.yml@refs/tags/v2.0.1" \
     --cert-oidc-issuer "https://token.actions.githubusercontent.com"
   ```
   (Download the `.whl` into `dist/` and its `.sigstore.json` bundle first.)

3. **Confirm the PyPI page.** Visit <https://pypi.org/project/mcp-warden-cli/> and check:
   - version `2.0.1` is listed;
   - the project URLs (homepage / repository) point at `DataScience-EngineeringExperts/mcp-warden`;
   - an automated upload records Trusted Publisher provenance; the manual 2.0.0
     recovery must not be described as an OIDC upload.

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
- **Ship a fix-forward release** (`2.0.2`) following section 1 again. This is the
  preferred remedy — never try to re-upload `2.0.1`.
- **GitHub Release**: you may delete or edit the GitHub Release and its assets
  only with a deliberate repair plan; that does not change PyPI bytes. For publisher
  repair, rerun only the failed upload job with the original artifacts. Normal
  duplicate handling uses `skip-existing` after successful authentication.

---

## Why this design

- **No stored secret.** OIDC Trusted Publishing means GitHub never holds a PyPI
  token; PyPI trusts the workflow identity directly. Same trust model as the repo's
  existing keyless Sigstore signing.
- **Heal thyself.** mcp-warden signs everyone else's locks; from v2.0.1 it signs its
  own release artifacts too (the `sign` job), so consumers can verify the wheel they
  install came from this repo's release workflow.
- **Explicit gesture.** A pushed tag does nothing; only *publishing a Release* ships.
  That keeps accidental tags from triggering a publish.
