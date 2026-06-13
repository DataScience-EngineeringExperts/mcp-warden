# How to pin MCP servers in CI

The pattern is the same on every CI system: **pin once, check on every PR,
re-pin only after a human reviews the diff.** This page shows it on GitHub
Actions and GitLab CI, and links runnable templates you can fork.

## The pin-once / check-on-PR pattern

1. **Pin once, locally.** Capture the server's declared surface, record an
   approval, and commit the resulting `warden.lock`:

    ```bash
    mcp-warden pin node ./build/index.js \
        --approve --approver you@example.com \
        --lock warden.lock
    git add warden.lock && git commit -m "chore: pin MCP surface baseline"
    ```

2. **Check on every PR.** CI re-captures the live surface and diffs it against
   the committed lock. Any drift exits non-zero and fails the build.

3. **Re-pin only after review.** When the surface legitimately changes, a human
   reviews the diff and re-pins on a dedicated change.

The lock is the human-approved baseline; CI is the deterministic gate that the
surface you run is still the surface you approved.

## GitHub Actions

### One-step drop-in (official Action)

```yaml
# .github/workflows/mcp-integrity.yml
permissions:
  contents: read
  security-events: write   # only needed when upload-sarif: true (the default)

jobs:
  mcp-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ernestprovo23/mcp-warden@v0
        with:
          server-cmd: "node ./build/index.js"
          lock: "warden.lock"
          # upload-sarif: "false"   # uncomment for private repos without GHAS
```

The Action installs mcp-warden from the exact `@ref` you pin, runs `check`,
fails the build on drift, and (by default) uploads a SARIF report to GitHub code
scanning. Set `upload-sarif: false` for fork pull requests or private repos
without GitHub Advanced Security.

### Manual multi-step (pip install)

```yaml
- name: Install mcp-warden
  run: pip install mcp-warden-cli       # PyPI dist `mcp-warden-cli`; CLI command `mcp-warden`

- name: MCP integrity gate
  run: |
    mcp-warden check node ./build/index.js \
      --lock warden.lock \
      --sarif warden.sarif

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: warden.sarif
```

### Runnable GitHub Actions templates

These live in the repository and are re-validated by CI on every change:

- [pin-on-merge + check-on-PR](https://github.com/ernestprovo23/mcp-warden/blob/main/examples/github-actions/pin-on-merge-check-on-pr.yml)
  — check on every PR, plus a manual re-pin job.
- [matrix over multiple servers](https://github.com/ernestprovo23/mcp-warden/blob/main/examples/github-actions/matrix-multiple-servers.yml)
  — one gate fanned out across several servers.
- [SARIF upload to code scanning](https://github.com/ernestprovo23/mcp-warden/blob/main/examples/github-actions/sarif-upload.yml)
  — the default mode.
- [private repo, no SARIF upload](https://github.com/ernestprovo23/mcp-warden/blob/main/examples/github-actions/private-repo-no-sarif.yml)
  — `upload-sarif: false` for private repos / fork PRs.

## GitLab CI

The same check gate on GitLab. Pin and commit `warden.lock` locally exactly as
above, then add a check job:

```yaml
mcp-integrity:
  image: python:3.11-slim
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  before_script:
    - pip install mcp-warden-cli       # PyPI dist `mcp-warden-cli`; CLI command `mcp-warden`
  script:
    - mcp-warden check node ./build/index.js --lock warden.lock --sarif warden.sarif
  artifacts:
    when: always
    paths:
      - warden.sarif
```

A complete, runnable GitLab template is in the repository:

- [`examples/gitlab-ci/.gitlab-ci.yml`](https://github.com/ernestprovo23/mcp-warden/blob/main/examples/gitlab-ci/.gitlab-ci.yml)

## Run it locally too (pre-commit)

To catch a rug pull before it ever reaches CI, run the *same* drift verdict on
every commit with the [pre-commit](https://pre-commit.com) hook. A complete,
copy-pasteable config (and a pre-push variant) is in the repository:

- [`examples/pre-commit/.pre-commit-config.yaml`](https://github.com/ernestprovo23/mcp-warden/blob/main/examples/pre-commit/.pre-commit-config.yaml)

## Worked examples: real pinned servers

The repository ships real, openly-available MCP servers pinned to a committed
`warden.lock` each, re-checked by CI so they never go stale:

- [`examples/pinned-servers/`](https://github.com/ernestprovo23/mcp-warden/tree/main/examples/pinned-servers)
  — `server-everything`, `server-memory`, and `server-sequential-thinking`, each
  with the exact `pin` argv and a sample `check`.

See the [examples index](https://github.com/ernestprovo23/mcp-warden/blob/main/examples/README.md)
for the full gallery.

!!! warning "What this does NOT cover"
    A CI drift gate verifies the **declared** surface against an approved
    baseline. It does **not** inspect runtime behavior, does **not** statically
    classify a new surface as malicious (pair it with a scanner — see the
    [comparison](comparison.md)), and makes **no compliance or regulatory
    claim**. Read the limits in the
    [threat model](https://github.com/ernestprovo23/mcp-warden/blob/main/docs/THREAT_MODEL.md).
