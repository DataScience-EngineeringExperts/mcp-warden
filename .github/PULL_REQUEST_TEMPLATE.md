<!--
Thanks for contributing to mcp-warden. mcp-warden is a security tool, so PRs are
held to a determinism + specs-in-sync bar. See CONTRIBUTING.md.
Do NOT use a PR to report a security vulnerability — follow SECURITY.md.
-->

## What & why

<!-- What does this change do, and what problem does it solve? Link any issue. -->

Closes #

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature / check (non-breaking)
- [ ] Breaking change (alters a hash, canonical form, rule verdict, or CLI contract)
- [ ] Docs / specs only
- [ ] CI / tooling

## Checklist

- [ ] **Tests pass** via the repo venv: `.venv/bin/python -m pytest -q` is green.
- [ ] **Specs updated.** Any behavior change (hashing, canonicalization, the
      `WRD-*` / `WRD-RES-*` catalogs, drift semantics, block posture, policy,
      reserved error codes) updates the matching `docs/` spec in this same PR.
- [ ] **Determinism preserved.** No unintended change to a digest, canonical form,
      or rule verdict on an unchanged surface. If a hash change is intentional, it
      is documented and the version is bumped.
- [ ] **`guard` / `inspect` parity** holds for any result-rule change
      (`tests/test_inspect_parity.py`).
- [ ] **No secrets.** No real credentials anywhere; test fixtures use obviously-fake
      placeholders (already allowlisted in `.gitleaks.toml`).
- [ ] **Docs in sync.** README / CLI reference / `DOCUMENTATION_INDEX.md` updated if
      user-facing behavior or flags changed.

## Notes for reviewers

<!-- Anything you want a reviewer to look at first; fixture/spec diffs welcome. -->
