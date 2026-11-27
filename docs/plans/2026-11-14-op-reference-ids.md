# 1Password Reference IDs Implementation Plan

> **For Claude:** Implement and verify each task in order; retain the scoped security review.

**Goal:** Recognize 1Password vault/item IDs without exempting credential literals elsewhere.

**Architecture:** Keep generic locator checks unchanged. Add a scheme- and
position-scoped exception, then mask validated IDs only for auth audit's entropy
scan; retain vendor-pattern scanning over the original value.

**Tech Stack:** Python, pytest, Ruff; all execution on the AWS builder.

---

### Task 1: Reproduce the false positive

Files: `tests/test_auth_refs_op_ids.py`.

1. Add valid vault/item ID references and negative twins for fields, fragments,
   other schemes, lengths, case, query strings and malformed paths.
2. Run `PYTHONPATH=src .venv/bin/pytest -q tests/test_auth_refs_op_ids.py` on the
   builder. Expected before the fix: valid-ID cases fail, negative controls pass.

### Task 2: Implement the scoped exception

Files: `src/mcp_warden/auth_refs.py`, `src/mcp_warden/auth_audit.py`.

1. Recognize `[a-z0-9]{26}` only in vault/item slots of a valid three-part `op://`
   reference. Keep field and fragment checks and generic locator logic.
2. Mask only validated IDs for entropy evaluation. Keep original-value vendor
   matches, and retain entropy checks outside the ID positions.
3. Run the new matrix plus `tests/test_auth_audit.py` and `tests/test_doctor.py`.
   Expected: all pass. Run Ruff over both modules and the new test module.

### Task 3: Verify and prepare review

Files: `docs/AGENT_GATES.md`, `DOCUMENTATION_INDEX.md`, `CHANGELOG.md`.

1. Document the exact exception and entropy/vendor boundaries; verify the core
   README and system diagram retain their accurate static-audit architecture.
2. Run the full pytest coverage suite and lint on the builder, then GitHub CI.
3. Obtain independent CSO review on the exact commit and open the scoped PR.

Rollback: revert the isolated change. No credentials, dependencies, network
access, transport semantics or release version changes are part of this work.
