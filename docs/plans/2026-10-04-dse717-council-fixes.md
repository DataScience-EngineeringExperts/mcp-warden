# DSE-717 Council Defensive Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Preserve quarantine, support independently trusted historical signer rotation, and require the complete V2 floor contract.

**Architecture:** Retain closed decisions and evidence-before-effect. Historical signatures use only TCB-supplied, previously root-activated authorizations and pinned public verifiers; current signing/governance still enforces current floors. Enforce required floor presence at the V2 coordinator read boundary, preserving legacy snapshot representation.

**Tech Stack:** Python 3.11–3.13, Pydantic, Ed25519, pytest, POSIX file logs.

---

### Task 1: Quarantine precedence and honest rejection codes

**Files:** `src/mcp_warden/policy_enforcement_v2.py`, `src/mcp_warden/governed_decision.py`, `tests/test_dse717_council_fixes.py`.

1. Add valid critical-taint request plus invalid override RED regression; add ordinary deny/allow input rejection and code-only exception regressions.
2. Run `PYTHONPATH=. /home/ubuntu/dev/worktrees/mcp-warden-dse717-integration/.venv/bin/pytest -q tests/test_dse717_council_fixes.py -k override` and retain failures.
3. Reevaluate rejected overrides without the override so strengthening remains effective; never downgrade quarantine. Distinguish known authority/input failure codes from recovery failure and hide arbitrary exception text.
4. Rerun focused tests and commit.

### Task 2: Historical signing authority across rotation

**Files:** `src/mcp_warden/signer_authorization.py`, `src/mcp_warden/receipt_verification.py`, `tests/test_dse717_council_fixes.py`.

1. Generate deterministic root-authorized generation/key rotation, append under old authority, advance floors, append under new authority, reopen, and verify complete chain. Record genuine pre-fix RED.
2. Factor sealed authorization integrity/time/grant/signature checks from current floor checks. Keep all live signing/governance callers strict.
3. Resolve historical receipts by digest only against bounded independently supplied `(activated_authorization, pinned_verifier)` tuples, never receipt-provided authorizations. Check current authorization floors on scans/chain verification.
4. Add negative regressions for absent/wrong/unactivated pins, tampering, stale live signing, and current-floor rollback; run focused tests and commit.

### Task 3: Complete V2 floor presence

**Files:** `src/mcp_warden/evidence_coordinator.py`, `src/mcp_warden/evidence_floor.py`, `tests/test_dse717_council_fixes.py`.

1. Omit each mandatory kind with recomputed valid state digest, including unused executable-bundle/fallback-log; require blocked effect and no primary permit receipt. Record pre-fix RED.
2. At `_read()` after protected-state integrity verification require adapter, executable-bundle, fallback-log, policy, receipt-log, revocation, rule, signer-authorization, trust-root. Keep override conditional on explicit use.
3. Preserve legacy snapshot construction/transition compatibility and add both conditional override cases.
4. Run focused tests and commit.

### Task 4: Document bounded APIs and validate

**Files:** `docs/DECISION_RECEIPTS.md` (plus core docs only where affected).

1. Document historical TCB pin retention and strict live floors, primary-only human projection, closed fallback/recovery result serializer, file-reopen-only reference conformance, and legacy scalar deprecation/divergence.
2. Run receipt/governance/V2 suites and Ruff using builder venv; inspect diff and clean status.
3. Return immutable commits, exact RED/GREEN evidence, file paths/lines and remaining independent evaluator/integration ownership to parent.

**Adversarial check:** Unknown exception text must never serialize; invalid override must not erase rule quarantine; current floor advance must block retired live signing while preserving old evidence. Missing pin must reject, not learn authority from receipt. All nine floors are mandatory even if unused; legacy constructor stays compatible. Rollback is reverting isolated commits before publication; independent real-platform protection remains Unsupported. Root owns full multi-interpreter gate, exact-head CSO review and human security publication receipt.
