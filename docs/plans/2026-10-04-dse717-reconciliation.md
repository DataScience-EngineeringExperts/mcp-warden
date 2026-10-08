# DSE-717 recovered-source integration implementation plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the recovered DSE-717 receipt foundation against current main,
without replacing the original work or claiming platform rollback conformance.

**Architecture:** Preserve the reviewed July design and DSE-716 V1. Introduce the
separate V2 governor, evidence coordinator and PEP over strict, independently
authorized signer and protected-state ports. Durable reference logs prove local
append durability and tamper detection; independent protected providers are an
explicit deployment requirement.

**Tech Stack:** Python, strict frozen Pydantic models, RFC 8785, injected offline
signer/verifier ports, SHA-256, pytest/Hypothesis, Ruff, MkDocs and pinned Actions.

## Brief and source provenance

The human checkpoint approves a reviewed tool version and its allowed actions
until either changes. Tools, retrieval, prompts and executable material remain
untrusted inputs; signed bytes do not prove harmless semantics. This wave supplies
the evidence foundation. DSE-1076 live guard integration remains a later dependency.

- Recovered branch: `codex/dse-717-receipts`, head
  `c319fa736d5439036bdf7ba4ee3f9d94bb251ea1`.
- Original base: `e0e1f46`; four commits include design, plan, provider syntax and
  protected-state contracts. No uncommitted code was supplied.
- Integration base: main `608ed25b20e2a43fcfe5ebbe999bcb9fdbcebb03` with the four
  original commits cherry-picked, ending at `09acfff`.
- Preserve the original recovered worktree and branch. Each agent has an isolated
  worktree; integration uses `codex/dse717-integration`.
- Canonical scope: [reviewed design](2026-07-19-decision-receipts-design.md) and
  [implementation plan](2026-07-19-decision-receipts-implementation.md), Tasks 0–8.
- Linear DSE-717 remains `In Progress`; do not mutate its started record.
- No new spend, protected platform deployment, key custody/enrollment, package
  release or production guard activation is authorized by source recovery.

## Task 1: Repair and complete the recovered state contract

**Owner:** Core specialist in its own worktree.
**Files:** `src/mcp_warden/evidence_state.py`, its state helper modules,
`tests/test_evidence_state.py`.

1. Run the original twelve tests in the current locked environment.
2. Add RED regressions proving primary/fallback sequence and tails are independent;
   generation changes cannot hide backward counters or lowered/dropped artifact
   floors; same-generation digest substitution fails.
3. Implement sorted bounded kind/generation/digest floors, self-integrity checks,
   recovery generation and independent latch snapshots/set/authenticated clear.
4. Validate exact untrusted objects again at every port boundary; preserve only
   registered error codes outside provider exception frames.
5. Rerun state tests, Ruff and staged secret scan; commit locally.

## Task 2: Complete the cohesive receipt pipeline

**Owner:** Core specialist. **Files:** New receipt, signer authorization, rule,
governed decision, log, coordinator, recovery, replay, verification, projection and
PEP V2 modules and their new tests from the July plan Tasks 1–6.

Execute the original RED/GREEN checkpoints in dependency order. The original
V1 PDP/PEP, handler identity, adapter conformance, trust verifier, workflows and
core/site docs are excluded from this specialist's file ownership. Keep modules
small, split implementation helpers rather than dropping invariants.

Required proof includes exact external signature/role/kind authorization,
strengthening-only rules, finite noncritical overrides, unsupported limits,
independent expected-tail stores, durable append then protected commit, every
negative recorded, one separately bound deny conversion after failed allow,
latch-clear-last recovery, restart disagreement denial, side-effect-free replay,
safe projections and bounded malformed input.

## Task 3: Close the deferred handler and CI boundary checks

**Owner:** Orchestrator. **Files:** `src/mcp_warden/handler_identity.py`,
`tests/test_handler_boundary.py`, `.github/workflows/integrity-gate.yml`,
`tests/test_workflow_pins.py`.

1. Add RED tests for serialized `CodeType` bytes in constants and immutable
   globals, including nested tuple constants. Keep normal bytes and marshaled
   non-code data accepted.
2. Add RED tests replacing the reported interpreter with CPython 3.10/3.14 and
   PyPy. Fail handler binding outside CPython 3.11–3.13, without narrowing the
   package's unrelated runtime support.
3. Reject code-bearing byte constants at the measured handler boundary, bound
   parsing by the existing identity byte cap, and check interpreter support at
   the public handler entry. Ensure stable code-only failures.
4. Add a narrow 3.11/3.12/3.13 handler compatibility matrix using the current
   pinned checkout/setup-python actions and the relevant enforcement tests.
5. Run focused tests and existing V1 enforcement tests; commit locally.

## Task 4: Strengthen the existing conformance and revocation proof

**Owner:** Orchestrator. **Files:** `src/mcp_warden/adapter_conformance.py`,
`tests/test_adapter_conformance.py`, `tests/test_policy_decision.py`.

1. Add a RED instrumented case with output emitted before the sink.
2. Require `decision < evidence < sink < output` for successful execution;
   preserve the existing no-output indeterminate sink-error behavior.
3. Add a regression that a newer valid revocation generation without explicit
   digest membership retains a lease; explicit membership denies it.
4. Run the focused suite. Add the fixed V2 receipt failure corpus after the new
   interfaces are available, without accepting caller omission of mandatory cases.

## Task 5: Integrate, verify and document accurate claims

**Owner:** Orchestrator; independent security evaluator through VP engineering.
**Files:** `README.md`, `SYSTEM_CONTEXT_DIAGRAM.md`, `DOCUMENTATION_INDEX.md`,
`CHANGELOG.md`, `docs/AGENT_TRUST_KERNEL.md`, `docs/POLICY_ENFORCEMENT.md`,
`docs/DECISION_RECEIPTS.md`, docs-site pages/navigation.

1. Integrate local core commits after inspecting their ownership and focused
   evidence. Reconcile against the original design, rather than replacing it.
2. Run all new and old suites with venv `PATH` and `PYTHONPATH=src`, full coverage
   floor, deterministic fuzz seed 0, Ruff, strict MkDocs and secret scan.
3. Document exact supported events/caps, externally governed signer/state ports,
   restart/fallback behavior, pure replay limits and reference-provider caveats.
   Keep whole-ATK/platform resistance and live guard enforcement claims pending.
4. Require independent adversarial evaluator `APPROVE` on the immutable integrated
   head. Resolve blockers with RED regressions and re-review the changed head.
5. The original plan separately requires explicit approval before sending
   unpublished code to the five-provider Conclave. Prepare the concrete reviewed
   candidate and review prompt first; do not transmit it without that approval.
6. Publish a ready PR only after implementation/review gates. Security-specific
   merge uses one fresh approval bound to the final built head, then the existing
   release-control REST helper and existing docs deployment path.

## Plan self-audit

The recovered state code incorrectly equated independent log tails and omitted
the full protected-floor/latch contract. Those gaps are implementation work,
not evidence that a provider is rollback-resistant. An in-memory/file provider
cannot satisfy the real snapshot gate, even if all deterministic tests pass.
Private signing stays outside agent-editable state. Recovery authorization does
not imply signer enrollment, external code disclosure or a new package release.
The original source remains recoverable if integration is rejected.
