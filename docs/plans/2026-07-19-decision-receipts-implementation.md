# DSE-717 Signed Receipts and Rules Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add canonical signed security receipts, durable tamper-evident evidence paths,
rollback-resistant state ports, governed deterministic rules, pure replay, and a PEP V2 that
records every decision before any permitted effect.

**Architecture:** Keep DSE-716 V1 stable. Build strict receipt, signer-authorization, rule,
protected-state, and log modules; compose them through a new `PolicyEnforcementPointV2`. Concrete
signer and protected-state providers are injected TCB ports. The reference file log proves local
durability/tamper detection only; platform rollback conformance stays explicit and separate.

**Tech Stack:** Python 3.11-3.13 handler boundary, Pydantic v2 strict models, RFC 8785, SHA-256,
pytest, Hypothesis, Ruff, MkDocs, gitleaks.

---

Implementation must follow strict RED/GREEN cycles. Never create production code for a step until
the named test has failed for the intended missing behavior. Every public error is code-only and
must be raised outside provider exception frames. No commit gets a `Co-Authored-By` line.

## Syntax and provider preflight

Before any external review or provider-backed test, capture the local command/API contract:

```bash
conclave providers
conclave ask --help
```

The currently configured friendly-name to model mapping is: `claude` →
`anthropic/claude-sonnet-4-6`, `gemini` → `gemini/gemini-2.5-pro`, `grok` → `xai/grok-4.3`,
`openai` → `openai/gpt-4.1`, and `perplexity` → `perplexity/sonar-pro`. `deepseek`, `groq`,
`mistral`, and `together` are listed but have no configured key and are not silently substituted.
Re-run `conclave providers` immediately before publication because model IDs and key availability
can drift.

Canonical adversarial invocation (only after explicit unpublished-code approval):

```bash
/Users/ernestprovo/.local/bin/ccl ask "$(cat /private/tmp/conclave-prompt.txt)" \
  --council claude,gemini,grok,openai,perplexity \
  --proposer claude --synthesizer claude --mode adversarial --json --cache
```

`--proposer` is valid for adversarial mode; `--synthesizer` selects the judge. `--json` emits the
full audit result and disables `--stream`; streaming is supported only for synthesize/raw and is
not a realtime/adversarial-review substitute. Conclave provider-specific runtime/model arguments
are not exposed by this CLI; use the resolved model IDs above and record any provider error rather
than inventing flags. DSE-717 signer, rule, state, coordinator, PEP, verifier, and replay APIs are
local typed contracts; their exact keyword arguments are defined by the RED tests in this plan.

## Worktree bootstrap

Create one isolated environment in this worktree and match CI pins before any RED test:

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev,sigstore]"
.venv/bin/pip install "ruff==0.15.21" "mkdocs-material==9.7.6"
PYTHONPATH=src .venv/bin/pytest --version
.venv/bin/ruff --version
.venv/bin/mkdocs --version
mmdc --version
```

All commands below run from `/private/tmp/mcp-warden-dse717`. `PYTHONPATH=src` is mandatory so
tests never import the root checkout. Do not disable plugin autoload: pytest-cov and Hypothesis are
part of the verified CI environment.

## Task 0: Protected-state contracts

**Files:**

- Create: `src/mcp_warden/evidence_state.py`
- Create: `tests/test_evidence_state.py`

**Step 1: Write RED tests for the strict state snapshot**

Cover exact primary/fallback sequence and tail digests, the four recovery modes, sorted artifact
generation/digest floors, below-floor rollback, equal-generation/different-digest, unavailable
state, and code-only provider failures.

```bash
PYTHONPATH=src .venv/bin/pytest tests/test_evidence_state.py -q
```

Expected: import failure because `mcp_warden.evidence_state` does not exist.

**Step 2: Implement only immutable state models and port protocols**

Define `ProtectedStateSnapshotV1`, exact floor lookup/validation, `ProtectedStateV1`, and
`RecoveryLatchV1`. No file/in-memory provider, receipt, or recovery coordinator belongs in this
task.

**Step 3: Verify, stage, scan, and commit**

```bash
PYTHONPATH=src .venv/bin/pytest tests/test_evidence_state.py -q
.venv/bin/ruff format --check src/mcp_warden/evidence_state.py tests/test_evidence_state.py
.venv/bin/ruff check src/mcp_warden/evidence_state.py tests/test_evidence_state.py
git add src/mcp_warden/evidence_state.py tests/test_evidence_state.py
gitleaks git --staged --redact --no-banner
git commit -m "feat: define protected evidence state (DSE-717)"
```

## Task 1: Canonical receipt and signer-authorization models

**Files:**

- Create: `src/mcp_warden/receipt_models.py`
- Create: `src/mcp_warden/decision_receipts.py`
- Create: `tests/test_decision_receipts.py`

**Step 1: Write the failing model and golden-vector tests**

Cover strict/frozen/exact-type construction, closed event/role/artifact registries, all event
discriminators, caps and cap+1, unsorted/duplicate rejection, deterministic unsigned bytes,
self-digest verification, and planted-secret absence. DSE-717 must reject every `limit` receipt
with `RCT-LIMIT-UNSUPPORTED`; future constraint support requires a separately reviewed version.

```python
def test_identical_inputs_make_identical_unsigned_receipt_bytes() -> None:
    left = create_unsigned_receipt(_receipt_input())
    right = create_unsigned_receipt(_receipt_input())
    assert serialize_unsigned_receipt(left) == serialize_unsigned_receipt(right)
```

Run:

```bash
PYTHONPATH=src .venv/bin/pytest tests/test_decision_receipts.py -q
```

Expected: FAIL during import because `mcp_warden.receipt_models` does not exist.

**Step 2: Implement the minimum strict receipt model surface**

Use frozen Pydantic models, exact validators, domain-separated digests, RFC 8785, and fixed caps.
Model `ReceiptEventContextV1` as an exact discriminated union. Do not include raw content,
arguments, internal rule IDs, signatures, exceptions, or provider values in unsigned payloads.

**Step 3: Verify GREEN, then add signer-authorization RED tests**

Add `SignerAuthorizationBundleV1`, signed candidate activation, exact trust-root verifier calls,
generation/validity checks against the exact Task 0 protected snapshot, role/artifact scoping, and
cross-role substitution cases.

```python
def test_rule_publisher_cannot_sign_receipt() -> None:
    with pytest.raises(ReceiptError, match="RCT-SIGNER-UNAUTHORIZED"):
        activate_signed_receipt(_receipt_signed_by_rule_publisher(), authorization=_auth())
```

Expected RED: missing authorization activation. Implement the minimum activation/verifier path and
rerun until the entire file is green.

**Step 4: Run scoped quality checks and commit**

```bash
.venv/bin/ruff format --check src/mcp_warden/receipt_models.py src/mcp_warden/decision_receipts.py \
  tests/test_decision_receipts.py
.venv/bin/ruff check src/mcp_warden/receipt_models.py src/mcp_warden/decision_receipts.py \
  tests/test_decision_receipts.py
git add src/mcp_warden/receipt_models.py src/mcp_warden/decision_receipts.py \
  tests/test_decision_receipts.py
gitleaks git --staged --redact --no-banner
git commit -m "feat: add canonical signed receipt models (DSE-717)"
```

## Task 2: Deterministic rules and governed enforcement decisions

**Files:**

- Create: `src/mcp_warden/rule_models.py`
- Create: `src/mcp_warden/rule_engine.py`
- Create: `src/mcp_warden/governed_decision.py`
- Create: `tests/test_rule_engine.py`

**Step 1: RED-test the exact grammar**

Test every field/type/operator combination from the design; reject empty groups, nesting,
duplicates, unsorted rules/conditions/`in` values, booleans as integers, unknown fields/operators,
and all cap+1 cases. Test no network/clock/environment/dynamic-import dependencies.

```python
@pytest.mark.parametrize("group", [(), (_condition(), _condition())])
def test_empty_or_duplicate_condition_groups_are_rejected(group) -> None:
    with pytest.raises(RuleError, match="RULE-BUNDLE-MALFORMED"):
        RuleGroupV1(mode="all", conditions=group)
```

Run the file; expected RED is a missing module.

**Step 2: Implement grammar/evaluation only and verify GREEN**

Implement the strict rule models and deterministic field/operator evaluation. Run
`PYTHONPATH=src .venv/bin/pytest tests/test_rule_engine.py -q` and require the grammar tests to pass
before adding activation tests.

**Step 3: Add RED activation and critical-corpus tests**

Test exact `rule-publisher` authorization, protected generation/digest floors, validity boundaries,
policy `rule_set_digest`, bad verifier behavior, isolated candidate rejection, and the mandatory
critical corpus without disturbing a known-good active bundle.

**Step 4: Implement activation and verify GREEN**

Apply fixed precedence `quarantine > deny > unchanged`. Bind only the aggregate rule-bundle digest
and coarse public reason to `EnforcementDecisionV2`. Candidate
activation must verify `rule-publisher` authorization, generation/freshness floors, exact policy
`rule_set_digest`, and a non-removable fixed critical corpus before replacing known-good state.
Run the focused file and require GREEN before override tests.

**Step 5: RED-test overrides and unsupported limits**

Add exact `OverrideAuthorizationV1` tests for request/base-decision/policy/rule/actor/scope/reason/
expiry bindings. Prove critical reasons and quarantine cannot be overridden. Prove every `limit`
attempt fails with the closed unsupported code.

**Step 6: Implement override handling, verify GREEN, and commit**

```bash
PYTHONPATH=src .venv/bin/pytest tests/test_rule_engine.py -q
.venv/bin/ruff format --check src/mcp_warden/rule_models.py src/mcp_warden/rule_engine.py \
  src/mcp_warden/governed_decision.py tests/test_rule_engine.py
.venv/bin/ruff check src/mcp_warden/rule_models.py src/mcp_warden/rule_engine.py \
  src/mcp_warden/governed_decision.py tests/test_rule_engine.py
git add src/mcp_warden/rule_models.py src/mcp_warden/rule_engine.py \
  src/mcp_warden/governed_decision.py tests/test_rule_engine.py
gitleaks git --staged --redact --no-banner
git commit -m "feat: add deterministic governed rules (DSE-717)"
```

## Task 3: Protected state, primary log, fallback, and recovery latch

**Files:**

- Modify: `src/mcp_warden/evidence_state.py`
- Create: `src/mcp_warden/receipt_log.py`
- Modify: `tests/test_evidence_state.py`
- Create: `tests/test_receipt_log.py`

**Step 1: RED-test concrete compare-and-advance providers**

Test primary/fallback sequence and tail compare-and-advance, artifact-floor integration used by
Tasks 1-2, concurrent stale snapshots, backward counters, unavailable state, and code-only provider
exceptions.

```python
def test_equal_generation_with_new_digest_is_integrity_failure() -> None:
    state = _state_with_floor("rule", generation=7, digest=_digest("old"))
    with pytest.raises(StateError, match="STATE-FLOOR-INTEGRITY"):
        validate_floor(state, kind="rule", generation=7, digest=_digest("new"))
```

**Step 2: Implement deterministic in-memory providers**

Implement the Task 0 ports with code-only results and compare-and-advance semantics. Primary and
fallback identities must differ. `RecoveryLatchV1` stays a separate provider. Do not label any
in-memory/file provider rollback-resistant.

**Step 3: RED-test framed append and crash cases**

Test exclusive expected-tail validation, full-write loops, file/directory `fsync`, canonical frame
caps, partial tail, truncation, reorder, duplicate sequence, wrong previous digest, restart scan,
primary rollback behind protected state, and log-ahead-after-state-failure. Repeat symmetrically for
fallback.

**Step 4: Implement the reference file log**

Use a small versioned length-prefixed frame with canonical payload bytes and record digest. Hold the
file lock while validating the expected sequence/tail and appending. Surface only stable codes.

**Step 5: Verify and commit**

```bash
PYTHONPATH=src .venv/bin/pytest tests/test_evidence_state.py tests/test_receipt_log.py -q
.venv/bin/ruff format --check src/mcp_warden/evidence_state.py src/mcp_warden/receipt_log.py \
  tests/test_evidence_state.py tests/test_receipt_log.py
.venv/bin/ruff check src/mcp_warden/evidence_state.py src/mcp_warden/receipt_log.py \
  tests/test_evidence_state.py tests/test_receipt_log.py
git add src/mcp_warden/evidence_state.py src/mcp_warden/receipt_log.py \
  tests/test_evidence_state.py tests/test_receipt_log.py
gitleaks git --staged --redact --no-banner
git commit -m "feat: add durable decision evidence state (DSE-717)"
```

## Task 4: Evidence coordinator and failure conversion

**Files:**

- Create: `src/mcp_warden/evidence_coordinator.py`
- Create: `tests/test_evidence_coordinator.py`

**Step 1: RED-test exact context/result bindings**

Test `EvidenceContextV1` and `DecisionEvidenceResultV1` exact types, self digests, request/decision/
policy/rules/runtime/manifest/store bindings, primary-only permit eligibility, and hostile provider
objects/exceptions with no retained context.

**Step 2: Implement context/result models and verify GREEN**

Implement only the immutable bindings and serializers, then run the focused file until Step 1 is
green. Do not create coordinator orchestration before this checkpoint.

**Step 3: RED-test the complete failure matrix**

Cover permit sign/append/state failures, negative primary failure, fallback success/failure, latch
success/failure, primary-tail mismatch, aliasing stores, and no evidence failure becoming
permission. The coordinator owns one attempt only; it never calls itself for converted denial.

```python
def test_failed_allow_evidence_is_bound_only_to_original_decision() -> None:
    result = _coordinator(primary=_failing_primary()).record_decision(_allow_context())
    assert result.mode == "unavailable"
    assert result.decision_digest == _allow_context().decision.decision_digest
```

**Step 4: Implement minimum orchestration and verify GREEN**

Keep canonicalization in receipt modules and state transitions in evidence-state modules. The
coordinator only orchestrates exact ports and returns code-only results.

**Step 5: RED/GREEN the recovery-exit crash protocol**

Test `RecoveryCoordinatorV1.exit()` protected `G+1/recovery-exit-authorized` first, latch-clear-last
exact tuple, identical retry, different retry rejection, crash before/after each mutation, derived
operational eligibility, and startup mismatch denial. Implement only after the RED tests fail.

**Step 6: Quality checks and commit**

```bash
PYTHONPATH=src .venv/bin/pytest tests/test_evidence_coordinator.py -q
.venv/bin/ruff format --check src/mcp_warden/evidence_coordinator.py tests/test_evidence_coordinator.py
.venv/bin/ruff check src/mcp_warden/evidence_coordinator.py tests/test_evidence_coordinator.py
git add src/mcp_warden/evidence_coordinator.py tests/test_evidence_coordinator.py
gitleaks git --staged --redact --no-banner
git commit -m "feat: coordinate fail-closed decision evidence (DSE-717)"
```

## Task 5: PEP V2 complete mediation and deferred hardening

**Files:**

- Create: `src/mcp_warden/policy_enforcement_v2.py`
- Create: `tests/test_policy_enforcement_v2.py`
- Modify: `src/mcp_warden/handler_identity.py`
- Modify: `src/mcp_warden/adapter_conformance.py`
- Modify: `tests/test_policy_enforcement.py`
- Modify: `tests/test_adapter_conformance.py`
- Modify: `tests/test_workflow_pins.py`
- Modify: `.github/workflows/integrity-gate.yml`

**Step 1: RED-test every PEP path before implementation**

Require one initial evidence call for structural blocks, PDP deny/quarantine, rule strengthening,
override, and allow. A failed allow evidence call must create one separate converted-deny decision
and second call. Only healthy `primary-durable` evidence reaches the handler. Assert exact
`decision < evidence < sink < output` trace order for executed results and no sink for negatives.

**Step 2: Implement `PolicyEnforcementPointV2`**

Reuse activated DSE-716 policy/adapter/bundle objects but do not accept caller decisions. Safely
construct fixed-digest structural decisions before hostile nested reads. Route all paths through
the governor and coordinator. Preserve V1 behavior and tests unchanged.

**Step 3: Close the remaining Conclave hardening notes with RED tests**

- Reject a bytes constant only when `marshal.loads()` produces a `CodeType` (including nested code),
  then add a regression that normal byte constants remain accepted.
- Fail the handler boundary closed outside CPython 3.11-3.13; add a focused CI matrix for 3.11,
  3.12, and 3.13 without narrowing unrelated MCP-Warden runtime support.
- Require `sink < output` in the existing conformance harness.
- Add revocation semantics tests/docs proving a generation bump alone does not revoke an old lease;
  explicit digest membership does.

**Step 4: Run focused and compatibility gates, then commit**

```bash
PYTHONPATH=src .venv/bin/pytest tests/test_policy_enforcement.py tests/test_policy_enforcement_v2.py \
  tests/test_adapter_conformance.py tests/test_workflow_pins.py -q
.venv/bin/ruff format --check src/mcp_warden/policy_enforcement_v2.py src/mcp_warden/handler_identity.py \
  src/mcp_warden/adapter_conformance.py tests/test_policy_enforcement_v2.py
.venv/bin/ruff check src/mcp_warden/policy_enforcement_v2.py src/mcp_warden/handler_identity.py \
  src/mcp_warden/adapter_conformance.py tests/test_policy_enforcement_v2.py
git add src/mcp_warden/policy_enforcement_v2.py src/mcp_warden/handler_identity.py \
  src/mcp_warden/adapter_conformance.py tests/test_policy_enforcement.py \
  tests/test_policy_enforcement_v2.py tests/test_adapter_conformance.py tests/test_workflow_pins.py \
  .github/workflows/integrity-gate.yml
gitleaks git --staged --redact --no-banner
git commit -m "feat: enforce durable evidence in PEP V2 (DSE-717)"
```

## Task 6: Verification, replay, and secret-safe projections

**Files:**

- Create: `src/mcp_warden/receipt_verification.py`
- Create: `src/mcp_warden/receipt_replay.py`
- Create: `src/mcp_warden/receipt_projection.py`
- Create: `tests/test_receipt_verification.py`
- Create: `tests/test_receipt_replay.py`
- Create: `tests/test_receipt_projection.py`

**Step 1: RED-test verification and pure replay**

Verify signature authorization, canonical form, chains, sequences, floors, event bindings, and
every tamper/reorder/truncate/replay/rollback case. `ReplayVectorV1` tests must remove each input in
turn and fail construction. Provider spies must prove historical replay calls no PEP, signer,
verifier, store, protected state, handler, or sink. Test current eligibility separately.

**Step 2: Implement minimal verifier/replay functions**

Historical replay recomputes bytes only. It never activates authority. Current eligibility consumes
an explicit protected snapshot and produces a code-only report.

**Step 3: RED-test exact human/agent allowlists**

Assert exact key sets, coarse agent reason/next-action mappings, and planted-secret absence. Feed
hostile provider exceptions/paths/classes and prove only registered codes cross serializers.

**Step 4: GREEN, checks, and commit**

```bash
PYTHONPATH=src .venv/bin/pytest tests/test_receipt_verification.py tests/test_receipt_replay.py \
  tests/test_receipt_projection.py -q
.venv/bin/ruff format --check src/mcp_warden/receipt_verification.py src/mcp_warden/receipt_replay.py \
  src/mcp_warden/receipt_projection.py tests/test_receipt_*.py
.venv/bin/ruff check src/mcp_warden/receipt_verification.py src/mcp_warden/receipt_replay.py \
  src/mcp_warden/receipt_projection.py tests/test_receipt_*.py
git add src/mcp_warden/receipt_verification.py src/mcp_warden/receipt_replay.py \
  src/mcp_warden/receipt_projection.py tests/test_receipt_verification.py \
  tests/test_receipt_replay.py tests/test_receipt_projection.py
gitleaks git --staged --redact --no-banner
git commit -m "feat: verify replay and project receipts (DSE-717)"
```

## Task 7: Fixed conformance corpus, fuzzing, and documentation

**Files:**

- Create: `tests/fuzz/test_fuzz_receipts.py`
- Create: `docs/DECISION_RECEIPTS.md`
- Modify: `src/mcp_warden/adapter_conformance.py`
- Modify: `tests/test_adapter_conformance.py`
- Modify: `docs/AGENT_TRUST_KERNEL.md`
- Modify: `docs/POLICY_ENFORCEMENT.md`
- Modify: `README.md`
- Modify: `SYSTEM_CONTEXT_DIAGRAM.md`
- Modify: `DOCUMENTATION_INDEX.md`

**Step 1: RED-test the non-optional DSE-717 corpus**

Add fixed primary/fallback/latch/restart/rollback/secret cases that callers cannot remove. Prove
every manifest operation has positive evidence ordering, every negative has durable primary or
fallback/latch evidence, and all serialized channels are scanned.

**Step 2: Implement the fixed corpus and verify GREEN**

Add the versioned cases to `adapter_conformance.py`, keep them non-optional, and rerun the focused
test until every RED failure turns green. Do not weaken expected codes or remove hostile cases.

**Step 3: Add deterministic property tests**

Use Hypothesis with seed 0 for canonical repeatability, event union round trips, caps, rule order
independence, taint matching, tamper detection, projection allowlists, and bounded malformed-byte
termination.

```bash
PYTHONPATH=src .venv/bin/pytest tests/fuzz/test_fuzz_receipts.py \
  -p no:randomly --hypothesis-seed=0 -q
```

**Step 4: Synchronize the three core docs and security scope**

Document exact V2 claims, reason/error matrix, caps, state/receipt diagrams, port trust boundary,
reference file limitations, override/limit behavior, and platform conformance gate. Keep
`AGENT_TRUST_KERNEL.md` normative and never claim whole-ATK conformance without real rollback tests.

**Step 5: Strict docs, Mermaid render, focused suite, and commit**

```bash
.venv/bin/mkdocs build --strict
mmdc -i docs/AGENT_TRUST_KERNEL.md -o /private/tmp/mcp-warden-dse717-atk.md
mmdc -i SYSTEM_CONTEXT_DIAGRAM.md -o /private/tmp/mcp-warden-dse717-system.md
PYTHONPATH=src .venv/bin/pytest tests/test_adapter_conformance.py \
  tests/fuzz/test_fuzz_receipts.py -p no:randomly \
  --hypothesis-seed=0 -q
git add src/mcp_warden/adapter_conformance.py tests/test_adapter_conformance.py \
  tests/fuzz/test_fuzz_receipts.py docs/DECISION_RECEIPTS.md docs/AGENT_TRUST_KERNEL.md \
  docs/POLICY_ENFORCEMENT.md README.md SYSTEM_CONTEXT_DIAGRAM.md DOCUMENTATION_INDEX.md
gitleaks git --staged --redact --no-banner
git commit -m "docs: integrate decision receipt evidence (DSE-717)"
```

## Task 8: Full verification, adversarial review, publication, and metadata

**Files:**

- Modify only if a verified finding requires a RED regression and scoped fix.
- Update canonical AI-SDLC records `00` through `06` outside the repository.

**Step 1: Run the complete local gate**

```bash
.venv/bin/ruff format --check .
.venv/bin/ruff check .
.venv/bin/python -m compileall -q src tests
.venv/bin/mkdocs build --strict
COVERAGE_PROCESS_START=pyproject.toml PYTHONPATH=src .venv/bin/pytest \
  --cov=mcp_warden --cov-report=term-missing --cov-fail-under=80
gitleaks git --redact --no-banner --log-opts=main..HEAD
git diff --check main...HEAD
```

Re-run the macOS process-lifecycle test outside the sandbox if the known `pgrep` restriction is the
only deselection. Record exact test and coverage counts.

**Step 2: Independent security review and Conclave**

Require read-only adversarial probes for every ATK-10..12 failure path. After owner approval for
external unpublished-code transfer, run the canonical five-provider Conclave against the immutable
candidate commit. Resolve every blocking finding with a new RED regression, then rerun the entire
gate and final review on the new immutable head.

**Step 3: Publish only the immutable reviewed head**

```bash
git push -u origin codex/dse-717-receipts
```

Open a ready PR linked to DSE-717. Wait for CI, Docs, Examples, dependency locking, Sigstore,
integrity, secret scan, lint, Python tests/coverage, and the 3.11-3.13 handler compatibility matrix.
Admin-merge only after every required check is green and the PR head still matches the reviewed
commit.

**Step 4: Close project metadata**

Fast-forward local `main`, mark DSE-717 Done with PR/merge SHA and review evidence, synchronize the
AI-SDLC records, and re-read Linear for the next dependency-unblocked MCP-Warden issue.
