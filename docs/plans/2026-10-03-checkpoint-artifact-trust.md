# Checkpoint Artifact Trust Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Verify externally approved DSE-716 governance artifacts using pinned public keys and artifact-specific signer roles, without exposing signing authority to an agent.

**Architecture:** Implement the existing `ArtifactVerifierV1` port using Ed25519. A consumer pins the complete public-key/role configuration by digest outside agent-editable state; each signature binds the exact canonical artifact, artifact kind, key identity, and signature format. Offline CLI commands prepare unsigned review artifacts and verify signatures; existing activation APIs retain all structural and policy checks.

**Tech Stack:** Python 3.11+, existing Pydantic/RFC 8785 serializers, optional `cryptography` Ed25519 support, Typer, pytest.

---

## Brief and scope

The owner approved development of a human checkpoint for a reviewed tool version and its allowed actions. DSE-716 already defines exact policy grants, leases, adapter operations, and executable/dependency closure. This wave replaces its test-only signature verifier seam with a usable public-key verifier and review/verification tooling.

DSE-717 is started and records unpublished work on `codex/dse-717-receipts` (design `cbf9dfe`, plan `73ab1b0`, protected-state task `c319fa7`). Those objects and that worktree are absent from the builder and GitHub. Recover them before implementing its receipt/recovery design. Do not mutate that started issue or recreate its unfinished modules. DSE-1076 runtime integration remains blocked by it.

Done means real signatures activate the existing policy/runtime/adapter/bundle contracts; wrong keys, roles, kinds, algorithms, changed bytes, malformed artifacts, and changed root configurations fail closed. Existing evidence gate and guard behavior stay unchanged. No claim of live human-checkpoint enforcement, protected-state persistence, artifact safety, or whole-kernel conformance follows from signature verification.

## Task 1: Canonical public-key trust and signing contract

**Files:** Create `src/mcp_warden/artifact_trust.py`, `src/mcp_warden/artifact_payload.py`; test `tests/test_artifact_trust.py`.

1. Write real Ed25519 fixtures and failing tests for canonical root pins, key-derived signer identity, role separation, exact signing bytes, and malformed/bounded inputs.
2. Run `.venv/bin/pytest -q tests/test_artifact_trust.py`; expect missing-module failures.
3. Implement immutable public-key/role records, bounded duplicate-rejecting JSON parsing, canonical existing-model validation, domain-separated signing bytes and `Ed25519ArtifactVerifierV1`. Require a pinned digest of the complete root configuration. Accept only `VerificationAlgorithmV1.EXTERNAL_V1`; do not introduce algorithm negotiation or private-key access.
4. Run the focused tests; expect valid signature verification and failure for every substitution case.

## Task 2: Offline review and verification CLI

**Files:** Create `src/mcp_warden/cli_trust.py`; modify `src/mcp_warden/cli.py`, `pyproject.toml`, `requirements-dev.lock`; test `tests/test_cli_trust.py`.

1. Write failing CLI tests for `trust roots-digest`, `trust prepare`, and `trust verify`, including secret-safe errors and output-file collisions.
2. Add an optional `artifact-trust` extra and a dev dependency using the existing locked cryptography version as the resolution baseline. Regenerate the dev lock with its documented universal/hash command.
3. Implement bounded file reads; create review outputs exclusively, reject clobbering or input/output collisions, and clean up partial new outputs. `prepare` emits canonical artifact JSON plus the exact bytes to sign externally. `verify` requires explicit roots, pinned roots digest, signer and detached 64-byte signature. Report only signature verification, not activation or execution authorization.
4. Run `.venv/bin/pytest -q tests/test_artifact_trust.py tests/test_cli_trust.py` and `.venv/bin/ruff check` on changed files.

## Task 3: Integration proof and documentation

**Files:** Test `tests/test_artifact_trust_integration.py`; create `docs/ARTIFACT_TRUST.md`; modify the three core docs and documentation navigation.

1. Prove actual signatures work through existing policy/runtime/adapter/bundle activation; use the existing instrumented adapter fixtures only in tests.
2. Demonstrate payload/kind/key substitutions fail activation and the default evidence gate still blocks execution. Test duplicate keys, unknown fields, booleans in integer fields, unsupported schemas, role changes, malformed signature lengths, over-cap data, and unavailable crypto support.
3. Document exact signing frame, public-key identity and trust digest, protected pin/key-custody requirements, SDK usage, offline CLI workflow, and remaining DSE-717/DSE-1076 dependencies. Signature verification alone does not enforce freshness, expiry, revocation, artifact/dependency measurements, or allowed actions; those checks remain in activated policy/runtime/adapter/bundle and PDP/PEP contracts.
4. Run focused integration tests, the existing DSE-716 suites, Ruff, strict docs build and the full CI-equivalent Python suite. Require independent security evaluator `APPROVE` against the final diff before release. Record any remaining release gate against a concrete PR/head.

## Adversarial plan pass

- **Root substitution:** require an independently pinned digest covering keys AND roles; a roots file supplied by an artifact cannot confer trust.
- **Cross-role signatures:** bind artifact kind and derived signer identity in the signing frame; every configured key must enumerate allowed kinds.
- **Ambiguous parsing:** reject duplicate keys/non-finite numbers and unknown fields; compare canonical payloads exactly in SDK verification.
- **Agent self-approval:** no private signing key, generation, or signing command exists in product code. Key enrollment/pin updates are governance operations outside the model.
- **Unfinished work:** preserve the unpublished DSE-717 implementation; no duplicate receipts, logs, or recovery stores in this wave.
- **Rollback:** revert the new opt-in CLI/verifier and its documentation; existing default-deny evidence behavior is unchanged. A local root file/pin controlled by the agent provides no defended trust boundary.
