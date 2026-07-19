# DSE-716 PDP/PEP implementation plan

> **Non-normative execution plan.** `docs/AGENT_TRUST_KERNEL.md` is the governing security
> contract. This plan may not weaken its invariants.

## Objective

Implement strict deterministic policy decision and structural enforcement APIs consuming the
DSE-715 envelope, with stable fail-closed reasons and an executable adapter conformance harness.

## Design choices

1. Explicit bounded digest-only request context; raw canonical effect arguments are held in a
   separate bounded non-serializable input whose digest the PEP recomputes before evaluation.
   No raw identities, content, secrets, ambient time, environment, or network state enter a
   decision or public result.
2. Signed policy, adapter, trusted-runtime, and executable-bundle candidates activate outside
   evaluation through a verifier TCB seam. Failed candidates cannot replace a fresh active
   snapshot; bundle activation binds exact evidence, publisher, policy, and adapter manifest.
3. Exact lease grants bind user, agent, device, session, data, adapter manifest, executable bundle
   for `execute`, operation, arguments, destination, purpose, authority generations, and trusted
   validity/freshness.
4. Closed mandatory critical floor and stable reason/recovery registries; policy may only add
   restrictions.
5. Finite signed operation manifest and frozen, closure-free, mechanically code/dependency-derived
   handler bijection; the
   caller never supplies a decision, and PEP ordering is effect-digest validation, exact
   adapter/bundle binding, decision, bound evidence gate, then sink.
6. Default pre-effect gate denies and returns no boolean bypass. DSE-717 supplies the bound durable
   evidence result before production effects.
7. V1 emits allow, deny, or quarantine only; `limit` is deferred until constraints can be
   mechanically enforced rather than represented by an advisory digest.


## TDD sequence

1. Add failing model/canonicalization/golden-vector tests, then strict versioned models and digest
   domains.
2. Add failing activation/default-deny/binding/time/revocation/critical-floor tests, then the pure
   deterministic PDP.
3. Add failing manifest/registry/decision-swap/evidence-order/unknown-operation tests, then the
   structural PEP.
4. Add failing conformance-corpus and planted-secret tests, then the adapter harness with a fixed
   non-optional versioned foundation corpus.
5. Add deterministic property/fuzz cases and exact cap/cap+1 tests.
6. Integrate the API/boundary documentation and core docs without claiming DSE-717 behavior.
7. Reopen after independent security review; reproduce and close executable-load, handler-TOCTOU,
   adapter-version binding, hostile-nested-input, caller-selected-corpus, and missing execution
   instrumentation/output-channel findings before publication.

## Verification

- focused unit suites after every RED/GREEN task;
- deterministic property/fuzz suite;
- exact no-I/O/no-ambient-clock/static import guards;
- full Ruff and repository suite with CI environment flags;
- strict MkDocs, relative links, Mermaid render, compile, diff, and secret scan;
- independent security review and Conclave adversarial regression;
- required GitHub Actions on the immutable final PR head.
