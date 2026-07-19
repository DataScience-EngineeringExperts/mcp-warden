# Deterministic policy decision and enforcement V1

**Status:** DSE-716 implemented foundation. These APIs are not wired into the historical
`guard` proxy and do not by themselves make MCP-Warden Agent Trust Kernel conformant.
`docs/AGENT_TRUST_KERNEL.md` remains the governing security contract.

## Security claim

The V1 policy decision point (PDP) is a total deterministic function over an exact canonical
request, a verified activated policy snapshot, and a verified explicit trusted-runtime snapshot.
It returns allow only for one exact signed lease grant after every user, agent, device, session,
data, operation, capability, argument, destination, purpose, policy, time, freshness, generation,
and revocation binding passes. Every missing, malformed, stale, revoked, rolled-back, unknown, or
internally errored condition denies or quarantines.

The V1 policy enforcement point (PEP) is the only supported route from an activated adapter
registry to its registered sinks. It validates exact canonical effect bytes and the lease-bound
adapter-manifest digest, requires a matching activated signed bundle for `execute`, evaluates
through the PDP internally, obtains evidence bound to the request/decision/manifest/policy tuple,
and only then invokes the registered sink. Callers cannot submit a decision. The default evidence
gate denies every otherwise allowed operation.

The implementation does **not** claim that arbitrary Python code cannot retain and call an
external raw function reference. A conforming adapter must use the signed manifest and one-shot
registry and expose no alternate sink path. An adapter that retains or exposes a bypass is
nonconformant. The conformance harness is executable evidence for the supported registry/PEP path,
not a proof about code outside that boundary.

## Public modules

| Module | Responsibility |
|---|---|
| `decision_models.py` | Closed V1 digest, capability, verdict, reason, recovery, identity, operation, lease, policy, runtime, request, and decision models |
| `policy_decision.py` | Canonical activation, exact request/lease construction, deterministic PDP, decision serialization |
| `policy_enforcement.py` | Signed adapter manifest, artifact/dependency closure, one-shot handler registry, canonical effect input, bound evidence result, structural PEP |
| `handler_identity.py` | Mechanically derived Python function-code evidence and frozen callable snapshots with pre-invocation drift checks |
| `executable_bundle.py` | Exact bundle evidence closure, signed publisher/policy/adapter-bound manifest activation, immutable activated bundle |
| `adapter_conformance.py` | Mandatory versioned foundation corpus plus instrumented operation coverage, planted-secret scans, deterministic reports |

All public failure exceptions are stable code-only `DecisionError`, `EnforcementError`, or
`ConformanceError` values. Public decisions, enforcement results, and conformance reports contain
only bounded identifiers, digests, registered codes, and digest-only content envelopes.

## Activation boundary

Policy, trusted-runtime, adapter, and executable-bundle candidates are activated outside decision
evaluation.
Activation:

1. requires exact V1 candidate/model types;
2. validates closed schemas, registries, sorting, uniqueness, and byte/count caps;
3. canonicalizes the candidate with RFC 8785;
4. calls the configured verifier exactly once with artifact kind, closed algorithm identifier,
   signer identity digest, exact canonical payload bytes, and detached signature bytes;
5. rejects verifier false, non-boolean, exception, or malformed output with a code-only error;
6. returns an immutable privately marked activated snapshot only after success.

The verifier and the issuer of the signed trusted-runtime snapshot are part of the TCB. They may
perform authenticated synchronization before activation, but evaluation itself performs no
network, clock, environment, filesystem, dynamic import, or verifier call. Candidate activation
returns a new object and mutates no current PDP/PEP, so a rejected candidate cannot displace a
fresh active snapshot.

Adapter activation additionally recomputes the exact adapter implementation digest, the complete
sorted unique dependency closure, and every registered handler digest from the actual Python code
object before it verifies the signed manifest. V1 accepts closure-free, default-free exact Python
functions only. Direct global function dependencies are recursively included in the handler digest
and cloned into the activated snapshot. Referenced data globals must be recursively immutable
scalars, tuples, or frozensets and are also digest bound; mutable globals, modules, classes,
callable builtins, imports, global/nonlocal writes, closure-controlled delegates, and dunder
introspection are rejected. Nested code objects (lambdas, comprehensions, generators, and nested
functions) are also rejected so they cannot conceal a second global or bytecode surface. The PEP
rechecks the frozen snapshot immediately before invocation.
Manifest operations and registrations must be a bijection. Missing, extra, duplicate,
digest-mismatched, drifted, or post-activation registration fails closed.

Executable-bundle activation recomputes the artifact, supply-chain signature evidence, version
claims, publisher claims, canonical dependency closure, and policy-binding claim digests from
exact bounded bytes. Its signed manifest also binds a verified publisher identity, explicit bundle
ID/version, policy ID/generation, and the exact activated adapter-manifest digest. The PEP accepts
an `execute` request only when its envelope evidence and lease-bound bundle-manifest digest match
that privately marked activated bundle exactly. Attacker-authored bundle metadata alone is never
load authority.

## Canonical request and lease binding

`DecisionRequestV1` contains:

- user, agent, device, and session identity digests;
- the complete `ContentEnvelopeV1` public projection and a data-scope digest;
- adapter ID, exact adapter-manifest digest, operation ID, closed capability, arguments digest,
  destination digest, and an exact executable-bundle manifest digest for `execute` only;
- purpose digest;
- an exact `CapabilityLeaseV1` and request self digest.

`CapabilityLeaseV1` binds the canonical request-binding digest, policy ID/generation, validity
interval, revocation generation, and its own digest. The signed policy grants only exact lease
digests. There are no wildcards, implicit grants, model-confidence grants, human per-decision
overrides, audit-only modes, or category opt-outs.

All time windows are half-open. Policy and lease `valid_from` / `not_before` values are inclusive;
their `valid_until` / `expires_at` values are exclusive. A trusted-runtime snapshot is stale when
`trusted_time == trusted_time_valid_until`, so an authority boundary can never gain an extra tick.

Raw canonical effect arguments live only in `EffectInputV1`. The PEP reparses them, requires exact
RFC 8785 bytes, recomputes the domain-separated digest, and compares that digest with the bound
request before evaluation. Raw arguments never enter a public decision, result, error, or report.

## Fixed decision precedence

For a representable exact request, the PDP evaluates in this order:

1. activated policy/runtime integrity and content-envelope self integrity;
2. request self digest;
3. recovery-only state;
4. trusted-time freshness;
5. policy validity;
6. policy and revocation generation floors, including equal-generation digest match;
7. mandatory critical floor;
8. lease self digest and policy/revocation binding;
9. lease not-before, expiry, and revocation;
10. complete multidimensional request-binding digest;
11. exact signed lease grant;
12. allow.

The first applicable condition selects the reason and recovery code. Unrepresentable input uses a
fixed invalid-input digest rather than serializing attacker-controlled values. Unexpected internal
exceptions return `PDP-INTERNAL-ERROR`, deny, and `recovery-only`.

## Decision matrix

| Condition | Verdict | Reason | Recovery |
|---|---|---|---|
| Exact fresh signed grant and every binding matches | allow | `PDP-ALLOW-EXACT-GRANT` | `none` |
| No exact grant | deny | `PDP-DENY-DEFAULT` | `obtain-new-lease` |
| Nonexact/hostile/unrepresentable request | deny | `PDP-INPUT-MALFORMED` | `reauthenticate` |
| Request self digest changed | deny | `PDP-REQUEST-INTEGRITY` | `reauthenticate` |
| Activated trusted runtime absent/invalid | deny | `PDP-AUTHORITY-UNAVAILABLE` | `refresh-authority` |
| Recovery-only runtime | deny | `PDP-RECOVERY-ONLY` | `recovery-only` |
| Trusted-time snapshot stale | deny | `PDP-TRUSTED-TIME-STALE` | `refresh-authority` |
| Policy outside signed validity | deny | `PDP-POLICY-STALE` | `refresh-authority` |
| Policy/revocation below floor or equal-generation digest mismatch | deny | `PDP-POLICY-ROLLBACK` | `recovery-only` |
| Envelope integrity invalid | quarantine | `PDP-ENVELOPE-INVALID` | `quarantine-input` |
| `core:critical` or `core:authority-injection` | quarantine | `PDP-CRITICAL-TAINT` | `quarantine-input` |
| `core:malformed` or `core:uninspectable` | quarantine | `PDP-UNINSPECTABLE-DATA` | `quarantine-input` |
| Policy administration or recovery repair through the normal lane | deny | `PDP-PRIVILEGED-PATH-REQUIRED` | `reauthenticate` |
| `core:executable` content requested for execution | quarantine | `PDP-EXECUTABLE-CONTENT` | `quarantine-input` |
| Lease too early / expired / revoked | deny | `PDP-LEASE-NOT-YET-VALID` / `PDP-LEASE-EXPIRED` / `PDP-LEASE-REVOKED` | `obtain-new-lease` |
| Lease/request dimension mismatch | deny | `PDP-LEASE-BINDING` | `reauthenticate` |
| Lease policy/generation mismatch | deny | `PDP-POLICY-BINDING` | `obtain-new-lease` or `refresh-authority` |
| Unexpected internal failure | deny | `PDP-INTERNAL-ERROR` | `recovery-only` |

V1 deliberately does not emit a `limit` verdict. A constraints digest without mechanically
enforced sink semantics would create false authority. A future interface version may add `limit`
only with an executable constraint contract.

## PEP ordering and result semantics

The PEP order is fixed:

```text
canonical effect bytes -> request/adapter/bundle match -> PDP -> bound evidence -> registered sink
```

- A deny or quarantine never calls the evidence gate or sink.
- Missing/failed evidence returns `PEP-EVIDENCE-UNAVAILABLE` and never calls the sink.
- Substituted request, decision, manifest, policy, or evidence digest returns
  `PEP-EVIDENCE-MISMATCH` and never calls the sink.
- The sink receives exact canonical effect bytes only after evidence success.
- A sink may return `None` or a validated `ContentEnvelopeV1`; raw output is rejected.
- A sink exception means invocation occurred and the effect outcome is indeterminate. The PEP
  returns `PEP-SINK-FAILED`, includes no exception text, and never retries automatically.

The shipped `FailClosedEvidenceGateV1` permits nothing. Test-only/instrumented gates can exercise
the ordering contract. DSE-717 must replace this seam with durable signed receipt append,
independent negative-decision fallback evidence, rollback-resistant sequence/generation state,
and the persistent recovery latch before production effects or whole-ATK conformance.

## Adapter conformance harness

`run_adapter_conformance()` accepts an exact bounded tuple of adapter-specific vectors and a PEP,
then invokes the PEP-owned instrumented execution path and always appends the non-optional
`dse716-foundation-v1` corpus. The report binds the exact activated registration set and count of
instrumented cases. Each case verifies code-only stage ordering, negative-case sink absence, and
scans both supported serialized output channels: the enforcement result and PEP trace. The closed
handler boundary cannot retain a mutable sink-owned channel; handlers requiring a wider host/IO
surface are unsupported until that surface has a separately instrumented TCB adapter. That fixed
corpus covers malformed request, runtime, and effect objects, hostile nested request values, and
effect substitution; callers cannot remove or replace those cases. It invokes sinks for positive
cases, so it must never be pointed at a live production adapter. A passing foundation report proves:

- every signed manifest operation has a successful instrumented allow vector;
- all five fixed negative vectors invoke no sink;
- each result matches the expected stable enforcement code and invocation state;
- every planted secret is absent from the serialized enforcement result;
- the report itself is deterministic and digest protected.

Manifest/registration bijection, late-registration rejection, code/delegate drift, signed bundle
activation, evidence-before-sink ordering, decision/evidence substitution, malformed-input
behavior, and no-I/O imports are covered by the repository test suite. This is deliberately a
DSE-716 foundation corpus, not the complete ATK §11 suite: DSE-717 must still add the fixed
receipt/fallback/log/restart/rollback cases. An alternate raw sink outside the registry is
nonconformant and is not made safe by a passing foundation report.

## Resource limits

| Surface | V1 cap |
|---|---:|
| Canonical effect arguments | 1 MiB |
| Policy canonical payload | 512 KiB |
| Trusted-runtime canonical payload | 64 KiB |
| Adapter manifest canonical payload | 256 KiB |
| Executable-bundle manifest canonical payload | 256 KiB |
| Adapter implementation or bundle component evidence | 256 KiB / 64 KiB each |
| Policy grants / revocations | 4,096 each |
| Manifest operations / dependencies | 1,024 each |
| Detached signature | 64 KiB |
| Conformance cases | 2,048, including five mandatory fixed cases |
| Planted secrets per case | 64, each at most 4 KiB |

Exact cap and cap-plus-one cases are tested for the high-volume policy, effect, operation,
dependency, and signature surfaces.

## Supported construction boundary

Security guarantees apply to the public constructors, activation functions, PDP/PEP methods, and
serializers. Public boundaries exact-type-check and revalidate Pydantic instances, recompute
self-digests, and reject hostile subclasses and incomplete `model_construct` objects. Underscored
module internals, arbitrary interpreter memory modification, and reflection that extracts private
module markers are outside the supported API and are TCB compromise, not an authorization path.

## Current product boundary

- The historical `guard` proxy remains governed by `GUARD_PROXY.md` / `GUARD_PROXY_V3.md`; it is
  not silently upgraded and is not ATK-conformant.
- DSE-716 APIs are importable client-agnostic foundations, not a new CLI command or deployed
  runtime adapter.
- No built-in production verifier, durable evidence gate, recovery store, or live protocol
  adapter is selected by this ticket.
- DSE-717 remains required before any whole-kernel or production effect claim.
