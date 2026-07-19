# DSE-717 signed receipts, transparency, and rules design

**Status:** Proposed security design. No production wiring or Agent Trust Kernel conformance claim.

## Decision

Implement DSE-717 as portable deterministic kernel logic around explicit TCB-owned ports. The
kernel owns canonical receipt and rule bytes, validation, state transitions, evidence ordering,
secret-safe projections, and conformance checks. Deployments supply authorized offline-capable
signing, primary and independent fallback persistence, protected monotonic state, and a persistent
recovery latch.

The repository will include a durable append-only file receipt log and deterministic test
providers. A file log is tamper-evident but not rollback-resistant under disk or VM snapshot
restore. Whole-ATK conformance therefore additionally requires a platform provider backed by a
TPM, HSM, Secure Enclave, hypervisor monotonic service, or an equivalent independent protected
store that passes the §11 snapshot and restart gates.

Rejected alternatives:

- **SQLite as the authority store:** useful transactions, but the database and WAL can roll back
  together and cannot serve as the independent fallback or protected counter.
- **One platform-specific secure backend in core:** stronger on one host, but makes the public
  engine nonportable and still does not prove other platforms. Platform adapters belong behind
  the same closed ports and must publish their own conformance evidence.

## Scope and version boundary

DSE-716 `DecisionV1` remains the authority decision type and emits `allow`, `deny`, or
`quarantine`. DSE-717 defines a broader receipt-event taxonomy without pretending that the V1 PDP
emits unsupported authority:

| Receipt event | V1 source |
|---|---|
| `allow`, `deny`, `quarantine` | exact DSE-716 decision |
| `override` | separately authorized, non-critical, finite governance action |
| `revoke`, `expiry` | signed authority-state transition bound to the affected artifact |
| `limit` | reserved; creation fails closed until a future decision version supplies an executable constraints contract and enforcement evidence |

This preserves the stable DSE-716 API. Merely naming `limit` in the receipt schema cannot grant or
represent limited authority. A canonical `limit` receipt can be created only when a future
version supplies activated executable-constraint evidence; DSE-717 integration otherwise rejects
it. Override can never affect a mandatory critical class.

DSE-717 adds `PolicyEnforcementPointV2` rather than weakening the frozen V1 contract. V2 produces
a canonical `EnforcementDecisionV2` for every PEP path, including structural blocks that occur
before a valid `DecisionV1` exists. It binds the optional base decision digest, request/effect,
policy/runtime/rule/adapter/bundle state, effective verdict, stable public reason/recovery codes,
and optional activated override or constraint evidence. The V1 PEP remains an isolated foundation;
V2 is the only route eligible for DSE-717 evidence and future production conformance.

## Components

### Canonical receipts

`receipt_models.py` defines strict, frozen, exact-type V1 models with closed registries and exact
caps. `decision_receipts.py` creates one unsigned RFC 8785 payload binding:

- receipt schema and event kind;
- request and decision digests, verdict, stable reason, and recovery code;
- policy, runtime, rule, revocation, adapter-manifest, bundle-manifest, and envelope digests plus
  their generations where applicable;
- TCB-issued sequence, trusted time, previous log-entry digest, and evidence-store identity;
- signer role and authorized signer identity digest; and
- override or state-transition scope only for the matching event kind.

Raw content, arguments, signatures, exception text, policy internals, rule identifiers, and match
thresholds are forbidden from the unsigned payload. Identical explicit inputs produce identical
unsigned bytes. A `ReceiptSignerV1` receives exactly those bytes once and returns bounded signature
evidence. Signature randomness is outside the determinism claim.

Signer identity and role are anchored by an independently activated
`SignerAuthorizationBundleV1`, not by self-assertion in the receipt. The bundle is verified against
an injected TCB trust root and binds its own generation/validity, exact signer identity digests,
closed roles (`receipt-signer`, `rule-publisher`, `override-authorizer`,
`recovery-administrator`), and the artifact kinds each role may sign. Its generation and digest
are checked against protected state; equal generation must match the protected digest. Receipt,
rule, override, and recovery activation verify exact bytes, artifact kind, algorithm, role, signer
identity, and authorization-bundle digest. A signature valid for one role or artifact kind is
never accepted for another.

### Evidence stores and protected state

The TCB ports are deliberately narrow and non-interchangeable:

- `PrimaryReceiptStoreV1.append(record, expected_tail) -> durable append evidence`
- `FallbackEvidenceStoreV1.append(event, expected_tail) -> durable append evidence`
- `ProtectedStateV1.read()/compare_and_advance()` for primary/fallback counters, recovery mode, and
  highest generation/digest floors
- `RecoveryLatchV1.read()/set()/authenticated_clear()` for persistent poison state

Primary and fallback ports must declare distinct store identities and the coordinator rejects
aliasing. The protected snapshot contains exact primary and fallback sequence/tail digests; a
monotonic recovery generation and closed mode (`healthy`, `evidence-degraded`,
`recovery-latched`, or `recovery-exit-authorized`);
and sorted generation/digest floors for policy, rule bundle, trust root, signer authorization,
adapter, executable bundle, revocation state, receipt log, and fallback log. Below-floor
generation is rollback; equal generation with another digest is integrity failure; unavailable or
inconsistent state is recovery-only deny.

The fallback event contains only the protected fallback counter, failed primary receipt digest,
stable failure code, trusted-time evidence digest, prior fallback digest, and recovery generation.
It uses the same expected-tail then durable-append then compare-and-advance protocol as the primary
log, but through the distinct fallback store and counter. It is separately canonical, capped, and
secret-safe. Any fallback append/protected-state disagreement sets the independent latch.

The reference primary file store uses an exclusive lock, an append-only framed record, full-write
loops, file `fsync`, and directory `fsync` on creation. Startup scans every frame, verifies caps,
canonical bytes, signatures, sequence continuity, and digest-chain continuity. Partial tails,
truncation, reorder, duplicate sequence, or digest mismatch fail closed. This is durability and
tamper evidence, not protected rollback resistance.

### PEP V2, governed decisions, and evidence ordering

`PolicyEnforcementPointV2` calls a closed `DecisionGovernorV1` after the base PDP decision and
before evidence. Its activated rule-bundle digest must exactly equal the active policy's
`rule_set_digest`. It returns an immutable `EnforcementDecisionV2`; callers cannot provide or
replace that decision. For malformed request/effect/adapter/bundle paths, V2 creates the same type
with a fixed invalid-input digest and a registered PEP reason without reading hostile nested
values.

Rules may preserve a decision or strengthen `allow` to `deny` or `quarantine`; they cannot turn a
negative result into allow. A separately activated, request-bound, signer-authorized, finite
`OverrideAuthorizationV1` may change only a registered non-critical deny to allow. It binds the
request, base-decision, policy, rule, actor, scope, reason, expiry, and trusted-time digests. The
governor rejects override for quarantine, critical reason classes, stale time, scope mismatch, or
any generation/digest mismatch. Its exact digest is bound into the governed decision and receipt.

`DecisionEvidenceCoordinatorV1.record_decision(context)` is called once for every initial
`EnforcementDecisionV2`, positive or negative. `EvidenceContextV1` exact-type binds the governed
decision, safely validated request/envelope/effect digests when available, trusted-runtime digest,
adapter/bundle manifests, and active signer-authorization digest. The coordinator reads the
protected primary counter and last-entry digest, builds and signs the next exact receipt, then asks
the primary store to append only if its locked tail matches that expected state. After the durable
append, it compare-and-advances protected state to the new sequence and entry digest. The PEP
invokes a permit-class sink only after both the append and protected-state commit verify.

This ordering makes rollback and crash disagreement detectable without pretending that the file
log and protected provider share a transaction. Append failure leaves protected state unchanged,
so a converted deny may retry the primary path at the same next sequence if the tail is still
healthy. A crash or protected-state failure after append leaves the log ahead of protected state;
startup and every later append detect that mismatch, enter recovery-only, and use the independent
fallback. A rollback of the file log leaves it behind the non-rollback protected state and fails
closed. Concurrent appenders cannot reuse a sequence because the primary store validates the exact
expected tail under its exclusive lock and protected state uses compare-and-advance.

The coordinator returns an exact `DecisionEvidenceResultV1` bound to the context and containing
only evidence mode (`primary-durable`, `fallback-durable`, `recovery-latched`, or `unavailable`),
receipt or fallback digest, sequence, store identity digest, recovery generation/mode, and its own
self digest. Only `primary-durable` with healthy recovery state can authorize a permit-class sink.
The PEP revalidates every field and binding rather than trusting a boolean.

For `deny` and `quarantine`, the PEP never invokes a sink but still calls the coordinator. Primary
success returns the original negative result. Primary failure preserves the negative result,
enters evidence-degraded recovery-only state, and attempts the independent fallback. If fallback
also fails, the coordinator sets the independent latch before emitting only a stable local signal.
Failure to set or read the latch remains fail closed. No evidence error can turn a negative result
into permission.

Permit signing, append, or protected-state commit failure returns a code-only failed evidence
result bound only to the original allow context; it never silently rewrites that decision. The PEP
then creates one new canonical `EnforcementDecisionV2` with effective verdict `deny`, registered
`PEP-EVIDENCE-UNAVAILABLE` reason, and `converted_from_decision_digest` bound to the original allow
decision. It calls `record_decision()` exactly once more for that negative conversion. The two
attempts and any receipts have distinct decision digests. If the original attempt left the primary
tail healthy, the converted deny can use the same next sequence because protected state did not
advance. If append succeeded but protected commit failed, the primary tail mismatch sends the
converted deny directly to fallback/recovery. No other evidence retry is permitted.

A sink exception remains indeterminate and is never retried automatically. Post-effect outcome
receipts are outside DSE-717: the pre-effect decision receipt does not claim that an effect
completed.

### Deterministic open rules

`rule_models.py` and `rule_engine.py` define signed, versioned, bounded rule bundles. Each rule has
exactly one non-nested `all` or `any` group and a non-empty tuple of conditions. Empty groups,
duplicate conditions, duplicate rule IDs, unsorted rules/conditions, empty `in` sets, and duplicate
or unsorted `in` values are invalid. Conditions sort by field, operator, then canonical value bytes.

The exact V1 field/type/operator matrix is:

| Field family | Exact value type | Operators |
|---|---|---|
| base verdict/reason/recovery | registered string | `equals`, `not-equals`, `in` |
| user/agent/device/session, request, purpose, scope, destination digests | digest string | `equals`, `not-equals`, `in` |
| operation ID, adapter ID | bounded identifier | `equals`, `not-equals`, `in` |
| capability, envelope media/source kind | registered string | `equals`, `not-equals`, `in` |
| envelope taint set | registered taint string | `contains-taint` |
| policy/revocation/rule generation, trusted time | non-negative integer | closed inclusive `integer-range` |

`in` accepts a sorted unique tuple of the field's exact scalar type. `integer-range` requires
`minimum <= maximum`. Unknown field/operator combinations, booleans as integers, coercion,
subclasses, nesting, regex, glob, expression language, import, callback, filesystem lookup,
network access, environment access, and caller clock are forbidden.

V1 rule effects are only `deny` or `quarantine`. They may strengthen an otherwise less restrictive
decision and may add a coarse registered explanation code. They cannot allow, override, remove
taint, change a lease, mutate policy, lower a generation floor, or weaken the mandatory critical
floor. Candidate activation verifies exact canonical bytes and authorized rule-publisher identity,
checks generation/freshness against protected state, evaluates a fixed critical-floor corpus in
isolated staging, then atomically returns a new immutable active bundle. A rejected candidate does
not disturb the known-good bundle.

All matching rules are evaluated. Effective precedence is `quarantine > deny > unchanged`; rule
order never changes the result. The governed decision exposes only the aggregate rule-bundle
digest and coarse `RULE-QUARANTINED` or `RULE-BLOCKED` public code, never matched rule IDs or values.

### Verification, replay, recovery, and projections

The verifier checks canonical form, authorization role, signature, receipt/event schema, digest
self-integrity, sequence continuity, previous-entry chain, protected sequence/generation floors,
and event-specific bindings.

`ReplayVectorV1` is the complete pure historical input: exact canonical request/effect or fixed
invalid-input digest, policy/runtime/rule candidates and activation digests, adapter/bundle
manifests, optional activated override/constraint evidence, signer-authorization digest, trusted-
time context, primary store identity, sequence, previous-entry digest, recovery generation/mode,
and one exact discriminated `ReceiptEventContextV1`. The vector separately binds signer role,
signer identity digest, signer-authorization generation/digest, and trust-root digest.

The event context supplies its own required reconstruction inputs: allow/deny/quarantine bind base
and effective decisions; limit binds executable-constraint evidence; override binds authorized
actor, scope, reason, and finite expiry; revoke binds artifact kind/identity/generation/digest and
revocation generation; expiry binds artifact kind/identity/digest and signed validity boundary.
Expected governed-decision and receipt bytes are comparison targets only and are never used as
inputs. Historical replay recomputes the
base decision, governed decision, and unsigned receipt and reports exact byte/digest equality. It
never calls a PEP, signer, verifier, evidence store, protected state, handler, or sink and cannot
grant authority. A separate pure current-eligibility check accepts an explicit protected-state
snapshot and reports freshness/floor compatibility; historical equality never implies current
authority.

Latch clearing is not a direct provider call. `RecoveryCoordinatorV1.exit()` requires an activated
recovery-administrator action bound to the current latch event and generation, fresh verified
policy/rules/trust/signer artifacts, healthy and reconciled primary/fallback tails, and successful
append plus protected commit of a recovery-exit receipt.

The crash protocol is ordered: first compare-and-advance protected state to recovery generation
`G+1` with mode `recovery-exit-authorized`, the exact prior latch-event digest, and recovery-exit
receipt digest. Clearing the independent latch is the final mutation and requires that exact
generation and both digests. The latch provider records the clear tuple and treats an identical
retry as success; any different retry fails closed. A crash before protected advance leaves the
old latch/state. A crash after protected advance but before clear leaves normal operation blocked;
startup may idempotently retry only the exact already-authorized clear. Normal startup requires an
exact match between protected `recovery-exit-authorized` state and the latch's cleared tuple. Any
missing, rolled-back, or mismatched side remains recovery-only and fails conformance.

`recovery-exit-authorized` alone never permits normal work. Normal-operation eligibility is a pure
derived result: either protected mode is `healthy` with a readable clear latch, or protected mode
is `recovery-exit-authorized` and the latch's cleared generation, prior event digest, and exit
receipt digest exactly match protected state. The exact matched pair is operationally healthy
without another mutation; a later successful ordinary protected-state compare-and-advance may
normalize the stored mode to `healthy`, but startup and safety do not depend on that write.

Failure at any step leaves recovery latched. Recovery administrators cannot publish or substitute
policy/rules unless separately authorized.

Human projection has an exact closed allowlist: schema version, receipt reference/digest, event
kind, primary/fallback sequence, trusted-time value/status, request and governed-decision digests,
base/effective verdict, public reason/recovery code, policy/rule generation and digest, signer role
and identity digest, store identity digest, evidence/recovery mode, and verification status. Agent
projection is smaller: schema version, receipt reference, effective verdict, one reviewed coarse
reason (`authorized`, `blocked`, `quarantined`, `reauthenticate`, `refresh-authority`, or
`recovery-only`), and one registered next action. Neither projection exposes raw inputs, protected
content, internal rule IDs, match values, thresholds, signature bytes, or exception text.

Provider failures, log diagnostics, metrics, and minimal local signals cross only closed code-only
serializers. Provider class names, paths, values, and exception text are never emitted.

## Failure precedence

1. unreadable or set recovery latch -> recovery-only deny;
2. protected state unavailable/inconsistent/rolled back -> recovery-only deny;
3. primary-tail/protected-state disagreement -> recovery-only deny and independent fallback;
4. signer-authorization, rule, override, or constraint mismatch -> deny or quarantine by the
   closed critical matrix;
5. malformed or integrity-invalid request/decision/rule/receipt -> deny or quarantine by the
   existing critical matrix;
6. permit receipt signing/primary append/state-commit failure -> convert to deny;
7. negative primary failure -> enforce negative, enter evidence-degraded recovery-only, fallback;
8. fallback failure -> set latch, emit one stable minimal signal, remain fail closed;
9. latch set/read failure -> remain fail closed and fail conformance.

Errors are stable code-only values raised outside provider exception frames. Provider objects and
untrusted values are never interpolated into errors or logs.

## Test and conformance strategy

Implementation follows strict RED/GREEN TDD. Required evidence includes:

- golden unsigned base/governed-decision and receipt bytes plus independently authorized signature
  verification and cross-role/artifact substitution rejection;
- every event-kind invariant, including fail-closed `limit` reservation and override critical-floor
  rejection;
- every PEP structural/PDP/rule/override path makes one initial evidence attempt; a failed permit
  makes exactly one separately bound converted-deny attempt; only healthy primary-durable evidence
  can reach a sink;
- primary success, permit primary failure, negative primary failure, fallback failure, latch
  read/set/clear, partial write, restart, truncation, reorder, replay, duplicate, and rollback;
- protected counter cap, backward step, equal-generation/different-digest, and unavailable-store
  cases;
- deterministic rule evaluation, isolated candidate rejection, caps, critical-floor strengthening,
  and no ambient I/O imports;
- replay-vector completeness, historical/current-eligibility separation, and proof replay invokes
  no handler, PEP, signer, verifier, protected state, or store;
- planted-secret byte scans across receipts, logs, fallback events, errors, metrics, human output,
  and agent output; and
- a fixed DSE-717 corpus added to adapter conformance with explicit
  `decision < evidence < sink < output` ordering for executed results.

Reference-file tests prove crash detection and local durability. Hardware/platform conformance is a
separate required profile and must exercise real restart and snapshot rollback. Until that profile
passes, docs say **implemented foundation**, never **ATK-conformant**.
