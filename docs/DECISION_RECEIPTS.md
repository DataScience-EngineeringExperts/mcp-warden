# Decision receipts and governed enforcement

## Development scope

DSE-717 adds a protocol-neutral SDK foundation over the existing content-envelope,
policy, runtime, adapter and executable-bundle contracts. It records a governed
security decision before the registered handler receives an allowed effect. The
historical `guard` proxy keeps its existing behavior; DSE-1076 owns live integration.
This development feature is not included in the published 2.0.0 package.

The intended human checkpoint approves an exact reviewed version and its bounded
actions until either changes. The trust boundary includes an externally governed
signer and independently protected roots, generations and recovery state. A
signature establishes the identity and integrity of signed bytes; it cannot prove
that arbitrary retrieved content, prompts or code are harmless.

The reference providers demonstrate local durability, tamper detection and failure
ordering. They do not establish hardware/platform rollback resistance. Passing a
reference conformance profile never means the complete Agent Trust Kernel has
passed its real restart and snapshot gates.

## Authority and signing

`SignerAuthorizationBundleV1` is activated against an injected TCB root verifier,
trusted time and protected generation/digest floors. A receipt's signer identity
cannot authorize itself. The closed roles and artifact kinds are:

| Role | Artifact kind |
| --- | --- |
| `receipt-signer` | `receipt` |
| `rule-publisher` | `rule` |
| `override-authorizer` | `override` |
| `recovery-administrator` | `recovery` |

`PinnedGovernanceVerifierV1` verifies Ed25519 signatures with public keys only.
An injected `ReceiptSignerV1` supplies signatures; product code provides no private
key loader, generator or signing CLI. Signing and verification commit to the exact
canonical payload, role, artifact kind, signer identity and authorization digest
under the separate `mcp-warden/dse717-signature/v1` domain. Existing artifact-trust
signatures use their own frozen domain and cannot be substituted.

The host must protect root configuration and its generation/digest floors outside
agent-editable inputs. Replacing both a root and its protected commitment replaces
the authority boundary. Runtime permission prompts and text in tool results do
not enroll a signer or grant capabilities.

## Receipt events

| Event | Source and restriction |
| --- | --- |
| `allow`, `deny`, `quarantine` | Governed enforcement decision; negatives never invoke a sink |
| `override` | Separately signed, request-bound, finite noncritical authorization |
| `revoke` | Explicit artifact/revocation evidence context; not a revocation command |
| `expiry` | Artifact validity evidence context; not an expiry command |
| `recovery-exit` | Authenticated recovery action bound to the current latch |
| `limit` | Reserved; creation fails closed with `RCT-LIMIT-UNSUPPORTED` |

Canonical unsigned receipts bind the request, base and effective decision,
policy/runtime/rules/revocation state, adapter/bundle/envelope commitments, sequence,
previous entry, store identity, trusted time, recovery state and signer authority.
They contain no raw content, call arguments, internal matched rule IDs, thresholds,
private keys, provider exception text or signature bytes. The separate signed record
contains bounded signature evidence and its receipt digest.

Identical explicit inputs produce identical unsigned bytes. Signature randomness
is outside that determinism claim. A pre-effect receipt records authorization; it
does not prove that the effect completed. Handler failure remains indeterminate and
is never automatically retried.

## Rules and overrides

Rules have bounded, closed fields and operators, one nonempty non-nested `all` or
`any` condition group, unique sorted rule IDs and unique sorted conditions. Supported
operators include exact equality, membership, integer range and taint membership;
regex, glob, imports, expression evaluation, ambient clocks and implicit network
lookups are absent. The activated bundle must match the policy's `rule_set_digest`.

Rules only strengthen decisions. Effective precedence is quarantine, deny, then
unchanged; matched internal rule IDs stay private. Rule activation cannot replace
the mandatory critical floor. An independently authorized override may change only
a registered noncritical deny, with exact request/base-decision/policy/rule/actor/
scope/reason/expiry bindings. It cannot override quarantine or critical reasons.

Overrides expire within 3,600 seconds of their explicit issue time. The permitted
override generation/digest is committed to protected state before effect. This is
finite-time authorization, not a one-use token or use-count guarantee; a still-valid
exact authorization may be reconsidered after failure. Post-effect consumption and
outcome evidence are outside this wave.

A revocation generation bump makes a newer snapshot available. It does not by
itself revoke every previously issued lease: explicit lease-digest membership is
what revokes an individual lease, alongside the existing freshness and validity
checks.

## Evidence before effects

```mermaid
sequenceDiagram
    participant P as PEP V2
    participant G as Decision governor
    participant C as Evidence coordinator
    participant L as Primary receipt log
    participant S as Protected state
    participant H as Registered handler
    P->>G: Exact request, activated authority and effect bindings
    G-->>P: Canonical governed decision
    P->>C: Record exact decision context
    C->>S: Read independent sequence/tail and authority floors
    C->>L: Expected-tail durable append of signed receipt
    L-->>C: Durable append evidence
    C->>S: Compare and advance exact sequence/tail
    S-->>C: Committed protected snapshot
    C-->>P: Bound primary-durable evidence
    P->>H: Invoke only after complete binding checks
    H-->>P: Enveloped output or indeterminate failure
```

V2 records every initial path, including structural blocks and PDP/rule negatives.
Only healthy, correctly bound primary-durable evidence can reach a handler. A
failed allow evidence attempt produces a new deny with
`PEP-EVIDENCE-UNAVAILABLE`, bound to the original decision digest, and exactly one
additional negative evidence attempt. This is not a retry of the original allow.

The primary and fallback logs have independent identities, counters and tails.
Their digests need not match. Negative primary failure uses the independent
fallback and enters recovery-only mode. Failure of both evidence stores sets the
independent persistent latch; latch failure remains fail closed. Diagnostics expose
registered codes rather than provider paths, exception text or planted secrets.

## Durability, restart and recovery

The POSIX reference file log requires `fcntl` locks and directory `fsync`. It
locks its expected tail, writes complete bounded frames,
flushes the file, and flushes the directory on creation. Startup verifies canonical
records, signatures, chain continuity, sequences and caps. Partial tails, missing
entries, reordered records and primary/protected-state disagreement block normal
operation. Primary and fallback providers cannot alias the same store identity.

The log and protected state do not share a transaction. A crash after append but
before protected advancement leaves a detectable disagreement. A log rolled back
behind an independent protected counter likewise fails closed. Restoring the log
and an ordinary local state file together cannot demonstrate resistance; deployers
must supply and validate a genuinely independent protected platform provider.

Recovery requires an activated administrator action, fresh authority, reconciled
log tails and durable recovery-exit evidence. Protected state advances to the exact
authorized recovery generation and receipt before the latch is cleared. An
identical clear tuple may be retried after a crash; a different tuple is rejected.
Startup accepts recovery exit only when both sides match exactly. A stored
`recovery-exit-authorized` mode alone never permits normal work.

## Verification, replay and safe explanations

Verification checks exact canonical bytes, signatures and signer roles, event
bindings, digest integrity, chains, sequences and explicit protected floors.
Historical replay consumes a complete explicit vector and recomputes the base
decision, governed decision and unsigned receipt. It calls no signer, verifier,
store, PEP or handler, and it cannot authorize current effects. The separate pure
`current_eligibility()` check reports historical authority's compatibility with
an explicitly supplied protected snapshot. It does not refresh trusted time,
activate new authority, authorize execution or replace the live PEP checks.

Human and agent projections have closed key allowlists. Human evidence exposes
reviewed commitments and coarse decision/evidence/recovery status. Agent output
contains only a receipt reference, effective verdict, coarse reason and registered
next action. Neither exposes content, arguments, matched rule IDs, signatures or
provider exceptions.

## Supported boundaries and outstanding deployment gates

- Use the public activation, coordinator, PEP and serialization APIs. Forged
  Pydantic instances and hostile provider values must fail closed at those boundaries.
- Handler measurement supports CPython 3.11–3.13. Executable code hidden in marshaled
  constants or immutable globals is rejected; ordinary bytes remain supported.
- Reference conformance proves instrumented ordering and failure behavior. Real
  platform restart/rollback conformance remains a separate required profile.
- DSE-1076 must wire the foundation into the actual guard path before the product
  can claim live human-checkpoint enforcement.

`run_receipt_conformance()` requires eight independently configured scenarios for
every registered operation: allow, deny, primary-log failure, dual-log failure,
protected-state commit failure, a pre-set latch, log rollback and a reopened file
log. It adds five nonoptional probes for malformed request/runtime/effect,
hostile nested data and effect substitution. Ordering and negative sink absence
are checked against the PEP's own trace; actual signed/fallback artifact bytes,
serialized results and safe projections are scanned for planted secrets.
It invokes positive test handlers, so use isolated test deployments. A passing
report always says `platform_status=unsupported` and `atk_conformant=false`.

The normative requirements remain in [Agent Trust Kernel](AGENT_TRUST_KERNEL.md).
The V1 isolation and adapter contract remain in
[Policy Enforcement](POLICY_ENFORCEMENT.md). Source provenance and the integration
gates are recorded in the [reconciliation plan](plans/2026-10-04-dse717-reconciliation.md).
