# Managed and self-hosted control-plane deployment

This proposal describes two ways to operate the same Warden control plane. In both, the
customer operates the enforcement point, and the [Agent Trust Kernel](../AGENT_TRUST_KERNEL.md)
governs every decision. The profiles differ in who runs the distribution service and where
optional telemetry goes. Both use the same artifact formats, validation rules and local
decision implementation. Qualification requires testing real installations of both profiles.

## Responsibilities and deployment topology

| Responsibility | Managed | Self-hosted |
| --- | --- | --- |
| Distribution and endpoint inventory | Service operator runs a regional delivery service and restores availability. Customer approves the tenant region and enrollment. | Customer runs a delivery service or supplies signed bundles through an offline import process. |
| Policy publication and trust | Customer policy administrator approves generations. Customer trust administrator enrolls roots and scopes signing roles. | Same roles and requirements. |
| Decision and evidence | Customer operates the local policy decision and enforcement points, local receipt signer, primary and fallback evidence logs, and rollback-resistant state and latch. | Same components and responsibilities. |
| Telemetry | Customer separately authorizes a projection, destination, region and retention period. | Same controls apply to customer-operated collectors. An offline deployment can disable export. |
| Recovery and upgrades | Service operator restores or upgrades distribution. Customer recovery administrator verifies endpoint integrity and authorizes recovery exit. | Customer owns both operations and records the distribution and endpoint checks separately. |

The customer chooses the region and approved backup locations at enrollment. Delivery replicas,
inventory, backups and any telemetry collection stay within that boundary. Cross-region
replication or failover requires the customer's explicit authorization. An isolated site uses
the same signed objects through a separate authenticated import path. The endpoint's decision
path performs no network I/O in either profile.

## Shared protocol and data model

Distribution is a delivery mechanism for canonical signed artifacts. HTTPS retrieval and
offline import use the same bounded parser, schema/version support and activation checks. The
first implementation must pin the supported versions and publish canonical vectors for both
delivery paths. The design reuses [artifact trust](../ARTIFACT_TRUST.md),
[policy enforcement](../POLICY_ENFORCEMENT.md) and [decision receipts](../DECISION_RECEIPTS.md)
for signing and verification semantics.

| Data | Required binding and use |
| --- | --- |
| Enrollment record | Customer trust administrator binds tenant, endpoint identity, region, verification-root digest and allowed artifact roles. The endpoint pins roots through the protected trust path. Inventory has no authority to amend that pin. |
| Published artifacts | Delivery indexes immutable bytes by tenant, kind, schema version, generation and canonical digest. Policy, rules, runtime and adapter artifacts, revocation snapshots and freshness material retain their own signed bindings. A delivery cursor or transport acknowledgement has no authority. |
| Local activation state | Protected state binds accepted generations and digests, relevant revocation and time floors, both evidence log tails and the recovery latch. A candidate is staged in isolation before activation. Older generations or equal generations with different digests cannot replace accepted state. |
| Audit and telemetry | Canonical decision receipts, independent fallback evidence and recovery records stay at the endpoint. Inventory or telemetry may use a separately authorized, versioned projection. The receiver has no role in committing evidence or granting authority. |

The shared delivery interface has three operations. An authenticated endpoint reads a bounded
catalog for its enrolled tenant, fetches an immutable artifact by its catalog identity and digest,
and imports it into local staging. Offline bundles carry the same catalog entries and artifact
bytes. The catalog describes availability. The signed material and protected local state determine
eligibility. Enrollment and optional telemetry use separate credentials and endpoints.

The endpoint authenticates synchronization separately from evaluation, validates artifact
identity, signer role, tenant scope, validity, freshness and protected floors, then stages a
candidate as a coherent set. Rejecting a candidate preserves an eligible active generation.
Loss of active authority or integrity follows the kernel's recovery matrix. During a delivery
outage the endpoint can use an eligible cache within the signed freshness bounds. Expiry,
unverified time and missing protected state fail closed under the same rules in both profiles.

## Data boundary and telemetry

Raw source content, tool arguments and results, local audit evidence, signing keys and secret
values stay in the customer's environment. Policy authors keep raw content and credentials out
of delivery artifacts. Provisioning, updates and normal operation require no content export.

Telemetry export is disabled at enrollment. A tenant-approved profile can allow a fixed
allowlist of coarse fields such as component version, health status and bucketed counts. Treat
tool and rule identifiers, event-level receipt references, content-derived digests, free text,
and provider exceptions as local data. Apply the allowlist on the endpoint before serialization
and validate the destination and region before sending. A malformed projection, unavailable
destination or missing authorization stops export. Telemetry runs separately from the evidence
path. Keep destination access tenant-scoped and apply the approved retention period to exports,
collector logs and backups. The conformance suite inspects actual serialized bytes, including
error paths and transport logs.

## Availability, backup and restore

- **Distribution.** Serve the same immutable artifact bytes from regional replicas. A fenced
  publication writer serializes catalog updates per tenant and artifact stream. Replicas serve
  only complete published sets. After failover, verify the replacement catalog against preserved
  publication records before resuming publication. The endpoint advances authority only after
  independently verifying the signed artifacts. Apply the cache and expiry rules during outages.
- **Backups.** Preserve encrypted delivery artifacts, inventory and publication history in approved
  locations. At the endpoint capture the signed log segments, fallback evidence and corresponding
  checkpoints. Keep protected state outside the endpoint snapshot's rollback domain. Provision
  recovery material separately from routine backups and restrict its access to the recovery role.
- **Endpoint restore.** Start with effects disabled. Reconcile recovered logs, chains, sequence and
  digest values against the independent protected state, then verify fresh policy, revocations and
  time. A backup behind a protected checkpoint needs the missing verified evidence before recovery
  exit. A mismatched or unavailable checkpoint keeps the endpoint in recovery. When the independent
  state is irrecoverable, retire the old endpoint identity and preserve the evidence for review.
  A replacement identity requires fresh enrollment, current authority and its own conformance
  evidence. Recovery exit follows the authenticated, durable receipt and latch sequence in the
  [receipt contract](../DECISION_RECEIPTS.md#durability-restart-and-recovery).

Set and test recovery-time and recovery-point objectives per installation. An availability
objective cannot justify advancing an unverifiable checkpoint or resuming effects with stale
authority. Evidence metrics should report delivery and endpoint recovery separately.

## Upgrade and key lifecycle

Stage verified releases in an isolated installation and run the shared corpus there before a
canary. Exercise the current-to-target upgrade and verify that old receipts still validate with
their original canonical schema and verification keys. Carry forward protected floors, active
policy identity, revocation state, both log tails and the recovery latch. A migration must detect
partial completion on restart and hold effects disabled until all preserved state reconciles.
An older binary can resume only if it remains authorized and can enforce the current floor and
understand the protected state and evidence formats. Otherwise use a freshly authorized repair
that preserves the advanced state.

Keep root, artifact, recovery and receipt signing authority role-scoped, with private keys in
independently protected storage. Delivery holds only material needed to serve artifacts and
authenticate transport. Rotate signing keys through a verified trust transition. Stage new
verification material before activation where the current trust policy permits it. Advance
revocation state when a key is withdrawn and retain the authorized historical verification
material for audit. A lost or compromised root requires a customer-authorized recovery ceremony
using independently preserved trust material. A delivery administrator cannot substitute a root.

## Deployment threat model

The service, artifact transport, inventory and optional collector are outside the endpoint
trusted computing base. Endpoint platform, protected state, authorized policy administrators and
root signing keys retain the trust assumptions of the kernel contract.

| Threat | Control and remaining exposure |
| --- | --- |
| Compromised delivery service or replica serves altered, stale or inconsistent data | Local signature, tenant, digest, freshness and generation checks reject invalid authority. Withholding a fresh bundle can cause denial at expiry. |
| Cross-tenant routing or enrollment error | Tenant-scoped catalogs, authenticated endpoint inventory and protected root/scope pins constrain what can activate. A correctly authorized but mistakenly enrolled root remains a customer governance risk. |
| Snapshot rollback, log deletion or a partial migration | Protected floors, both log tails and the recovery latch are checked outside the snapshot's rollback domain. A lost evidence segment can prevent recovery. |
| Signer loss or misuse by a distribution or recovery operator | Segregated roles, explicit signer scope, revocation and authenticated recovery limit available authority. Compromise of a configured root or authorized administrator remains a kernel trust boundary. |
| Raw content leaks through telemetry, errors, or operational backups | Export defaults off, uses a closed projection and approved destinations, and is exercised with synthetic markers. Intended recipients can still infer activity from approved aggregate fields. |

## Shared conformance and release evidence

Run one versioned set of signed fixtures through isolated managed and self-hosted installations.
For fixtures with identical explicit inputs, compare the canonical unsigned decision and receipt
bytes. Where an installation legitimately uses different endpoint identities or signing keys,
verify each exact payload/signature and its identity separately, then compare verdict, reason,
effective generation, evidence sequence transitions, sink effects and permitted export fields.
Record source and artifact digests, fixture version, provider identities, trust and region
settings, observed effects and results for each profile. Retain the same result schema for
offline-import and network-delivery variants.

| Qualification case | Evidence required in both profiles |
| --- | --- |
| Valid policy, malformed candidate and stale/revoked artifacts | Match decisions and receipt commitments, preserve an eligible active policy on candidate rejection, and record no unauthorized sink invocations. |
| Disconnection, delivery failover and expiry | Observe eligible offline decisions, consistent denial at expiry, and activation of only fresh authorized generations after connectivity returns. |
| Restore old snapshots and interrupt an upgrade | Verify that the actual independent provider detects rollback or inconsistent evidence. Observe zero protected effects until authorized recovery exit and verify pre-upgrade receipts afterward. |
| Primary, fallback or protected-state failure | Observe evidence-before-effect, independent fallback and latch behavior using the deployed providers. Confirm that restart preserves the denial state. |
| Region and privacy controls | Observe delivery and backup placement, capture approved and refused telemetry, and verify planted raw markers remain absent from egress and exported logs. Repeat with export disabled. |

The existing reference harnesses cover portions of decision and receipt behavior. Real
installation parity, protected platform restart and rollback, live mediation and telemetry
placement still require deployment evidence. This design specifies the qualification criteria
for that work.
