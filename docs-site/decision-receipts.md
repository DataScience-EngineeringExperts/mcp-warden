# Understand signed decision receipts

The development SDK adds signed evidence for agent security decisions. A receipt
binds the reviewed authority, exact request, effective decision, execution identity
and evidence sequence. This feature is not included in the published **2.0.0**
package, and the existing `guard` command does not yet enforce these checkpoints.

## Keep approval outside untrusted inputs

An agent can encounter hostile tool results, retrieved documents, prompts and
executable material. Those inputs cannot enroll a signer, clear recovery state or
grant a capability. Human approval commits to a reviewed version and its allowed
actions; a changed version or action needs a fresh matching authorization.

The host controls the protected roots and generations. An external signer holds
private signing authority. Warden verifies public-key signatures and exact bindings.
Hashing and signing establish integrity and identity; content can still be malicious
even when its origin is authenticated.

## Require evidence before an effect

`PolicyEnforcementPointV2` makes the policy decision, applies deterministic rules,
records its signed receipt, and checks durable append plus protected-state commitment
before invoking the registered handler. Rules can strengthen a decision. They cannot
remove the mandatory critical floor or turn arbitrary tool text into authority.

A deny or quarantine also receives evidence and invokes no handler. Failure to
record an allow converts it to a separately recorded deny. Failure of the primary
evidence path uses an independent fallback; failure of both sets recovery state and
keeps effects blocked. Handler exceptions are indeterminate and are not retried.

## Separate evidence from permission

| Result | Meaning |
| --- | --- |
| Valid artifact signature | The exact bytes were signed by the enrolled role |
| Verified receipt | The recorded decision and evidence bindings validate |
| Historical replay match | Explicit historical inputs reproduce the recorded bytes |
| Current eligibility | Explicit protected-snapshot floor compatibility; grants no current execution authority |
| Completed effect | Requires separate outcome evidence; a pre-effect receipt does not establish it |

Historical replay runs no handler and grants no current authority. Agent-facing
explanations expose a receipt reference, coarse verdict/reason and registered next
action. They omit raw content, arguments, matched rule details and signatures.

## Check the deployment boundary

Reference file logs provide local durability and tamper detection. In-memory state
and ordinary files cannot prove resistance to restoring an old machine snapshot.
Deployers must validate an independent protected platform provider and the real
restart/rollback profile before claiming full Agent Trust Kernel conformance.

Live checkpoint enforcement also requires integration with the actual guard path.
See the [decision receipt contract](https://github.com/DataScience-EngineeringExperts/mcp-warden/blob/main/docs/DECISION_RECEIPTS.md)
for signing roles, event restrictions, recovery ordering, safe projections and
the remaining deployment gates.
