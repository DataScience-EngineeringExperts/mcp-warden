# Capability selection and request preparation

**Status:** Isolated development foundation for DSE-725. This module selects from
existing exact signed grants and prepares data. It does not issue leases, consume
calls, sign receipts, execute a tool, authenticate callers, or mediate a transport.
It is absent from the published 2.0.0 package and is not wired into `guard`.

The governing security contracts remain [Agent Trust Kernel](AGENT_TRUST_KERNEL.md),
[PDP/PEP](POLICY_ENFORCEMENT.md) and [decision receipts](DECISION_RECEIPTS.md).
Prepared data is untrusted input to independent final PDP/PEP authorization.

## API and authority

| Module | Public data operations |
|---|---|
| `capability_models.py` | `CapabilityIntentV1`, `PreparedCapabilityV1`, `ToolProjectionV1`, `serialize_prepared_capability` |
| `capability_broker.py` | `select_capability`, `project_tools` |
| `mcp_capability_adapter.py` | `prepare_mcp_call`, `project_mcp_tool_list` |
| `client_capability_adapter.py` | `prepare_client_call` |

Each selector/adapter takes an explicit intent, an exact tuple of existing
`DecisionRequestV1` candidates, a `PolicyDecisionPointV1`, an `ActivatedAdapterV1`
and an activated trusted-runtime snapshot. These are supplied by a trusted host
integration; there is no loader, client registration, environment lookup or CLI.
The host must authenticate identity/session context before supplying it. Matching
caller-authored identity digests alone proves no identity.

An intent names one closed existing `CapabilityV1` plus exact identity, envelope,
data, purpose, destination and arguments digests. The request remains untrusted.
Only exact lease-digest membership in activated signed policy grants authority.
The selector checks the sealed adapter/policy relationship, signed manifest
identity, registered operation and capability, all intent bindings and the existing
PDP's full current-eligibility decision. It cannot manufacture a grant or bypass
trusted-time, revocation, critical-floor or malformed-input decisions.

## Exact comparison schema

`scope_schema="exact-bound-operation-v1"` defines **temporal least authority for
the same operation**, not general least-privilege tool ranking:

1. Identity, envelope, data scope, purpose, arguments, destination and capability
   must exactly match the desired context.
2. Each operation must match the activated adapter's ID, manifest digest and
   registered operation/capability. Tool names are exactly signed operation IDs;
   there are no aliases or model-derived mappings.
3. Only candidates with identical request-binding digest and operation are
   comparable. No semantic ordering is inferred from opaque digests, tool names,
   descriptions, capabilities or permission counts.
4. Interval A is strictly narrower than B only when
   `A.not_before >= B.not_before`, `A.expires_at <= B.expires_at`, and at least one
   bound differs. Both candidates must independently pass the PDP.
5. A result exists only when one candidate is strictly narrower than every other
   eligible candidate, or is the sole eligible candidate. Distinct operations,
   equal intervals and incomparable intervals are ambiguous and return no result.

Intervals are half-open: `trusted_time == expires_at` denies. Duplicate request
digests reject the candidate batch. Selection is permutation-independent.
No eligible candidate or ambiguity returns `None`; list projection returns `()`.
Candidate validation/selection is bounded to 64 requests; the tournament plus
minimum verification is linear after independent PDP evaluations. Every PDP
evaluation retains its existing canonical-policy validation.

## MCP and client preparation

`prepare_mcp_call` accepts exact RFC 8785 JSON bytes for one message containing
exactly `jsonrpc`, `id`, `method`, and `params`. Only `tools/call` is accepted and
params must contain exactly `name` and an object `arguments`. The operation name
must equal the selected signed operation ID, and canonical arguments must match
its effect-arguments digest. A same-arguments/different-name substitution fails.

JSON-RPC IDs are bounded correlation data, never authority. Changing an ID does
not issue another lease or consume a call. Unknown methods, notifications, batch
messages, duplicate JSON keys, extra metadata, noncanonical input, invalid IDs
and malformed/oversize arguments reject with a closed code. Wire messages are
capped at the existing 1 MiB effect cap plus 4096 envelope bytes; IDs are at most
256 UTF-8 bytes or an exact JCS-range integer. Existing effect limits still apply.

`prepare_client_call` accepts only an exact name and canonical JSON-object bytes.
It shares MCP preparation; SDK clients/callables are not accepted. Neither path
retains raw arguments, a transport handle or an executable callback in its result.
`serialize_prepared_capability` emits canonical advisory bytes, capped at 256 KiB,
with digest-only request context. Those bytes are neither a receipt nor an
executable authorization token.

`project_mcp_tool_list` accepts only a canonical `tools/list` request with empty
params. It returns zero or one synthetic `ToolProjectionV1(name, capability)`
descriptor using the same selection. This is not a live MCP server response:
it does not invent an input schema or forward upstream prose. Pagination/cursors,
including `cursor=null`, are unsupported and rejected. No upstream list is read.

## Errors and remaining enforcement work

Public preparation boundaries use only `CAP-INPUT-MALFORMED`,
`CAP-AUTHORITY-UNAVAILABLE` and `CAP-WIRE-REJECTED`. Raw parse/provider exceptions
and rejected payloads are not included in those errors. Pydantic models are
strict/frozen and revalidated at public selection/serialization boundaries.
An intent requesting `call_limit` other than `None` is rejected. There is no
single-use, durable consumption, immediate live-revocation or rollback guarantee.

Actual effects must independently revalidate current authority through the PEP
and require the existing V2 signed durable evidence-before-effect sequence. A
prepared request can become stale. Reference providers remain
`platform_status=unsupported` / `atk_conformant=false`; a passing synthetic test
does not prove a protected host boundary or prevent direct server access.
Full DSE-725 still requires reviewed issuance-event semantics, protected atomic
call accounting, a protected IO provider and real transport-bypass conformance.
DSE-1076 owns guard integration and DSE-1077 owns HTTP mediation. No preparation
API changes the existing guard opt-outs, handler restrictions or lease schemas.
