# Offline capability review

`mcp-warden trust review-capabilities` projects prepared declaration and observation
records into individual capability rows. Use the human view on an
operator-controlled terminal. Give the agent the agent view through a separate
output channel and keep both the source file and the human view under operator
control. The audience flag selects an output format. The host controls file
access and who may receive each output.

```bash
mcp-warden trust review-capabilities evidence.json --audience human
mcp-warden trust review-capabilities evidence.json --audience agent
```

The command reads a local file and uses no network or live runtime. Exit 0 means
the projection completed, including when rows are ineligible or absent. Exit 2
reports an unreadable, oversized or malformed input without printing its contents.

## Evidence input

Supply a version-1 JSON object with both a `declarations` array and an
`observations` array. Each array accepts up to 1,024 records within the 512 KiB
file limit. Use the same normalized adapter ID, operation ID and capability
class to refer to an exact capability across both sources. Every record holds
the SHA-256 reference to a distinct evidence record available to the operator.
The operator obtains declaration records from the declared surface and
observation records independently from measurement. Preserve the underlying
evidence in the host's evidence store.

A binding contains the exact identity digest and a scope with a purpose ID, data
scope ID, environment ID and exact scope digest. IDs use the kernel's lowercase
identifier syntax. Digests use `sha256:` followed by 64 lowercase hex characters.
Use a null binding to represent an unresolved record. Extra fields, duplicate
JSON keys, unknown capability classes and invalid identifiers are rejected.
Keep raw source text, logs and arguments in the underlying evidence store.
The projection compares the supplied references and bindings. Verification of
the referenced evidence and its origin belongs to the operator-controlled host.

This example uses synthetic digests. Real inputs need references and bindings
derived from the reviewed sources.

```json
{
  "schema_version": 1,
  "declarations": [
    {
      "adapter_id": "catalog",
      "operation_id": "lookup",
      "capability": "read",
      "evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "binding": {
        "identity_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "scope": {
          "purpose_id": "inventory",
          "data_scope_id": "internal-fixture",
          "environment_id": "test",
          "scope_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      }
    }
  ],
  "observations": [
    {
      "adapter_id": "catalog",
      "operation_id": "lookup",
      "capability": "read",
      "evidence_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "binding": {
        "identity_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "scope": {
          "purpose_id": "inventory",
          "data_scope_id": "internal-fixture",
          "environment_id": "test",
          "scope_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      }
    }
  ]
}
```

## Review results

The human view shows adapter and operation IDs, scoped bindings, source-specific
evidence digests, standardized risk and discrepancy codes. The risk tier is
`moderate` for read and transform, `high` for disclose and communicate, and
`critical` for execute, administer-policy and repair-recovery. This tier
describes the operation class. Review the actual scope and evidence for each
row.

A row is `pending-human-review` only when both sources provide evidence with one
matching complete binding, the adapter operation maps to one capability class
and each evidence digest refers to a single source record. Missing, incomplete,
ambiguous or conflicting records are visible as `ineligible` with applicable
`CAP-REVIEW-*` codes. Repeating an identical record within the same source
leaves the result unchanged. Review IDs commit to each row's canonical evidence
fields and are stable across input ordering.

The agent view has only status and reason codes on ineligible rows. Pending
rows also include the capability class and opaque review ID. Every result is a
review projection and grants no authority. Approver enrollment, signed
baselines, revocation, policy changes and activation belong to the subsequent
approval and enforcement workflow.
