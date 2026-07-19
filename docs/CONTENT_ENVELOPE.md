# Deterministic Content Envelope V1

**Status:** Implemented foundation (DSE-715). This is evidence plumbing, not an authority or
whole Agent Trust Kernel conformance claim.

`ContentEnvelopeV1` records exact content bytes as a domain-separated SHA-256 digest plus a
strict, immutable, RFC 8785 wire object. Every envelope is explicitly `untrusted`; every taint
set contains `core:untrusted`. The API has no operation or field that grants authority, marks
content trusted, or removes taint.

## Implemented behavior

- Nine ingress kinds cover tool results, web, documents, email, database text, MCP prompts,
  MCP resources, bundle metadata, and agent messages. Derived envelopes use the code-owned
  `derived` source kind.
- Opaque content and signature evidence are hashed as exact bytes. Structured source,
  transform, and bundle metadata must arrive as exact canonical RFC 8785 bytes; malformed,
  duplicate-key, noncanonical, non-finite, deep, or oversized inputs reject before use.
  Every byte API requires the exact built-in `bytes` type; mutable buffers and subclasses
  reject rather than silently widening the byte contract.
- Every digest is `sha256(domain + NUL + payload)` using the closed `DigestDomain` enum.
- Transform identity is code-owned. Callers choose an exact `TransformKindV1` enum, not raw
  ID/version text: ingress accepts only `INGRESS_CAPTURE`, derivation accepts only
  `DETERMINISTIC`, and an immutable append-only V1 registry supplies the serialized
  `(id, version)` pair. An exact reverse registry binds every ingress source context to the
  capture pair and every derived source context to the deterministic pair in the model and
  parser—not only in constructors. Self-coherent pair swaps reject as `ENV-MALFORMED` for
  roots and `ENV-LINEAGE-INVALID` for derived envelopes. Adding a registry entry is a
  security-sensitive change requiring a new enum member, updated model/parser context
  enforcement, and explicit cross-pair and wire-forgery tests. The implementation digest
  binds the exact executing bytes to the identity; deciding whether those bytes are
  pre-approved belongs to DSE-716.
- Parent references are sorted immutable `{envelope_digest, content_digest}` pairs. Derivation
  recomputes every parent self-digest before accepting its refs or taints, then preserves the
  complete bounded local taint union. Lineage verification is bounded and one-hop; it does not
  claim transitive graph verification. Parent and taint inputs are consumed through fixed
  `cap + 1` loops, bounding consumed elements and preventing unbounded logical materialization
  from infinite iterables that continue yielding. The loop cannot prevent a blocking
  synchronous `__next__` call from stalling its calling thread; deadline enforcement is the
  caller's responsibility and is outside this boundary.
- Derived source identity and claims are recomputed from the exact sorted parent refs and
  transform evidence during parsing and lineage verification; self-coherent caller-forged
  source digests reject. Model-level invariants also enforce the source-context/transform-pair
  binding and prevent roots with parents, derived envelopes without parents, and
  bundle-metadata roots without bundle evidence.
- Every accepting public boundary completely revalidates the top-level envelope and each
  nested frozen model. Pydantic instance revalidation plus explicit field-specific checks
  prevent `model_copy(update=...)` from bypassing digest, media, source-kind, transform,
  parent-order, taint-order, or bundle invariants. A storage-level required-field/type
  preflight also rejects incomplete `model_construct(...)` objects before any field is
  dereferenced or any parent digest is recomputed. Hostile-subclass rejection is enforced at
  every current public accepting boundary through an exact-type check before attribute access;
  this test-enforced convention is required for every future public accepting boundary.
- Parsing rejects unknown fields/versions, missing `bundle`, noncanonical bytes, invalid trust
  or taint state, malformed lineage, and self-digest mismatch. Errors expose a stable `ENV-*`
  code only and retain no third-party exception context.
- Public output explicitly selects digest-only V1 fields. Raw content, source claims,
  implementation metadata, parameters, signatures, and bundle policy claims are discarded
  after hashing and are never serialized. Pydantic validation is configured to hide input
  values, including when callers instantiate strict public models directly.
- Supported direct model boundaries—construction, `model_validate`, `model_validate_json`,
  `model_validate_strings`, and frozen assignment/deletion—convert validation failures to
  code-only `ContentEnvelopeError` values. Pydantic `TypeAdapter`, private
  `__pydantic_validator__`, core-schema APIs, and unsafe `model_construct` are not validation
  boundaries and MUST NOT receive untrusted input. Public envelope APIs still reject a
  constructed or copied invalid model before use. Secret-safety and stable-error guarantees
  apply at these documented boundaries, not to unsupported Pydantic introspection paths.
- The legacy generic `canon()` logger is excluded from this subsystem. An AST import guard
  forbids importing the `mcp_warden.hashing` module as a dynamic attribute handle and permits
  only the named `hash_bytes` import, keeping raw ingress metadata off legacy canonicalization,
  hashing, and logging paths.

Hard caps are 16 MiB content, 64 KiB envelope, 16 JSON levels, 4,096 JSON nodes, 64 parents,
32 taints, and 256 bundle dependencies. Component-specific caps are defined in
`content_models.py`. The pre-parser depth scan handles JSON string quoting/escaping without
allocation proportional to nesting and rejects over-depth inputs before `json.loads`.
Bundle input requires exact bytes and an exact tuple of byte dependencies at runtime; invalid
shapes fail with a stable bundle code before iteration or hashing.
Regression tests exercise exact-cap acceptance and cap-plus-one rejection for every structured
component, bundle component/signature/dependency, JSON depth/nodes/keys/string bytes, envelope
bytes, parent count, taint input count, and dependency count.

## API boundary

The pure API is `create_ingress`, `derive_envelope`, `serialize_envelope`, `parse_envelope`,
`verify_envelope`, `verify_lineage`, `to_public_dict`, and `to_public_bytes`. It performs no
I/O, network, clock, environment, policy decision, or effect. Bundle fields are descriptive
evidence only; DSE-716 must verify artifacts and enforce the PDP/PEP load gate. DSE-717 must
provide durable signed receipts and evidence-before-effect.

## ATK coverage

Tests provide the DSE-715 foundation for ATK-01, ATK-02, and the envelope portions of ATK-05,
ATK-06, ATK-09, and ATK-12: untrusted state, monotonic taint, no authority fields, strict
fail-closed parsing, canonical explicit inputs, and secret-safe output. MCP-Warden remains
nonconformant with the whole ATK contract until DSE-716 and DSE-717 land and the complete
conformance suite passes.
