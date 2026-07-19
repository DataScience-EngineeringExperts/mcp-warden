# Deterministic Content Envelope Implementation Plan

> **Status:** Non-normative DSE-715 execution plan. The binding security requirements live in
> `docs/AGENT_TRUST_KERNEL.md`. Do not claim whole-kernel conformance from this ticket.

**Goal:** Add a byte-deterministic, secret-safe content envelope that preserves untrusted
ingress, source evidence, transform lineage, and monotonic taint across all ATK content kinds.

**Architecture:** Build a strict new Pydantic v2 subsystem and separate canonical codec. Reuse
RFC 8785 and SHA-256, add a domain-separated raw-byte hashing primitive, derive only from
verified parent envelopes, and expose no V1 taint-removal or authority operation.

`content_models.py` and `content_envelope.py` must not import or call legacy `canon()` or
`hash_value()` on any path. Structured ingress may use only the subsystem's secret-safe
canonical-metadata prevalidator followed by `hash_bytes(DigestDomain)`; opaque ingress goes
directly to that typed raw-byte hasher. An AST/import guard forbids a module handle to
`mcp_warden.hashing` and permits only the named `hash_bytes` import, closing alias, `getattr`,
and dynamic attribute paths to the legacy helpers. The generic `canon()` logger remains
legacy-only, is excluded from this subsystem, and never receives ingress data.

## Fixed contract

- Source kinds: tool result, web, document, email, database text, MCP prompt, MCP resource,
  bundle metadata, and agent message; derived content has a constructor-owned `derived` source.
- Every envelope is schema v1 and explicitly `untrusted`.
- Content and signature evidence are opaque raw bytes: never decoded, parsed, or normalized.
  Every structured metadata input must be exact RFC 8785 bytes, must pass
  `canon(parsed) == input`, and is then domain-hashed exactly. There is no `json.dumps` path;
  structured metadata is discarded, never serialized, and receives no Unicode normalization.
- The wire schema has no absent fields. `bundle` is the only nullable field and must be present
  as null or a complete object. It has no Pydantic default; the parser checks explicit key
  presence before model construction. Omitted bundle rejects and golden vectors cover both.
- Parent identity is exactly `{envelope_digest, content_digest}`. Refs sort lexicographically
  by the full lowercase ASCII envelope digest then content digest and are unique by envelope
  digest. Revalidating
  the parent self-digest commits source kind, source claims, taints, and content digest, so
  repeating source kind in the flat ref would be redundant.
- Parent refs and taints are tuples in frozen nested models. Derived taints are every parent
  taint plus added registered taints plus `core:untrusted`; no removal API exists. Mutation
  tests cover the top-level envelope and every nested object/collection.
- Strict unknown-field/version rejection, exact RFC 8785 parsing, duplicate-key rejection,
  domain-separated digests, stable code-only errors, and explicit public-field extraction.
- Transform IDs and versions are never caller text. Exact `TransformKindV1` values select an
  immutable append-only registry pair: ingress is fixed to `INGRESS_CAPTURE`, derivation to
  `DETERMINISTIC`, and the implementation digest completes exact transform identity. The
  registry has an exact collision-checked reverse mapping. Model validation and parsing bind
  every ingress root to the capture pair and every derived envelope to the deterministic pair,
  including self-coherent wire objects whose source digests and envelope digest were recomputed
  after a pair swap. Registry additions are security-sensitive and require a new enum member,
  updated context enforcement, and explicit cross-pair/wire-forgery tests. The implementation
  digest binds exact executing bytes; approval of that digest remains DSE-716 scope.
- Supported model construction/class-validation and frozen mutation entrypoints convert
  Pydantic failures to code-only errors. `TypeAdapter`, private validators, core-schema APIs,
  and unsafe construction are explicitly outside the untrusted-input boundary; every public
  envelope API revalidates exact model types before use. Exact-type-before-access checks are a
  required, test-enforced convention for every future public accepting boundary.
- Hard caps: content 16 MiB, envelope 64 KiB, source identity 8 KiB, source claims/parameters
  32 KiB, transform identity 8 KiB, bundle component 64 KiB, depth 16, nodes 4,096, parents
  64, taints 32, dependencies 256.
- Bundle digests are descriptive evidence only; DSE-716 owns verification and load authority.
- The taint registry is reviewed, append-only security code within V1. Unknown labels reject
  the whole envelope as `ENV-TAINT-UNKNOWN` and are never dropped. Removing/changing a label or
  incompatible wire evolution requires a schema bump and parallel explicit parser; V1 never
  guesses or silently upgrades. The parser consumes a private immutable module `frozenset`
  snapshot, not a caller-mutable registry.

### Digest domains

Every locally computed digest uses the exact construction
`sha256(domain + b"\x00" + payload)`, formatted as `sha256:<64 lowercase hex>`. Domains are:

```text
mcp-warden/content-envelope/v1/content
mcp-warden/content-envelope/v1/source-identity
mcp-warden/content-envelope/v1/source-claims
mcp-warden/content-envelope/v1/derived-source-identity
mcp-warden/content-envelope/v1/derived-source-claims
mcp-warden/content-envelope/v1/transform-implementation
mcp-warden/content-envelope/v1/transform-parameters
mcp-warden/content-envelope/v1/bundle-artifact
mcp-warden/content-envelope/v1/bundle-signature
mcp-warden/content-envelope/v1/bundle-version
mcp-warden/content-envelope/v1/bundle-publisher
mcp-warden/content-envelope/v1/bundle-dependency
mcp-warden/content-envelope/v1/bundle-policy-binding
mcp-warden/content-envelope/v1/envelope
```

Golden tests prove same-domain repeatability and different-domain separation.
`content_models.py` owns a frozen `DigestDomain` string enum for every entry. All call sites use
enum members—never inline strings—and a programmatic pairwise test covers every distinct pair.

## Task 1: Pin strict models and byte hashing

**Files:**
- Create `src/mcp_warden/content_models.py`
- Modify `src/mcp_warden/hashing.py`
- Create `tests/test_content_envelope.py`

1. Write failing golden tests for strict schema/version/trust state, explicit null versus
   omitted bundle/key presence, frozen nested models/every primitive and collection mutation,
   frozen domain enum, digest syntax, exact raw-byte digest, programmatic pairwise domain
   separation, and an AST/import guard forbidding `canon`/`hash_value` in both modules.
2. Run the targeted tests and record the expected failures in the AI-SDLC log.
3. Add strict frozen models, enums/registries/caps, `ContentEnvelopeError`, and
   `hash_bytes(payload, domain=...)`.
4. Rerun targeted tests to green; refactor common digest validation only after green.

## Task 2: Ingress construction

**Files:**
- Create `src/mcp_warden/content_envelope.py`
- Extend `tests/test_content_envelope.py`

1. Write failing tests for all nine source kinds, exact non-UTF-8 content, canonical metadata,
   opaque signature bytes, exact UTF-8/no-normalization/no-`json.dumps` behavior, media
   registry, bundle requirement, sorted taints, and every cap boundary. Safely monkeypatch a
   parser-owned immutable registry snapshot to prove drift/unknown taints reject rather than
   disappear. Exercise exact cap and cap+1 boundary arithmetic.
   The boundary matrix covers source identity/claims, transform implementation/parameters,
   every bundle component, dependency count/component size, JSON depth/nodes/keys/string,
   serialized envelope bytes, parents, and taint input count.
2. Implement `create_ingress()` and canonical-metadata validation.
3. Prove raw source identity/claims, transform implementation/parameters, bundle metadata,
   and content never appear in envelope serialization or error text.
4. Before stdlib JSON parsing, run one allocation-free pass over byte-capped, UTF-8-validated
   bytes with only integer `depth`, boolean `in_string`, and boolean `escape`. Outside strings,
   ASCII `{`/`[` increments, `}`/`]` decrements, and `"` enters a string. Inside strings,
   backslash escapes exactly the next byte and an unescaped quote exits; `\uXXXX`, bracket
   bytes in strings, and multibyte UTF-8 are never structural. Reject depth >16, negative or
   nonzero final depth, unterminated strings, and dangling escapes. Then use `json.loads` with
   duplicate-key-rejecting `object_pairs_hook` and an iterative structural-cap pass. A
   10,000-level input under 64 KiB must reject before `json.loads`; monkeypatch it to prove no
   call and no `RecursionError`.

## Task 3: Deterministic transforms and lineage

**Files:**
- Modify `src/mcp_warden/content_envelope.py`
- Extend `tests/test_content_envelope.py`

1. Write failing tests for every parent ordering, exact ASCII lexicographic dual-digest refs,
   deterministic derived source, atomic parent self-digest tamper rejection before refs/taints,
   exact parent-set comparison, duplicate/missing/self parents, flat crafted cycles, and
   complete bounded taint union. Cover direct model construction, public validation, and
   canonical parse rejection of both source-context/transform-pair swaps, recomputing derived
   source evidence and the envelope self-digest so the forged wire is otherwise self-coherent.
2. Implement `derive_envelope()` and `verify_lineage()` from verified parent objects.
3. Prove no API/schema key can remove taint, upgrade trust, or grant authority.
4. Store only flat immutable refs. Verification is iterative one-hop/exact-set, does not walk
   ancestors, and rejects self-parent. Prevalidate at most 64 parents and 32 taints each, build
   the complete local union over at most 2,048 parent labels plus bounded caller labels, then
   perform one final 32-taint cap check. Discard the local set on error. Property tests prove
   all parent orderings return the same success or stable failure code.
5. `derive_envelope()` must atomically recompute every parent's self-digest from its in-memory
   constituent fields as its first step. One-hop verification commits the parent's own flat
   refs but intentionally does not prove a transitive graph; multi-hop orchestration belongs
   to DSE-716/717.

## Task 4: Codec, verification, and public output

**Files:**
- Modify `src/mcp_warden/content_envelope.py`
- Extend `tests/test_content_envelope.py`

1. Write failing golden round-trip tests and malformed cases: unknown version/field, duplicate
   key, noncanonical JSON, NaN/infinity, bad digest, self/content mismatch, wrong ordering,
   exact scanner state/escape cases, deep/large structures, and attempted authority fields.
2. Implement `serialize_envelope()`, `parse_envelope()`, `verify_envelope()`,
   `to_public_dict()`, and `to_public_bytes()`.
   `parse_envelope()` atomically recomputes the self-digest from parsed constituent fields and
   rejects mismatch before returning any envelope.
3. Public output must use explicit field extraction, never whole-model dumping.
4. Plant a unique secret in every raw input, including policy-like bundle metadata, and
   byte-scan canonical/public output, `str(error)`, `repr(error)`, and formatted traceback.
   Catch third-party/Pydantic/RFC/JSON errors and raise `ContentEnvelopeError(code) from None`:
   no raw error logging/chaining/context, and tests assert cause/context absent. The generic
   `canon()` logger must never receive raw untrusted metadata; body canon sees digests only.
   A `caplog` planted-secret test proves the subsystem never logs raw exception/input text.

## Task 5: Property and fuzz tests

**Files:**
- Create `tests/fuzz/test_fuzz_content_envelope.py`

Add Hypothesis properties for repeated byte identity, parent permutation invariance, sorted
uniqueness, taint monotonicity, canonical round-trip, single-byte mutation rejection, bounded
termination on malformed/deep bytes, flat-cycle non-recursion, registry drift rejection, and
planted-secret absence. Prefer deterministic structural bounds; do not use flaky wall-clock
deadlines as a correctness assertion.

## Task 6: Document verified behavior

**Files:**
- Create `docs/CONTENT_ENVELOPE.md`
- Modify `DOCUMENTATION_INDEX.md`
- Modify `SYSTEM_CONTEXT_DIAGRAM.md`
- Modify `docs/AGENT_TRUST_KERNEL.md`

Document only the behavior proved by tests. Map ATK-01/02/05/06/09/12 and keep DSE-716/717
bindings and current whole-kernel nonconformance explicit.

## Verification

Run after each red/green slice:

```bash
PYTHONPATH=src .venv/bin/python -m pytest tests/test_content_envelope.py -q
PYTHONPATH=src .venv/bin/python -m pytest tests/fuzz/test_fuzz_content_envelope.py -q
```

Final local gate:

```bash
.venv/bin/ruff check src/mcp_warden/content_models.py \
  src/mcp_warden/content_envelope.py src/mcp_warden/hashing.py \
  tests/test_content_envelope.py tests/fuzz/test_fuzz_content_envelope.py
PYTHONPATH=src .venv/bin/python -m pytest -q
git diff --check
```

Then run link/docs checks, adversarial Conclave review, independent security review, and CI.
Only verified, reviewed work proceeds to admin merge.
