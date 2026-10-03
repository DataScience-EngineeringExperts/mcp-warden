# Public-key governance artifact trust

This opt-in verifier implements the existing DSE-716 `ArtifactVerifierV1` port
for externally signed policy, runtime, adapter, and executable-bundle artifacts.
It is a foundation for human checkpoints. It does not wire those checkpoints
into the historical `guard`, implement DSE-717's durable receipts or protected
state, or establish whole-kernel conformance.

## Trust and key custody

Install this development branch with the `artifact-trust` extra. The published
2.0.0 package does not include this feature. No signing command, private-key
loader, or key generator exists in the product. Use an independently governed
external signing service or signing station; keep its private signing capability
outside agent/tool access. The external signer must review the canonical
artifact and sign exactly the prepared frame, not merely a displayed summary.

The consumer explicitly configures raw Ed25519 public keys and the artifact
kinds each may sign. Governance and runtime signing roles should use separate
keys. In particular, a key allowed to sign reviewed policy or executable bundles
does not acquire permission to attest to runtime health or trusted time.

The consumer MUST obtain `expected_roots_digest` through a protected trusted
boundary independent of the roots file and artifact. The complete key AND role
configuration is pinned. Computing a digest from attacker-supplied roots and
immediately passing it as the pin does not establish trust. Replacing both roots
and pin defeats this local boundary; filesystem permissions and custody belong
to the embedding host. This verifier provides no protection against host/TCB or
authorized-admin compromise.

## Public roots format

```json
{
  "schema_version": 1,
  "keys": [
    {
      "public_key": "<64 lowercase hex characters encoding 32 raw public-key bytes>",
      "artifact_kinds": ["adapter", "bundle", "policy"]
    }
  ]
}
```

Replace the illustrative public-key placeholder with an enrolled public key.
Kinds are a nonempty, sorted, duplicate-free subset of `adapter`, `bundle`,
`policy`, `runtime`. Duplicate keys, unknown fields, unsupported schemas,
non-finite numbers, and duplicate JSON object keys are rejected. Roots are
bounded to 64 keys and 64 KiB. SDK records are immutable; verification snapshots
the public keys and allowed roles.

Let `H(domain, bytes)` be `sha256:` plus the lowercase hexadecimal SHA-256 of
`ASCII(domain) || 0x00 || bytes`.

- Signer identity: `H("mcp-warden/artifact-signature/v1/key-id", raw_public_key)`.
- Roots digest: `H("mcp-warden/artifact-signature/v1/roots", canonical_roots)`.
- Canonical roots: RFC 8785 JSON with `schema_version: 1`, keys sorted by signer
  identity, public keys encoded as lowercase hex, and kinds sorted as above.

The signer identity identifies a key, not a verified human name. The operator's
external enrollment record binds that key to a human or service and its role.
Adding/removing a key or changing its roles changes the root pin. Root freshness,
rotation and revocation require independently governed configuration updates;
the verifier does not infer them from untrusted input.

## Signature format

Sign the exact byte concatenation:

```text
ASCII("mcp-warden/artifact-signature/v1") || 0x00 ||
ASCII(artifact_kind) || 0x00 || ASCII(signer_identity) || 0x00 ||
canonical_artifact_payload
```

Use Ed25519 and a raw detached 64-byte signature. The existing external port
selector remains `VerificationAlgorithmV1.EXTERNAL_V1`; this implementation
does not negotiate algorithms. There is no base64/hex/signature-envelope
autodetection. Kind, key identity and format version are signed to prevent
cross-role/context reuse. Signing raw artifact JSON without the frame is invalid.

The payload is the existing canonical serialization from
`canonical_policy_bytes`, `canonical_runtime_bytes`, `canonical_manifest_bytes`,
or `canonical_bundle_manifest_bytes`. Preparation accepts an unambiguous JSON
draft and validates the strict existing model. Verification requires exact
canonical bytes. Unknown artifact fields and schemas are rejected; schema
integers cannot be booleans. The global input cap is 512 KiB, with narrower
existing artifact caps retained.

## Offline CLI workflow

Enrollment inspection prints the candidate root digest and derived signer
identities. A trusted administrator independently reviews/enrolls the keys and
roles and pins this digest; the command itself does not approve enrollment.

```bash
mcp-warden trust roots-digest public-roots.json
mcp-warden trust prepare policy policy-draft.json \
  --signer "$ENROLLED_SIGNER_DIGEST" \
  --canonical-out policy.canonical.json --signing-out policy.signing.bin
```

The second command creates an **unsigned** canonical review artifact and exact
signing frame. Outputs must be new files. Input/output collisions and clobbering
are rejected; failures clean up newly created outputs. Review all resolved
grants/leases and their subject, input, action, argument, destination, policy and
version bindings before signing externally. A policy's digest-only grants are
not a substitute for that review package.

After the external signer returns `policy.sig`:

```bash
mcp-warden trust verify policy policy.canonical.json \
  --roots public-roots.json --roots-digest "$PROTECTED_ROOTS_DIGEST" \
  --signer "$ENROLLED_SIGNER_DIGEST" --signature policy.sig
```

`$PROTECTED_ROOTS_DIGEST` and `$ENROLLED_SIGNER_DIGEST` above are illustrative
values supplied by the trusted host; environment variables writable by the
agent do not create a protected boundary. Success emits `signature-verified`;
it is not an execution authorization. Failure exits 2 with a code-only error and
no raw artifact, signature, key file, or lower-layer exception text.

## SDK activation

```python
from mcp_warden.artifact_trust import Ed25519ArtifactVerifierV1, parse_roots
from mcp_warden.policy_decision import activate_policy

# The host supplies protected_roots_digest independently and bounds roots_bytes.
verifier = Ed25519ArtifactVerifierV1(
    parse_roots(roots_bytes), expected_roots_digest=protected_roots_digest
)
active_policy = activate_policy(signed_policy_candidate, verifier=verifier)
```

The same verifier can be passed to `activate_runtime`, `activate_adapter`, and
`activate_executable_bundle`, with separately enrolled roles. Existing APIs
still require exact request/lease/policy matching and actual adapter, handler,
artifact and dependency evidence. Invalid signatures return false through the
verification port and fail activation. Missing optional crypto support fails
explicitly with `TRUST-CRYPTO-UNAVAILABLE`.

## Limits and next dependencies

A valid signature authenticates exact bytes under an enrolled key/role. It does
not establish that code/content is safe, authenticate every tool result, clear
taint, verify current executable measurements, or permit effects. It also does
not enforce expiry, trusted time, revocation or rollback floors by itself.
Existing PDP/PEP policy/runtime checks remain necessary; an expired artifact can
have a mathematically valid signature while being unusable for authorization.

The default evidence gate continues to permit nothing. DSE-717 must deliver
durable signed receipts, negative-decision fallback, rollback-resistant state
and recovery before DSE-1076 can connect the kernel to live `guard`. Its recorded
unpublished implementation must be recovered rather than duplicated.

Tests use ephemeral test-only private keys for all four real activation paths,
key/role/kind/payload substitution, invalid parsing/pins, dependency drift, and
proof that valid signatures cannot bypass the default evidence gate.
