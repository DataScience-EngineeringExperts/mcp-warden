# Verify externally approved artifacts

The development branch adds public-key signature verification for Agent Trust
Kernel policy, runtime, adapter, and executable-bundle artifacts. This feature
is not included in the published **2.0.0** package. Install a reviewed Git commit
with the `artifact-trust` extra to use it.

It prepares unsigned review artifacts and verifies external Ed25519 signatures.
Live human-checkpoint enforcement still requires the durable evidence layer and
guard integration.

## Enroll public keys and signer roles

Configure the public keys and the artifact kinds each key may sign. Keep the
private signing capability in an independently governed external signer, outside
agent and tool access.

```bash
mcp-warden trust roots-digest public-roots.json
```

This prints a candidate root digest and signer identities for independent
enrollment review. Pin the reviewed digest through a protected host boundary.
An agent-controlled roots file and matching agent-controlled pin do not
establish trust.

## Prepare an unsigned review artifact

```bash
mcp-warden trust prepare policy policy-draft.json \
  --signer "$ENROLLED_SIGNER_DIGEST" \
  --canonical-out policy.canonical.json \
  --signing-out policy.signing.bin
```

Review the canonical artifact together with its resolved grant/lease bindings.
Then have the external signer sign the exact prepared bytes. Preparation does
not approve the artifact or execute an action. Both output paths must be new.

## Verify the returned signature

```bash
mcp-warden trust verify policy policy.canonical.json \
  --roots public-roots.json \
  --roots-digest "$PROTECTED_ROOTS_DIGEST" \
  --signer "$ENROLLED_SIGNER_DIGEST" \
  --signature policy.sig
```

Success reports `signature-verified`. The variables here illustrate values
provided by the trusted host; writable environment variables alone are not a
protected boundary. The signature must be exactly 64 raw bytes.

Signature validity alone does not check current authority, expiry, revocation,
dependency measurements, or whether an action is allowed. Existing activation
and policy enforcement APIs remain responsible for those checks. The default
evidence gate continues to block effects pending durable evidence integration.

See the [artifact trust contract](https://github.com/DataScience-EngineeringExperts/mcp-warden/blob/main/docs/ARTIFACT_TRUST.md)
for the roots schema, exact signing frame, SDK usage and remaining dependencies.
