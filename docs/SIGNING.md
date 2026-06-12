# Sigstore signing + verification of `warden.lock` (#16)

mcp-warden can **Sigstore-sign** the identity of a pinned surface and later
**cryptographically verify** that signature in CI — keyless (Fulcio short-lived
certs + Rekor transparency log), no long-lived private keys to manage.

Signing is **opt-in** and lives behind an optional extra. The base install is
unchanged and ships no sigstore dependency.

```bash
pip install 'mcp-warden[sigstore]'
```

---

## What is signed (and why it survives `lock rotate`)

A signature binds **only** the lock's `overall_digest` — the canonical digest of
the *definition portion* of the surface — **not** the whole `warden.lock` file.

At both sign time and verify time we build a single DETERMINISTIC statement:

```json
{"_type":"mcp-warden-lock-digest/v1","digest":"sha256:<64 hex>"}
```

(canonical JSON: keys sorted, no whitespace). `_type` is the domain separator for
raw-bytes (hashedrekord) signing. This statement is byte-identical on both sides
because both sides recompute it from `lock.overall_digest`.

Because the signed thing is the surface identity (`overall_digest`), **out-of-digest
mutations do not invalidate the signature**: `warden lock rotate` (#19), appended
attestations, and new provenance fields all leave `overall_digest` byte-stable, so
a previously-produced bundle still verifies.

---

## What the signature covers / does NOT cover

The signature binds **only** `overall_digest`, which is the canonical digest of the
**tool identity surface**:

- **Covers** — the server launch command, the server's capabilities, the tool
  input-schema skeleton, and the inspection policy that fed the captured surface
  (i.e. `server.command_digest` + the sorted per-entry `entry_digests`).
- **Does NOT cover** — the lock's `findings`, `pin`/provenance metadata, the
  signer pointer attestation, or any other out-of-digest field. These are
  excluded from `overall_digest` BY DESIGN (see the schema's digest definition).

Security consequence: an attacker with **post-sign write access** to the lock can
alter the `findings` (or `pin`/provenance) section and the signature will STILL
verify, because those bytes are not part of the signed statement. A tampered
`findings` section does **not** invalidate the signature. `check --verify` therefore
attests to the tool surface identity ONLY — it is **not** evidence of findings
integrity. The `check --verify` success line says this explicitly.

> Future enhancement: a separate findings digest could be folded into the signed
> statement to extend coverage to `findings`. That is intentionally out of scope
> for #16 (it would change statement canonicalization — see "Refreshing the
> offline fixture").

---

## `pin --sign`

```bash
# Ambient / CI OIDC (GitHub Actions, GitLab, etc. with id-token permission):
mcp-warden pin python ./server.py --lock warden.lock --sign

# Explicit identity token:
mcp-warden pin python ./server.py --lock warden.lock --sign --identity-token "$OIDC_TOKEN"
```

What it does, in order (all fail **closed**):

1. Builds + writes the lock as usual.
2. Builds the statement from `overall_digest`, Sigstore-signs it.
3. Atomically writes the bundle to the **fixed sidecar** `warden.lock.sigstore`
   next to the lock (`Bundle.to_json()`).
4. Appends an **out-of-digest pointer attestation** to the lock:
   `{role:"signer", method:"sigstore-keyless", bound_digest:<overall_digest>,
   signature_bundle:"warden.lock.sigstore"}` and bumps `pin.provenance_version`
   1 → 2 (additive, OUTSIDE `overall_digest`).

> **The `signature_bundle` pointer field is INFORMATIONAL ONLY.** It always holds
> the fixed value `"warden.lock.sigstore"` and is never written as a tampered or
> relative path. `check --verify` **ignores** this field entirely and always loads
> the bundle from the fixed sidecar path next to the lock (or `--offline-bundle`).
> Trusting the pointer for pathing would be a vulnerability — so verify does not.

Sign **atomicity invariant** (Fix 3): the on-disk state is ALWAYS consistent —
either BOTH the pointer-bearing lock AND its sidecar are present, or NEITHER. The
bundle is staged to `warden.lock.sigstore.tmp`, the pointer-bearing lock is written,
then the temp sidecar is `os.replace`d into `warden.lock.sigstore`. On ANY failure
the unsigned lock is restored if needed and no orphan `.sigstore` or `.tmp` remains,
so a signed lock never claims a signature it cannot back with a sidecar.

Fail-closed semantics:

- `--sign` without the extra → exit non-zero with an install message. Never a
  silent no-op.
- Any signing error → exit non-zero, **no half-written sidecar and no `.tmp`**
  (bundle is staged to a temp file then atomically `os.replace`d into place).
- An explicit `--identity-token` that is empty/invalid → hard failure. We never
  fall back to ambient OIDC when the operator asked for a specific identity.
- The signature/bundle/pointer are all OUTSIDE `overall_digest`, so a signed pin's
  `overall_digest` is byte-identical to an unsigned pin of the same surface.
- The OIDC JWT is **never written to disk or logged** — only the resulting Fulcio
  public certificate is embedded in the bundle.

---

## `check --verify`

```bash
mcp-warden check \
  --lock warden.lock \
  --verify \
  --certificate-identity "https://github.com/<owner>/<repo>/.github/workflows/<wf>.yml@<ref>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  [--offline-bundle path/to/warden.lock.sigstore]
```

This is a pure cryptographic check — it does **not** spawn the server.

Fixed-sidecar verify contract (this is the security boundary):

- If the extra is absent → exit non-zero + install message (**not** skip).
- If the lock has no `overall_digest` → exit 2 with a clear
  "lock has no overall_digest" message BEFORE building any statement.
- The bundle is loaded from the **FIXED** path
  `dirname(abspath(lock))/warden.lock.sigstore` (or `--offline-bundle` if given).
  The lock's pointer `signature_bundle` field is **never** read for pathing — it
  is attacker-controllable, so trusting it would be a vulnerability.
- The statement is **recomputed from the lock's own `overall_digest`**. The
  pointer's `bound_digest` is ignored entirely (attacker-controllable).
- Missing sidecar → exit non-zero ("bundle not found"), **not** skip.
- Verification succeeds **only** when the underlying sigstore call raises no
  exception. `VerificationError` → exit 1; **any** other exception (TUF refresh /
  network / malformed bundle / API type errors) → exit 1. There is no return
  value to mis-read as a pass.

On a clean verify the success output reads:

```
OK tool surface signature verified for <identity>
  issuer: <issuer>
  overall_digest: sha256:<64 hex>
  bundle: <path to warden.lock.sigstore>
  note: findings, pins, and provenance metadata are NOT covered by this signature
```

The wording is deliberate: it attests to the **tool surface**, and the trailing
note prevents the result from being read as findings/pins/provenance integrity.

### Identity/issuer matching is EXACT

`check --verify` builds `policy.Identity(identity=…, issuer=…)`, and sigstore 4.3.0
performs **exact-string equality** on both — the SAN identity via
`self._identity in all_sans` (set membership) and the OIDC issuer via
`ext_value != self._value`. There is no substring/prefix/regex matching. The
`--certificate-identity` you pass must therefore be the FULL workflow identity
**including the ref** (e.g.
`https://github.com/<owner>/<repo>/.github/workflows/<wf>.yml@<full ref>`). In CI,
derive the ref from `$GITHUB_REF` rather than hardcoding it so the check is correct
on any branch/tag.

### No repository/filename binding in the statement

The signed statement is `{"_type":"mcp-warden-lock-digest/v1","digest":<overall_digest>}`
— it carries **no** repository, filename, or path binding. Two CI runs that sign the
**same** `overall_digest` produce **interchangeable** bundles. Run isolation comes
entirely from the verify-time policy: the `--certificate-identity` and
`--certificate-oidc-issuer` you pass pin WHO signed it (which workflow/ref, via which
issuer). If you need stronger per-repo binding, enforce it through the identity policy,
not the statement.

---

## Fail-closed matrix (tested)

Every one of these produces a **non-zero** exit; none can reach exit 0:

| Failure mode | Result |
|---|---|
| Bad signature (`VerificationError`) | exit 1 |
| Generic exception (TUF / network down) | exit 1 |
| `AttributeError` / `TypeError` (API drift) | exit 1 |
| Missing sidecar bundle | exit 1 |
| Identity mismatch | exit 1 |
| Malformed bundle JSON | exit 1 |
| Statement / digest mismatch | exit 1 |
| Optional extra absent | exit 2 |
| Lock has no `overall_digest` | exit 2 |

---

## Accepted trade-offs

1. **Rotate-replay.** A valid bundle proves `overall_digest` was signed by the
   identity at that time; it does **not** prove the signer reviewed the lock's
   *current* (out-of-digest) provenance metadata. `lock rotate` can append new
   attestations without re-signing, and the old bundle still verifies. This is
   intentional — the signature attests to surface identity, not to provenance
   review.

2. **Committed-fixture coverage gap.** The offline-fixture test
   (`tests/test_signing.py::test_offline_fixture_verifies_when_present`) **SKIPS**
   until a real signed bundle is dropped into `tests/fixtures/signed/`. The live
   crypto round-trip runs in CI (`sigstore-e2e`), but the committed offline
   fixture must be generated by the dedicated `sigstore-fixture.yml` workflow.

---

## TUF cache / offline caveat

Sigstore verification needs Sigstore's TUF-distributed trust root. The first
verify in an environment performs a TUF refresh (network). In a fully
network-isolated runner you must pre-warm the TUF cache; `verify` fails closed
(exit 1) rather than guessing if the trust root cannot be obtained.

---

## CI workflows

- **`integrity-gate.yml` → `sigstore-e2e` job** — the LIVE crypto evidence:
  signs a test server with ambient OIDC, then verifies against the workflow's own
  identity (`permissions: id-token: write`). Skips on forks (no id-token), never
  fails them. Uploads the signed lock + bundle as an artifact.
- **`.github/workflows/sigstore-fixture.yml`** — DEDICATED, **contractually
  stable**: signs the fixture and uploads it as an artifact for offline coverage.
  **NEVER rename or move this file** — the committed fixture's signer identity is
  pinned to its path.

### Refreshing the offline fixture

**When the committed fixture MUST be regenerated** (Nit C): re-run the workflow and
re-drop the fixture whenever the **statement canonicalization changes** (the
`STATEMENT_TYPE` domain separator, the statement key set, or the canonical-JSON
serialization in `signing.build_statement`) or whenever the **Sigstore trust root
changes** (a new TUF root / `ClientTrustConfig.production()` shift). In either case
the old bundle no longer corresponds to the recomputed statement / current trust
root and the offline-fixture test would fail closed. A routine `lock rotate` or any
out-of-digest provenance change does NOT require regeneration (the signed
`overall_digest` is unchanged).

1. Run `sigstore-fixture.yml` on `main` (push or `workflow_dispatch`).
2. Download the `mcp-warden-signed-fixture` artifact.
3. Drop `warden.lock` + `warden.lock.sigstore` into `tests/fixtures/signed/`.
4. The offline-fixture test now runs (no longer skips), verifying the committed
   bundle against the pinned identity
   `https://github.com/ernestprovo23/mcp-warden/.github/workflows/sigstore-fixture.yml@refs/heads/main`
   (issuer `https://token.actions.githubusercontent.com`).
