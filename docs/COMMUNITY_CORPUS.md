# Community lock corpus — multi-attester surface consensus (DSE-1515)

**Status:** phase 1 shipped (engine, `check --against-community`, fixture corpus).
Phase 2 — the live public corpus repo and the nightly attester — is **pending** and
is not required to use the flag against a corpus you host yourself.

---

## 1. Why this exists — the TOFU hole

`check` answers exactly one question: *has the declared surface changed since I
approved it?* It structurally cannot answer two questions that matter more to a
first-time consumer:

1. **Was the surface already poisoned at first pin?** The baseline is trust-on-first-use.
   A server that ships malicious on day one pins clean and gates clean forever.
2. **Am I being served a surface nobody else sees?** A targeted rug-pull — poisoned
   definitions returned only to one organisation's CI egress — is invisible to a
   single-party lock by construction.

Both reduce to one missing primitive: **independent observation**. If several
unaffiliated attesters Sigstore-signed the same surface for `npm:@foo/server@1.2.3`
and you observe something different, that is signal a solo lock can never produce.

## 2. What consensus proves — and what it does not

> **Consensus attests observation, not safety.** Every finding this feature emits
> carries that sentence, and the CLI repeats it on a clean match.

| Consensus **does** establish | Consensus does **not** establish |
|---|---|
| N declared attesters each captured a surface with this launch-independent digest for this exact package version | that the server is safe, benign, correct, or free of prompt injection |
| your observation is (or is not) the same declared surface those attesters saw | anything about runtime behaviour (`T-BEHAVE` remains out of scope, see `THREAT_MODEL.md`) |
| the attesters disagree among themselves (`SPLIT`) — the corpus or the upstream is compromised | who is right in a split; a split is a stop signal, not an adjudication |

A poisoned server that is poisoned *identically for everyone* matches consensus. That
is the residual risk and it is deliberate: the corpus turns a targeted attack into a
loud one; it does not review content. Pair it with a static tool-poisoning scanner.

## 3. The digest that is compared

`overall_digest` (WARDEN_LOCK_SCHEMA §6.1) binds `server.command_digest`, i.e. the
exact launch argv. Two parties launching the same package through different runners
(`npx -y pkg@1.0.0` vs `node ./node_modules/.bin/pkg`) get different overall
digests although the *declared surface* is identical. Consensus therefore compares
the **surface digest**:

```
surface_digest = sha256( JCS({ schema_version, tools: [entry_digest…],
                               resources: [entry_digest…], prompts: [entry_digest…] }) )
```

— the §6.1 payload minus `server`. It is derived, never stored, and recomputable from
any lock (`mcp_warden.lockfile.surface_digest`).

The Sigstore signature in the corpus still binds the attester's full `overall_digest`.
To make that signature cover the derived surface digest, every corpus lock must also
**reproduce its own `overall_digest` from its entries** (`lock_is_self_consistent`).
A lock whose entries were edited under an intact signature is rejected as
`UNVERIFIABLE`.

## 4. Corpus layout

```
attesters.json
locks/<ecosystem>/<segment>/<version>/<attester-id>.lock
locks/<ecosystem>/<segment>/<version>/<attester-id>.lock.sigstore
```

- `ecosystem` ∈ `npm` | `pypi`.
- `segment` is the package name with `/` replaced by `__`, so the scoped npm package
  `@example/clean` lives under `locks/npm/@example__clean/`. PyPI names are PEP 503
  normalised (`Mcp_Server.Foo` → `mcp-server-foo`).
- `<attester-id>` is a `[A-Za-z0-9._-]{1,64}` id that **must** appear in
  `attesters.json`; an entry from an undeclared attester rejects the coordinate.
- `.lock.sigstore` is the Sigstore bundle `pin --sign` writes (`docs/SIGNING.md`),
  signed over `build_statement(overall_digest)`.

`attesters.json`:

```json
[
  {
    "id": "alice",
    "certificate_identity": "https://github.com/example/attester-alice/.github/workflows/attest.yml@refs/heads/main",
    "oidc_issuer": "https://token.actions.githubusercontent.com"
  }
]
```

Identity and issuer are matched **exactly** by `sigstore.verify.policy.Identity`; a
near-miss fails closed.

## 5. Coordinates

A coordinate names one published artifact: `<ecosystem>:<name>@<version>`. It is
inferred from the launch argv or given explicitly with `--coordinate` (which wins).

| Launch | Coordinate |
|---|---|
| `npx -y @modelcontextprotocol/server-github@2025.4.8` | `npm:@modelcontextprotocol/server-github@2025.4.8` |
| `npx -p @scope/pkg@1.2.3 some-bin` | `npm:@scope/pkg@1.2.3` |
| `uvx mcp-server-git==0.6.2` | `pypi:mcp-server-git@0.6.2` |
| `uvx --from Mcp_Server_Fetch[extra]==1.0.0 mcp-server-fetch` | `pypi:mcp-server-fetch@1.0.0` |
| `pipx run --spec foo==2.0 foo` | `pypi:foo@2.0` |
| `npx -y @modelcontextprotocol/server-github` (unpinned) | **`UNRESOLVED` → exit 2** |
| `node ./build/index.js`, `--url …` | **`UNRESOLVED` → exit 2** unless `--coordinate` is given |

A version must be concrete (leading digit). Tags (`latest`), ranges (`^1`), and
bare names cannot be attested, so they fail closed instead of guessing. The
coordinate is resolved **before** the server is spawned.

## 6. Verdicts and exit codes

| Rule | Severity | Meaning | Exit |
|---|---|---|---|
| *(match)* | — | every verified attester saw your surface; one stderr line | 0 |
| `WRD-CONSENSUS-NOVEL` | low | no attestation exists for the coordinate; nothing to compare | 0 (finding is emitted) |
| `WRD-CONSENSUS-MISMATCH` | high | your surface differs from **every** attested digest | **1** |
| `WRD-CONSENSUS-SPLIT` | high | attesters disagree among themselves — reported even if you match one | **1** |
| `WRD-CONSENSUS-UNRESOLVED` | — | launch cannot be turned into a pinned coordinate | **2** |
| `WRD-CONSENSUS-UNVERIFIABLE` | — | sigstore missing, unknown attester, missing/corrupt/failing sidecar, inconsistent lock, malformed `attesters.json` | **2** |
| `WRD-CONSENSUS-UNREACHABLE` | — | corpus path/URL unreachable, clone/checkout failed, `--corpus-ref` missing or not `HEAD` | **2** |

Findings go through the same SARIF and `--json` JSONL emitters as static checks and
drift; the exit code composes with drift (`drift or MISMATCH or SPLIT → 1`). With the
flag absent, `check` is byte-for-byte unchanged.

## 7. Using it

```bash
# against a corpus checkout you already have
mcp-warden check npx -y @foo/server@1.2.3 --lock warden.lock \
    --against-community --corpus ../mcp-warden-locks

# against a git URL, pinned to an exact corpus commit (required for URLs)
mcp-warden check node ./build/index.js --lock warden.lock \
    --against-community --corpus https://github.com/<org>/mcp-warden-locks.git \
    --corpus-ref 0123456789abcdef0123456789abcdef01234567 \
    --coordinate npm:@foo/server@1.2.3
```

A URL is cloned with `git clone --no-checkout` + `git checkout <sha>` into a temporary
directory (argv list, never a shell) and removed afterwards; the checkout's `HEAD` must
equal `--corpus-ref`. Requires `mcp-warden[sigstore]`.

## 8. Phase 2 — the live corpus (pending)

Planned, not shipped: a public append-only repo `mcp-warden-locks` (PR-only merges; a
required check rejects any modify/delete under `locks/`) fed by a nightly attester
that reads the official MCP registry, spawns each top-N server in a sandbox, and
opens a PR of `pin --sign` outputs containing only *new* paths.

**Sandbox contract an attester must meet** (so a malicious server cannot poison the
attester itself): ephemeral runner, non-root, network egress cut after package
install, no secrets in the environment beyond the OIDC token used to sign, one
package per job, the lock written only from the SDK handshake (`tools/list` /
`resources/list` / `prompts/list`) — never from tool results.

## 9. Test fixture

`tests/fixtures/corpus/` is a local corpus whose sidecars are **fakes**
(`{"over": <statement>}`) accepted only by the monkeypatched boundary in
`tests/test_corpus.py`. Real Sigstore verification rejects them — which is itself
tested. Regenerate with `tests/fixtures/gen_corpus.py`.
