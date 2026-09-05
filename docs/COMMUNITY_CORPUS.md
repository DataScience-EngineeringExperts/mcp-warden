# Community lock corpus — multi-attester surface consensus (DSE-1515)

**Status:** phase 1 shipped (engine, `check --against-community`, fixture corpus),
hardened after security review (C1–C3, M1–M3, L1–L3 in the PR). Phase 2 — the
live public corpus repo and the nightly attester — is **pending** and is not
required to use the flag against a corpus you host yourself.

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
attesters *you have chosen to trust* Sigstore-signed the same surface for
`npm:@foo/server@1.2.3` and you observe something different, that is signal a solo
lock can never produce.

## 2. Trust model — read this before the rest

> **Consensus attests observation, not safety.** Every finding this feature emits
> carries that sentence, and the CLI repeats it on a clean match.

Three things are cryptographically bound, and nothing else:

| Bound by the signature | How |
|---|---|
| the attester's **identity + issuer** | Sigstore certificate SAN + OIDC issuer, exact-match (`policy.Identity`) |
| the lock's **`overall_digest`** | the signed v2 statement `{_type: mcp-warden-lock-digest/v2, coordinate, digest}` |
| the **package coordinate** the digest was observed for | the same v2 statement; the consumer rebuilds it from the *directory* the entry sits in, so a genuine signature copied under another package fails |

From `overall_digest` the consumer derives the launch-independent **surface digest**
(§3) only after checking the lock's entries reproduce the signed `overall_digest`, so
the entries are covered too.

**The trust root is yours, never the corpus's.** A corpus ships an `attesters.json`,
but that file is a *discovery* list — it tells you which ids file entries and what
identity each claims. Which of those ids you *believe* is the consumer pin you MUST
supply (`--attester` / `--attesters-file`). A corpus that could name its own trust
root would verify anything its operator signed; the pin is what stops a forked or
hostile corpus from producing "verified" consensus. Rules:

- no pin → `WRD-CONSENSUS-UNPINNED-TRUST`, exit 2, before any spawn or fetch;
- a corpus id you did not pin is **ignored with a warning** — its entries are never verified;
- a pinned id the corpus declares with a **different** identity/issuer → exit 2
  (someone is lying about who `alice` is; it does not matter which side);
- a duplicate id in either list → exit 2;
- `--min-attesters N` (default **2**): a clean match needs ≥ N trusted attesters
  agreeing, otherwise `WRD-CONSENSUS-INSUFFICIENT` (low, exit 0). One attester is an
  observation; it is not consensus.

| Consensus **does** establish | Consensus does **not** establish |
|---|---|
| N attesters *you trust* each captured a surface with this digest **for this coordinate** | that the server is safe, benign, correct, or free of prompt injection |
| your observation is (or is not) the same declared surface those attesters saw | anything about runtime behaviour (`T-BEHAVE` remains out of scope, see `THREAT_MODEL.md`) |
| the attesters disagree among themselves (`SPLIT`) — the corpus or the upstream is compromised | who is right in a split; a split is a stop signal, not an adjudication |

A poisoned server that is poisoned *identically for everyone* matches consensus. That
is the residual risk and it is deliberate: the corpus turns a targeted attack into a
loud one; it does not review content. Pair it with a static tool-poisoning scanner.

**Evidence suppression — what a corpus can hide.** The corpus can prove an entry is
genuine; it cannot prove an entry *does not exist*. If the directory for your
coordinate is absent the verdict is `WRD-CONSENSUS-NOVEL` (advisory, exit 0), and a
hostile or forked corpus can turn an exit-1 `MISMATCH` into that pass simply by
withholding the entries. There is no authenticated "no entry" proof in a git tree.
Two controls close the gap, and you should use both in CI:

- pin `--corpus-ref` to a commit you (or someone you trust) have audited, so the
  operator cannot swap the tree under you between runs;
- pass **`--require-consensus`** wherever the coordinate is *expected* to be
  attested — then `NOVEL` and `INSUFFICIENT` are `high` and **exit 1**, and a run
  that compared nothing can no longer be green.

**Network.** Verifying a Sigstore bundle initialises the production trust root
(`Verifier.production()`, TUF). That needs network on first use (cached afterwards);
an air-gapped runner gets `WRD-CONSENSUS-UNVERIFIABLE` (exit 2) on every run unless
sigstore's trust root is pre-seeded. The verifier is built once per run, not per entry.

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
any lock (`mcp_warden.lockfile.surface_digest`). The signature binds `overall_digest`
and the coordinate (§2); every corpus lock must also **reproduce its own
`overall_digest` from its entries** (`lock_is_self_consistent`), so a lock whose
entries were edited under an intact signature is rejected as `UNVERIFIABLE`. A lock
written at a different `schema_version` than this mcp-warden implements is
`WRD-CONSENSUS-SCHEMA-MISMATCH` (exit 2) — a format break, reported as one.

## 4. Corpus layout

```
attesters.json                                          discovery list (NOT the trust root)
locks/<ecosystem>/<segment>/<version>/<attester-id>.lock
locks/<ecosystem>/<segment>/<version>/<attester-id>.lock.sigstore
```

- `ecosystem` ∈ `npm` | `pypi`.
- `segment` is the package name with `/` replaced by `__`, so the scoped npm package
  `@example/clean` lives under `locks/npm/@example__clean/`. PyPI names are PEP 503
  normalised (`Mcp_Server.Foo` → `mcp-server-foo`).
  **This mapping is not injective**: an unscoped npm package literally named
  `@example__clean`, or a name differing only by case on a case-insensitive
  filesystem, maps to the *same* directory. That collision **fails closed** — the
  signed statement carries the exact coordinate, so an entry from the other package
  fails verification (`UNVERIFIABLE`) rather than being counted — but it means such a
  package cannot share a corpus with its twin. Percent-encoding the segment would
  lift the restriction if a real `__`-named package ever matters.
- `<attester-id>` is a `[A-Za-z0-9._-]{1,64}` id that **must** appear in
  `attesters.json` (an entry from an undeclared attester rejects the coordinate) and
  in your pin (otherwise it is ignored).
- `.lock.sigstore` is the Sigstore bundle `pin --sign --coordinate <c>` writes,
  signed over `build_statement(overall_digest, coordinate)` (the v2 statement).
  A lock signed **without** `--coordinate` (v1 statement, what `pin --sign` produces
  for your own repo) is *not* a valid corpus entry.
- Bounds: a lock ≤ 1 MiB, a sidecar ≤ 256 KiB, `attesters.json` ≤ 256 KiB, ≤ 64
  entries per coordinate. Every path is resolved and must stay inside the corpus root
  (a symlink pointing out is rejected).

`attesters.json` (also the schema for `--attesters-file`):

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

A version must be concrete (leading digit). Tags (`latest`), ranges (`^1`), bare
names, and any name or version containing whitespace or a control character cannot be
attested, so they fail closed instead of guessing — a trailing newline in an argv token
is `UNRESOLVED`, never a quiet `NOVEL`. The coordinate is resolved **before** the
server is spawned.

## 6. Verdicts and exit codes

| Rule | Severity | Meaning | Exit |
|---|---|---|---|
| *(match)* | — | ≥ `--min-attesters` trusted attesters saw your surface; one stderr line | 0 |
| `WRD-CONSENSUS-INSUFFICIENT` | low (high with `--require-consensus`) | fewer trusted attesters agree than `--min-attesters` | 0 — **1 with `--require-consensus`** |
| `WRD-CONSENSUS-NOVEL` | low (high with `--require-consensus`) | no trusted attestation exists for the coordinate | 0 — **1 with `--require-consensus`** |
| `WRD-CONSENSUS-MISMATCH` | high | your surface differs from **every** trusted attested digest | **1** |
| `WRD-CONSENSUS-SPLIT` | high | trusted attesters disagree among themselves — reported even if you match one | **1** |
| `WRD-CONSENSUS-UNPINNED-TRUST` | — | no consumer pin, duplicate id, or pin/corpus identity divergence | **2** |
| `WRD-CONSENSUS-UNRESOLVED` | — | launch cannot be turned into a pinned coordinate | **2** |
| `WRD-CONSENSUS-UNVERIFIABLE` | — | sigstore missing, undeclared attester, missing/corrupt/failing sidecar, relocated signature, inconsistent lock, size cap, path escape, malformed `attesters.json`, any unexpected error | **2** |
| `WRD-CONSENSUS-SCHEMA-MISMATCH` | — | corpus lock is at a different lock `schema_version` | **2** |
| `WRD-CONSENSUS-UNREACHABLE` | — | corpus path/URL unreachable or not allowed, clone/checkout failed, `--corpus-ref` missing or not `HEAD` | **2** |

Findings go through the same SARIF and `--json` JSONL emitters as static checks and
drift; the exit code composes with drift (`drift or MISMATCH or SPLIT → 1`, and with
`--require-consensus` also `NOVEL or INSUFFICIENT → 1`). With the
flag absent, `check` is byte-for-byte unchanged — and any community option given
*without* `--against-community` is exit 2, never a silent no-op.

## 7. Using it

```bash
# against a corpus checkout you already have, trusting two attesters
mcp-warden check npx -y @foo/server@1.2.3 --lock warden.lock \
    --against-community --corpus ../mcp-warden-locks \
    --attester alice=https://github.com/…/attest.yml@refs/heads/main@https://token.actions.githubusercontent.com \
    --attester bob=https://github.com/…/attest.yml@refs/heads/main@https://token.actions.githubusercontent.com

# against a git URL, pinned to an exact corpus commit, trust root from a file you keep;
# --require-consensus because CI expects this package to be attested (NOVEL would be a red flag)
mcp-warden check node ./build/index.js --lock warden.lock \
    --against-community --corpus https://github.com/<org>/mcp-warden-locks.git \
    --corpus-ref 0123456789abcdef0123456789abcdef01234567 \
    --coordinate npm:@foo/server@1.2.3 --attesters-file trusted-attesters.json \
    --require-consensus
```

`--attester` is `<id>=<certificate_identity>@<oidc_issuer>`; the identity itself
contains `@`, so the issuer is split at the last one. A URL must start with `https://`,
`ssh://` or `git@` — `ext::`, `file://`, `git://`, scp shorthand and anything starting
with `-` are refused before git runs. The clone is `git -c protocol.allow=never -c
protocol.https.allow=always -c protocol.ssh.allow=always -c core.hooksPath=/dev/null -c
core.symlinks=false -c submodule.recurse=false -c credential.helper= -c core.askPass=
clone --no-checkout -- <url>` (the last two disable any credential helper or askpass
program a `~/.gitconfig` would otherwise make git exec) with a
scrubbed environment (`PATH`, `HOME`, `SSH_AUTH_SOCK`, `GIT_TERMINAL_PROMPT=0`;
`GIT_SSH_COMMAND` is forwarded **only** to the clone of an `ssh://`/`git@` source,
never for https and never to checkout/rev-parse), into a temporary directory removed
afterwards; the checkout's `HEAD` must equal `--corpus-ref`. `git` is resolved to an
absolute path once per process and must be **≥ 2.14.1** (the release that refuses an
ssh host starting with `-`, which the option-injection defenses above rely on) —
older or missing git is `UNREACHABLE`. Requires `mcp-warden[sigstore]`.

### Producing a corpus entry

```bash
mcp-warden pin npx -y @foo/server@1.2.3 --lock alice.lock --sign \
    --coordinate npm:@foo/server@1.2.3
# verify your own entry locally with the same coordinate:
mcp-warden check --verify --lock alice.lock --coordinate npm:@foo/server@1.2.3 \
    --certificate-identity … --certificate-oidc-issuer …
```

## 8. Phase 2 — the live corpus

Live at <https://github.com/DataScience-EngineeringExperts/mcp-warden-locks>: a public
append-only repo (a required check rejects any modify/delete under `locks/`) fed by a
nightly attester that spawns each target package in a sandbox and lands
`pin --sign --coordinate` outputs containing only *new* paths. Its README carries the
current attester identity to pin and the consumer invocation.

**Sandbox contract an attester must meet** (so a malicious server cannot poison the
attester itself): ephemeral runner, non-root, network egress cut after package
install, no secrets in the environment beyond the OIDC token used to sign, one
package per job, the lock written only from the SDK handshake (`tools/list` /
`resources/list` / `prompts/list`) — never from tool results.

## 9. Test fixture

`tests/fixtures/corpus/` is a local corpus whose sidecars are **fakes**
(`{"over": <v2 statement>}`) accepted only by the monkeypatched boundary in
`tests/test_corpus.py`. Real Sigstore verification rejects them — which is itself
tested. It declares three attesters (`alice`, `bob`, `carol`); the tests pin only the
first two so the ignore-unpinned path is exercised. Regenerate with
`tests/fixtures/gen_corpus.py`.
