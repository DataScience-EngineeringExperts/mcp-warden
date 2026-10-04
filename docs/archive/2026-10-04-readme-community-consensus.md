# Community consensus — `check --against-community` (phase 1)

A single lock is trust-on-first-use: it cannot tell you the surface was poisoned on
day one, or that you are being served a surface nobody else
sees. `--against-community` compares what you just captured with what independent
attesters **you pin** Sigstore-signed for the same package version:

```bash
mcp-warden check npx -y @foo/server@1.2.3 --lock warden.lock \
    --against-community --corpus https://github.com/<org>/mcp-warden-locks.git \
    --corpus-ref <40-hex corpus commit> --attesters-file trusted-attesters.json
#  -> WRD-CONSENSUS-MISMATCH:     observed surface differs from every attested digest … (exit 1)
#  -> WRD-CONSENSUS-SPLIT:        attesters disagree — corpus or upstream may be compromised (exit 1)
#  -> WRD-CONSENSUS-NOVEL:        no trusted attestation exists yet (exit 0)
#  -> WRD-CONSENSUS-INSUFFICIENT: fewer than --min-attesters (default 2) agree (exit 0)
#  add --require-consensus in CI that EXPECTS the package to be attested: NOVEL and
#  INSUFFICIENT then exit 1 — a corpus that withholds an entry cannot turn a MISMATCH into a pass
```

The trust root is yours: the corpus's `attesters.json` is only a discovery list, and
without `--attester`/`--attesters-file` the command exits 2. Each signature binds the
attester identity, the lock digest **and** the package coordinate, so a genuine
signature cannot be relocated under another package. Everything that cannot be
established — an unpinned launch, an unpinned trust root, an undeclared attester, a
missing or failing signature, an unreachable or disallowed corpus URL — is exit 2.
**Consensus attests observation, not safety**; the CLI says so on every verdict. The
default `check` path is unchanged when the flag is absent.

Contract, trust model, layout, and the pending phase-2 live corpus:
[Community corpus contract](../COMMUNITY_CORPUS.md).
