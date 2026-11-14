# Supplied-content normalization — DSE-718

This opt-in Linux feature gives all nine supplied-input families one bounded
normalization and recursive-extraction engine. It creates **untrusted evidence**;
the existing policy/enforcement boundary owns delivery authorization. It does
not fetch websites, connect to mailboxes/databases, confer trust, or establish
whole-ATK, fleet-wide or Streamable HTTP guard conformance.

## Architecture and activation

`normalization_ingress.normalize_supplied()` captures original bytes with
`create_ingress`, then `normalization.normalize_ingress()` invokes a separately
packaged parser image through `normalization_sandbox.run_worker()`. The trusted
coordinator validates the complete bounded response and creates a derived
envelope and digest-bound source map. Original byte hashes and parent taints are
preserved. Content and parser output never acquire authority.

The coordinator and worker require Python 3.12 / Unicode 15.0.0 on qualified
Linux amd64. The worker independently pins pypdf 7.1.0, markdown-it-py 4.3.0
and mdurl 0.1.2. Existing commands retain their earlier Python/platform support.
The [component](../components/normalizer/README.md) has an independent hash-locked
parser closure outside the base CLI dependencies. Build on a Linux executor:

```bash
docker build --iidfile /tmp/normalizer-image-id -f components/normalizer/Dockerfile .
```

Use the resulting **immutable `sha256:<64 hex>` local image ID**, never a tag.
Building/registering an image does not approve it: the caller must bind the
reviewed/qualified exact artifact in its approved configuration. The CLI does
not pull, sign, approve or register worker images automatically. On the shared
DSE builder, reserve and register produced artifacts using the installed
builder-artifact protocol before building; qualification consumers acquire
their independent claims. Do not prune another consumer's artifacts.

```bash
mcp-warden normalize supplied.pdf --media-type application/pdf \
  --source-kind document --normalizer-image sha256:<qualified-local-image-id>
mcp-warden guard --normalizer-image sha256:<qualified-local-image-id> -- python server.py
mcp-warden inspect trace.jsonl --normalizer-image sha256:<qualified-local-image-id>
```

`normalize` emits evidence hashes, precision/segment counts and redacted findings,
not extracted text. Exit 0 means the configured deterministic inspection found
no blocking finding, 1 means blocking findings, 2 means refusal/configuration
or input failure. It never returns permission to disclose or execute content.
The Python API additionally returns the in-memory segments and source-map bytes
for the caller's separately authorized use.

## Finite supported matrix

Every `IngressKindV1` enters through the same supplied-bytes adapter and preserves
its captured source kind and descriptive source claims:

| Input family | Exercised supplied-payload example |
|---|---|
| `tool_result` | MCP content-block JSON |
| `web` | HTML with hidden text/attributes/comments |
| `document` | Text-based PDF |
| `email` | RFC822/MIME with nested supported parts |
| `database_text` | CSV and JSON text |
| `mcp_prompt` | Prompt message/content JSON |
| `mcp_resource` | Resource text or supported supplied base64 blob |
| `bundle_metadata` | Plugin/bundle descriptive JSON; no executable approval |
| `agent_message` | Supplied role/content JSON |

Supported MIME types: `text/plain`, `application/json`, `application/xml`,
`text/xml`, `text/html`, `text/markdown`, `text/csv`, `message/rfc822`,
`application/zip`, and a **conservative text-PDF subset** of `application/pdf`.
This is universal across the declared input families, not arbitrary formats.
Office documents, OCR, unknown binaries, encrypted content and unsupported
compression/parsing profiles refuse. A Linux host without every qualified
sandbox control also refuses. macOS/Windows retain their existing commands but
cannot execute this worker profile.

The component contract specifies stricter PDF/ZIP/HTML support boundaries.
For example, PDF embedded fonts/object streams/active content/unsupported
filters and image-only pages refuse; ZIP extra fields/descriptors/directories
and unsupported members refuse; HTML requires balanced explicit non-void tags.
These conservative limitations can reject otherwise valid documents.

## Representations and provenance

The pinned inspection transform applies NFKC, then removes Unicode `Cf` and `Cc`
characters except TAB/LF/CR. It preserves original extracted text as `raw_text`.
Raw ANSI/control and secret checks run before delivery alongside the normalized
view. JSON keys, syntax, decoded values and supplied embedded payloads; HTML/XML
hidden text, attributes and decoded character data; MIME headers/bodies; ZIP
members; and PDF metadata/streams/page text remain represented. Dedicated
concatenated character-data views expose text split across markup/nodes.

Only an unchanged UTF-8 root plain-text segment receives exact byte attribution.
Other views carry explicitly conservative original-container byte ranges and
page/member/object/view locators. The coordinator maps every output span and
labels synthesized separators as having no source range. It never invents an
exact offset through decompression or PDF extraction.
Each real map entry also commits its raw extracted view's digest and records
whether normalization changed it; inspection revalidates the full evidence,
map/usage/profile and envelope bindings instead of trusting model construction.
Root UTF-8 syntax is independently bound to original bytes, JSON strings/keys
receive an independent bounded coverage check, and the coordinator refuses an
unqualified Unicode implementation rather than skipping the transform check.

`structurally-complete` means bounded structural coverage under this finite
profile, **not proof of semantic extraction completeness**. Digests and valid
range shapes cannot prove a parser omitted nothing. Reviewed parser code and
independent corpora provide assurance; parser omission/compromise remains a
residual. Known partial, empty/unexplained, ambiguous and malformed extraction
refuses. Worker output remains untrusted even after validation.

Retained encoded carriers may trigger conservative entropy findings. Warden
does not automatically exempt base64 from secret inspection. Existing reviewed
per-tool inspection precision remains applicable; a source cannot change it.
The fuzzy injection tier retains its existing opt-in blocking policy.

## Budgets and refusal

All nested members and alternate views share one root ledger:

| Limit | V1 ceiling |
|---|---:|
| Root input | 16 MiB |
| Expanded bytes | 64 MiB |
| Normalized UTF-8 output | 16 MiB |
| Recursion depth / parse nodes / members | 8 / 4,096 / 256 |
| Source-map spans / full segment-list bytes | 100,000 / 8 MiB |
| Consecutive combining characters | 64 |
| Versioned semantic work units | 100 million |
| IPC frame / aggregate message / depth / structural tokens | 64 KiB / 64 MiB / 32 / 200,000 |
| Worker memory / scratch / processes | 256 MiB / 16 MiB / 16 |
| Worker aggregate CPU / wall-clock deadline | 2 CPU seconds / 5 seconds |

Profiles can tighten semantic limits, never raise V1 ceilings. `depth` and
`combining_run` are high-water marks; other semantic counters are cumulative.
Repeated syntax/decoded views consume budgets, so map/output caps can be reached
before the root-size ceiling. Operational CPU/memory/time refusals are separate
from deterministic semantic counters; identical elapsed timing is not promised.

The Linux supervisor uses the fixed local Docker socket and immutable image,
no network/IPC sharing, no credentials or host-data mounts, UID/GID 10001,
read-only root, dropped capabilities, no-new-privileges, seccomp, bounded tmpfs,
memory/swap/PIDs, and parent-observed aggregate cgroup-v2 CPU. It verifies the
created container controls and boot assertions before running the parser.
Unrecognized cgroup layouts, missing controls, output overflow, worker death,
timeouts, malformed/trailing IPC or cleanup failure refuse. There is no local
in-process fallback. The trusted local daemon, host kernel and reviewed image
are assumptions; these controls are not a proof against every kernel escape.

## Live/offline enforcement and limits

With `--normalizer-image`, all complete server-to-client JSON-RPC frames are
inspected before legacy delivery handling, including errors, notifications,
tool results, resources and prompts. Unknown/binary blocks and reference-only
resources refuse rather than fetching or silently passing through. A blocked
response becomes a safe error; blocked notifications/malformed or over-cap
frames terminate the session with the existing strict-abort machinery. Results
are held atomically; worker or inspection failure cannot deliver a prefix.
The live adapter captures the exact JSON body bytes (transport headers excluded)
and rejects duplicate keys before any parsed-object reserialization can hide
them. Offline object traces cannot reconstruct original wire formatting or
escapes that were never recorded; their supplied frame objects are captured
using an explicit canonical serialization, without claiming original wire bytes.

Universal mode forces both strictness controls, rejects audit/deterministic
shadow flags and raw trace recording, and cannot use a legacy exception/pass
path as fallback. Removing the option returns to the explicitly narrower legacy
mode; the posture banner states whether normalization is enabled. Source-kind
adapters outside MCP are supplied-payload APIs, not live external connectors.
MCP HTTP runtime mediation, policy completeness, host-wide agent enforcement and
child-server stderr mediation are outside this feature's claim.

Offline universal inspection requires explicit `c2s`/`s2c` trace wrappers, at most
64 MiB total, 16 MiB per line and 4,096 records. It uses the same engine and
findings as the live wrapper. Legacy mode retains its established contracts.

## Qualification and rollback

After building the exact image and installing the separate parser test closure:

```bash
bash scripts/qualify_normalizer.sh sha256:<qualified-local-image-id>
pytest -q tests/fuzz/test_fuzz_normalization.py --hypothesis-seed=0
```

On the shared builder, the script requires `DSE_NORMALIZER_SESSION_ID` to hold
the current actual session ID and takes/releases only its own QA claim. The
dedicated Linux CI job exercises the actual sandbox, every input family,
recursive formats, negative vectors, sink refusal, repeatability and CLI
redaction. Parser-only tests or a skipped real-image suite are not qualification.

Rollback selects the previous qualified exact package/image or disables this
new integration. Disabled legacy mode must be reported as narrower coverage,
never as universal protection. Keep the previous scoped fallback until the
replacement succeeds in normal use. No new PyPI version or registry publication
is implied by a source merge or a successful image build.
