# Local encrypted evidence

Enable evidence capture on a Linux stdio guard when the organization has approved retaining MCP tool arguments and results locally. Capture is opt-in. Warden stores the argument map and the result field as separate encrypted JSON objects. Protocol envelopes, tool names, RPC IDs and unrelated messages are excluded from the vault. The guard waits for the encrypted object, its signed audit record and the protected local checkpoint to commit before forwarding a covered request or result. A failure terminates the protected session. Warden preserves the existing receipt projection APIs.

## Custodian setup

Install the optional dependency with `pip install 'mcp-warden-cli[local-evidence]'`. Provision a dedicated non-root Linux account for the daemon and different non-root accounts for the recorder, approved reviewers and authorized retention operators. Record the daemon UID through the customer’s authenticated account provisioning process. The service uses Unix peer credentials to check each caller. The caller checks the daemon UID before sending evidence. Use Unix accounts with customer-managed authentication and move only approved roles into the socket group.

Use absolute paths on a dedicated local filesystem. Create owner-only mode `0700` directories for the vault and the customer’s service configuration. Create a daemon-owned mode `02750` socket directory with the shared runtime group. Parents must be trusted by the daemon and paths must have no symlink components. Use a mode `0400` or `0600` regular file for each daemon configuration document, owned by the daemon and with one filesystem link.

Provision a keyring with at least one independently generated AES-256 key in lowercase hexadecimal, using shape `{"version":1,"active":"key-1","keys":{"key-1":"<64 lowercase hex characters>"}}`. Retain historical keys required by captured objects and approved backup recovery. Rotation selects a new active key on restart. Retire historical keys only after their disposition and backup dependencies have been reconciled. The daemon holds keys in memory and uses the host wall clock for expiry. The vault refuses backward clock movement relative to the verified audit head. Use a customer-controlled clock configuration and monitor it for unauthorized jumps.

The grant manifest is `{"version":1,"grants":[...]}`. Each grant has the exact fields `uid`, `tenant`, `category`, `action`, `role` and `purpose`. Duplicate grants are refused. Provision capture grants for both `tool-arguments` and `tool-result` with role `recorder` and purpose `evidence-capture`. The reviewer role accepts individually granted `audit`, `read`, `export` and `summary` actions. The custodian role accepts `hold`, `release` and `delete`. Use bounded purpose labels that identify approved workflows without including sensitive information. Grant, revocation and keyring changes take effect on service restart.

Run the following as the daemon account. Use the same initialized vault for subsequent starts.

```sh
mcp-warden evidence init --store /var/lib/warden-evidence/vault
mcp-warden evidence serve --store /var/lib/warden-evidence/vault \
  --socket /run/warden-evidence/vault.sock \
  --policy /etc/warden-evidence/policy.json --keyring /etc/warden-evidence/keyring.json \
  --retention-seconds 2592000
```

The command handles SIGTERM and SIGINT for graceful socket cleanup. After an unclean exit, verify that the previous process is gone and the socket inode belongs to the daemon before removing a stale socket. The vault verifies its audit chain, state and filesystem ownership on restart. A stale database restore fails against a newer finalized checkpoint. Preserve the checkpoint independently from ordinary database backups, and give restoration operators an authenticated reference for it. The model trusts the daemon, its host and backup administrators, and the custodian-managed filesystem. Coordinated rollback of the database and checkpoint by that trusted boundary requires separate customer controls.

As the recorder, start the appropriately configured MCP launch command. In this example, `1234` is the enrolled daemon UID.

```sh
mcp-warden guard --evidence-socket /run/warden-evidence/vault.sock \
  --evidence-service-uid 1234 --evidence-tenant customer-a -- python ./server.py
```

The protected profile refuses Streamable HTTP, plaintext trace recording, JSON and SARIF findings reports, and the universal normalization profile. It suppresses tool stderr and the usual detailed diagnostic output. The configured stdio peers still exchange ordinary protocol input and allowed output. The customer controls those applications, their network access, crash dumps, swap and any independent logging. Restrict guard deployment flags and the recorder and reviewer accounts to supervised workflows. A process sharing the recorder UID, including the tool child, can submit a capture. Signed audit establishes the local peer account and action. Confirm human presence and tool execution provenance through separate controls when required.

## Review, hold and disposition

As an authorized account, use `mcp-warden evidence act` with the exact action, socket, enrolled service UID, tenant, category and purpose. For example, review local metadata by category.

```sh
mcp-warden evidence act audit --socket /run/warden-evidence/vault.sock \
  --service-uid 1234 --tenant customer-a --category tool-result --purpose incident-review
```

The result contains up to 100 signed events and a verification key. Use the last sequence number as `--after` for another page. Local audit includes object IDs, Unix identities, operator purpose labels and exact timestamps. Keep it in the approved local boundary. Sequence gaps can reflect activity elsewhere in the same vault. Use separate vaults where that metadata must be isolated.

Use `--object-id` for `read`, `export`, `hold`, `release` and `delete`. Read displays raw JSON to a terminal after the service commits the access record. Export additionally requires `--output` with a new absolute file path in a private reviewer directory. Keep export destinations on approved local storage outside synchronization and network mounts. The audited export event records release to the authenticated reviewer. Track destination copies and any later human-authorized handling separately.

Expiry is fixed at capture according to the configured interval. Expired objects are unavailable for ordinary review unless preserved by legal hold. Holds take effect when committed. The daemon serializes holds, release and deletion with the audit update. Use the authorized delete action after expiry and after holds are released. The result records deletion from the primary vault. Apply the deployer’s retention and hold schedule to database backups, offline copies, exports, replicas and filesystem snapshots. A primary delete does not certify physical erasure or backup disposition. Keep the audit signing key and the encryption keyring out of routine database backups, and keep authorized key recovery copies separately.

## Verify a minimized summary

An explicitly granted `summary` action returns a signed closed projection using record counts grouped as 0, 1–9, 10–99 and 100+. Counts cover capture, raw review or export, and primary deletion for the selected local scope. The artifact contains the schema version, the three count bands and an Ed25519 signature. It carries no tenant, tool, UID, object identifier, timestamp, raw digest or verification key. The command writes locally and the component has no network sender.

The custodian obtains the public key using `mcp-warden evidence public-key --store /var/lib/warden-evidence/vault`. Enroll that key through an authenticated independent channel. Reviewers can then verify an artifact offline.

```sh
mcp-warden evidence verify-summary --artifact /approved/local/summary.json \
  --verification-key '<enrolled Ed25519 public key in hexadecimal>'
```

The signature verifies the anonymous count bands under the enrolled key. Establish tenant, category, publication authorization and freshness through the customer’s separate exchange record before accepting an artifact for a specific reporting scope.

## Contain a Linux stdio session

Add `--contain-incidents` to the evidence-enabled guard invocation for a customer-supervised text-only MCP tool. Grant the recorder an additional `incident` action for `tool-result` with role `recorder` and purpose `evidence-capture`. A distinct reviewer account can receive `incident-summary` for `tool-result` with an approved reporting purpose. The custodian daemon refuses an incident grant without a corresponding result-capture grant. For tenants with incident grants, it also refuses reviewer grants for recorder UIDs.

```sh
mcp-warden guard --contain-incidents \
  --evidence-socket /run/warden-evidence/vault.sock \
  --evidence-service-uid 1234 --evidence-tenant customer-a -- python ./server.py
```

For covered `tools/call` responses, the guard accepts a `content` list of text-only blocks and an optional boolean `isError`. Detection uses strict charset and secret-echo defaults plus the existing offline domain and IP literal rules. DNS hostname queries are disabled in this profile. Deterministic findings in scope always withhold the entire result and end the session. The guard refuses audit-only, category demotions and secret redaction options. Fuzzy phrase matches stay monitor-only unless the operator enables `--block-inject-phrase` or `--block-inject-phrase-only`. RPC errors, unsupported tool result shapes and unsolicited server messages cause a generic fail-closed exit. Other request and response methods retain their existing inspection scope, including the separate lock-based tools/list gate.

The vault stores the decoded blocked result and the private finding codes as one encrypted object, subject to its 1 MiB serialized payload limit, with its signed `incident` audit event in the same database commit. The guard stops forwarding in both directions, attempts bounded termination of the owned child process group, and returns the same generic exit code 3 and JSON-RPC error for a covered block or an unavailable vault. A disconnected or stalled client may only observe that the relay closed. To confirm durable capture, inspect the local audit. Storage failure before commit can leave no incident event.

A reviewer can locate the exact local object in the `tool-result` audit and inspect it with a separately granted `read` or `export`. Use the existing hold and retention procedures for the incident object. Request the minimized report separately.

```sh
mcp-warden evidence act incident-summary --socket /run/warden-evidence/vault.sock \
  --service-uid 1234 --tenant customer-a --category tool-result \
  --purpose approved-report --object-id "$INCIDENT_OBJECT_ID" > incident-summary.json

mcp-warden evidence verify-summary --incident --artifact incident-summary.json \
  --verification-key "$ENROLLED_VAULT_PUBLIC_KEY"
```

The signed report contains the schema version, `reported-withheld` disposition and an opaque identifier stable for that incident. The signature attests that the vault recorded a withholding report from an authorized recorder account. It contains no raw evidence, rule details, local object ID, tenant or timestamp. The opaque identifier permits deduplication and links repeat exports of the same report. The historical report remains available from audit after raw evidence disposition. Use the customer's separate exchange record to establish source, intended audience and freshness.

Containment applies to this relay session. Independent sessions retain their ordinary admission path. The customer owns the recorder account, tool process supervision and prevention of direct access. The child shares the recorder UID and can exercise that UID's grants. Prior effects and processes outside the owned process group are outside this profile. Verified live bundle identity, persistent quarantine, capability lease revocation and governed bundle recovery remain open.

## Qualification

Run `python -m pytest tests/test_local_evidence_vault.py tests/test_evidence_key_service.py` on Linux. The cross-UID fixture uses only synthetic data through the real CLI and Unix socket. Run it on an isolated sudo-enabled Linux test host, with test dependencies installed and the checkout accessible to the fixture’s temporary numeric accounts.

```sh
sudo -n env WARDEN_EVIDENCE_CROSS_UID=1 PYTHONPATH=src \
  /absolute/path/to/venv/bin/python -m pytest tests/test_local_evidence_system.py
```

Record customer-specific qualification with the [deployment record](PRIVACY_OPERATOR_TEMPLATE.md).
