# US privacy control evidence

Use the [deployment record](PRIVACY_OPERATOR_TEMPLATE.md) to document one approved processing purpose, its data flows and its accountable operator. Begin with local processing, raw recording disabled and no forwarding. The operator and counsel determine applicability, deadlines and exceptions. Passing a fixture establishes the behavior of the tested source version. Production controls, organizational policy and legal compliance require separate evidence.

| Control | Product behavior and source | Evidence and deployment responsibility |
|---|---|---|
| Purpose limitation | The [policy decision SDK](../src/mcp_warden/policy_decision.py) binds a request to an exact scope, purpose and envelope. | The purpose fixture changes each binding. The host assigns the purpose and must enforce the decision before the effect. |
| Data minimization | The [result emitters](../src/mcp_warden/emit_res.py) support a bounded injection phrase projection. Universal normalization covers supplied server-to-client stdio frames when the operator enables a qualified immutable worker via --normalizer-image. | The fixture tests injection telemetry only. It plants content and checks its absence. Inventory all enabled outputs. Legacy recording captures raw frames, and locks may include arguments. |
| Sensitive data | [Result inspection](../src/mcp_warden/result_inspection.py) detects recognized credential echoes and supports redaction. | The synthetic secret fixture checks detection and redaction. The operator must classify sensitive categories that credential matching cannot recognize. |
| Retention | The [receipt store](../src/mcp_warden/receipt_log.py) supports chain verification across reopen and detects truncation against a protected floor. | A verified chain supports review of storage actions. The storage owner documents retention periods, expiry, backup rotation and legal holds and exercises them on synthetic records. |
| Deletion requests | [Offline replay](DECISION_RECEIPTS.md) supports review of separately collected evidence. The operator controls the inventory and local destinations. | Exercise a synthetic request across primary stores, backups and vendors. Record verification, lawful exceptions, dates, responsible parties and completion. Worker cleanup alone cannot establish subject erasure. |
| Vendor oversight | The [guard](../src/mcp_warden/guard_result.py) can compare the server surface to a reviewed lock. | The live stdio fixture changes server metadata and verifies blocking. Maintain approved providers, data categories, destinations, contract terms and renewal dates outside Warden. |
| Audit evidence | The [receipt projection contract](DECISION_RECEIPTS.md) limits agent and reviewer output to defined fields. | The projection fixture checks for private details and signature material. Restrict access to source evidence and review linkability before release. |

## Export a local fixture report

From a clean source checkout with the project's test dependencies installed, run the following command. The script runs a fixed set of synthetic tests. It writes only the source revision, UTC time, scope and control verdicts to standard output. Keep the resulting file in an approved local evidence store. Retention and subject erasure remain operator checks in every export.

```sh
python scripts/privacy_evidence.py > /path/to/local/evidence.json
```

Exit zero means every selected fixture ran and passed. A missing dependency, failed or skipped test, or incomplete report yields a nonzero exit. Review failures by running the named source test locally. Production reports, raw requests and customer data are unnecessary for this check.

The [Colorado Attorney General](https://coag.gov/resources/colorado-privacy-act/) describes controller and processor responsibilities, sensitive-data consent and individual rights. The [California Attorney General](https://oag.ca.gov/privacy/ccpa) describes deletion and correction, covered businesses, exceptions and limits on use of sensitive information. The template records the evidence and decisions a deployment owner needs to assess those themes.
