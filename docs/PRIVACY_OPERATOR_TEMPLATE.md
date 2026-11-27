# Privacy control record for a Warden installation

Complete one record for each deployment and processing purpose. Store the record locally with the approved change evidence. Counsel and the deployment owner determine applicable jurisdictions, covered data, duties and deadlines.

| Record field | Operator entry or default |
|---|---|
| Deployment, build and purpose | Record the release digest, owner, permitted operation and approved data categories. Record a separate purpose before enabling a new use. |
| Inputs and outputs | Classify each input, permitted result, retention location and recipient. Process supplied content locally. Disable optional trace capture and external forwarding until the operator documents a purpose, audience and expiry. |
| Minimization | Export the control ID, build digest, test result, scope and observation date. Review exported fields for linkability. Retain raw content only under a separately approved local evidence policy. |
| Sensitive data | Identify applicable sensitive categories and any consent requirements before enabling the proposed workload. Record classifier limitations and the owner of manual review. |
| Deletion and retention | Record the configured store, retention period, backup expiry, legal-hold owner and deletion-verification method. Open a tracked request for each approved deletion. Verify downstream copies and record exceptions. |
| Vendor access | Identify each processor, contracted purpose, approved region, support role and allowed metadata. Record the revocation procedure and latest access review. |
| Rights requests | Identify intake and identity-verification owners, systems searched, due date, response owner and any exception decision. Keep verification material out of ordinary audit exports. |
| Evidence and signoff | Attach the [versioned control evidence table](PRIVACY_EVIDENCE.md) and the deployment's test run; record the operator and review date. Identify every control whose production enforcement remains unverified. |

## Local evidence custody record

Complete this section when local evidence capture is enabled. Keep the completed record in the deployment's access-controlled store.

| Field | Record |
|---|---|
| Custody | Owner of the local key service, service account, protected storage location, key recovery owner and most recent recovery exercise. |
| Access | Approved operator accounts, roles, purposes and evidence categories. Record who approves human review, when access expires and who can revoke it. |
| Capture and disclosure | Data categories selected for capture, reason for retaining them, permitted local output destinations and controls on copies made by reviewers. |
| Retention and holds | Retention periods by category, hold authority, release procedure, deletion evidence, backup schedule and backup expiry owner. |
| Verification | Deployment version, dates and verdicts for offline authorized read, denied read, service outage, hold and expiry exercises with synthetic data. |

## Source mapping

For covered Colorado controllers, the Colorado Attorney General describes purpose specification, minimization, secondary-use limits, security, rights handling, and assessments. These topics correspond to the purpose, inputs, minimization, sensitive-data and rights-request entries above. [Colorado Attorney General](https://coag.gov/resources/colorado-privacy-act/)

The California Attorney General describes consumer deletion requests, verification, service-provider handling and exceptions. The retention and rights-request entries identify the owner and evidence needed to assess a particular request. [California Attorney General](https://www.oag.ca.gov/privacy/ccpa)

## Export fields

Use a local record with the fields below for each tested control. The evidence reference should resolve to an access-controlled artifact; review the reference itself for identifying content. This record alone cannot establish a deployed control's effectiveness.

```json
{
  "control_id": "local-minimization",
  "deployment_profile": "local",
  "release_commit": null,
  "observed_at_utc": null,
  "test_reference": null,
  "result": "unverified",
  "gap_owner": "deployment operator"
}
```
