"""Fixed PEP V2 failure corpus with actual evidence scanning and ordered mediation.

Trusted test deployments supply isolated providers for each mandatory scenario.
Passing this reference corpus never establishes independent rollback protection.
"""

from mcp_warden.enforcement_result_v2 import EnforcementResultV2, serialize_enforcement_result_v2
from mcp_warden.policy_enforcement import EnforcementTraceV1, create_effect_input
from mcp_warden.receipt_conformance_models import (
    SCENARIOS,
    ReceiptConformanceReportV1,
    ReceiptConformanceScenarioV1,
    ReceiptConformanceVectorV1,
    report_digest,
    serialize_receipt_conformance_report,
)
from mcp_warden.receipt_kernel import (
    ZERO_DIGEST,
    ReceiptError,
    canonical,
    parse_canonical,
    receipt_digest,
)
from mcp_warden.receipt_log import FilePrimaryReceiptStoreV1
from mcp_warden.receipt_projection import agent_projection, human_projection
from mcp_warden.receipt_verification import parse_signed_receipt, verify_signed_receipt

# Re-export the complete public harness contract.
__all__ = [
    "ReceiptConformanceScenarioV1",
    "ReceiptConformanceVectorV1",
    "run_receipt_conformance",
    "serialize_receipt_conformance_report",
]
FIXED_SECRET = b"PLANTED-FIXED-RECEIPT-SECRET"


def _fixed(seed):
    class Hostile:
        def __eq__(self, other):
            raise ValueError(FIXED_SECRET.decode())

    op = seed.request.operation.model_copy(update={"arguments_digest": Hostile()})
    substitute = create_effect_input(b'{"fixed_receipt_substitution":1}')
    if substitute.arguments_digest == seed.effect.arguments_digest:
        substitute = create_effect_input(b'{"fixed_receipt_substitution":2}')
    return (
        (object(), seed.runtime, seed.effect),
        (seed.request, object(), seed.effect),
        (seed.request, seed.runtime, object()),
        (seed.request.model_copy(update={"operation": op}), seed.runtime, seed.effect),
        (seed.request, seed.runtime, substitute),
    )


def _matches(name, result, scenario):
    e, d = result.evidence, result.decision
    if name in {"allow", "restarted"}:
        return (
            result.invoked
            and result.code == "PEP-EXECUTED"
            and e.mode == "primary-durable"
            and e.recovery_mode == "healthy"
            and (
                name != "restarted"
                or (
                    e.sequence >= 2
                    and type(scenario.pep._coordinator.primary) is FilePrimaryReceiptStoreV1
                )
            )
        )
    if result.invoked or d.effective_verdict == "allow":
        return False
    if name == "deny":
        return d.converted_from_decision_digest is None and e.mode == "primary-durable"
    if name == "primary_failure":
        return d.converted_from_decision_digest is not None and e.mode == "fallback-durable"
    if name == "dual_failure":
        return (
            d.converted_from_decision_digest is not None
            and e.mode in {"unavailable", "recovery-latched"}
            and e.recovery_mode == "recovery-latched"
        )
    if name == "state_failure":
        return d.converted_from_decision_digest is not None and e.recovery_mode != "healthy"
    if name in {"latched", "rollback"}:
        return d.recovery_code == "recovery-only" and e.recovery_mode != "healthy"
    return True


def _trace_valid(result, trace):
    if (
        type(trace) is not EnforcementTraceV1
        or type(trace.events) is not tuple
        or not trace.events
        or type(trace.output_channels) is not tuple
        or not trace.output_channels
        or len(trace.events) > 16
        or len(trace.output_channels) > 16
        or any(type(c) is not bytes or len(c) > 256 * 1024 for c in trace.output_channels)
        or any(
            type(e) is not str
            or e not in {"decision", "evidence", "sink", "output", "result:" + result.code}
            for e in trace.events
        )
    ):
        return False
    events = trace.events
    if (
        "decision" not in events
        or "evidence" not in events
        or events[-1] != "result:" + result.code
    ):
        return False
    if events.index("decision") >= events.index("evidence"):
        return False
    count = 2 if result.decision.converted_from_decision_digest is not None else 1
    if events.count("decision") != count or events.count("evidence") != count:
        return False
    if count == 2 and events[:4] != ("decision", "evidence", "decision", "evidence"):
        return False
    if result.invoked:
        if events.count("sink") != 1 or events.index("evidence") >= events.index("sink"):
            return False
        if result.code == "PEP-EXECUTED":
            return events.count("output") == 1 and events.index("sink") < events.index("output")
    return "sink" not in events and "output" not in events if not result.invoked else True


def _evidence_channels(result, trace, scenario):
    """Return additional safe projections; require the actual result-bound artifact."""
    e = result.evidence
    if e.mode not in {"primary-durable", "fallback-durable"}:
        return ()
    coordinator = scenario.pep._coordinator
    for payload in trace.output_channels:
        try:
            if e.mode == "primary-durable":
                record = parse_signed_receipt(payload)
                if (
                    record.receipt_digest != e.evidence_digest
                    or record.receipt.decision_digest != e.decision_digest
                ):
                    continue
                verify_signed_receipt(
                    record,
                    authorization=coordinator.authorization,
                    verifier=coordinator.verifier,
                    snapshot=coordinator.protected_state.read(),
                )
                return (
                    canonical(agent_projection(record)),
                    canonical(human_projection(record, evidence=e, verification_status="verified")),
                )
            from mcp_warden.evidence_models import FallbackEventV1

            event = FallbackEventV1.model_validate(parse_canonical(payload), strict=True)
            if (
                receipt_digest(canonical(event), "fallback") == e.evidence_digest
                and event.sequence == e.sequence
            ):
                return ()
        except Exception:
            continue
    raise ReceiptError("RCT-INTEGRITY")


def run_receipt_conformance(vectors, *, planted_secrets=()):
    if (
        type(vectors) is not tuple
        or not 1 <= len(vectors) <= 64
        or any(type(v) is not ReceiptConformanceVectorV1 for v in vectors)
        or type(planted_secrets) is not tuple
        or len(planted_secrets) > 64
        or any(type(s) is not bytes or not 0 < len(s) <= 4096 for s in planted_secrets)
    ):
        raise ReceiptError("RCT-MALFORMED")
    for vector in vectors:
        vector.__post_init__()
        if vector.allow.pep.manifest_digest != vectors[0].allow.pep.manifest_digest:
            raise ReceiptError("RCT-MALFORMED")
    failures, covered = set(), set()
    instrumented = 0
    for vector in vectors:
        cases = [(name, getattr(vector, name), None) for name in SCENARIOS]
        cases.extend(("fixed", vector.allow, inputs) for inputs in _fixed(vector.allow))
        for name, scenario, inputs in cases:
            request, runtime, effect = inputs or (
                scenario.request,
                scenario.runtime,
                scenario.effect,
            )
            try:
                result, trace = scenario.pep._execute_instrumented(
                    request, runtime=runtime, effect=effect
                )
                if type(result) is not EnforcementResultV2:
                    raise ReceiptError("RCT-MALFORMED")
                serialized = serialize_enforcement_result_v2(result)
                if not _matches(name, result, scenario) or (name == "fixed" and result.invoked):
                    failures.add("CONF-CASE-MISMATCH")
                if not _trace_valid(result, trace):
                    failures.add("CONF-INSTRUMENTATION")
                else:
                    instrumented += 1
                try:
                    projections = _evidence_channels(result, trace, scenario)
                except Exception:
                    failures.add("CONF-INSTRUMENTATION")
                    projections = ()
                channels = (serialized, *trace.output_channels, *projections)
                if any(s in c for s in (*planted_secrets, FIXED_SECRET) for c in channels):
                    failures.add("CONF-SECRET-LEAK")
                if name == "allow" and result.invoked:
                    covered.add(scenario.request.operation.operation_id)
            except Exception:
                failures.add("CONF-CASE-ERROR")
    registrations = tuple(sorted(vectors[0].allow.pep.registration_operations))
    if covered != set(registrations):
        failures.add("CONF-OPERATION-UNCOVERED")
    report = ReceiptConformanceReportV1(
        manifest_digest=vectors[0].allow.pep.manifest_digest,
        total_cases=len(vectors) * 13,
        fixed_cases=len(vectors) * 5,
        instrumented_cases=instrumented,
        registration_operations=registrations,
        covered_operations=tuple(sorted(covered)),
        passed=not failures,
        failures=tuple(sorted(failures)),
        report_digest=ZERO_DIGEST,
    )
    return report.model_copy(
        update={
            "report_digest": report_digest(
                report.model_dump(mode="json", exclude={"report_digest"})
            )
        }
    )
