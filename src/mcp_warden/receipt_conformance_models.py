"""Closed inputs and reports for reference receipt conformance, without platform claims."""

import hashlib
from dataclasses import dataclass, fields
from typing import Literal

from pydantic import StrictBool, StrictInt, model_validator

from mcp_warden.decision_models import DecisionRequestV1
from mcp_warden.policy_decision import (
    ActivatedRuntimeV1,
    _has_activation_marker,
    _request_preflight,
)
from mcp_warden.policy_enforcement import EffectInputV1, create_effect_input
from mcp_warden.policy_enforcement_v2 import PolicyEnforcementPointV2
from mcp_warden.receipt_kernel import ReceiptError, ReceiptModel, canonical, exact

FAILURES = frozenset(
    {
        "CONF-CASE-MISMATCH",
        "CONF-CASE-ERROR",
        "CONF-SECRET-LEAK",
        "CONF-OPERATION-UNCOVERED",
        "CONF-INSTRUMENTATION",
    }
)
SCENARIOS = (
    "allow",
    "deny",
    "primary_failure",
    "dual_failure",
    "state_failure",
    "latched",
    "rollback",
    "restarted",
)


@dataclass(frozen=True, slots=True)
class ReceiptConformanceScenarioV1:
    pep: PolicyEnforcementPointV2
    request: DecisionRequestV1
    runtime: ActivatedRuntimeV1
    effect: EffectInputV1

    def __post_init__(self):
        valid = False
        try:
            valid = (
                type(self.pep) is PolicyEnforcementPointV2
                and type(self.request) is DecisionRequestV1
                and _request_preflight(self.request)
                and _has_activation_marker(self.runtime, ActivatedRuntimeV1)
                and type(self.effect) is EffectInputV1
                and create_effect_input(self.effect.arguments) == self.effect
                and self.effect.arguments_digest == self.request.operation.arguments_digest
            )
        except Exception:
            pass
        if not valid:
            raise ReceiptError("RCT-MALFORMED")


@dataclass(frozen=True, slots=True)
class ReceiptConformanceVectorV1:
    """All eight independently configured scenarios are mandatory for each operation."""

    allow: ReceiptConformanceScenarioV1
    deny: ReceiptConformanceScenarioV1
    primary_failure: ReceiptConformanceScenarioV1
    dual_failure: ReceiptConformanceScenarioV1
    state_failure: ReceiptConformanceScenarioV1
    latched: ReceiptConformanceScenarioV1
    rollback: ReceiptConformanceScenarioV1
    restarted: ReceiptConformanceScenarioV1

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not ReceiptConformanceScenarioV1:
                raise ReceiptError("RCT-MALFORMED")
            value.__post_init__()
            if (
                value.pep.manifest_digest != self.allow.pep.manifest_digest
                or value.pep.registration_operations != self.allow.pep.registration_operations
                or value.request.operation.operation_id != self.allow.request.operation.operation_id
                or value.request.operation.capability != self.allow.request.operation.capability
            ):
                raise ReceiptError("RCT-MALFORMED")


class ReceiptConformanceReportV1(ReceiptModel):
    schema_version: Literal[1] = 1
    corpus_version: Literal["dse717-reference-v1"] = "dse717-reference-v1"
    platform_status: Literal["unsupported"] = "unsupported"
    atk_conformant: StrictBool = False
    manifest_digest: str
    total_cases: StrictInt
    fixed_cases: StrictInt
    instrumented_cases: StrictInt
    registration_operations: tuple[str, ...]
    covered_operations: tuple[str, ...]
    passed: StrictBool
    failures: tuple[str, ...]
    report_digest: str

    @model_validator(mode="after")
    def _report(self):
        if (
            self.atk_conformant is not False
            or not 13 <= self.total_cases <= 832
            or self.fixed_cases * 13 != self.total_cases * 5
            or not 0 <= self.instrumented_cases <= self.total_cases
            or self.failures != tuple(sorted(set(self.failures)))
            or any(f not in FAILURES for f in self.failures)
            or self.passed != (not self.failures)
            or not self.registration_operations
            or len(self.registration_operations) > 64
            or self.registration_operations != tuple(sorted(set(self.registration_operations)))
            or self.covered_operations != tuple(sorted(set(self.covered_operations)))
            or not set(self.covered_operations) <= set(self.registration_operations)
            or any(
                type(op) is not str or not 0 < len(op) <= 128 for op in self.registration_operations
            )
            or (
                self.passed
                and (
                    self.instrumented_cases != self.total_cases
                    or self.covered_operations != self.registration_operations
                )
            )
        ):
            raise ValueError("invalid conformance report")
        return self


def report_digest(body):
    return (
        "sha256:"
        + hashlib.sha256(b"mcp-warden/dse717-conformance/v1\x00" + canonical(body)).hexdigest()
    )


def serialize_receipt_conformance_report(report):
    exact(report, ReceiptConformanceReportV1)
    body = report.model_dump(mode="json", exclude={"report_digest"})
    if report_digest(body) != report.report_digest:
        raise ReceiptError("RCT-INTEGRITY")
    return canonical(body | {"report_digest": report.report_digest})
