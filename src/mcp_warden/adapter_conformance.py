"""Deterministic adapter conformance harness for instrumented PEP tests."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import rfc8785
from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    StrictInt,
    ValidationError,
    field_validator,
    model_validator,
)

from mcp_warden.decision_models import (
    DIGEST_RE,
    CapabilityV1,
    DecisionDigestDomain,
    DecisionRequestV1,
    OperationBindingV1,
    digest_decision_bytes,
)
from mcp_warden.policy_decision import ActivatedRuntimeV1
from mcp_warden.policy_enforcement import (
    EffectInputV1,
    EnforcementCodeV1,
    EnforcementResultV1,
    PolicyEnforcementPointV1,
    create_effect_input,
)

CASE_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
MAX_CONFORMANCE_CASES = 2_048
MAX_PLANTED_SECRETS = 64
MAX_PLANTED_SECRET_BYTES = 4_096
MAX_REPORT_BYTES = 64 * 1024
FOUNDATION_CORPUS_VERSION = "dse716-foundation-v1"


class ConformanceError(Exception):
    """Stable code-only conformance failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code

    def __repr__(self) -> str:
        return self.code


class ConformanceFailureV1(StrEnum):
    CASE_MISMATCH = "CONF-CASE-MISMATCH"
    CASE_ERROR = "CONF-CASE-ERROR"
    SECRET_LEAK = "CONF-SECRET-LEAK"
    OPERATION_UNCOVERED = "CONF-OPERATION-UNCOVERED"
    NEGATIVE_CASE_MISSING = "CONF-NEGATIVE-CASE-MISSING"
    INSTRUMENTATION = "CONF-INSTRUMENTATION"


@dataclass(frozen=True, slots=True)
class AdapterConformanceCaseV1:
    name: str
    request: object
    runtime: object
    effect: object
    expected_code: EnforcementCodeV1
    expected_invoked: bool
    planted_secrets: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or CASE_NAME_RE.fullmatch(self.name) is None
            or type(self.expected_code) is not EnforcementCodeV1
            or type(self.expected_invoked) is not bool
            or type(self.planted_secrets) is not tuple
            or len(self.planted_secrets) > MAX_PLANTED_SECRETS
        ):
            raise ConformanceError("CONF-CASE-MALFORMED") from None
        if any(
            type(secret) is not bytes or not secret or len(secret) > MAX_PLANTED_SECRET_BYTES
            for secret in self.planted_secrets
        ):
            raise ConformanceError("CONF-CASE-MALFORMED") from None


def _digest(value: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise ValueError("invalid digest")
    return value


class ConformanceReportV1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    schema_version: StrictInt
    corpus_version: str
    manifest_digest: str
    total_cases: StrictInt
    caller_cases: StrictInt
    fixed_cases: StrictInt
    instrumented_cases: StrictInt
    registration_operations: tuple[str, ...]
    passed: StrictBool
    covered_operations: tuple[str, ...]
    failures: tuple[str, ...]
    report_digest: str

    _manifest = field_validator("manifest_digest")(_digest)
    _report = field_validator("report_digest")(_digest)

    @field_validator("corpus_version")
    @classmethod
    def _corpus(cls, value: str) -> str:
        if value != FOUNDATION_CORPUS_VERSION:
            raise ValueError("unknown corpus")
        return value

    def __init__(self, **data: Any) -> None:
        invalid = False
        try:
            super().__init__(**data)
        except ValidationError:
            invalid = True
        if invalid:
            raise ConformanceError("CONF-REPORT-MALFORMED") from None

    def __setattr__(self, name: str, value: Any) -> None:
        invalid = False
        try:
            super().__setattr__(name, value)
        except ValidationError:
            invalid = True
        if invalid:
            raise ConformanceError("CONF-REPORT-MALFORMED") from None

    def __delattr__(self, name: str) -> None:
        invalid = False
        try:
            super().__delattr__(name)
        except (TypeError, ValidationError):
            invalid = True
        if invalid:
            raise ConformanceError("CONF-REPORT-MALFORMED") from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        invalid = False
        result: Any = None
        try:
            result = super().model_validate(obj, **kwargs)
        except ValidationError:
            invalid = True
        if invalid:
            raise ConformanceError("CONF-REPORT-MALFORMED") from None
        return result

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: int) -> int:
        if value != 1:
            raise ValueError("unknown schema")
        return value

    @field_validator("total_cases")
    @classmethod
    def _total(cls, value: int) -> int:
        if value < 1 or value > MAX_CONFORMANCE_CASES:
            raise ValueError("invalid case count")
        return value

    @field_validator("caller_cases", "fixed_cases", "instrumented_cases")
    @classmethod
    def _case_partition(cls, value: int) -> int:
        if value < 0 or value > MAX_CONFORMANCE_CASES:
            raise ValueError("invalid case partition")
        return value

    @model_validator(mode="after")
    def _partition_matches_total(self) -> ConformanceReportV1:
        if (
            self.caller_cases + self.fixed_cases != self.total_cases
            or self.instrumented_cases > self.total_cases
        ):
            raise ValueError("invalid case partition")
        return self

    @field_validator("registration_operations")
    @classmethod
    def _registrations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("invalid registration operations")
        return value

    @field_validator("covered_operations")
    @classmethod
    def _covered(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("invalid operation coverage")
        return value

    @field_validator("failures")
    @classmethod
    def _failures(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            item not in {failure.value for failure in ConformanceFailureV1} for item in value
        ):
            raise ValueError("invalid failures")
        return value


def _report_body(report: ConformanceReportV1) -> dict[str, object]:
    return {
        "schema_version": report.schema_version,
        "corpus_version": report.corpus_version,
        "manifest_digest": report.manifest_digest,
        "total_cases": report.total_cases,
        "caller_cases": report.caller_cases,
        "fixed_cases": report.fixed_cases,
        "instrumented_cases": report.instrumented_cases,
        "registration_operations": list(report.registration_operations),
        "passed": report.passed,
        "covered_operations": list(report.covered_operations),
        "failures": list(report.failures),
    }


def _make_report(
    *,
    manifest_digest: str,
    total_cases: int,
    caller_cases: int,
    fixed_cases: int,
    instrumented_cases: int,
    registration_operations: tuple[str, ...],
    covered_operations: tuple[str, ...],
    failures: tuple[str, ...],
) -> ConformanceReportV1:
    invalid = False
    report: ConformanceReportV1 | None = None
    try:
        provisional = ConformanceReportV1(
            schema_version=1,
            corpus_version=FOUNDATION_CORPUS_VERSION,
            manifest_digest=manifest_digest,
            total_cases=total_cases,
            caller_cases=caller_cases,
            fixed_cases=fixed_cases,
            instrumented_cases=instrumented_cases,
            registration_operations=registration_operations,
            passed=not failures,
            covered_operations=covered_operations,
            failures=failures,
            report_digest=digest_decision_bytes(
                b"provisional", domain=DecisionDigestDomain.CONFORMANCE_REPORT
            ),
        )
        payload = rfc8785.dumps(_report_body(provisional))
        report = provisional.model_copy(
            update={
                "report_digest": digest_decision_bytes(
                    payload, domain=DecisionDigestDomain.CONFORMANCE_REPORT
                )
            }
        )
    except (ConformanceError, ValidationError, TypeError, ValueError):
        invalid = True
    if invalid or report is None:
        raise ConformanceError("CONF-REPORT-MALFORMED") from None
    return report


def serialize_conformance_report(report: ConformanceReportV1) -> bytes:
    if type(report) is not ConformanceReportV1:
        raise ConformanceError("CONF-REPORT-MALFORMED") from None
    invalid = False
    payload: bytes | None = None
    try:
        ConformanceReportV1.model_validate(report)
        expected = digest_decision_bytes(
            rfc8785.dumps(_report_body(report)),
            domain=DecisionDigestDomain.CONFORMANCE_REPORT,
        )
        if report.report_digest != expected:
            raise ConformanceError("CONF-REPORT-INTEGRITY") from None
        payload = rfc8785.dumps(_report_body(report) | {"report_digest": report.report_digest})
    except ConformanceError:
        raise
    except Exception:
        invalid = True
    if invalid or payload is None:
        raise ConformanceError("CONF-REPORT-MALFORMED") from None
    if len(payload) > MAX_REPORT_BYTES:
        raise ConformanceError("CONF-REPORT-OVER-CAP") from None
    return payload


def run_adapter_conformance(
    pep: PolicyEnforcementPointV1, *, cases: tuple[AdapterConformanceCaseV1, ...]
) -> ConformanceReportV1:
    """Run explicit vectors against an instrumented adapter PEP.

    This harness invokes sinks for positive cases.  Callers must supply only
    instrumented/test sinks, never a live production adapter.
    """
    if (
        type(pep) is not PolicyEnforcementPointV1
        or type(cases) is not tuple
        or not cases
        or len(cases) > MAX_CONFORMANCE_CASES - 5
        or any(type(case) is not AdapterConformanceCaseV1 for case in cases)
        or len({case.name for case in cases}) != len(cases)
    ):
        raise ConformanceError("CONF-CASES-MALFORMED") from None

    seed = next(
        (
            case
            for case in cases
            if type(case.request) is DecisionRequestV1
            and type(case.runtime) is ActivatedRuntimeV1
            and type(case.effect) is EffectInputV1
        ),
        None,
    )
    if seed is None:
        raise ConformanceError("CONF-SEED-MISSING") from None

    class _HostileDigest:
        def __eq__(self, _other: object) -> bool:
            raise RuntimeError("PLANTED-FIXED-CORPUS-SECRET")

    hostile_operation = OperationBindingV1.model_construct(
        adapter_id=seed.request.operation.adapter_id,
        adapter_manifest_digest=seed.request.operation.adapter_manifest_digest,
        operation_id=seed.request.operation.operation_id,
        capability=CapabilityV1.READ.value,
        arguments_digest=_HostileDigest(),
        destination_digest=seed.request.operation.destination_digest,
        bundle_manifest_digest=None,
    )
    substituted_effect = create_effect_input(
        b'{"mcp_warden_fixed_corpus":"effect-substitution-v1"}'
    )
    if substituted_effect.arguments_digest == seed.effect.arguments_digest:
        substituted_effect = create_effect_input(
            b'{"mcp_warden_fixed_corpus":"effect-substitution-v1-alt"}'
        )
    fixed_cases = (
        AdapterConformanceCaseV1(
            name="fixed.malformed-request",
            request=object(),
            runtime=seed.runtime,
            effect=seed.effect,
            expected_code=EnforcementCodeV1.DECISION_BLOCKED,
            expected_invoked=False,
        ),
        AdapterConformanceCaseV1(
            name="fixed.malformed-runtime",
            request=seed.request,
            runtime=object(),
            effect=seed.effect,
            expected_code=EnforcementCodeV1.DECISION_BLOCKED,
            expected_invoked=False,
        ),
        AdapterConformanceCaseV1(
            name="fixed.malformed-effect",
            request=seed.request,
            runtime=seed.runtime,
            effect=object(),
            expected_code=EnforcementCodeV1.EFFECT_MALFORMED,
            expected_invoked=False,
        ),
        AdapterConformanceCaseV1(
            name="fixed.hostile-nested-request",
            request=seed.request.model_copy(update={"operation": hostile_operation}),
            runtime=seed.runtime,
            effect=seed.effect,
            expected_code=EnforcementCodeV1.DECISION_BLOCKED,
            expected_invoked=False,
            planted_secrets=(b"PLANTED-FIXED-CORPUS-SECRET",),
        ),
        AdapterConformanceCaseV1(
            name="fixed.effect-substitution",
            request=seed.request,
            runtime=seed.runtime,
            effect=substituted_effect,
            expected_code=EnforcementCodeV1.EFFECT_DIGEST_MISMATCH,
            expected_invoked=False,
        ),
    )

    failures: set[str] = set()
    covered: set[str] = set()
    instrumented_cases = 0
    negative_case_seen = False
    manifest_operations = {item.operation_id for item in pep.manifest.operations}

    all_cases = cases + fixed_cases
    for case in all_cases:
        if not case.expected_invoked:
            negative_case_seen = True
        result: EnforcementResultV1 | None = None
        output_channels: tuple[bytes, ...] = ()
        try:
            result, instrumentation = pep._execute_instrumented(
                case.request, runtime=case.runtime, effect=case.effect
            )
            output_channels = instrumentation.output_channels
            instrumented_cases += 1
        except Exception:
            failures.add(ConformanceFailureV1.CASE_ERROR.value)
        if result is None:
            continue
        if result.code != case.expected_code.value or result.invoked is not case.expected_invoked:
            failures.add(ConformanceFailureV1.CASE_MISMATCH.value)
        if any(secret in channel for secret in case.planted_secrets for channel in output_channels):
            failures.add(ConformanceFailureV1.SECRET_LEAK.value)
        events = instrumentation.events
        ordered_effect = False
        if result.invoked is True:
            try:
                ordered_effect = (
                    events.index("decision") < events.index("evidence") < events.index("sink")
                )
            except ValueError:
                ordered_effect = False
        if (
            not events
            or events[-1] != "result:" + result.code
            or (result.invoked is False and "sink" in events)
            or (result.invoked is True and not ordered_effect)
        ):
            failures.add(ConformanceFailureV1.INSTRUMENTATION.value)
        if (
            result.code == EnforcementCodeV1.EXECUTED.value
            and result.invoked is True
            and type(case.request) is DecisionRequestV1
            and type(case.effect) is EffectInputV1
            and case.request.operation.operation_id in manifest_operations
        ):
            covered.add(case.request.operation.operation_id)

    if covered != manifest_operations:
        failures.add(ConformanceFailureV1.OPERATION_UNCOVERED.value)
    if not negative_case_seen:
        failures.add(ConformanceFailureV1.NEGATIVE_CASE_MISSING.value)
    registrations = pep.registration_operations
    if set(registrations) != manifest_operations:
        failures.add(ConformanceFailureV1.INSTRUMENTATION.value)
    return _make_report(
        manifest_digest=pep.manifest_digest,
        total_cases=len(all_cases),
        caller_cases=len(cases),
        fixed_cases=len(fixed_cases),
        instrumented_cases=instrumented_cases,
        registration_operations=registrations,
        covered_operations=tuple(sorted(covered)),
        failures=tuple(sorted(failures)),
    )
