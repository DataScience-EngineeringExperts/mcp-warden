"""Deterministic offline review of separately attributable capability evidence."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StringConstraints,
    ValidationError,
    field_validator,
)

from mcp_warden.artifact_payload import ArtifactTrustError, bounded_json
from mcp_warden.decision_models import DIGEST_RE, IDENTIFIER_RE, CapabilityV1
from mcp_warden.hashing import canon, hash_value

MAX_REVIEW_BYTES = 512 * 1024
MAX_RECORDS_PER_SOURCE = 1024
_INPUT_MALFORMED = "CAP-REVIEW-INPUT-MALFORMED"
_ROW_DOMAIN = "mcp-warden/capability-review/v1/row"
_IDENTIFIER = Annotated[str, StringConstraints(pattern=IDENTIFIER_RE.pattern)]
_DIGEST = Annotated[str, StringConstraints(pattern=DIGEST_RE.pattern)]


class ReviewAudienceV1(StrEnum):
    HUMAN = "human"
    AGENT = "agent"


class _ReviewModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )


class CapabilityScopeV1(_ReviewModel):
    purpose_id: _IDENTIFIER
    data_scope_id: _IDENTIFIER
    environment_id: _IDENTIFIER
    scope_digest: _DIGEST


class CapabilityBindingV1(_ReviewModel):
    identity_digest: _DIGEST
    scope: CapabilityScopeV1


class CapabilityEvidenceV1(_ReviewModel):
    adapter_id: _IDENTIFIER
    operation_id: _IDENTIFIER
    capability: str
    evidence_digest: _DIGEST
    binding: CapabilityBindingV1 | None

    @field_validator("capability")
    @classmethod
    def _known_capability(cls, value: str) -> str:
        return CapabilityV1(value).value


class CapabilityReviewEvidenceV1(_ReviewModel):
    schema_version: StrictInt
    declarations: tuple[CapabilityEvidenceV1, ...] = Field(max_length=MAX_RECORDS_PER_SOURCE)
    observations: tuple[CapabilityEvidenceV1, ...] = Field(max_length=MAX_RECORDS_PER_SOURCE)

    @field_validator("schema_version")
    @classmethod
    def _v1(cls, value: int) -> int:
        if value != 1:
            raise ValueError("unsupported review schema")
        return value

    @field_validator("declarations", "observations", mode="before")
    @classmethod
    def _arrays(cls, value: object) -> object:
        return tuple(value) if type(value) is list else value


def _validated_evidence(value: object) -> CapabilityReviewEvidenceV1:
    try:
        return CapabilityReviewEvidenceV1.model_validate(value)
    except ValidationError:
        pass
    raise ArtifactTrustError(_INPUT_MALFORMED)


def parse_review_evidence(payload: bytes) -> CapabilityReviewEvidenceV1:
    """Parse strict, bounded JSON without echoing evidence on failure."""
    return _validated_evidence(bounded_json(payload, cap=MAX_REVIEW_BYTES, code=_INPUT_MALFORMED))


class _Source(StrEnum):
    DECLARATION = "declaration"
    OBSERVATION = "observation"


_RISK = {
    CapabilityV1.READ: "moderate",
    CapabilityV1.TRANSFORM: "moderate",
    CapabilityV1.DISCLOSE: "high",
    CapabilityV1.COMMUNICATE: "high",
    CapabilityV1.EXECUTE: "critical",
    CapabilityV1.ADMINISTER_POLICY: "critical",
    CapabilityV1.REPAIR_RECOVERY: "critical",
}

_Locator = tuple[str, str, str]


@dataclass(frozen=True)
class _ReviewRow:
    locator: _Locator
    declarations: tuple[CapabilityEvidenceV1, ...]
    observations: tuple[CapabilityEvidenceV1, ...]
    discrepancies: tuple[str, ...]

    def status_fields(self) -> dict:
        if self.discrepancies:
            return {"status": "ineligible", "reasons": list(self.discrepancies)}
        return {
            "status": "pending-human-review",
            "reasons": ["CAP-REVIEW-HUMAN-REVIEW-REQUIRED"],
        }

    def evidence_fields(self) -> dict:
        adapter_id, operation_id, capability = self.locator
        return {
            "adapter_id": adapter_id,
            "operation_id": operation_id,
            "capability": capability,
            "declarations": [_record_reference(item) for item in self.declarations],
            "observations": [_record_reference(item) for item in self.observations],
        }


def _record_reference(item: CapabilityEvidenceV1) -> dict:
    return item.model_dump(mode="json", include={"evidence_digest", "binding"})


def _source_discrepancies(source: _Source, entries: set[CapabilityEvidenceV1]) -> list[str]:
    prefix = f"CAP-REVIEW-{source.value.upper()}"
    if not entries:
        return [f"{prefix}-MISSING"]
    discrepancies = []
    if any(item.binding is None for item in entries):
        discrepancies.append(f"{prefix}-INCOMPLETE")
    if len({item.binding for item in entries if item.binding is not None}) > 1:
        discrepancies.append(f"{prefix}-AMBIGUOUS")
    return discrepancies


def _ordered(entries: set[CapabilityEvidenceV1]) -> tuple[CapabilityEvidenceV1, ...]:
    return tuple(
        sorted(entries, key=lambda item: (item.evidence_digest, canon(_record_reference(item))))
    )


def _review_rows(value: CapabilityReviewEvidenceV1) -> list[_ReviewRow]:
    evidence = _validated_evidence(value)
    declarations: dict[_Locator, set[CapabilityEvidenceV1]] = defaultdict(set)
    observations: dict[_Locator, set[CapabilityEvidenceV1]] = defaultdict(set)
    capabilities: dict[tuple[str, str], set[str]] = defaultdict(set)
    references: dict[str, set[tuple[_Source, CapabilityEvidenceV1]]] = defaultdict(set)
    for source, entries, grouped in (
        (_Source.DECLARATION, evidence.declarations, declarations),
        (_Source.OBSERVATION, evidence.observations, observations),
    ):
        for item in entries:
            locator = (item.adapter_id, item.operation_id, item.capability)
            grouped[locator].add(item)
            capabilities[(item.adapter_id, item.operation_id)].add(item.capability)
            references[item.evidence_digest].add((source, item))

    rows = []
    for locator in sorted(declarations.keys() | observations.keys()):
        declared = declarations[locator]
        observed = observations[locator]
        discrepancies = [
            *_source_discrepancies(_Source.DECLARATION, declared),
            *_source_discrepancies(_Source.OBSERVATION, observed),
        ]
        if len(capabilities[(locator[0], locator[1])]) > 1:
            discrepancies.append("CAP-REVIEW-CAPABILITY-CONFLICT")
        entries = declared | observed
        if any(len(references[item.evidence_digest]) > 1 for item in entries):
            discrepancies.append("CAP-REVIEW-EVIDENCE-REUSED")
        bindings = {item.binding for item in entries if item.binding is not None}
        if len({binding.identity_digest for binding in bindings}) > 1:
            discrepancies.append("CAP-REVIEW-IDENTITY-CONFLICT")
        if len({binding.scope for binding in bindings}) > 1:
            discrepancies.append("CAP-REVIEW-SCOPE-CONFLICT")
        rows.append(
            _ReviewRow(
                locator, _ordered(declared), _ordered(observed), tuple(sorted(discrepancies))
            )
        )
    return rows


def _review_id(evidence_fields: dict) -> str:
    return hash_value({"domain": _ROW_DOMAIN, "evidence": evidence_fields})


def project_human_review(evidence: CapabilityReviewEvidenceV1) -> dict:
    """Return scoped review details for an operator-controlled output channel."""
    rows = []
    for row in _review_rows(evidence):
        fields = row.evidence_fields()
        rows.append(
            {
                **fields,
                **row.status_fields(),
                "risk": _RISK[row.locator[2]],
                "review_id": _review_id(fields),
            }
        )
    return {"schema_version": 1, "rows": rows}


def project_agent_review(evidence: CapabilityReviewEvidenceV1) -> dict:
    """Return only closed states and opaque handles for eligible capability descriptors."""
    rows = []
    for row in _review_rows(evidence):
        public = row.status_fields()
        if not row.discrepancies:
            public["capability"] = row.locator[2]
            public["review_id"] = _review_id(row.evidence_fields())
        rows.append(public)
    return {"schema_version": 1, "rows": sorted(rows, key=canon)}
