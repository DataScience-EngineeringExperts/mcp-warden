"""Bounded declarative rule grammar. No code, regex or ambient lookups."""

from __future__ import annotations

from typing import Literal

from pydantic import StrictInt, model_validator

from mcp_warden.decision_models import CapabilityV1, DecisionReasonV1, DecisionRecoveryV1
from mcp_warden.evidence_state import DIGEST_RE
from mcp_warden.receipt_kernel import ReceiptModel, canonical

STR_FIELDS = {
    "base.verdict": {"allow", "deny", "quarantine"},
    "base.reason": {v.value for v in DecisionReasonV1},
    "base.recovery": {v.value for v in DecisionRecoveryV1},
    "capability": {v.value for v in CapabilityV1},
}
DIGEST_FIELDS = frozenset(
    {
        "user_digest",
        "agent_digest",
        "device_digest",
        "session_digest",
        "request_digest",
        "purpose_digest",
        "scope_digest",
        "destination_digest",
    }
)
ID_FIELDS = frozenset({"operation_id", "adapter_id"})
INT_FIELDS = frozenset(
    {"policy_generation", "revocation_generation", "rule_generation", "trusted_time"}
)


class RuleConditionV1(ReceiptModel):
    field: str
    operator: Literal["equals", "not-equals", "in", "contains-taint", "integer-range"]
    value: str | tuple[str, ...] | None = None
    minimum: StrictInt | None = None
    maximum: StrictInt | None = None

    @model_validator(mode="after")
    def _grammar(self):
        from mcp_warden.content_models import IngressKindV1, MediaTypeV1, TaintV1

        registries = STR_FIELDS | {
            "envelope.media": {v.value for v in MediaTypeV1},
            "envelope.source": {v.value for v in IngressKindV1},
            "envelope.taints": {v.value for v in TaintV1},
        }
        if self.field in INT_FIELDS:
            if (
                self.operator != "integer-range"
                or self.value is not None
                or self.minimum is None
                or self.maximum is None
                or not 0 <= self.minimum <= self.maximum <= 2**53 - 1
            ):
                raise ValueError("invalid integer condition")
            return self
        if self.minimum is not None or self.maximum is not None:
            raise ValueError("unexpected range")
        if self.field == "envelope.taints":
            if self.operator != "contains-taint":
                raise ValueError("invalid taint operator")
        elif self.field not in registries and self.field not in DIGEST_FIELDS | ID_FIELDS:
            raise ValueError("unknown field")
        elif self.operator not in {"equals", "not-equals", "in"}:
            raise ValueError("invalid scalar operator")
        values = self.value if self.operator == "in" else (self.value,)
        if (
            type(values) is not tuple
            or not values
            or len(values) > 128
            or self.operator == "in"
            and self.value != tuple(sorted(set(values)))
        ):
            raise ValueError("invalid membership")
        from mcp_warden.decision_models import IDENTIFIER_RE

        for value in values:
            if type(value) is not str:
                raise ValueError("invalid scalar")
            if self.field in registries and value not in registries[self.field]:
                raise ValueError("unknown scalar")
            if self.field in DIGEST_FIELDS and DIGEST_RE.fullmatch(value) is None:
                raise ValueError("invalid digest")
            if self.field in ID_FIELDS and IDENTIFIER_RE.fullmatch(value) is None:
                raise ValueError("invalid identifier")
        return self


def condition_key(condition: RuleConditionV1):
    return condition.field, condition.operator, canonical(condition)


class RuleGroupV1(ReceiptModel):
    mode: Literal["all", "any"]
    conditions: tuple[RuleConditionV1, ...]

    @model_validator(mode="after")
    def _group(self):
        keys = tuple(condition_key(c) for c in self.conditions)
        if (
            not keys
            or len(keys) > 64
            or any(type(c) is not RuleConditionV1 for c in self.conditions)
            or keys != tuple(sorted(set(keys)))
        ):
            raise ValueError("invalid group")
        return self


class RuleV1(ReceiptModel):
    rule_id: str
    group: RuleGroupV1
    effect: Literal["deny", "quarantine"]

    @model_validator(mode="after")
    def _rule(self):
        from mcp_warden.decision_models import IDENTIFIER_RE

        if IDENTIFIER_RE.fullmatch(self.rule_id) is None or type(self.group) is not RuleGroupV1:
            raise ValueError("invalid rule")
        return self


class RuleBundleV1(ReceiptModel):
    schema_version: Literal[1] = 1
    generation: StrictInt
    valid_from: StrictInt
    valid_until: StrictInt
    critical_floor_version: Literal["atk-critical-v1"] = "atk-critical-v1"
    rules: tuple[RuleV1, ...]

    @model_validator(mode="after")
    def _bundle(self):
        ids = tuple(r.rule_id for r in self.rules)
        if (
            len(ids) > 256
            or ids != tuple(sorted(set(ids)))
            or self.valid_until <= self.valid_from
            or any(type(r) is not RuleV1 for r in self.rules)
        ):
            raise ValueError("invalid rules")
        canonical(self.model_dump(mode="json"))
        return self
