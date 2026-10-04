"""Closed public reason registry for governed enforcement decisions."""

from mcp_warden.decision_models import DecisionReasonV1, DecisionRecoveryV1
from mcp_warden.policy_enforcement import EnforcementCodeV1

PUBLIC_REASONS = (
    frozenset(r.value for r in DecisionReasonV1)
    | frozenset(r.value for r in EnforcementCodeV1)
    | {
        "RULE-BLOCKED",
        "RULE-QUARANTINED",
        "RULE-OVERRIDE",
        "PEP-REQUEST-MALFORMED",
        "PEP-RECOVERY-ONLY",
    }
)
RECOVERY_CODES = frozenset(r.value for r in DecisionRecoveryV1)
