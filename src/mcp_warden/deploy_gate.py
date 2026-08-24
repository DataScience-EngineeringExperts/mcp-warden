"""Fail-closed CI deploy gate for agent deployments (WRD-GATE-*) — DSE-1257.

"release_control for agents": a deterministic gate that reads a declared gate
policy plus an evidence bundle produced by a deploy pipeline, and fail-closes
the deploy unless every required control is present and passing. It runs in CI
and exits non-zero on any unmet requirement.

The gate is intentionally evidence-driven and deterministic. It does not run
evals itself — it verifies that declared eval suites ran, met their thresholds,
that required guardrails are present, that a budget/quota is declared, and that
a human-approval receipt is present when the policy requires one. Missing or
malformed evidence is a failure, never a pass (fail closed).

Policy and evidence are JSON. See DEPLOY_GATE.md for the schema.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Finding


class DeployGateError(ValueError):
    """Raised on unreadable/malformed policy or evidence (fail closed)."""


@dataclass(frozen=True)
class GateOutcome:
    """Result of a deploy-gate evaluation."""

    findings: list[Finding]
    controls_checked: int

    @property
    def passed(self) -> bool:
        return not self.findings


def _load_json(path: Path, kind: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DeployGateError(f"cannot read {kind} {path}: {exc}") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DeployGateError(f"invalid JSON in {kind} {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise DeployGateError(f"{kind} {path}: top-level must be a JSON object")
    return doc


def _fail(rule: str, severity: str, target: str, message: str, snippet: str = "") -> Finding:
    return Finding(rule_id=rule, severity=severity, target=target, message=message, snippet=snippet)


def _check_evals(policy: dict[str, Any], evidence: dict[str, Any]) -> list[Finding]:
    """Each required eval suite must be present and meet its min score."""
    findings: list[Finding] = []
    required = policy.get("required_evals") or []
    reported = evidence.get("evals") or {}
    if not isinstance(reported, dict):
        return [_fail("WRD-GATE-EVAL-EVIDENCE", "high", "evals",
                      "evidence 'evals' must be an object of suite -> {score}")]
    for spec in required:
        if not isinstance(spec, dict):
            continue
        name = str(spec.get("suite", ""))
        threshold = spec.get("min_score")
        target = f"evals/{name}"
        result = reported.get(name)
        if result is None:
            findings.append(_fail("WRD-GATE-EVAL-MISSING", "high", target,
                                  f"required eval suite '{name}' has no result in evidence"))
            continue
        score = result.get("score") if isinstance(result, dict) else None
        if not isinstance(score, (int, float)):
            findings.append(_fail("WRD-GATE-EVAL-MALFORMED", "high", target,
                                  f"eval suite '{name}' reported no numeric score"))
            continue
        if isinstance(threshold, (int, float)) and score < threshold:
            findings.append(_fail("WRD-GATE-EVAL-THRESHOLD", "high", target,
                                  f"eval '{name}' scored {score} < required {threshold}",
                                  snippet=f"{score}<{threshold}"))
    return findings


def _check_guardrails(policy: dict[str, Any], evidence: dict[str, Any]) -> list[Finding]:
    """Every required guardrail must be declared active in the evidence."""
    findings: list[Finding] = []
    required = policy.get("required_guardrails") or []
    active = evidence.get("guardrails") or []
    active_set = {str(g) for g in active} if isinstance(active, list) else set()
    for name in required:
        if str(name) not in active_set:
            findings.append(_fail("WRD-GATE-GUARDRAIL-MISSING", "high", f"guardrails/{name}",
                                  f"required guardrail '{name}' is not active in this deploy"))
    return findings


def _check_budget(policy: dict[str, Any], evidence: dict[str, Any]) -> list[Finding]:
    """When the policy requires a budget, evidence must declare a positive one."""
    if not policy.get("require_budget"):
        return []
    budget = evidence.get("budget")
    if not isinstance(budget, dict):
        return [_fail("WRD-GATE-BUDGET-MISSING", "medium", "budget",
                      "policy requires a declared budget/quota; none present in evidence")]
    limit = budget.get("limit")
    if not isinstance(limit, (int, float)) or limit <= 0:
        return [_fail("WRD-GATE-BUDGET-INVALID", "medium", "budget",
                      "declared budget has no positive limit", snippet=str(limit))]
    return []


def _check_approval(policy: dict[str, Any], evidence: dict[str, Any]) -> list[Finding]:
    """When the policy requires human approval, a valid receipt must be present."""
    if not policy.get("require_approval"):
        return []
    receipt = evidence.get("approval")
    if not isinstance(receipt, dict):
        return [_fail("WRD-GATE-APPROVAL-MISSING", "critical", "approval",
                      "policy requires human approval; no approval receipt in evidence")]
    approver = receipt.get("approver")
    approved = receipt.get("approved")
    if approved is not True or not isinstance(approver, str) or not approver.strip():
        return [_fail("WRD-GATE-APPROVAL-INVALID", "critical", "approval",
                      "approval receipt is not an affirmative, attributed approval",
                      snippet=str(approver))]
    return []


def evaluate_gate(policy: dict[str, Any], evidence: dict[str, Any]) -> GateOutcome:
    """Evaluate an agent deploy against the gate policy; fail closed on any gap."""
    findings: list[Finding] = []
    findings.extend(_check_evals(policy, evidence))
    findings.extend(_check_guardrails(policy, evidence))
    findings.extend(_check_budget(policy, evidence))
    findings.extend(_check_approval(policy, evidence))
    controls = (
        len(policy.get("required_evals") or [])
        + len(policy.get("required_guardrails") or [])
        + (1 if policy.get("require_budget") else 0)
        + (1 if policy.get("require_approval") else 0)
    )
    findings.sort(key=lambda f: (f.target, f.rule_id))
    return GateOutcome(findings=findings, controls_checked=controls)


def run_deploy_gate(policy_path: Path, evidence_path: Path) -> GateOutcome:
    """Load policy + evidence from disk and evaluate the gate."""
    policy = _load_json(policy_path, "policy")
    evidence = _load_json(evidence_path, "evidence")
    return evaluate_gate(policy, evidence)
