"""Score the offline injection-monitor corpus through the shared result inspector."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_warden.injection_catalog import INJECTION_RULES
from mcp_warden.res_rules import SEED_EXFIL_DENYLIST, SEED_INJECT_PHRASES
from mcp_warden.result_inspection import InspectionPolicy, ResultFinding, inspect_result

CORPUS = json.loads(
    Path(__file__).with_name("fixtures").joinpath("rule_catalog_quality.json").read_text(
        encoding="utf-8"
    )
)
CATEGORIES = {
    "authority-impersonation": "WRD-RES-INJECT-AUTHORITY-IMPERSONATION",
    "instruction-override": "WRD-RES-INJECT-INSTRUCTION-OVERRIDE",
    "secret-extraction": "WRD-RES-INJECT-SECRET-EXTRACTION",
    "tool-coercion": "WRD-RES-INJECT-TOOL-COERCION",
    "data-exfiltration": "WRD-RES-INJECT-DATA-EXFILTRATION",
    "policy-evasion": "WRD-RES-INJECT-POLICY-EVASION",
}
MONITOR_RULE = "WRD-RES-INJECT-PHRASE"


def _variants(text: str) -> dict[str, str]:
    return {
        "plain": text,
        "uppercase": text.upper(),
        "whitespace": " \t\n".join(text.split()),
        "quoted-bullet": f'- "{text}"',
    }


def _inspect(text: str) -> list[ResultFinding]:
    return inspect_result(
        {"content": [{"type": "text", "text": text}]},
        "catalog_quality",
        InspectionPolicy(),
        exfil_denylist=SEED_EXFIL_DENYLIST,
        inject_phrases=SEED_INJECT_PHRASES,
    )


@pytest.mark.parametrize("category", tuple(CORPUS))
def test_catalog_quality_by_category(category):
    misses = []
    false_positives = []
    contract_failures = []
    samples = 0
    expected_hits = 0
    benign_samples = 0

    for case in CORPUS[category]:
        expected = case["expected"]
        for variant, text in _variants(case["text"]).items():
            label = f"{case['id']}/{variant}"
            samples += 1
            expected_hits += len(expected)
            benign_samples += not expected
            findings = _inspect(text)
            if findings != _inspect(text):
                contract_failures.append(f"{label}: findings changed on repeat")

            seen_ids = []
            actual = {}
            for finding in findings:
                if finding.rule_id != MONITOR_RULE or finding.tier != "monitor":
                    false_positives.append(f"{label}: {finding.rule_id} ({finding.tier})")
                    continue
                if not finding.injection_matches:
                    false_positives.append(f"{label}: unclassified {MONITOR_RULE}")

                for match in finding.injection_matches:
                    if CATEGORIES.get(match.category) != match.rule_id:
                        contract_failures.append(
                            f"{label}: incorrect category {match.category} for {match.rule_id}"
                        )
                    if match.evidence_ids != tuple(sorted(set(match.evidence_ids))):
                        contract_failures.append(
                            f"{label}: unsorted or duplicate evidence for {match.rule_id}"
                        )
                    seen_ids.append(match.rule_id)
                    actual[match.rule_id] = match.evidence_ids

            if seen_ids != sorted(actual):
                contract_failures.append(f"{label}: unsorted or duplicate rule IDs")

            misses.extend(f"{label}: {rule_id}" for rule_id in sorted(expected.keys() - actual))
            false_positives.extend(f"{label}: {rule_id}" for rule_id in sorted(actual.keys() - expected))
            for rule_id in sorted(actual.keys() & expected.keys()):
                expected_ids = set(expected[rule_id])
                actual_ids = set(actual[rule_id])
                misses.extend(
                    f"{label}: {rule_id}/{evidence_id}"
                    for evidence_id in sorted(expected_ids - actual_ids)
                )
                false_positives.extend(
                    f"{label}: {rule_id}/{evidence_id}"
                    for evidence_id in sorted(actual_ids - expected_ids)
                )

    assert not (misses or false_positives or contract_failures), "\n".join(
        (
            f"{samples} samples, {expected_hits} expected rule hits, {benign_samples} benign samples",
            f"Misses ({len(misses)}): {', '.join(misses)}",
            f"False positives ({len(false_positives)}): {', '.join(false_positives)}",
            f"Contract failures ({len(contract_failures)}): {', '.join(contract_failures)}",
        )
    )


def test_corpus_covers_each_catalog_evidence_id_and_has_benign_controls():
    published = {
        rule.rule_id: {indicator.evidence_id for indicator in rule.evidence}
        for rule in INJECTION_RULES
    }
    assert published.keys() == set(CATEGORIES.values())
    assert set(CORPUS) == {*CATEGORIES, "mixed"}

    for cases in CORPUS.values():
        assert len({case["id"] for case in cases}) == len(cases)
        assert all(case["text"].strip() for case in cases)

    for category, rule_id in CATEGORIES.items():
        cases = CORPUS[category]
        assert any(not case["expected"] for case in cases)
        covered = set()
        for case in cases:
            expected = case["expected"]
            if expected:
                assert expected.keys() == {rule_id} and len(expected[rule_id]) == 1
                covered.update(expected[rule_id])
        assert covered == published[rule_id]

    assert CORPUS["mixed"]
    for case in CORPUS["mixed"]:
        expected = case["expected"]
        assert len(expected) >= 2
        for rule_id, evidence_ids in expected.items():
            assert set(evidence_ids) <= published[rule_id]
