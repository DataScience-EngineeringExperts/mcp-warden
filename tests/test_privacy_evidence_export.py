"""A partial or repeated JUnit case cannot qualify the vendor-drift control."""

import runpy
from pathlib import Path

import pytest

EXPORTER = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/privacy_evidence.py"))


@pytest.mark.parametrize(
    "cases, expected",
    [
        ([("mutation0", "")], False),
        ([("mutation0", ""), ("mutation0", "")], False),
        ([("mutation0", ""), ("mutation1", "<skipped/>")], False),
        ([("mutation0", ""), ("mutation1", "<error/>")], False),
        ([("mutation0", ""), ("mutation1", "")], True),
    ],
)
def test_drift_report_requires_every_reviewed_case_once(tmp_path, cases, expected):
    report = tmp_path / "report.xml"
    rows = [
        f'<testcase classname="tests.test_tool_integrity_guard" '
        f'name="test_real_guard_blocks_metadata_change[{case}]">{status}</testcase>'
        for case, status in cases
    ]
    report.write_text("<testsuite>" + "".join(rows) + "</testsuite>")
    required = EXPORTER["fixture_nodes"]("vendor-drift", EXPORTER["CHECKS"]["vendor-drift"])
    assert (set(required) <= EXPORTER["verified_cases"](report)) is expected


def test_incomplete_xml_is_unverified(tmp_path):
    report = tmp_path / "report.xml"
    report.write_text("<testsuite")
    assert EXPORTER["verified_cases"](report) == set()
