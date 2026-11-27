"""Export closed verdicts from fixed local, synthetic privacy-control fixtures."""

import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = {
    "purpose": "test_policy_decision.py::test_scope_purpose_and_envelope_are_bound",
    "minimization": "test_emitters.py::test_no_raw_result_content_leaks_into_inject_phrase_telemetry",
    "sensitive-data": "test_result_inspection.py::test_secret_echo_fires_and_is_redacted",
    "vendor-drift": "test_tool_integrity_guard.py::test_real_guard_blocks_metadata_change",
    "audit-projection": "test_receipt_projection.py::test_closed_projections_are_signature_and_private_detail_free",
}


def fixture_nodes(control, node):
    if control == "vendor-drift":
        return [f"{node}[mutation0]", f"{node}[mutation1]"]
    return [node]


def verified_cases(report):
    try:
        cases = ET.parse(report).findall(".//testcase")
    except (OSError, ET.ParseError):
        return set()
    verified = set()
    seen = set()
    duplicates = set()
    for case in cases:
        classname = case.get("classname", "")
        if not classname.startswith("tests."):
            continue
        module = classname.removeprefix("tests.")
        node = f"{module}.py::{case.get('name', '')}"
        if node in seen:
            duplicates.add(node)
        seen.add(node)
        if all(case.find(tag) is None for tag in ("error", "failure", "skipped")):
            verified.add(node)
    return verified - duplicates


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    revision = git("rev-parse", "HEAD")
    if git("status", "--porcelain"):
        sys.exit("A clean checkout is required to identify the tested source.")
    outcomes = dict.fromkeys(CHECKS, "unverified")
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")},
        "PYTHONPATH": str(ROOT / "src"),
        "PYTEST_ADDOPTS": "",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / "report.xml"
        args = [sys.executable, "-m", "pytest", "-o", "addopts=", "--junitxml", str(report)]
        args.extend(
            f"tests/{case}"
            for control, node in CHECKS.items()
            for case in fixture_nodes(control, node)
        )
        run = subprocess.run(
            args,
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        verified = verified_cases(report)
        for control, node in CHECKS.items():
            if set(fixture_nodes(control, node)) <= verified:
                outcomes[control] = "passed"
    passed = run.returncode == 0 and all(value == "passed" for value in outcomes.values())
    outcomes.update(retention="operator-evidence-required", deletion="operator-evidence-required")
    print(
        json.dumps(
            {
                "schema_version": 1,
                "scope": "synthetic-source-fixtures",
                "revision": revision,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "controls": outcomes,
            },
            indent=2,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
