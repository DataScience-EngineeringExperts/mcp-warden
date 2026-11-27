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


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    revision = git("rev-parse", "HEAD")
    if git("status", "--porcelain"):
        sys.exit("A clean checkout is required to identify the tested source.")
    outcomes = dict.fromkeys(CHECKS, "unverified")
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "PYTEST_ADDOPTS": "",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / "report.xml"
        args = [sys.executable, "-m", "pytest", "-o", "addopts=", "--junitxml", str(report)]
        args.extend(f"tests/{node}" for node in CHECKS.values())
        run = subprocess.run(
            args,
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if report.exists():
            cases = ET.parse(report).findall(".//testcase")
            for control, node in CHECKS.items():
                module, name = node.split("::")
                matches = [
                    case
                    for case in cases
                    if case.get("classname") == f"tests.{module[:-3]}"
                    and case.get("name", "").split("[")[0] == name
                ]
                if matches:
                    outcomes[control] = (
                        "passed"
                        if all(
                            all(case.find(tag) is None for tag in ("error", "failure", "skipped"))
                            for case in matches
                        )
                        else "unverified"
                    )
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
