"""Exercise installed CLI entry points through an actual multi-UID Linux socket."""

from __future__ import annotations

import json
import os
import secrets
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("WARDEN_EVIDENCE_CROSS_UID") != "1",
    reason="opt-in synthetic qualification on an isolated Linux builder with sudo",
)
DAEMON, RECORDER, REVIEWER, CUSTODIAN, OTHER = range(65431, 65436)
GROUP = 65440
SOURCE = Path(__file__).resolve().parents[1] / "src"
ARGUMENT = "SYNTHETIC-ARGUMENT-WARDEN-86e937fe"
RESULT = "synthetic result lavender maple lantern"
MARKER = "flag synthetic lavender maple lantern"


def _cli(uid, cwd, *args, launch=False):
    command = [sys.executable, "-m", "mcp_warden.cli", *map(str, args)]
    extra = [int(os.environ["SUDO_GID"])] if "SUDO_GID" in os.environ else []
    kwargs = {
        "user": uid, "group": GROUP, "extra_groups": extra, "cwd": cwd,
        "env": {"PYTHONPATH": str(SOURCE), "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8",
                "PATH": os.defpath},
        "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
    }
    if launch:
        return subprocess.Popen(command, stdin=subprocess.PIPE, **kwargs)
    return subprocess.run(command, stdin=subprocess.DEVNULL, timeout=12, **kwargs)


def _private_file(path, value, uid):
    path.write_text(json.dumps(value))
    os.chown(path, uid, GROUP)
    path.chmod(0o600)


def _wait(predicate):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    pytest.fail("the isolated fixture did not reach the expected state")


def _ok(result):
    assert result.returncode == 0, result.stderr.decode()


def _terminate(process):
    if process.poll() is None:
        if process.stdin is not None:
            process.stdin.close()
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize("containment", [False, True])
def test_real_cli_and_vault_over_distinct_unix_peers(containment):
    with tempfile.TemporaryDirectory(prefix="warden-local-") as directory:
        fixture = Path(directory)
        fixture.chmod(0o755)
        vault, settings, runtime, work, export = (
            fixture / name for name in ("vault", "settings", "socket", "work", "export")
        )
        for path, uid, mode in (
            (vault, DAEMON, 0o700), (settings, DAEMON, 0o700), (runtime, DAEMON, 0o2750),
            (work, RECORDER, 0o700), (export, REVIEWER, 0o700),
        ):
            path.mkdir()
            os.chown(path, uid, GROUP)
            path.chmod(mode)
        socket = runtime / "key.sock"
        keyring, policy = settings / "keys.json", settings / "policy.json"
        grants = [
            dict(uid=uid, tenant="synthetic", category=category, action=action, role=role, purpose=purpose)
            for category in ("tool-arguments", "tool-result")
            for uid, action, role, purpose in (
                (RECORDER, "capture", "recorder", "evidence-capture"),
                (REVIEWER, "audit", "reviewer", "incident-review"),
                (REVIEWER, "export", "reviewer", "incident-review"),
                (REVIEWER, "summary", "reviewer", "approved-report"),
                (CUSTODIAN, "hold", "custodian", "legal-preservation"),
                (CUSTODIAN, "release", "custodian", "legal-preservation"),
                (CUSTODIAN, "delete", "custodian", "retention-disposition"),
                (OTHER, "audit", "reviewer", "incident-review"),
            )
        ]
        if containment:
            grants.extend(
                dict(uid=uid, tenant="synthetic", category="tool-result", action=action, role=role, purpose=purpose)
                for uid, action, role, purpose in (
                    (RECORDER, "incident", "recorder", "evidence-capture"),
                    (REVIEWER, "incident-summary", "reviewer", "approved-report"),
                )
            )
        _private_file(keyring, {"version": 1, "active": "synthetic", "keys": {"synthetic": secrets.token_hex(32)}}, DAEMON)
        _private_file(policy, {"version": 1, "grants": grants}, DAEMON)
        _ok(_cli(DAEMON, fixture, "evidence", "init", "--store", vault))
        def start_service():
            return _cli(
                DAEMON, fixture, "evidence", "serve", "--store", vault, "--socket", socket,
                "--keyring", keyring, "--policy", policy, "--retention-seconds", "3600", launch=True,
            )

        service = start_service()
        guard = None
        try:
            _wait(lambda: socket.exists() or service.poll() is not None)
            assert service.poll() is None, service.stderr.read().decode() if service.poll() is not None else ""
            script = fixture / "tool.py"
            script.write_text(
                "import json, os, pathlib, sys, time\n"
                "pathlib.Path('child').write_text(str(os.getpid()))\n"
                "for line in sys.stdin.buffer:\n"
                "    request = json.loads(line)\n"
                f"    print({ARGUMENT!r}, file=sys.stderr, flush=True)\n"
                "    if request['id'] == 2:\n"
                "        pathlib.Path('waiting').touch()\n"
                "        while not pathlib.Path('release').exists(): time.sleep(0.02)\n"
                f"    text = {MARKER!r} if {containment!r} and request['id'] in (2, 3) else {RESULT!r}\n"
                "    print(json.dumps(dict(jsonrpc='2.0', id=request['id'], result=dict(content=[dict(type='text',text=text)]))), flush=True)\n"
            )
            phrases = fixture / "phrases.txt"
            phrases.write_text(MARKER + "\n")
            options = (
                ("--contain-incidents", "--inject-phrases", phrases, "--block-inject-phrase-only", phrases)
                if containment else ()
            )

            def start_guard(*flags, launch=True):
                return _cli(
                    RECORDER, work, "guard", "--quiet", "--evidence-socket", socket,
                    "--evidence-service-uid", DAEMON, "--evidence-tenant", "synthetic",
                    *options, *flags, "--", sys.executable, script, launch=launch,
                )

            if containment:
                for flag in ("--audit-only", "--no-block-secret-echo", "--redact-secret-echo"):
                    assert start_guard(flag, launch=False).returncode == 2
                assert not (work / "child").exists()
            guard = start_guard()

            def send(identifier):
                request = dict(jsonrpc="2.0", id=identifier, method="tools/call",
                               params=dict(name="fixture", arguments=dict(value=ARGUMENT)))
                guard.stdin.write((json.dumps(request) + "\n").encode())
                guard.stdin.flush()

            def act(uid, command, *args, purpose="incident-review"):
                return _cli(
                    uid, fixture, "evidence", "act", command, "--socket", socket, "--service-uid", DAEMON,
                    "--tenant", "synthetic", "--category", "tool-result", "--purpose", purpose, *args,
                )

            send(1)
            assert select.select([guard.stdout], [], [], 12)[0]
            result = json.loads(guard.stdout.readline())
            assert "result" in result, result
            assert result["result"]["content"][0]["text"] == RESULT
            audit = act(REVIEWER, "audit")
            _ok(audit)
            audit_result = json.loads(audit.stdout)
            event = audit_result["receipts"][0]["event"]
            assert event["action"] == "capture"
            object_id = event["object_id"]
            assert RESULT.encode() not in audit.stdout
            summary = act(REVIEWER, "summary", purpose="approved-report")
            _ok(summary)
            assert json.loads(summary.stdout)["summary"] == {
                "schema_version": 1, "capture_count_band": "1-9", "review_count_band": "0", "deletion_count_band": "0",
            }
            assert all(value.encode() not in summary.stdout for value in (RESULT, ARGUMENT, object_id, "synthetic"))
            summary_path = fixture / "summary.json"
            summary_path.write_bytes(summary.stdout)
            verification = _cli(DAEMON, fixture, "evidence", "public-key", "--store", vault)
            _ok(verification)
            public_key = verification.stdout.decode().strip()
            assert public_key == audit_result["verification_key"]
            _ok(_cli(OTHER, fixture, "evidence", "verify-summary", "--artifact", summary_path,
                     "--verification-key", public_key))
            assert _cli(OTHER, fixture, "evidence", "verify-summary", "--artifact", summary_path,
                        "--verification-key", "00" * 32).returncode == 2
            assert act(REVIEWER, "summary").returncode == 2
            destination = export / "incident.json"
            assert act(OTHER, "export", "--object-id", object_id, "--output", destination).returncode == 2
            _ok(act(REVIEWER, "export", "--object-id", object_id, "--output", destination))
            assert RESULT in destination.read_text()
            assert destination.stat().st_mode & 0o777 == 0o600
            _ok(act(CUSTODIAN, "hold", "--object-id", object_id, purpose="legal-preservation"))
            assert act(CUSTODIAN, "delete", "--object-id", object_id, purpose="retention-disposition").returncode == 2
            raw_backup = (vault / "vault.sqlite").read_bytes()
            assert ARGUMENT.encode() not in raw_backup and RESULT.encode() not in raw_backup

            if containment:
                blocked_pid = int((work / "child").read_text())
                send(3)
                assert guard.wait(timeout=12) == 3
                blocked_response = guard.stdout.read()
                blocked_error = json.loads(blocked_response)
                assert blocked_error["id"] == 3
                assert blocked_error["error"]["code"] == -32003
                assert blocked_error["error"]["data"] == {
                    "warden": True, "stage": "strict_abort", "site": "local-containment",
                    "reason": "protected session terminated; operator review required",
                }
                assert guard.stderr.read() == b'{"event":"protected_session_terminated"}\n'
                assert MARKER.encode() not in blocked_response
                with pytest.raises(ProcessLookupError):
                    os.kill(blocked_pid, 0)
                _terminate(service)
                service = start_service()
                _wait(lambda: socket.exists() or service.poll() is not None)
                assert service.poll() is None

                audit = act(REVIEWER, "audit")
                _ok(audit)
                incident, = (row["event"] for row in json.loads(audit.stdout)["receipts"]
                             if row["event"]["action"] == "incident")
                incident_id = incident["object_id"]
                assert incident["uid"] == RECORDER
                assert MARKER.encode() not in audit.stdout
                assert MARKER.encode() not in (vault / "vault.sqlite").read_bytes()

                report = act(REVIEWER, "incident-summary", "--object-id", incident_id, purpose="approved-report")
                _ok(report)
                projection = json.loads(report.stdout)["summary"]
                assert set(projection) == {"schema_version", "disposition", "report_id"}
                assert projection["disposition"] == "reported-withheld"
                assert all(value.encode() not in report.stdout for value in (MARKER, incident_id, "synthetic"))
                assert act(OTHER, "incident-summary", "--object-id", incident_id, purpose="approved-report").returncode == 2
                assert act(REVIEWER, "incident-summary", "--object-id", object_id, purpose="approved-report").returncode == 2
                summary_path.write_bytes(report.stdout)
                _ok(_cli(OTHER, fixture, "evidence", "verify-summary", "--incident", "--artifact", summary_path,
                         "--verification-key", public_key))
                assert _cli(OTHER, fixture, "evidence", "verify-summary", "--artifact", summary_path,
                            "--verification-key", public_key).returncode == 2
                incident_export = export / "blocked.json"
                _ok(act(REVIEWER, "export", "--object-id", incident_id, "--output", incident_export))
                assert json.loads(incident_export.read_text()) == {
                    "result": {"content": [{"type": "text", "text": MARKER}]},
                    "finding_codes": ["WRD-RES-INJECT-PHRASE"],
                }

                guard = start_guard()
                send(1)
                assert select.select([guard.stdout], [], [], 12)[0]
                assert json.loads(guard.stdout.readline())["result"]["content"][0]["text"] == RESULT

            send(2)
            _wait(lambda: (work / "waiting").exists())
            _terminate(service)
            assert not socket.exists()
            (work / "release").touch()
            assert guard.wait(timeout=12) == 3
            failure_response = guard.stdout.read()
            assert RESULT.encode() not in failure_response and MARKER.encode() not in failure_response
            failure_stderr = guard.stderr.read()
            assert ARGUMENT.encode() not in failure_stderr
            if containment:
                assert json.loads(failure_response)["error"] == blocked_error["error"]
                assert failure_stderr == b'{"event":"protected_session_terminated"}\n'
        finally:
            if guard is not None:
                _terminate(guard)
            _terminate(service)
