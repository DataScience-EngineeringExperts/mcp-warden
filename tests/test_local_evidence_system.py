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


def test_real_cli_and_vault_over_distinct_unix_peers():
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
        _private_file(keyring, {"version": 1, "active": "synthetic", "keys": {"synthetic": secrets.token_hex(32)}}, DAEMON)
        _private_file(policy, {"version": 1, "grants": grants}, DAEMON)
        _ok(_cli(DAEMON, fixture, "evidence", "init", "--store", vault))
        service = _cli(
            DAEMON, fixture, "evidence", "serve", "--store", vault, "--socket", socket,
            "--keyring", keyring, "--policy", policy, "--retention-seconds", "3600", launch=True,
        )
        guard = None
        try:
            _wait(lambda: socket.exists() or service.poll() is not None)
            assert service.poll() is None, service.stderr.read().decode() if service.poll() is not None else ""
            script = fixture / "tool.py"
            script.write_text(
                "import json, pathlib, sys, time\n"
                "for line in sys.stdin.buffer:\n"
                "    request = json.loads(line)\n"
                f"    print({ARGUMENT!r}, file=sys.stderr, flush=True)\n"
                "    if request['id'] == 2:\n"
                "        pathlib.Path('waiting').touch()\n"
                "        while not pathlib.Path('release').exists(): time.sleep(0.02)\n"
                f"    print(json.dumps(dict(jsonrpc='2.0', id=request['id'], result=dict(content=[dict(type='text',text={RESULT!r})]))), flush=True)\n"
            )
            guard = _cli(
                RECORDER, work, "guard", "--quiet", "--evidence-socket", socket, "--evidence-service-uid", DAEMON,
                "--evidence-tenant", "synthetic", "--", sys.executable, script, launch=True,
            )
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

            send(2)
            _wait(lambda: (work / "waiting").exists())
            _terminate(service)
            assert not socket.exists()
            (work / "release").touch()
            assert guard.wait(timeout=12) == 3
            assert RESULT.encode() not in guard.stdout.read()
            assert ARGUMENT.encode() not in guard.stderr.read()
        finally:
            if guard is not None:
                _terminate(guard)
            _terminate(service)
