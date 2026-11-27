"""Synthetic key custody and authenticated Linux socket regressions."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

import pytest

from mcp_warden.evidence_key_service import (
    _LENGTH,
    _MAX_FRAME,
    MAX_EVIDENCE_BYTES,
    EvidenceKeyServiceError,
    LocalKeyAccess,
    LocalKeyService,
    LocalServiceClient,
    _load_keyring,
    _load_policy,
    _receive,
    decode_payload,
    encode_payload,
)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux Unix credential boundary")

_RECORDER_UID = 65533
_REVIEWER_UID = 65532
_DAEMON_UID = 65534
_SCOPE = {"tenant": "acme", "object_id": "opaque-1", "category": "tool-result"}
_READ = {"action": "read", "role": "reviewer", "purpose": "investigation"}
_TEST_PAYLOAD = b"synthetic tool result for local evidence testing"


def _write_config(path: Path, value: dict[str, object]) -> Path:
    path.write_text(json.dumps({"version": 1, **value}))
    path.chmod(0o600)
    return path


def _key_config(private: Path, *, active: str = "k1", old: bool = True) -> Path:
    key_material = {"k2": "02" * 32}
    if old:
        key_material["k1"] = "01" * 32
    return _write_config(private / "keyring.json", {"active": active, "keys": key_material})


def _policy_config(private: Path) -> Path:
    result_scope = {"tenant": "acme", "category": "tool-result"}
    grants = [
        {
            **result_scope,
            "uid": _RECORDER_UID,
            "action": "capture",
            "role": "recorder",
            "purpose": "evidence-capture",
        },
        {**result_scope, "uid": _REVIEWER_UID, **_READ},
    ]
    return _write_config(private / "policy.json", {"grants": grants})


def test_incident_policy_requires_result_capture_and_a_separate_reviewer(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    policy = _policy_config(private)
    capture, reviewer = json.loads(policy.read_text())["grants"]
    incident = {**capture, "action": "incident"}
    report = {**reviewer, "action": "incident-summary"}
    for rows in (
        [incident],
        [incident, {**capture, "category": "tool-arguments"}],
        [capture, incident, {**report, "uid": _RECORDER_UID}],
        [capture, incident, {**reviewer, "uid": _RECORDER_UID}],
    ):
        _write_config(policy, {"grants": rows})
        with pytest.raises(EvidenceKeyServiceError):
            _load_policy(policy)
    _write_config(policy, {"grants": [capture, incident, reviewer, report]})
    assert len(_load_policy(policy)) == 4


def test_key_rotation_and_context_authentication(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    policy = _policy_config(private)
    rows = json.loads(policy.read_text())["grants"]
    reviewer_grant = rows[1]
    _write_config(
        policy,
        {
            "grants": [
                *rows,
                {**reviewer_grant, "tenant": "not-acme"},
                {**reviewer_grant, "category": "tool-arguments"},
            ]
        },
    )
    grants = _load_policy(policy)
    keys = _load_keyring(_key_config(private))
    recorder = LocalKeyAccess(_RECORDER_UID, grants, keys)
    reviewer = LocalKeyAccess(_REVIEWER_UID, grants, keys)
    ciphertext = recorder.encrypt(**_SCOPE, plaintext=_TEST_PAYLOAD)

    assert _TEST_PAYLOAD not in ciphertext
    assert recorder.encrypt(**_SCOPE, plaintext=_TEST_PAYLOAD) != ciphertext
    assert reviewer.decrypt(**_SCOPE, ciphertext=ciphertext, **_READ) == _TEST_PAYLOAD
    for attributes in (
        {"object_id": "substituted"},
        {"tenant": "not-acme"},
        {"category": "tool-arguments"},
    ):
        arguments = {**_SCOPE, **attributes}
        with pytest.raises(EvidenceKeyServiceError, match="authenticate"):
            reviewer.decrypt(**arguments, ciphertext=ciphertext, **_READ)
    for attributes in ({"role": "custodian"}, {"purpose": "other-purpose"}):
        arguments = {**_READ, **attributes}
        with pytest.raises(EvidenceKeyServiceError):
            reviewer.decrypt(**_SCOPE, ciphertext=ciphertext, **arguments)
    with pytest.raises(EvidenceKeyServiceError):
        recorder.decrypt(**_SCOPE, ciphertext=ciphertext, **_READ)
    with pytest.raises(EvidenceKeyServiceError):
        reviewer.encrypt(**_SCOPE, plaintext=_TEST_PAYLOAD)
    for altered in (ciphertext[:-1], ciphertext[:2] + b"k2" + ciphertext[4:]):
        with pytest.raises(EvidenceKeyServiceError, match="authenticate"):
            reviewer.decrypt(**_SCOPE, ciphertext=altered, **_READ)

    rotated = _load_keyring(_key_config(private, active="k2"))
    new_recorder = LocalKeyAccess(_RECORDER_UID, grants, rotated)
    new_reviewer = LocalKeyAccess(_REVIEWER_UID, grants, rotated)
    assert new_recorder.encrypt(**_SCOPE, plaintext=_TEST_PAYLOAD)[2:4] == b"k2"
    assert new_reviewer.decrypt(**_SCOPE, ciphertext=ciphertext, **_READ) == _TEST_PAYLOAD
    retired = _load_keyring(_key_config(private, active="k2", old=False))
    with pytest.raises(EvidenceKeyServiceError, match="authenticate"):
        LocalKeyAccess(_REVIEWER_UID, grants, retired).decrypt(
            **_SCOPE, ciphertext=ciphertext, **_READ
        )


def test_rejects_missing_keys_and_unsafe_service_files(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = _key_config(private, active="missing")
    with pytest.raises(EvidenceKeyServiceError, match="active"):
        _load_keyring(path)
    _write_config(path, {"active": "k1", "keys": {"k1": "01" * 32, "k2": "01" * 32}})
    with pytest.raises(EvidenceKeyServiceError, match="distinct"):
        _load_keyring(path)
    _key_config(private)
    path.chmod(0o640)
    with pytest.raises(EvidenceKeyServiceError, match="configuration file"):
        _load_keyring(path)
    path.chmod(0o600)
    hardlink = private / "hardlink"
    hardlink.hardlink_to(path)
    with pytest.raises(EvidenceKeyServiceError, match="configuration file"):
        _load_keyring(path)
    hardlink.unlink()
    symlink = private / "symlink"
    symlink.symlink_to(path)
    with pytest.raises(EvidenceKeyServiceError, match="unavailable"):
        _load_keyring(symlink)
    alias = tmp_path / "alias"
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(EvidenceKeyServiceError, match="unavailable"):
        _load_keyring(alias / path.name)
    private.chmod(0o750)
    with pytest.raises(EvidenceKeyServiceError, match="configuration directory"):
        _load_keyring(path)
    private.chmod(0o700)
    path.unlink()
    with pytest.raises(EvidenceKeyServiceError, match="unavailable"):
        _load_keyring(path)
    assert not path.exists()


def test_policy_requires_separate_uid_role_and_purpose(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    policy = _policy_config(private)
    grants = json.loads(policy.read_text())["grants"]
    for changes in (
        {"uid": os.geteuid()},
        {"uid": 0},
        {"uid": True},
        {"role": "reviewer"},
        {"purpose": "different-capture-purpose"},
        {"tenant": "*"},
    ):
        _write_config(policy, {"grants": [{**grants[0], **changes}]})
        with pytest.raises(EvidenceKeyServiceError):
            _load_policy(policy)
    _write_config(policy, {"grants": [grants[1], grants[1]]})
    with pytest.raises(EvidenceKeyServiceError, match="duplicate"):
        _load_policy(policy)


def test_frame_and_payload_limits() -> None:
    sender, receiver = socket.socketpair()
    with sender, receiver:
        sender.sendall(_LENGTH.pack(_MAX_FRAME + 1))
        with pytest.raises(EvidenceKeyServiceError, match="length"):
            _receive(receiver)
        malformed = b'{"version":1,"version":1}'
        sender.sendall(_LENGTH.pack(len(malformed)) + malformed)
        with pytest.raises(EvidenceKeyServiceError, match="duplicate"):
            _receive(receiver)
    assert decode_payload(encode_payload(b"x" * MAX_EVIDENCE_BYTES)) == b"x" * MAX_EVIDENCE_BYTES
    with pytest.raises(EvidenceKeyServiceError):
        encode_payload(b"x" * (MAX_EVIDENCE_BYTES + 1))
    with pytest.raises(EvidenceKeyServiceError):
        decode_payload("invalid base64")


def test_wrong_daemon_uid_receives_no_client_content() -> None:
    with tempfile.TemporaryDirectory(prefix="wkv-") as workspace:
        path = Path(workspace) / "listen.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wrong_daemon:
            wrong_daemon.bind(str(path))
            wrong_daemon.listen(1)
            different = _DAEMON_UID if os.geteuid() != _DAEMON_UID else _REVIEWER_UID
            client = LocalServiceClient(path, service_uid=different)
            with pytest.raises(EvidenceKeyServiceError, match="identity mismatch"):
                client.request({"payload": encode_payload(_TEST_PAYLOAD)})
            connection, _ = wrong_daemon.accept()
            with connection:
                connection.settimeout(1)
                assert connection.recv(1) == b""


def _become(uid: int, shared_group: int) -> None:
    os.setgroups([])
    os.setgid(shared_group)
    os.setuid(uid)


def _wait_success(pid: int) -> None:
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0


@pytest.mark.skipif(
    getattr(os, "geteuid", lambda: -1)() != 0,
    reason="real credential separation requires UID switching",
)
def test_kernel_credentials_with_distinct_daemon_and_client_accounts() -> None:
    # Load the Python modules before a child drops access to the test runner's virtualenv.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    assert AESGCM is not None
    group = 65531
    with tempfile.TemporaryDirectory(prefix="wkv-") as workspace:
        top = Path(workspace)
        top.chmod(0o755)
        private = top / "private"
        runtime = top / "run"
        private.mkdir(mode=0o700)
        runtime.mkdir()
        keys = _key_config(private)
        policy = _policy_config(private)
        for path in (keys, policy, private, runtime):
            os.chown(path, _DAEMON_UID, group)
        runtime.chmod(0o2750)
        endpoint = runtime / "warden.sock"

        def dispatch(payload: dict[str, object], access: LocalKeyAccess) -> dict[str, object]:
            if payload == {"operation": "store-local", "payload": encode_payload(_TEST_PAYLOAD)}:
                ciphertext = access.encrypt(**_SCOPE, plaintext=decode_payload(payload["payload"]))
                return {"uid": access.peer_uid, "protected": _TEST_PAYLOAD not in ciphertext}
            raise EvidenceKeyServiceError("unexpected fixture operation")

        daemon = os.fork()
        if daemon == 0:
            try:
                _become(_DAEMON_UID, group)
                with LocalKeyService(
                    endpoint, keyring_path=keys, policy_path=policy, dispatch=dispatch
                ) as service:
                    service.serve_once(timeout=5)
                    service.serve_once(timeout=5)
            except BaseException:
                os._exit(1)
            os._exit(0)

        try:
            for _ in range(100):
                if endpoint.exists():
                    break
                time.sleep(0.02)
            assert endpoint.exists()
            for uid, has_grant in ((_RECORDER_UID, True), (65530, False)):
                client = os.fork()
                if client == 0:
                    try:
                        _become(uid, group)
                        with pytest.raises(PermissionError):
                            keys.read_bytes()
                        requester = LocalServiceClient(endpoint, service_uid=_DAEMON_UID)
                        request = {
                            "operation": "store-local",
                            "payload": encode_payload(_TEST_PAYLOAD),
                        }
                        if has_grant:
                            assert requester.request(request) == {"uid": uid, "protected": True}
                        else:
                            with pytest.raises(EvidenceKeyServiceError):
                                requester.request(request)
                    except BaseException:
                        os._exit(1)
                    os._exit(0)
                _wait_success(client)
        finally:
            _wait_success(daemon)
        assert not endpoint.exists()
