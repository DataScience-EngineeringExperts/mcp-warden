"""Supervisor faults plus opt-in real Linux image qualification.

Set NORMALIZER_TEST_IMAGE to the exact built image ID to qualify that artifact;
unit success without that setting does not establish functional isolation.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from mcp_warden import normalization_sandbox as sandbox
from mcp_warden.normalization_ipc import NormalizationError, encode_message
from mcp_warden.normalization_models import NormalizationProfileV1


def test_fixed_command_has_no_ambient_configuration():
    command = sandbox._create_command("fixed", "sha256:" + "a" * 64)
    for control in ("--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                    "--memory=268435456", "--memory-swap=268435456", "--pids-limit=16",
                    "--cpus=1", "--user=10001:10001", "--ulimit=cpu=2:2",
                    "--security-opt=no-new-privileges=true", "--log-driver=none"):
        assert control in command
    assert command[:3] == list(sandbox._DOCKER)
    assert not any(option.startswith(("--env", "--mount", "--volume")) for option in command)


def test_unsupported_platform_refuses(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(NormalizationError, match="NRM-SANDBOX"):
        sandbox.run_worker({}, NormalizationProfileV1("sha256:" + "a" * 64))


@pytest.mark.parametrize("script,code", [
    ("import time; time.sleep(1)", "NRM-TIMEOUT"),
    ("import sys; sys.stdout.buffer.write(b'\\x00\\x01\\x00\\x01')", "NRM-OVER-CAP"),
    ("import sys; sys.stdout.buffer.write(b'\\0'*4+b'x')", "NRM-PROTOCOL"),
    ("import sys; sys.stderr.write('private payload'); sys.exit(1)", "NRM-WORKER"),
    ("import sys; sys.stderr.write('x'*100000)", "NRM-OVER-CAP"),
])
def test_bounded_exchange_never_returns_errors(script, code):
    with pytest.raises(NormalizationError, match=code) as caught:
        sandbox._exchange([sys.executable, "-c", script], b"", time.monotonic() + .2,
                          sandbox._WIRE_LIMIT, framed=True)
    assert str(caught.value) == code


def test_exchange_handles_backpressure_without_deadlock():
    script = "import sys; sys.stdout.buffer.write(b'x'*65536); sys.stdout.flush(); sys.stdin.buffer.read()"
    assert len(sandbox._exchange([sys.executable, "-c", script], b"y" * 100000,
                                time.monotonic() + 3, 65536)) == 65536


def test_failed_inspection_still_removes_container(monkeypatch):
    calls = []

    def exchange(command, *_args, **_kwargs):
        calls.append(command)
        if "inspect" in command:
            return b"[]"
        return b""

    monkeypatch.setattr(sandbox, "_exchange", exchange)
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(NormalizationError, match="NRM-SANDBOX"):
        sandbox.run_worker({}, NormalizationProfileV1("sha256:" + "a" * 64))
    assert calls[-1][3:5] == ["rm", "--force"]
    assert calls[-1][-1] == calls[0][5]


@pytest.fixture
def qualified_image():
    image = os.environ.get("NORMALIZER_TEST_IMAGE")
    if sys.platform != "linux" or not image:
        pytest.skip("real isolation qualification requires Linux and exact NORMALIZER_TEST_IMAGE")
    return NormalizationProfileV1(image)


def _probe(monkeypatch, profile, script):
    bootstrap = sandbox._BOOTSTRAP.rsplit("runpy.run_path", 1)[0]
    # Test-only hostile worker replacement; the public API accepts no commands.
    monkeypatch.setattr(sandbox, "_BOOTSTRAP", bootstrap + script)
    return sandbox.run_worker({}, profile)


def test_real_isolation_and_credential_denial(monkeypatch, qualified_image):
    monkeypatch.setenv("WARDEN_HOST_SECRET", "test-only-ambient-canary")
    script = """
import socket, sys, json, struct
assert not os.environ
for path in ('/home/ubuntu/.aws/credentials', '/home/ubuntu/dev/aws_configure/.env', '/var/run/docker.sock'):
    assert not Path(path).exists()
for address in ('1.1.1.1', '169.254.169.254'):
    s = socket.socket(); s.settimeout(.1)
    try:
        s.connect((address, 80))
        raise AssertionError('network unexpectedly available')
    except OSError:
        pass
    finally:
        s.close()
try:
    Path('/worker/write-test').write_text('forbidden')
    raise AssertionError('writable root')
except OSError:
    pass
b = b'{"qualified":true}'
sys.stdout.buffer.write(struct.pack('>I', len(b)) + b + bytes(4))
"""
    assert _probe(monkeypatch, qualified_image, script) == {"qualified": True}


@pytest.mark.parametrize("script", [
    "while True: pass",
    "import time; time.sleep(30)",
    "a = bytearray(400 * 1024 * 1024)",
    "import sys; sys.stdout.buffer.write(bytes.fromhex('ffffffff'))",
    "import sys; sys.stderr.write('x'*100000)",
    "import sys; sys.stdout.buffer.write(bytes(4)+b'extra')",
    "import sys; sys.stdout.buffer.write(b'\\x00\\x00\\x00\\x10incomplete')",
])
def test_real_hostile_worker_refuses_and_cleans_up(monkeypatch, qualified_image, script):
    before = subprocess.check_output([*sandbox._DOCKER, "ps", "-aq", "--filter", "name=mcp-warden-normalizer-"])
    with pytest.raises(NormalizationError):
        _probe(monkeypatch, qualified_image, script)
    after = subprocess.check_output([*sandbox._DOCKER, "ps", "-aq", "--filter", "name=mcp-warden-normalizer-"])
    assert after == before


def test_real_pid_limit(monkeypatch, qualified_image):
    script = """
import subprocess, sys, struct
children = []
try:
    for _ in range(32):
        children.append(subprocess.Popen(['/usr/local/bin/python3', '-I', '-c', 'import time;time.sleep(2)']))
    raise AssertionError('pids unlimited')
except BlockingIOError:
    pass
finally:
    for child in children:
        child.kill(); child.wait()
b = b'{"pids_bounded":true}'
sys.stdout.buffer.write(struct.pack('>I',len(b))+b+bytes(4))
"""
    assert _probe(monkeypatch, qualified_image, script) == {"pids_bounded": True}


def test_real_worker_protocol(qualified_image):
    import base64
    from dataclasses import asdict

    request = {"schema_version": 1, "profile_id": qualified_image.profile_id,
               "content_b64": base64.b64encode(b"hello").decode(),
               "media_type": "text/plain", "budget": asdict(qualified_image.budget)}
    response = sandbox.run_worker(request, qualified_image)
    assert response["status"] == "structurally-complete"
    assert response["segments"][0]["text"] == "hello"
    assert encode_message(response)
