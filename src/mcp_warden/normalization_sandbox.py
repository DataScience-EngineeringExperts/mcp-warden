"""Linux-only, fail-closed Docker supervisor for the immutable parser image.

The local Docker daemon and reviewed image are trusted. No caller-supplied
command, mount, environment, daemon endpoint or executable is accepted.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .normalization_ipc import (
    MAX_FRAME,
    MAX_MESSAGE,
    NormalizationError,
    decode_message,
    encode_message,
)
from .normalization_models import NormalizationProfileV1

_DOCKER = ("/usr/bin/docker", "--host=unix:///var/run/docker.sock", "--config=/nonexistent")
_WALL_SECONDS = 5.0
_WIRE_LIMIT = MAX_MESSAGE + (MAX_MESSAGE // MAX_FRAME + 1) * 4
_MEMORY = 256 * 1024 * 1024
# Checks run in the same isolated process immediately before the parser. A
# daemon ignoring a required isolation control must fail closed, not qualify.
_BOOTSTRAP = """
import os, resource, runpy
from pathlib import Path
# CPython can synthesize LC_CTYPE while coercing its initially empty locale.
assert set(os.environ) <= {'LC_CTYPE'}
os.environ.clear()
s = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert os.getuid() == os.getgid() == 10001
assert os.getpid() == 1
assert not os.environ
assert int(s['CapEff'].strip(), 16) == 0
assert s['NoNewPrivs'].strip() == '1' and s['Seccomp'].strip() == '2'
assert set(os.listdir('/sys/class/net')) == {'lo'}
assert Path('/sys/fs/cgroup/memory.max').read_text().strip() == '268435456'
assert Path('/sys/fs/cgroup/memory.swap.max').read_text().strip() == '0'
assert Path('/sys/fs/cgroup/pids.max').read_text().strip() == '16'
assert Path('/sys/fs/cgroup/cpu.max').read_text().strip() == '100000 100000'
assert resource.getrlimit(resource.RLIMIT_CPU) == (2, 2)
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
assert os.statvfs('/').f_flag & os.ST_RDONLY
assert not Path('/var/run/docker.sock').exists()
runpy.run_path('/worker/worker.py', run_name='__main__')
"""


def _create_command(name: str, image: str) -> list[str]:
    return [*_DOCKER, "create", "--name", name, "--pull=never", "--network=none",
            "--ipc=none", "--cgroupns=private",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
            "--user=10001:10001", "--pids-limit=16", "--memory=268435456",
            "--memory-swap=268435456", "--cpus=1", "--ulimit=cpu=2:2",
            "--ulimit=nofile=64:64", "--ulimit=core=0:0", "--restart=no",
            "--stop-timeout=0", "--log-driver=none", "--no-healthcheck",
            "--hostname=normalizer", "--workdir=/worker", "--interactive",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=700,uid=10001,gid=10001",
            "--entrypoint=/usr/bin/env", image, "-i", "/usr/local/bin/python3",
            "-I", "-B", "-c", _BOOTSTRAP]


def _exchange(command: list[str], data: bytes, deadline: float, limit: int,
              *, framed: bool = False, container_id: str | None = None) -> bytes:
    """Drain both pipes while writing; cap output before any unbounded allocation."""
    process = None
    output = bytearray()
    stderr_bytes = offset = checked = remaining = 0
    terminal = False
    started = time.monotonic()
    cpu_seen = False
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env={}, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            for pipe in (process.stdout, process.stderr):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            if data:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while selector.get_map():
                if container_id:
                    # These are the two qualified Docker cgroup-v2 layouts. A
                    # host with another layout refuses rather than losing the
                    # root-cumulative CPU ceiling. The parser cannot write them.
                    for directory in (f"system.slice/docker-{container_id}.scope", f"docker/{container_id}"):
                        counter = Path("/sys/fs/cgroup", directory, "cpu.stat")
                        try:
                            usage = dict(line.split() for line in counter.read_text().splitlines())
                        except FileNotFoundError:
                            continue
                        cpu_seen = True
                        if int(usage["usage_usec"]) >= 2_000_000:
                            raise NormalizationError("NRM-CPU")
                        break
                    if not cpu_seen and time.monotonic() - started >= 1:
                        raise NormalizationError("NRM-SANDBOX")
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    raise NormalizationError("NRM-TIMEOUT")
                for key, _ in selector.select(min(timeout, 0.05)):
                    pipe = key.fileobj
                    if pipe is process.stdin:
                        try:
                            offset += os.write(pipe.fileno(), data[offset:offset + MAX_FRAME])
                        except BrokenPipeError:
                            offset = len(data)
                        if offset == len(data):
                            selector.unregister(pipe)
                            pipe.close()
                        continue
                    chunk = os.read(pipe.fileno(), MAX_FRAME)
                    if not chunk:
                        selector.unregister(pipe)
                        pipe.close()
                        continue
                    if pipe is process.stderr:
                        stderr_bytes += len(chunk)
                        if stderr_bytes > MAX_FRAME:
                            raise NormalizationError("NRM-OVER-CAP")
                        continue
                    if len(output) + len(chunk) > limit:
                        raise NormalizationError("NRM-OVER-CAP")
                    output.extend(chunk)
                    if framed:
                        while checked < len(output):
                            if terminal:
                                raise NormalizationError("NRM-PROTOCOL")
                            if remaining:
                                amount = min(remaining, len(output) - checked)
                                checked += amount
                                remaining -= amount
                            elif len(output) - checked >= 4:
                                remaining = int.from_bytes(output[checked:checked + 4], "big")
                                checked += 4
                                if remaining > MAX_FRAME:
                                    raise NormalizationError("NRM-OVER-CAP")
                                terminal = remaining == 0
                            else:
                                break
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise NormalizationError("NRM-TIMEOUT")
            if process.wait(timeout=timeout) != 0 or stderr_bytes:
                raise NormalizationError("NRM-WORKER")
        return bytes(output)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise NormalizationError("NRM-SANDBOX") from None
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=1)
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()


def _inspect_container(name: str, image: str, deadline: float) -> str:
    try:
        info, = json.loads(_exchange([*_DOCKER, "inspect", name], b"", deadline, MAX_FRAME))
        host, config = info["HostConfig"], info["Config"]
        controls = (
            info["Image"] == image,
            config["User"] == "10001:10001" and config["WorkingDir"] == "/worker",
            config["Entrypoint"] == ["/usr/bin/env"],
            config["Cmd"] == ["-i", "/usr/local/bin/python3", "-I", "-B", "-c", _BOOTSTRAP],
            not info["Mounts"] and not host["Binds"] and not host["Privileged"],
            host["ReadonlyRootfs"] and host["NetworkMode"] == "none",
            host["CapDrop"] == ["ALL"] and not host["CapAdd"],
            host["SecurityOpt"] == ["no-new-privileges=true"],
            host["Memory"] == host["MemorySwap"] == _MEMORY,
            host["NanoCpus"] == 1_000_000_000 and host["PidsLimit"] == 16,
            host["PidMode"] == host["UTSMode"] == "" and host["CgroupnsMode"] == "private",
            host["IpcMode"] == "none" and host["LogConfig"]["Type"] == "none",
            not host.get("Devices") and not host.get("DeviceRequests"),
        )
        if not all(controls):
            raise NormalizationError("NRM-SANDBOX")
        if not re.fullmatch(r"[a-f0-9]{64}", info["Id"]):
            raise NormalizationError("NRM-SANDBOX")
        return info["Id"]
    except (ValueError, TypeError, KeyError):
        raise NormalizationError("NRM-SANDBOX") from None


def run_worker(request: dict, profile: NormalizationProfileV1) -> dict:
    """Run a reviewed image with fixed controls; every failure refuses delivery."""
    if (sys.platform != "linux" or type(profile) is not NormalizationProfileV1
            or type(profile.image_digest) is not str
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", profile.image_digest)):
        raise NormalizationError("NRM-SANDBOX")
    payload = encode_message(request)
    name = "mcp-warden-normalizer-" + uuid.uuid4().hex
    deadline = time.monotonic() + _WALL_SECONDS
    try:
        _exchange(_create_command(name, profile.image_digest), b"", deadline, MAX_FRAME)
        container_id = _inspect_container(name, profile.image_digest, deadline)
        response = _exchange([*_DOCKER, "start", "--attach", "--interactive", name],
                             payload, deadline, _WIRE_LIMIT, framed=True, container_id=container_id)
        return decode_message(response)
    finally:
        # Killing the CLI alone leaves a parser running inside the daemon. Use
        # the private random name even if create timed out before returning an ID.
        try:
            _exchange([*_DOCKER, "rm", "--force", name], b"",
                      time.monotonic() + 3, MAX_FRAME)
        except NormalizationError:
            raise NormalizationError("NRM-SANDBOX") from None
