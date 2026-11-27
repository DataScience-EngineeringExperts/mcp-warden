# Official Python 3.12.16 slim-bookworm linux/amd64 manifest, reviewed 2026-11-14.
FROM python:3.12.16-slim-bookworm@sha256:0f086103b026048cc50cb5da25ec435c023c5241a83fc44daea593377abc61c4

COPY components/normalizer/requirements.lock /worker/requirements.lock
RUN python -m pip install --no-cache-dir --no-compile --require-hashes \
      --only-binary=:all: --no-deps -r /worker/requirements.lock
COPY components/normalizer/*.py /worker/
COPY src/mcp_warden/normalization_ipc.py /worker/normalization_ipc.py
COPY LICENSE /worker/LICENSE
COPY components/normalizer/THIRD_PARTY_NOTICES.md /worker/THIRD_PARTY_NOTICES.md
WORKDIR /worker
USER 10001:10001
ENTRYPOINT ["/usr/bin/env", "-i", "/usr/local/bin/python3", "-I", "-B", "/worker/worker.py"]
