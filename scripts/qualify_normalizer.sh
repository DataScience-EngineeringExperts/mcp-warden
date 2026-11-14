#!/usr/bin/env bash
# Reproducible consumer qualification; never installs or weakens host controls.
set -euo pipefail
cd "$(dirname "$0")/.."
normalizer_image=${1:?supply the exact locally built sha256 image ID}
[[ $(uname -s) == Linux && $normalizer_image =~ ^sha256:[a-f0-9]{64}$ ]]
python - <<'PY'
import sys, unicodedata, pypdf
assert sys.version_info[:2] == (3, 12)
assert unicodedata.unidata_version == '15.0.0'
assert pypdf.__version__ == '7.1.0'
PY
normalizer_claim=''
if command -v dse-artifacts >/dev/null 2>&1; then
  : "${DSE_NORMALIZER_SESSION_ID:?supply the actual current session ID for the builder artifact ledger}"
  dse-artifacts ack --session "$DSE_NORMALIZER_SESSION_ID" --harness qa --version 1 >/dev/null
  normalizer_claim=$(dse-artifacts protect --kind image --ref "$normalizer_image" \
    --repo "$(git rev-parse --show-toplevel)" --worktree "$PWD" --commit "$(git rev-parse HEAD)" \
    --session "$DSE_NORMALIZER_SESSION_ID" --harness qa --purpose qa --classification reproducible \
    | python -c 'import json,sys; print(json.load(sys.stdin)["result"]["claim_file"])')
  trap 'dse-artifacts release --claim-file "$normalizer_claim" >/dev/null' EXIT
fi
export NORMALIZER_TEST_IMAGE="$normalizer_image"
python -m pytest -q tests/test_normalization_contract.py tests/test_normalization_coordinator.py \
  tests/test_normalization_integration.py tests/test_normalizer_formats.py \
  tests/test_normalization_sandbox.py tests/test_normalization_e2e.py
