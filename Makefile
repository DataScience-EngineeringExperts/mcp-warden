# mcp-warden developer tasks. Run everything through the repo .venv (CONTRIBUTING.md):
# the system Python may be polluted by an unrelated global conftest.py.
PY ?= ./.venv/bin/python

.PHONY: test fuzz fuzz-ci help

help:
	@echo "make test     - full test suite (repo .venv)"
	@echo "make fuzz      - deep property-fuzz soak (20k examples/property, persistent DB)"
	@echo "make fuzz-ci   - the deterministic ci-profile fuzz run CI uses (seed=0)"

# Full suite (the supported path).
test:
	$(PY) -m pytest -q

# Deep local soak: the 'fuzz' hypothesis profile (20k examples + persistent DB).
# Use this to hunt new counterexamples; freeze any finding as an @example.
fuzz:
	HYPOTHESIS_PROFILE=fuzz $(PY) -m pytest tests/fuzz -p no:randomly

# The deterministic, replayable fuzz run that CI executes (ci profile + fixed seed).
fuzz-ci:
	$(PY) -m pytest tests/fuzz -p no:randomly --hypothesis-seed=0
