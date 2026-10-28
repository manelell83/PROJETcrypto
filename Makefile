# Thin wrapper around tools/run.py (which also works on Windows without make).
PY ?= python

.PHONY: setup lint test kat lab-up lab-down demo scenario audit fuzz exp report

setup lint test kat lab-up lab-down demo scenario audit:
	$(PY) tools/run.py $@

fuzz exp report:
	@echo "target '$@' is not implemented yet (see docs/status.md)"; exit 2
