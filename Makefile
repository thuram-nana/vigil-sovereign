# CRUCIBLE benchmark + regression targets.
#
# The credibility spine: `make gate` runs the labelled in-process benchmark and
# fails CI on any regression in CRUCIBLE's accuracy (a new false positive, a
# newly-missed finding, or a precision drop) against the committed baseline. It
# needs no Docker and no external tools, so it runs anywhere.
#
# The dockerized multi-app corpus (`make bench-corpus`) is the operator's
# extension — it pulls/builds real vulnerable + real-production apps and scores
# CRUCIBLE against their ground truth, skipping heavy/unavailable apps honestly.

PY := python3
V2 := $(PY) -m framework.v2

.PHONY: gate bench bench-corpus gate-corpus baseline test help

help:
	@echo "make gate          - regression-gate CRUCIBLE on the in-process benchmark (CI; no Docker)"
	@echo "make bench         - run the in-process benchmark, print the table, write the report"
	@echo "make bench-corpus  - run the dockerized multi-app corpus (needs Docker; skips heavy)"
	@echo "make gate-corpus   - regression-gate the dockerized corpus against a baseline"
	@echo "make baseline      - regenerate the committed in-process baseline (accept new numbers)"
	@echo "make test          - run the full framework/v2 test suite"

# CI gate: exit non-zero on any CRUCIBLE regression. CRUCIBLE-only for determinism
# (incumbent tools vary by host and are not a pass/fail signal).
gate:
	$(V2) benchmark --gate --no-incumbents

# Full public benchmark: CRUCIBLE vs whatever incumbents are installed here.
bench:
	$(V2) benchmark --report benchmark-report.md

# Dockerized corpus (operator; needs a working Docker daemon).
bench-corpus:
	$(V2) benchmark --corpus

gate-corpus:
	$(V2) benchmark --corpus --gate --baseline eval-corpus-baseline.json

# Accept this run's numbers as the new committed baseline.
baseline:
	$(V2) benchmark --update-baseline --no-incumbents

test:
	$(PY) -m pytest framework/v2 -q

# Loopback, read-only operator console (a UI over the artifacts; never in the hot path).
console:
	$(V2) console --open
