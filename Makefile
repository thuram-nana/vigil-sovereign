# VIGIL — thin convenience targets over bootstrap.sh + docker compose.
# `make setup` on a fresh machine does everything. The rest are day-to-day ops.
.DEFAULT_GOAL := help
SHELL := /bin/bash

.PHONY: help all setup up down services services-down logs smoke strix aegis-image systemd envs egress-guard clean-services bench benchmark bench-perf bench-perf-record

# extra flags for `make up`, e.g.  make up ARGS="--domain vigil.example.com --no-browser"
ARGS ?=
# extra flags for the bootstrap step of `make all`, e.g.  make all BOOTSTRAP_ARGS="--yes --with-strix"
# (a truly non-interactive fresh-machine run needs --yes so Rust/host-tool installs are auto-approved)
BOOTSTRAP_ARGS ?=
# Canonical committed benchmark artifacts live beside the engine, so `make bench` /
# `make benchmark` regenerate exactly the files that ship. BENCH_KEY is a repo-local,
# gitignored signing key that pins a STABLE, reproducible trust-root fingerprint; when it is
# absent (a fresh clone) the CLI mints a fresh key per run and prints its fingerprint to pin
# out-of-band — the committed .sig.json/.fingerprint.txt stay independently verifiable either way.
BENCH_DOCS := engine/crucible/framework/v2/docs
BENCH_KEY  := engine/crucible/framework/v2/eval/baselines/benchmark-scorecard.privkey
# prefer the offense-venv launcher, fall back to `vigil` on PATH (installed by bootstrap.sh)
VIGIL := $(shell if [ -x .venv-offense/bin/vigil ]; then echo .venv-offense/bin/vigil; \
                 elif command -v vigil >/dev/null 2>&1; then echo vigil; fi)

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-14s\033[0m %s\n",$$1,$$2}'

all: ## fresh-machine one-liner: full setup THEN bring the UI up in the browser (= setup + up)
	# Prereqs it does NOT install for you: Python 3.13 (the hash locks target it; bootstrap also accepts
	# 3.12 but the --require-hashes build may then fail on missing cp313 wheels) and, for real
	# containers, Docker (optional — Qdrant has an embedded fallback). Rust auto-installs with consent
	# (use BOOTSTRAP_ARGS=--yes for non-interactive). bootstrap builds both venvs from the hash locks;
	# the sub-make re-resolves the `vigil` launcher it just installed, then opens the UI in the browser.
	./bootstrap.sh $(BOOTSTRAP_ARGS)
	@$(MAKE) up ARGS="$(ARGS)"

setup: ## full one-command setup on a fresh machine (venvs + kernel + services + config + vault + smoke)
	./bootstrap.sh

up: ## bring the WHOLE unified UI up at ONE origin (vigil up; ARGS=... for --domain/--host/--no-browser)
	@[ -n "$(VIGIL)" ] || { echo "vigil not found — run ./bootstrap.sh (or make setup) first" >&2; exit 127; }
	$(VIGIL) up $(ARGS)

bench: ## CRUCIBLE-only SIGNED accuracy scorecard (no external tools) → the canonical committed docs
	@PYTHONPATH=engine/crucible .venv-offense/bin/python -m framework.v2 benchmark --no-incumbents \
	  --report $(BENCH_DOCS)/benchmark-scoreboard.md --json $(BENCH_DOCS)/benchmark-results.json \
	  --sign $$( [ -f $(BENCH_KEY) ] && printf -- '--signing-key %s --key-id benchmark-owner' "$$(cat $(BENCH_KEY))" )

benchmark: ## comparative head-to-head vs installed incumbents (sqlmap/wapiti/nikto) → SIGNED comparative scorecard
	@PYTHONPATH=engine/crucible .venv-offense/bin/python -m framework.v2 benchmark \
	  --report $(BENCH_DOCS)/benchmark-comparative.md --json $(BENCH_DOCS)/benchmark-comparative.json \
	  --sign $$( [ -f $(BENCH_KEY) ] && printf -- '--signing-key %s --key-id benchmark-owner' "$$(cat $(BENCH_KEY))" )

# PERFORMANCE regression gate (issue #423) — the complement to the ACCURACY scorecard above.
# `bench` gates recall/precision; `bench-perf` gates wall-clock / throughput / peak-memory over the
# vigil_core hot integrity paths against a COMMITTED baseline (tools/perf/baselines/perf-baseline.json),
# failing on regression beyond the band. Stdlib-only harness; vigil_core supplies the real cases (needs
# `pip install -e packages/core/vigil_core`, or its deps on PYTHONPATH). See tools/perf/README.md.
bench-perf: ## PERFORMANCE gate: wall-clock/throughput/peak-mem floors over vigil_core hot paths vs committed baseline
	@PYTHONPATH=packages/core/vigil_core python3 tools/perf/perf_bench.py check

bench-perf-record: ## re-record the committed perf baseline (EXPLICIT, reviewed change — COMMIT the diff)
	@PYTHONPATH=packages/core/vigil_core python3 tools/perf/perf_bench.py record

down: ## stop a running `vigil up` (backends + reverse proxy)
	@[ -n "$(VIGIL)" ] || { echo "vigil not found — run ./bootstrap.sh (or make setup) first" >&2; exit 127; }
	$(VIGIL) down

services: ## start the default backend services (Qdrant), bound to 127.0.0.1
	@[ -f .env ] || { cp .env.example .env && chmod 600 .env && echo "wrote .env (0600)"; }
	docker compose --env-file .env up -d qdrant

services-down: ## stop all compose services (data volumes are preserved)
	docker compose down

logs: ## follow the Qdrant logs
	docker compose logs -f qdrant

strix: ## build the local Kali strix sandbox image (large; needs Docker)
	docker compose --profile strix build strix-sandbox

aegis-image: ## build the AEGIS defensive gateway sidecar image (framework/v2/aegis/Dockerfile; needs Docker)
	docker compose --profile aegis build aegis-gateway

systemd: ## install the user systemd units (cockpit + consolidate)
	./bootstrap.sh --systemd

envs: ## (re)build only the two isolated venvs + the Rust kernel (also builds the egress guard)
	bash envs/build_envs.sh

egress-guard: ## build the loopback-only egress guard (seccomp connect(2) supervisor; Linux-only)
	$(MAKE) -C tools/egress-guard

smoke: ## run the boundary + core smoke checks (no pytest needed)
	.venv-sovereign/bin/python -c "import importlib.util as u, sys, sigil, vigil_integration, sigil.reuse; sigil.reuse.assert_no_offense(); [sys.exit('VIOLATION: '+m+' resolvable') for m in ('framework','strix') if u.find_spec(m)]; print('boundary ok')"
	@T=$$(mktemp -d); : > $$T/CLAUDE.md; \
	if CRUCIBLE_ROOT=$$T .venv-offense/bin/vigil provision --slug make-smoke --scope 127.0.0.1 --base-dir $$T >/dev/null; then \
	  rm -rf $$T; echo "vigil (offense native verb) ok"; \
	else \
	  rm -rf $$T; echo "vigil native verb FAILED (offense venv / framework wiring)" >&2; exit 1; \
	fi
	@echo "self-check (advisory deps — Claude/TPM/keyring — do NOT fail it; a REQUIRED control does):"
	SIGIL_HOME=$${SIGIL_HOME:-$$HOME/.sigil} .venv-sovereign/bin/sigil doctor

clean-services: ## stop services AND delete their data volumes (destructive)
	docker compose down -v

deploy-console: ## mirror the console UI + backend to the running-demo tree (VIGIL_DEPLOY_DIR, default /home/kali/vigil) and restart the unit
	bash tools/deploy-console.sh
