# VIGIL — thin convenience targets over bootstrap.sh + docker compose.
# `make setup` on a fresh machine does everything. The rest are day-to-day ops.
.DEFAULT_GOAL := help
SHELL := /bin/bash

.PHONY: help setup up down logs smoke strix systemd envs clean-services

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-14s\033[0m %s\n",$$1,$$2}'

setup: ## full one-command setup on a fresh machine (venvs + kernel + services + config + vault + smoke)
	./bootstrap.sh

up: ## start the default backend services (Qdrant), bound to 127.0.0.1
	@[ -f .env ] || { cp .env.example .env && chmod 600 .env && echo "wrote .env (0600)"; }
	docker compose --env-file .env up -d qdrant

down: ## stop all compose services (data volumes are preserved)
	docker compose down

logs: ## follow the Qdrant logs
	docker compose logs -f qdrant

strix: ## build the local Kali strix sandbox image (large; needs Docker)
	docker compose --profile strix build strix-sandbox

systemd: ## install the user systemd units (cockpit + consolidate)
	./bootstrap.sh --systemd

envs: ## (re)build only the two isolated venvs + the Rust kernel
	bash envs/build_envs.sh

smoke: ## run the boundary + core smoke checks (no pytest needed)
	.venv-sovereign/bin/python -c "import importlib.util as u, sys, sigil, vigil_integration, sigil.reuse; sigil.reuse.assert_no_offense(); [sys.exit('VIOLATION: '+m+' resolvable') for m in ('framework','strix') if u.find_spec(m)]; print('boundary ok')"
	@T=$$(mktemp -d); : > $$T/CLAUDE.md; \
	if CRUCIBLE_ROOT=$$T .venv-offense/bin/vigil provision --slug make-smoke --scope 127.0.0.1 --base-dir $$T >/dev/null; then \
	  rm -rf $$T; echo "vigil (offense native verb) ok"; \
	else \
	  rm -rf $$T; echo "vigil native verb FAILED (offense venv / framework wiring)" >&2; exit 1; \
	fi
	@echo "self-check (informational — missing Claude/TPM/keyring are optional):"
	SIGIL_HOME=$${SIGIL_HOME:-$$HOME/.sigil} .venv-sovereign/bin/sigil doctor || true

clean-services: ## stop services AND delete their data volumes (destructive)
	docker compose down -v
