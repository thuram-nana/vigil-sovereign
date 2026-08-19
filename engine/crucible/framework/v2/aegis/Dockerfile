# AEGIS Gateway — the DEFENSIVE "provable firewall" as a Docker sidecar.
#
# BUILD (from the monorepo ROOT). The image needs the offense engine (engine/crucible → framework.v2)
# AND the shared integrity substrate framework.v2 imports at load (packages/core/vigil_core), so the
# substrate is passed as a NAMED build context. The wired one-liner (recommended):
#     make aegis-image        # == docker compose --profile aegis build aegis-gateway
# or the equivalent raw build:
#     docker build -f engine/crucible/framework/v2/aegis/Dockerfile \
#         --build-context vigil_core=packages/core/vigil_core -t aegis-gateway engine/crucible
#
# RUN (observe = read-only; point --upstream at YOUR app; bind 0.0.0.0 to be reachable):
#     docker run --rm -p 8080:8080 aegis-gateway \
#         --upstream http://host.docker.internal:3000 --host 0.0.0.0 --mode observe
#
# Defensive-only, fail-open, loopback-friendly. No telemetry, no external calls, no cloud
# CI. The image ships NO secrets and NO offensive tooling data — only the importable
# Python package. The per-deployment secret / entitlement are supplied at run time.
# Full walkthrough: framework/v2/aegis/QUICKSTART.md.
#
# A14 (supply chain): digest-pinned. This is a public-facing DATA PLANE — it sits inline in front
# of someone's app — so "whatever :3.11-slim resolves to today" is not an acceptable provenance
# story for it. A digest is content-addressed: it either matches or the pull fails.
# Re-pin with: bash infra/supply-chain/resolve-image-digests.sh   (see docs/SUPPLY-CHAIN.md)
# python:3.11-slim, resolved 2026-08-12.

FROM python:3.11-slim@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff

# --- build + install the package (the repo-root pyproject delivers importable framework.v2) ---
WORKDIR /src
# The shared integrity substrate lives OUTSIDE this (engine/crucible) build context — it is the
# monorepo's packages/core/vigil_core — so it is supplied as a NAMED build context (docker-compose.yml
# wires it as `additional_contexts.vigil_core`; the standalone build command in the header passes it via
# --build-context). framework.v2 imports it at module load (common.errors → vigil_core.IntegrityError),
# so the gateway cannot even start without it. Pure-Python; its deps (cryptography, pydantic) are also
# crucible deps, so installing it pulls nothing extra into the image.
COPY --from=vigil_core . ./vigil_core
RUN pip install --no-cache-dir ./vigil_core
# COPY only what the wheel build needs; the rest of the repo (offensive playbooks,
# engagement data under targets/, the knowledge graph) is deliberately NOT shipped in
# this defensive image.
COPY pyproject.toml README.md LICENSE LICENSING.md ./
COPY framework ./framework
RUN pip install --no-cache-dir . && rm -rf /src

# --- a writable CRUCIBLE_ROOT so enforce-mode kill-switch / audit state has a home ---
# crucible_root() validates CRUCIBLE_ROOT via a CLAUDE.md sentinel; the gateway writes its
# per-slug kill-switch + authority state under <root>/framework/v2/. Observe mode never
# touches it (short-circuit + fail-safe on read error); enforce mode wants it persistent —
# mount a volume at /var/lib/aegis to keep the kill-switch across restarts.
ENV CRUCIBLE_ROOT=/var/lib/aegis
RUN mkdir -p /var/lib/aegis \
 && printf '%s\n' \
      '# AEGIS gateway state root (CRUCIBLE_ROOT sentinel).' \
      'Marks this directory as the framework root for the gateway kill-switch + audit state.' \
      > /var/lib/aegis/CLAUDE.md

# --- drop privileges: a public-facing data plane should not run as root ---
RUN useradd --system --create-home --uid 10001 aegis \
 && chown -R aegis:aegis /var/lib/aegis
USER aegis

EXPOSE 8080

# `aegis gateway` REQUIRES --upstream at run time, and needs --host 0.0.0.0 to be reachable
# from outside the container. Default CMD keeps it READ-ONLY (observe); override to enforce
# only after confirming zero false positives against your real traffic in observe.
ENTRYPOINT ["python3", "-m", "framework.v2", "aegis", "gateway"]
CMD ["--mode", "observe"]
