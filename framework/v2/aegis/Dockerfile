# AEGIS Gateway — the DEFENSIVE "provable firewall" as a Docker sidecar.
#
# BUILD from the REPO ROOT (the build context must see pyproject.toml + framework/):
#     docker build -f framework/v2/aegis/Dockerfile -t aegis-gateway .
#
# RUN (observe = read-only; point --upstream at YOUR app; bind 0.0.0.0 to be reachable):
#     docker run --rm -p 8080:8080 aegis-gateway \
#         --upstream http://host.docker.internal:3000 --host 0.0.0.0 --mode observe
#
# Defensive-only, fail-open, loopback-friendly. No telemetry, no external calls, no cloud
# CI. The image ships NO secrets and NO offensive tooling data — only the importable
# Python package. The per-deployment secret / entitlement are supplied at run time.
# Full walkthrough: framework/v2/aegis/QUICKSTART.md.

FROM python:3.11-slim

# --- build + install the package (the repo-root pyproject delivers importable framework.v2) ---
WORKDIR /src
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
