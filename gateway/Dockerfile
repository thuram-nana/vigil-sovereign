# vigil-gateway — the host-side deny-default egress gate (the A7-hardened filtering forward proxy).
#
# Python runtime is STDLIB-ONLY (see pyproject: dependencies = []), so the image carries no third-party
# RUNTIME python packages — just the gateway + a non-root user. The proxy needs no privileges: it binds a
# socket and dials only charter-authorized hosts, and in compose it drops ALL capabilities and runs
# read-only. The image DOES carry the `nftables` OS package: the L3/L4 backstop is loaded by the one-shot
# `vigil-gateway-firewall` compose sidecar, which runs in the HOST netns with ONLY CAP_NET_ADMIN, runs
# `vigil-gateway apply-firewall`, and exits — the proxy container itself still gets no netfilter access.
# (Build note: `pip install .` still fetches the hatchling BUILD backend via PEP 517 unless you build with
# a warm pip cache — the runtime image itself stays python-dependency-free.)
#
# Build (from the repo root):   docker build -t vigil-gateway:latest gateway
# Run it via:                   vigil services up   (or docker compose -f infra/docker/docker-compose.yml up -d)
#
# The base is a build-arg so a builder with a cached base image can avoid a registry pull for it
# (e.g. --build-arg PYTHON_BASE=python:3.11-slim); the runtime is stdlib-only, so any >=3.11 base works.
#
# A14 (supply chain): the DEFAULT is digest-pinned. A tag is a mutable pointer — `python:3.13-slim`
# alone means "whatever the registry serves today", so a silently-retagged or compromised base would
# be pulled with no signal. A digest is content-addressed: it either matches or the pull fails.
# Overriding --build-arg PYTHON_BASE=<unpinned> remains possible and is the operator's call; the
# committed default is what CI and `vigil services up` actually build, and that is pinned.
# Re-pin with: bash infra/supply-chain/resolve-image-digests.sh   (see docs/SUPPLY-CHAIN.md)
# python:3.13-slim, resolved 2026-08-12.
ARG PYTHON_BASE=python:3.13-slim@sha256:afd91e25d0d1b40e4c92bf716154ec3c4a9f0de1ce2a5c3663007fb6918eaf9c
FROM ${PYTHON_BASE}

# A dedicated unprivileged user — the proxy drops all capabilities and runs read-only in compose.
RUN useradd --system --create-home --uid 10001 vigil
WORKDIR /app

# The nftables OS package supplies `nft`, which the privileged one-shot compose sidecar runs to load the
# L3/L4 backstop into the host netns. The proxy service never uses it (it drops all caps), so it is inert
# there. --no-install-recommends keeps the layer small; the apt lists are removed to keep the image lean.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*

# Install the package (provides the `vigil-gateway` console script). No third-party python deps → nothing to fetch.
# The runtime is stdlib-only (pyproject `dependencies = []`), so pip itself is not needed after install. We
# remove it (W3-7 #430): pip bundles vendored copies under pip/_vendor/ (msgpack, setuptools, ...) that the
# `trivy image` gate reports as FIXABLE HIGH though they are never on the gateway's runtime path. Uninstalling
# pip removes those findings AND shrinks the runtime attack surface; the `apt-get upgrade` above pulls the
# distro security fixes (util-linux et al.). Verified: the HIGH+CRITICAL fixable image gate then exits 0.
COPY pyproject.toml README.md ./
COPY vigil_gateway ./vigil_gateway
RUN pip install --no-cache-dir . && rm -rf /root/.cache/pip \
    && python -m pip uninstall -y pip

USER vigil
# Bind host/port + the charter slug + the proxy token come from the environment at run time (the compose
# file supplies them). A public/unspecified bind is refused by the proxy itself (proxy.bind_ok).
ENV VIGIL_GATEWAY_PROXY_HOST=127.0.0.1 \
    VIGIL_GATEWAY_PROXY_PORT=48081
EXPOSE 48081

# W6-2 (#453): the gate is only "up" when the proxy is actually LISTENING on its bind. This is a CONNECT
# forward proxy, not an HTTP-routes server, so it has no /readyz (W6-1 deliberately excluded it) — its
# readiness surface IS the listening socket. A bare TCP connect to the configured bind (the same check
# infra/docker/docker-compose.yml uses) surfaces a serve-proxy that fail-closed and exited (bad/missing
# charter scope) as UNHEALTHY instead of a silent exit-0-but-dead container. Stdlib-only python, read-only
# safe (connect + close, no writes), reads the run-time bind from the env the compose file supplies.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import os,socket; socket.create_connection((os.environ.get('VIGIL_GATEWAY_PROXY_HOST','127.0.0.1'), int(os.environ.get('VIGIL_GATEWAY_PROXY_PORT','48081'))), 2).close()"]

ENTRYPOINT ["vigil-gateway"]
CMD ["serve-proxy"]
