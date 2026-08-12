# vigil-gateway — the host-side deny-default egress gate (the A7-hardened filtering forward proxy).
#
# Runtime is STDLIB-ONLY (see pyproject: dependencies = []), so the image carries no third-party RUNTIME
# packages — just the gateway + a non-root user. The proxy needs no privileges: it binds a socket and dials
# only charter-authorized hosts. The nftables L3/L4 backstop is applied HOST-side (needs CAP_NET_ADMIN),
# not from this container. (Build note: `pip install .` still fetches the hatchling BUILD backend via PEP
# 517 unless you build with a warm pip cache — the runtime image itself stays dependency-free.)
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
ARG PYTHON_BASE=python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a
FROM ${PYTHON_BASE}

# A dedicated unprivileged user — the proxy drops all capabilities and runs read-only in compose.
RUN useradd --system --create-home --uid 10001 vigil
WORKDIR /app

# Install the package (provides the `vigil-gateway` console script). No third-party deps → nothing to fetch.
COPY pyproject.toml README.md ./
COPY vigil_gateway ./vigil_gateway
RUN pip install --no-cache-dir . && rm -rf /root/.cache/pip

USER vigil
# Bind host/port + the charter slug + the proxy token come from the environment at run time (the compose
# file supplies them). A public/unspecified bind is refused by the proxy itself (proxy.bind_ok).
ENV VIGIL_GATEWAY_PROXY_HOST=127.0.0.1 \
    VIGIL_GATEWAY_PROXY_PORT=48081
EXPOSE 48081
ENTRYPOINT ["vigil-gateway"]
CMD ["serve-proxy"]
