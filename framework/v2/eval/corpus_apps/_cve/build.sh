#!/usr/bin/env bash
# Build the real-CVE corpus images locally.
#
# Each subdirectory pins a REAL npm package at a version with a PUBLISHED CVE and
# exposes that package's documented vulnerability over HTTP. Because the vulnerable
# dependency comes from the npm registry (reachable where Docker Hub may not be), the
# app is built on the host and copied into the cached node base — so these run in
# environments where pulling a prebuilt vulnerable-app image is blocked.
#
# Usage:  bash build.sh            # build every _cve app
#         bash build.sh st-2014-3744
#
# Produces images tagged  crucible-cve-<dir>:local  that the matching
# eval/corpus_apps/cve-*.json descriptors reference.
set -euo pipefail
cd "$(dirname "$0")"

apps=("${@:-}")
if [ -z "${apps[0]:-}" ]; then
  apps=()
  for d in */; do [ -f "${d}package.json" ] && apps+=("${d%/}"); done
fi

for app in "${apps[@]}"; do
  echo "== building ${app} =="
  ( cd "$app"
    # host npm resolves over IPv4 where the docker-build network may not
    NODE_OPTIONS="--dns-result-order=ipv4first" npm install --no-audit --no-fund --loglevel=error
    docker build -t "crucible-cve-${app}:local" .
  )
  echo "== built crucible-cve-${app}:local =="
done
