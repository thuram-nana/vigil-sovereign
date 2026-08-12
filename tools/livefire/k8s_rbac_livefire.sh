#!/usr/bin/env bash
# =============================================================================
# VIGIL LIVE-FIRE — Kubernetes RBAC (E4 TIER-1 + TIER-2) against a REAL cluster
# =============================================================================
#
# WHAT THIS IS. Every other proof of the Kubernetes RBAC confirmations runs over
# FIXTURES: evidence we wrote by hand. This script runs them over evidence a REAL
# Kubernetes API server produced, and it is fully reproducible by anyone — a
# customer, an auditor, or a sceptical evaluator — on their own machine.
#
# WHY IT IS AUTHORIZED. It creates its own throwaway single-node cluster in a
# container on loopback, does its work there, and destroys it. It never touches
# infrastructure it does not own. That is the whole point: the same claim can be
# re-checked by anyone without borrowing anybody's cloud account.
#
# WHAT IT PROVES, and — just as important — what it proves the system does NOT do:
#
#   1. A genuinely dangerous binding (the anonymous user bound to cluster-admin)
#      is CONFIRMED from real API bytes, a signed certificate is minted, and that
#      certificate RE-VERIFIES OFFLINE.
#   2. Benign bindings in the SAME real cluster are NOT confirmed:
#        - the anonymous user bound to the harmless built-in `view` role;
#        - a NAMED user bound to cluster-admin (a real admin, not an anonymous one).
#   3. The near-zero-false-positive control that matters most, on real data: the
#      namespace-default service account bound to the built-in `admin` role inside
#      one namespace. This is the single most common legitimate delegation in real
#      Kubernetes ("let this app own its own namespace"). The real `admin` role
#      genuinely grants get/list/watch on Secrets, so a naive detector WOULD flag
#      it — and would be wrong, on a completely normal cluster. It must stay a lead.
#
# A detector that only ever says "found something" is worthless. The controls are
# the product.
#
# USAGE:   tools/livefire/k8s_rbac_livefire.sh            # run, then clean up
#          KEEP_CLUSTER=1 tools/livefire/k8s_rbac_livefire.sh   # leave it running
#
# REQUIRES: docker, and the offense virtualenv at .venv-offense.
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTAINER="${CONTAINER:-vigil-livefire-k3s}"
K3S_IMAGE="${K3S_IMAGE:-rancher/k3s:v1.31.5-k3s1}"
WORK="$(mktemp -d)"
# Docker's credential helper can need an interactive GPG unlock; a clean config
# avoids it for public pulls. (Failing this way is silent and confusing, so we
# pre-empt it rather than let the pull mysteriously fail.)
export DOCKER_CONFIG="${DOCKER_CONFIG:-$WORK/dockercfg}"
mkdir -p "$DOCKER_CONFIG" && echo '{}' > "$DOCKER_CONFIG/config.json"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
k()   { docker exec "$CONTAINER" kubectl "$@"; }

cleanup() {
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then
    echo "KEEP_CLUSTER=1 — leaving '$CONTAINER' running. Remove it with: docker rm -f $CONTAINER"
  else
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

say "1. Starting a real Kubernetes cluster (throwaway, loopback-only, ours)"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker pull "$K3S_IMAGE" >/dev/null
docker run -d --name "$CONTAINER" --privileged -p 127.0.0.1:6443:6443 \
  "$K3S_IMAGE" server --disable-agent --disable traefik --disable metrics-server >/dev/null

printf '   waiting for the API server'
for _ in $(seq 1 60); do
  if k get --raw /readyz >/dev/null 2>&1; then break; fi
  printf '.'; sleep 2
done
echo
k get --raw /version | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   real Kubernetes:", d["gitVersion"])'

say "2. Creating the test conditions inside our own cluster"
k create clusterrolebinding lf-anon-admin  --clusterrole=cluster-admin --user=system:anonymous >/dev/null
echo "   [dangerous] anonymous user -> cluster-admin"
k create clusterrolebinding lf-anon-view   --clusterrole=view          --user=system:anonymous >/dev/null
echo "   [benign]    anonymous user -> view"
k create clusterrolebinding lf-named-admin --clusterrole=cluster-admin --user=alice           >/dev/null
echo "   [benign]    named user 'alice' -> cluster-admin"
k create rolebinding lf-ns-owner -n default --clusterrole=admin --serviceaccount=default:default >/dev/null
echo "   [benign]    default service account -> admin, inside one namespace (the common delegation)"

say "3. Capturing what the real API server returns"
# The built-in `admin` and `view` roles are AGGREGATED: their permissions are not written in the object
# itself, they are assembled by a controller shortly after the cluster starts. Read too early and the
# rules come back empty — which would silently weaken the very control we are trying to demonstrate, so
# wait for the controller to finish rather than capturing a half-built role.
printf '   waiting for the aggregated built-in roles to be populated'
for _ in $(seq 1 60); do
  if k get clusterrole admin -o json 2>/dev/null | python3 -c 'import json,sys; sys.exit(0 if (json.load(sys.stdin).get("rules") or []) else 1)' 2>/dev/null; then
    break
  fi
  printf '.'; sleep 2
done
echo

for b in lf-anon-admin lf-anon-view lf-named-admin; do
  k get clusterrolebinding "$b" -o json > "$WORK/$b.json"
done
k get rolebinding lf-ns-owner -n default -o json > "$WORK/lf-ns-owner.json"
for r in cluster-admin view admin; do
  k get clusterrole "$r" -o json > "$WORK/role-$r.json"
done
echo "   captured $(ls "$WORK"/*.json | wc -l) real API responses"

say "4. Adjudicating the real evidence through the production path"
cd "$REPO"
# shellcheck disable=SC1091
source .venv-offense/bin/activate
WORK="$WORK" PYTHONPATH=integration:engine/crucible:gateway python3 "$REPO/tools/livefire/k8s_rbac_livefire.py"

say "LIVE-FIRE COMPLETE"
