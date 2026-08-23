#!/usr/bin/env bash
# VIGIL HA — the gated Kubernetes deploy (issue W16-20).
#
# The NetworkPolicy is REQUIRED, NOT optional. This script REFUSES to apply the stack unless:
#   (a) the proxy-only NetworkPolicy manifest is PRESENT and actually DENIES the cross-workload path,
#   (b) it is LISTED in the kustomization so `kubectl apply -k` cannot omit it, and
#   (c) the target cluster has a NetworkPolicy controller (CNI) that will ENFORCE it — a NetworkPolicy
#       object with no enforcing controller is silently unenforced, which is exactly the owner-token-leak
#       vector this closes.
# The refusal is done by tools/ha/require_networkpolicy.py (exit 3 on any of the above). A second
# preflight, tools/ha/require_probes.py (W6-2), then REFUSES to apply unless every workload declares real
# liveness+readiness probes wired to /healthz + /readyz. Only after both pass do we apply — and we then confirm the policy actually landed in the cluster.
#
# If your cluster enforces NetworkPolicy via a CNI this script cannot auto-detect, attest it out of band:
#     VIGIL_NETPOL_CONTROLLER_CONFIRMED=1 tools/ha/deploy.sh
# Do NOT set that flag to "get past" the gate on a cluster with no enforcement — the leak stays open.
#
# See docs/architecture/HA-PROFILE.md §1.2 and infra/ha/k8s/README.md.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFESTS="${VIGIL_HA_MANIFESTS:-$REPO/infra/ha/k8s}"

confirm_args=()
if [ "${VIGIL_NETPOL_CONTROLLER_CONFIRMED:-0}" = "1" ]; then
  confirm_args+=(--controller-confirmed)
fi

echo "==> preflight: the NetworkPolicy is REQUIRED — verifying BEFORE any apply"
# Exits 3 (refuse) if the policy is absent, does not deny the cross-workload path, is not in the
# kustomization, or no NetworkPolicy controller is present. `set -e` aborts the deploy on that non-zero.
python3 "$REPO/tools/ha/require_networkpolicy.py" --manifests "$MANIFESTS" "${confirm_args[@]}"

echo "==> preflight: REAL health probes are REQUIRED (W6-2) — verifying BEFORE any apply"
# Exits 3 (refuse) if any workload ships without BOTH a liveness and a readiness probe, if a VIGIL-owned
# workload's probes are not wired to /readyz (readiness) + /healthz (liveness) — never a shallow `GET /`
# on the static bundle — or if a shipped server Dockerfile declares no HEALTHCHECK. `set -e` aborts.
python3 "$REPO/tools/ha/require_probes.py" --manifests "$MANIFESTS" --repo-root "$REPO"

echo "==> applying the HA stack via kustomize (the NetworkPolicy is the first resource, applied first)"
kubectl apply -k "$MANIFESTS"

echo "==> confirming the NetworkPolicy actually landed in the cluster"
if ! kubectl get networkpolicy vigil-sovereign-proxy-only >/dev/null 2>&1; then
  echo "FATAL: kubectl apply -k succeeded but the vigil-sovereign-proxy-only NetworkPolicy is not present." >&2
  echo "The sovereign cockpit MUST NOT run without it. Investigate before exposing the stack." >&2
  exit 4
fi

echo "==> OK: HA stack applied; the sovereign cockpit is proxy-only (NetworkPolicy present and enforced)."
