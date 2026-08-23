#!/usr/bin/env bash
# =============================================================================
# VIGIL LIVE-FIRE — k8s readiness probes wired to /readyz, against a REAL cluster
# (issue W6-2 #453, acceptance criterion: "killing the backend behind the proxy
#  makes the pod go NotReady, asserted in a kind/k3s test").
# =============================================================================
#
# WHAT THIS IS. The manifest-parsing proof (apps/sigil/tests/test_ha_probes_required.py)
# asserts the proxy Deployment's readinessProbe is httpGet /readyz; the W6-1 process
# proof (integration/tests/test_uiproxy_health_readyz.py) asserts /readyz returns 503
# when the sovereign backend is dead. This script closes the loop on a REAL Kubernetes
# API server: it deploys a proxy whose readinessProbe is httpGet /readyz — the SAME
# shape as infra/ha/k8s/proxy-deployment.yaml — over a backend, then KILLS the backend
# and asserts the kubelet flips the pod to NotReady (Ready=False), i.e. the Service
# stops routing to a replica whose backend is dead. Restoring the backend flips it back.
#
# WHY IT IS AUTHORIZED + REPRODUCIBLE. It creates its own throwaway single-node cluster
# in a container on loopback, does its work there, and destroys it. It never touches
# infrastructure it does not own. Anyone — a customer, an auditor, a sceptic — can
# re-run it on their own machine. (This is why it is an operator-run script, like
# tools/livefire/k8s_rbac_livefire.sh, not a required per-PR CI job: it needs a
# privileged container to run k3s, which the required ubuntu-latest CI lacks.)
#
# THE NEGATIVE CONTROL — the point of the test. A readiness probe that flipped to
# NotReady no matter what would be useless. So the script ALSO asserts the pod is Ready
# BEFORE the kill and Ready AGAIN after restore: the probe reflects the REAL backend
# state, it is not stuck NotReady (nor stuck Ready — the pre-fix `GET /` bug).
#
# USAGE:   tools/livefire/k8s_probes_livefire.sh
#          KEEP_CLUSTER=1 tools/livefire/k8s_probes_livefire.sh   # leave it running
# REQUIRES: docker.
# =============================================================================
set -euo pipefail

CONTAINER="${CONTAINER:-vigil-livefire-k3s-probes}"
K3S_IMAGE="${K3S_IMAGE:-rancher/k3s:v1.31.5-k3s1}"
APP_IMAGE="${APP_IMAGE:-python:3.13-slim}"
WORK="$(mktemp -d)"
export DOCKER_CONFIG="${DOCKER_CONFIG:-$WORK/dockercfg}"
mkdir -p "$DOCKER_CONFIG" && echo '{}' > "$DOCKER_CONFIG/config.json"

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
k()   { docker exec -i "$CONTAINER" kubectl "$@"; }

cleanup() {
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then
    echo "KEEP_CLUSTER=1 — leaving '$CONTAINER' running. Remove it with: docker rm -f $CONTAINER"
  else
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

ready_status() {
  # Ready condition of the (single) proxy pod: "True" / "False" / "" (no pod yet).
  k get pod -l app=probe-proxy -o \
    'jsonpath={.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true
}

wait_ready() {  # $1 = desired status (True/False), $2 = timeout seconds
  local want="$1" deadline=$(( SECONDS + ${2:-120} ))
  while [ "$SECONDS" -lt "$deadline" ]; do
    [ "$(ready_status)" = "$want" ] && return 0
    sleep 3
  done
  echo "FATAL: proxy pod Ready did not reach '$want' in time (is: '$(ready_status)')" >&2
  k get pods -o wide >&2 || true
  return 1
}

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
k get --raw /version | python3 -c 'import json,sys; print("   real Kubernetes:", json.load(sys.stdin)["gitVersion"])'

say "2. Deploying a backend + a proxy whose readinessProbe is httpGet /readyz (the real manifest shape)"
k apply -f - <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata: { name: probe-demo }
data:
  backend.py: |
    import http.server
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length","2"); self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass
    http.server.ThreadingHTTPServer(("0.0.0.0", 80), H).serve_forever()
  proxy.py: |
    # Mirrors the uiproxy W6-1 probe semantics: /healthz = the process answers (liveness, no dependency
    # I/O); /readyz = a LIVE connect to the backend it federates to (readiness, 503 when that is down).
    import http.server, socket, os
    BH = os.environ.get("BACKEND_HOST", "backend"); BP = int(os.environ.get("BACKEND_PORT", "80"))
    class H(http.server.BaseHTTPRequestHandler):
        def _w(self, code, body):
            self.send_response(code); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            if self.path == "/healthz": return self._w(200, b'{"ok":true}')
            if self.path == "/readyz":
                try:
                    socket.create_connection((BH, BP), 2).close(); return self._w(200, b'{"ok":true}')
                except OSError: return self._w(503, b'{"ok":false}')
            return self._w(200, b"ok")
        def log_message(self, *a): pass
    http.server.ThreadingHTTPServer(("0.0.0.0", 8770), H).serve_forever()
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: backend, labels: { app: backend } }
spec:
  replicas: 1
  selector: { matchLabels: { app: backend } }
  template:
    metadata: { labels: { app: backend } }
    spec:
      containers:
        - name: backend
          image: python:3.13-slim
          command: ["python3", "/cfg/backend.py"]
          ports: [ { containerPort: 80 } ]
          volumeMounts: [ { name: cfg, mountPath: /cfg } ]
      volumes: [ { name: cfg, configMap: { name: probe-demo } } ]
---
apiVersion: v1
kind: Service
metadata: { name: backend }
spec:
  selector: { app: backend }
  ports: [ { port: 80, targetPort: 80 } ]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: probe-proxy, labels: { app: probe-proxy } }
spec:
  replicas: 1
  selector: { matchLabels: { app: probe-proxy } }
  template:
    metadata: { labels: { app: probe-proxy } }
    spec:
      containers:
        - name: proxy
          image: python:3.13-slim
          command: ["python3", "/cfg/proxy.py"]
          env:
            - { name: BACKEND_HOST, value: "backend" }
            - { name: BACKEND_PORT, value: "80" }
          ports: [ { name: http, containerPort: 8770 } ]
          # THE ASSERTION UNDER TEST: readiness wired to /readyz (drains when the backend is dead),
          # liveness wired to /healthz (the process answers) — exactly infra/ha/k8s/proxy-deployment.yaml.
          readinessProbe:
            httpGet: { path: /readyz, port: http }
            initialDelaySeconds: 3
            periodSeconds: 5
            failureThreshold: 2
          livenessProbe:
            httpGet: { path: /healthz, port: http }
            initialDelaySeconds: 10
            periodSeconds: 10
          volumeMounts: [ { name: cfg, mountPath: /cfg } ]
      volumes: [ { name: cfg, configMap: { name: probe-demo } } ]
YAML

say "3. Baseline: the proxy pod becomes Ready while its backend is up"
wait_ready True 180
echo "   [ok] proxy Ready=True with the backend up"

say "4. NEGATIVE-CONTROL KILL: scale the backend to 0 — the proxy's /readyz must flip it to NotReady"
k scale deployment backend --replicas=0 >/dev/null
k wait --for=delete pod -l app=backend --timeout=60s >/dev/null 2>&1 || true
wait_ready False 90
echo "   [ok] backend dead -> proxy Ready=False (the Service drains it; a dead backend does NOT stay Ready)"

say "5. RESTORE: bring the backend back — the proxy must return to Ready (probe reflects REAL state)"
k scale deployment backend --replicas=1 >/dev/null
wait_ready True 120
echo "   [ok] backend restored -> proxy Ready=True again"

say "PASS — readiness probe wired to /readyz reflects the real backend state on a REAL cluster."
