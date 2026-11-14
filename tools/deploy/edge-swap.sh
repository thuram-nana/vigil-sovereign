#!/usr/bin/env bash
# =============================================================================
# edge-swap.sh — replace a running customer edge or public site with a fresh
# process, without a gap, and leave it on its first port.
#
#   VIGIL_EDGE_SWAP_CUSTOMER_URL=https://app.vigilguard.net tools/deploy/edge-swap.sh customer
#   VIGIL_EDGE_SWAP_PUBLIC_URL=https://vigilguard.net       tools/deploy/edge-swap.sh public
#
# The edge runs as a systemd user instance whose name is its loopback port:
# sigil-customer@8734 / @8744, sigil-public@8735 / @8745 (deploy/systemd/*@.service).
# The shipped nginx vhosts try the first port for every request and the second
# when the first does not take the connection; neither port is ever marked
# unavailable (max_fails=0). The edge's resting place is the FIRST port: there
# nginx's first try succeeds, so nginx logs no refused connection per request.
#
# The swap moves the edge in HOPS: from the first port to the second and back,
# or, from the second port (a swap that stopped half way), once to the first.
# Each hop:
#   1. starts a new instance on the other port and waits for its /healthz (not
#      /readyz, which is 503 while the cockpit restarts);
#   2. waits VIGIL_EDGE_SWAP_SETTLE_S more seconds with both edges up and checks
#      that the new one still runs and answers /healthz;
#   3. enables the new instance, stops the old one — which first answers every
#      request it accepted (graceful SIGTERM, ui/graceful.py; the customer edge
#      waits up to 75 s for an action the cockpit is still completing) — and
#      disables it, so a reboot starts the edge that is running now;
#   4. checks THROUGH THE REVERSE PROXY that the proxy reaches the new edge:
#      <url>/version.json must name the build the new edge serves.
# Before the first hop, <url>/version.json must name the running edge's build,
# so a wrong URL changes nothing.
# If a new edge does not become healthy, or stops answering during the settle,
# it is stopped and the running edge keeps serving; the script exits 1. If the
# proxy does not reach a new edge (a vhost or Caddyfile naming one port only),
# the swap hops back to the port the proxy reached — the proxy had no edge for
# those few seconds, as in a restart — and exits 1.
#
# The new process reads the code and files on disk now: check out the release
# first (docs/runbooks/EDGE-SWAP.md).
#
# Settings (environment): VIGIL_EDGE_SWAP_CUSTOMER_URL / VIGIL_EDGE_SWAP_PUBLIC_URL
# (required) — the address the reverse proxy serves that edge at;
# VIGIL_EDGE_SWAP_HEALTH_S (30) — the wait for /healthz; VIGIL_EDGE_SWAP_SETTLE_S (3);
# the ports VIGIL_CUSTOMER_PORT / VIGIL_CUSTOMER_ALT_PORT (8734 / 8744) and
# VIGIL_PUBLIC_PORT / VIGIL_PUBLIC_ALT_PORT (8735 / 8745).
# =============================================================================
set -euo pipefail

edge="${1:-}"
case "$edge" in
  customer) a="${VIGIL_CUSTOMER_PORT:-8734}"; b="${VIGIL_CUSTOMER_ALT_PORT:-8744}"; unit=sigil-customer
            url_var=VIGIL_EDGE_SWAP_CUSTOMER_URL; url="${VIGIL_EDGE_SWAP_CUSTOMER_URL:-}" ;;
  public)   a="${VIGIL_PUBLIC_PORT:-8735}";   b="${VIGIL_PUBLIC_ALT_PORT:-8745}";   unit=sigil-public
            url_var=VIGIL_EDGE_SWAP_PUBLIC_URL; url="${VIGIL_EDGE_SWAP_PUBLIC_URL:-}" ;;
  *) echo "usage: $0 customer|public" >&2; exit 2 ;;
esac
if [ -z "$url" ]; then
  echo "edge-swap: set $url_var to the address the reverse proxy serves the $edge edge at" \
       "(e.g. https://app.vigilguard.net); the swap checks through it that the proxy reaches each new edge" >&2
  exit 2
fi
url="${url%/}"
health_s="${VIGIL_EDGE_SWAP_HEALTH_S:-30}"
settle_s="${VIGIL_EDGE_SWAP_SETTLE_S:-3}"

sc() { systemctl --user "$@"; }
active() { sc is-active --quiet "$1"; }
healthy() { curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:$1/healthz" 2>/dev/null; }
# the build an edge serves, read from <base>/version.json; empty when it does not answer
build_at() {
  { curl -fsS --max-time 5 "$1/version.json" 2>/dev/null || true; } \
    | sed -n 's/.*"build": *"\([0-9a-f]\{1,64\}\)".*/\1/p'
}
# reached=1 when the reverse proxy answers with build $1 (three tries, a second apart), else reached=0
check_proxy() {
  local i
  reached=0
  for i in 1 2 3; do
    if [ "$(build_at "$url")" = "$1" ]; then
      reached=1
      return 0
    fi
    if [ "$i" -lt 3 ]; then
      sleep 1
    fi
  done
}

if active "$unit@$a.service"; then
  cur="$unit@$a.service"; at="$a"
elif active "$unit@$b.service"; then
  cur="$unit@$b.service"; at="$b"
elif active "$unit.service"; then
  cur="$unit.service"; at="$a"                    # the plain unit listens on the first port
else
  echo "edge-swap: no $edge edge is running; start one first: systemctl --user start $unit@$a.service" >&2
  exit 1
fi

running_build="$(build_at "http://127.0.0.1:$at")"
if [ -z "$running_build" ]; then
  echo "edge-swap: the running edge on port $at does not answer /version.json; restart it once" \
       "(systemctl --user restart $cur) and swap after; nothing was changed" >&2
  exit 1
fi
check_proxy "$running_build"
if [ "$reached" != 1 ]; then
  echo "edge-swap: $url/version.json does not name the build of the edge running on port $at ($running_build);" \
       "check $url_var and the reverse proxy; nothing was changed" >&2
  exit 1
fi

# hop <port>: move the edge from $cur (on port $at) to a new instance on <port>, then set reached (check_proxy).
# Exits 1 with $cur untouched when the new edge does not come up.
hop() {
  local port="$1" new="$unit@$1.service" waited=0 build
  if healthy "$port"; then
    echo "edge-swap: something already answers on port $port; refusing (stop it first) — $cur keeps serving" >&2
    exit 1
  fi
  echo "edge-swap: starting $new (the running edge is $cur)"
  sc start "$new"
  until healthy "$port"; do
    if [ "$waited" -ge "$health_s" ] || ! active "$new"; then
      echo "edge-swap: $new did not answer /healthz within ${health_s}s; stopping it — $cur keeps serving" >&2
      sc stop "$new" || true
      exit 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
  sleep "$settle_s"                               # both edges up; the new one must still be there after it
  build="$(build_at "http://127.0.0.1:$port")"
  if ! active "$new" || ! healthy "$port" || [ -z "$build" ]; then
    echo "edge-swap: $new stopped answering during the ${settle_s}s settle; stopping it — $cur keeps serving" >&2
    sc stop "$new" || true
    exit 1
  fi
  sc enable "$new"
  sc stop "$cur"                                  # graceful: the old edge answers what it accepted, then exits
  sc disable "$cur"
  echo "edge-swap: $cur -> $new"
  cur="$new"; at="$port"
  check_proxy "$build"
}

if [ "$at" = "$a" ]; then
  ports="$b $a"                                   # out to the second port and back
else
  ports="$a"
fi
for port in $ports; do
  from="$at"
  hop "$port"
  if [ "$reached" != 1 ]; then
    echo "edge-swap: $url does not reach the edge on port $port: the reverse proxy must name both ports" \
         "(the two-port upstream, docs/runbooks/EDGE-SWAP.md); moving the edge back to port $from" >&2
    hop "$from"
    if [ "$reached" != 1 ]; then
      echo "edge-swap: $url does not reach the edge on port $from either; check the reverse proxy now" >&2
    fi
    exit 1
  fi
done
echo "edge-swap: done — $cur serves on port $at, reached through $url"
