#!/usr/bin/env bash
# =============================================================================
# edge-swap.sh — replace a running customer edge or public site with a fresh
# process, without a gap.
#
#   tools/deploy/edge-swap.sh customer|public
#
# The edge runs as a systemd user instance whose name is its loopback port:
# sigil-customer@8734 / @8744, sigil-public@8735 / @8745 (deploy/systemd/*@.service).
# The shipped nginx vhosts send every request to the first port while it accepts
# connections and to the second when it does not. This script:
#   1. finds the edge that runs now (an instance, or the plain sigil-<edge>.service
#      on the first port — the first swap moves it to an instance);
#   2. starts a new instance on the other port and waits for its /healthz (not
#      /readyz, which is 503 while the cockpit restarts);
#   3. waits VIGIL_EDGE_SWAP_SETTLE_S more seconds (longer than the vhost's
#      fail_timeout, so nginx has seen the new edge), then stops the old one —
#      it finishes the requests it accepted (graceful SIGTERM);
#   4. enables the new instance and disables the old unit, so a reboot starts
#      the edge that is running now.
# If the new edge does not become healthy it is stopped and the old one keeps
# serving: nothing changes and the script exits 1.
#
# The new process reads the code and files on disk now: check out the release
# first (docs/runbooks/EDGE-SWAP.md). Needs the two-port nginx upstream.
#
# Settings (environment): VIGIL_EDGE_SWAP_HEALTH_S (30) — the wait for /healthz;
# VIGIL_EDGE_SWAP_SETTLE_S (3); the ports VIGIL_CUSTOMER_PORT / VIGIL_CUSTOMER_ALT_PORT
# (8734 / 8744) and VIGIL_PUBLIC_PORT / VIGIL_PUBLIC_ALT_PORT (8735 / 8745).
# =============================================================================
set -euo pipefail

edge="${1:-}"
case "$edge" in
  customer) a="${VIGIL_CUSTOMER_PORT:-8734}"; b="${VIGIL_CUSTOMER_ALT_PORT:-8744}"; unit=sigil-customer ;;
  public)   a="${VIGIL_PUBLIC_PORT:-8735}";   b="${VIGIL_PUBLIC_ALT_PORT:-8745}";   unit=sigil-public ;;
  *) echo "usage: $0 customer|public" >&2; exit 2 ;;
esac
health_s="${VIGIL_EDGE_SWAP_HEALTH_S:-30}"
settle_s="${VIGIL_EDGE_SWAP_SETTLE_S:-3}"

sc() { systemctl --user "$@"; }
active() { sc is-active --quiet "$1"; }
healthy() { curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:$1/healthz"; }

if active "$unit@$a.service"; then
  old="$unit@$a.service"; port="$b"
elif active "$unit@$b.service"; then
  old="$unit@$b.service"; port="$a"
elif active "$unit.service"; then
  old="$unit.service"; port="$b"                 # the plain unit listens on the first port
else
  echo "edge-swap: no $edge edge is running; start one first: systemctl --user start $unit@$a.service" >&2
  exit 1
fi
new="$unit@$port.service"

if healthy "$port"; then
  echo "edge-swap: something already answers on port $port; refusing (stop it first)" >&2
  exit 1
fi

echo "edge-swap: starting $new (the running edge is $old)"
sc start "$new"
waited=0
until healthy "$port"; do
  if [ "$waited" -ge "$health_s" ] || ! active "$new"; then
    echo "edge-swap: $new did not answer /healthz within ${health_s}s; stopping it — $old keeps serving" >&2
    sc stop "$new" || true
    exit 1
  fi
  sleep 1
  waited=$((waited + 1))
done

sleep "$settle_s"                                # longer than nginx's fail_timeout: it has seen the new edge
sc enable "$new"
sc stop "$old"                                   # graceful: the old edge finishes what it accepted
sc disable "$old"
echo "edge-swap: $old -> $new"
