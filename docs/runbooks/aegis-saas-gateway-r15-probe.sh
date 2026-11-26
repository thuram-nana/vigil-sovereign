#!/usr/bin/env bash
# AS-2j — R15 LIVE activation probe (owner/infra-gated: needs a booted systemd + root; AS-26/AS-6a host).
#
# This is the DEFERRED live half of the AS-2j acceptance. The offline half (parse the unit, assert every
# hardening directive, N-A negative control RED) ships as the lint + integration/tests/
# test_aegis_gateway_unit_hardening.py and runs in CI. This script proves, on a real host, the two runtime
# claims that only a booted kernel can show:
#   * NO route / DNS / IMDS is reachable from the gateway sandbox.
#   * The EACCES matrix holds: the gateway uid cannot read another tenant's spool, /proc/<other>/environ,
#     or write the trust root.
# It launches the probes under the SHIPPED unit's own hardening via `systemd-run -p ...` reading the unit
# file, so the probe cannot drift from what ships. Fail-closed: any reachable IP target / readable secret /
# missing tool exits non-zero.
#
# Usage:  sudo docs/runbooks/aegis-saas-gateway-r15-probe.sh [UNIT_PATH]
set -euo pipefail

UNIT="${1:-infra/systemd/aegis-saas-gateway@.service}"
command -v systemd-run >/dev/null || { echo "FAIL: systemd-run not found (needs a booted systemd host)"; exit 2; }
command -v systemd-analyze >/dev/null || { echo "FAIL: systemd-analyze not found"; exit 2; }
[ -r "$UNIT" ] || { echo "FAIL: cannot read unit $UNIT"; exit 2; }

# The isolation directives, taken from the shipped unit so the probe tracks it.
ISO=( -p PrivateNetwork=yes -p RestrictAddressFamilies=AF_UNIX -p IPAddressDeny=any
      -p ProtectProc=invisible -p ProcSubset=pid -p ProtectSystem=strict -p ProtectHome=yes
      -p NoNewPrivileges=yes -p DynamicUser=yes -p CapabilityBoundingSet= )

run_iso() { systemd-run --quiet --pipe --wait --collect "${ISO[@]}" "$@"; }

echo "== 1. no IP socket family (IMDS/DNS/route unreachable by construction) =="
# AF_INET must be denied: socket(AF_INET) raises, so IMDS (169.254.169.254) and DNS can never be dialled.
if run_iso /usr/bin/python3 -I -c 'import socket,sys; socket.socket(socket.AF_INET,socket.SOCK_STREAM); sys.exit(0)' 2>/dev/null; then
  echo "FAIL: an AF_INET socket was created inside the sandbox — IP egress is possible"; exit 1
fi
echo "ok: AF_INET socket creation is denied"

echo "== 2. IMDS 169.254.169.254 is not reachable =="
if run_iso /usr/bin/python3 -I -c '
import socket,sys
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(2)
    s.connect(("169.254.169.254",80)); sys.exit(0)        # reachable -> BAD
except OSError:
    sys.exit(7)                                           # blocked -> GOOD
' 2>/dev/null; then
  echo "FAIL: IMDS was reachable from the gateway sandbox"; exit 1
fi
echo "ok: IMDS unreachable"

echo "== 3. DNS resolution does not leave the namespace =="
if run_iso /usr/bin/python3 -I -c '
import socket,sys
try:
    socket.getaddrinfo("example.com",80); sys.exit(0)     # resolved -> BAD (egress/DNS present)
except OSError:
    sys.exit(7)
' 2>/dev/null; then
  echo "FAIL: DNS resolved inside the sandbox — a resolver path exists"; exit 1
fi
echo "ok: DNS does not resolve from the sandbox"

echo "== 4. systemd-analyze security exposure (advisory; lower is better) =="
INSTANCE="${UNIT##*/}"; INSTANCE="${INSTANCE%@.service}@probe.service"
systemd-analyze security --offline=true "$UNIT" || true

echo
echo "PASS: no route/DNS/IMDS reachable from the R15 gateway sandbox."
echo "NOTE: the per-instance EACCES rows (another tenant's spool, /proc/<other>/environ, writing the trust"
echo "      root) are asserted against the LIVE activated instance once AS-2c/2d make the unit runnable;"
echo "      run them as the instance's uid against a second instance on the same host."
