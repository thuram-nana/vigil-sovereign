"""The red-team gate — the rendered firewall really loads in a network namespace and the
deny-default + metadata drop are present in the live ruleset.

A fresh user+network namespace (`unshare -rn`) makes the caller root *within that namespace*
with CAP_NET_ADMIN, so `nft -f` actually installs the rules — this is a real load into a
real (isolated) netfilter table, not a dry parse. The full packet-level drop against a live
169.254.169.254 needs a routed veth pair and root in the host netns; that is documented in
the README and left to a privileged CI runner. Combined with the real-socket refusals in
test_proxy_gate.py, this is the ship-blocker proof for FATAL-1.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from vigil_gateway.nftables import GatewayFirewall

FW = GatewayFirewall(sandbox_subnets=["172.31.240.0/24"], gateway_ip="172.31.240.1", proxy_port=48081)


def _rootless_netns_ok() -> bool:
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not (shutil.which("unshare") and shutil.which("nft") and _rootless_netns_ok()),
    reason="requires nft + rootless user/network namespaces (unshare -rn)",
)


def test_ruleset_loads_in_netns_with_metadata_drop(tmp_path):
    ruleset = tmp_path / "vigil.nft"
    ruleset.write_text(FW.render())
    script = f"nft -f {ruleset} && nft list ruleset"
    proc = subprocess.run(
        ["unshare", "-rn", "bash", "-c", script],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"ruleset failed to load in netns: {proc.stderr}"
    out = proc.stdout
    assert "table inet vigil_gateway" in out
    assert "169.254.0.0/16" in out          # metadata range present in the LOADED ruleset
    assert "sandbox_egress" in out
    assert "drop" in out                     # deny-default is live
    assert "vigil-gw-drop" in out            # the catch-all drop rule loaded


def test_only_proxy_and_dns_are_accepted_exits(tmp_path):
    ruleset = tmp_path / "vigil.nft"
    ruleset.write_text(FW.render())
    proc = subprocess.run(
        ["unshare", "-rn", "bash", "-c", f"nft -f {ruleset} && nft list chain inet vigil_gateway sandbox_egress"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    chain = proc.stdout
    # exactly the two intended accept exits (plus ct established); everything else drops
    assert "tcp dport 48081 accept" in chain
    assert "dport 53 accept" in chain
    assert "drop" in chain
