"""nftables — the rendered ruleset expresses deny-default, and nft accepts it."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from vigil_gateway import denylist
from vigil_gateway.nftables import GatewayFirewall

FW = GatewayFirewall(sandbox_subnets=["172.31.240.0/24"], gateway_ip="172.31.240.1", proxy_port=48081)


def _nft_usable() -> bool:
    """True iff nft can reach netlink in THIS namespace. `nft --check` still initialises the
    ruleset cache, which needs CAP_NET_ADMIN; unprivileged uid in the root netns cannot.
    The netns load test (test_netns_gate.py) covers the unprivileged case via `unshare -rn`."""
    if not shutil.which("nft"):
        return False
    try:
        return subprocess.run(["nft", "list", "tables"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


_NFT_USABLE = _nft_usable()


def test_render_expresses_deny_default_and_exits():
    txt = FW.render()
    assert "table inet vigil_gateway" in txt
    assert "169.254.0.0/16" in txt                      # metadata /16 in the hard-deny set
    # forward hook stays policy-accept and only jumps sandbox traffic (co-tenants untouched)
    assert "hook forward" in txt and "policy accept" in txt
    assert "ip saddr 172.31.240.0/24 jump sandbox_egress" in txt
    # the only exits are the proxy and DNS
    assert "tcp dport 48081 accept" in txt
    assert "udp dport 53 accept" in txt
    # the sandbox egress chain default-drops everything else
    assert 'log prefix "vigil-gw-drop " drop' in txt
    # gateway's own egress hard-drops metadata (backstop against a proxy bug)
    assert "chain output" in txt
    assert "@hard_deny4" in txt


def test_hard_deny_set_covers_every_denylist_cidr():
    txt = FW.render()
    for c in denylist.hard_deny_cidrs():
        assert c in txt, f"denylist CIDR {c} missing from rendered ruleset"


def test_ipv6_sandbox_renders_ip6_rules():
    fw6 = GatewayFirewall(sandbox_subnets=["fd00:5a11::/64"], gateway_ip="fd00:5a11::1", proxy_port=48081)
    txt = fw6.render()
    assert "ip6 saddr fd00:5a11::/64 jump sandbox_egress" in txt
    assert "ip6 daddr @hard_deny6" in txt
    assert "ip6 daddr fd00:5a11::1 tcp dport 48081 accept" in txt


@pytest.mark.skipif(not _NFT_USABLE, reason="nft cannot reach netlink here (needs CAP_NET_ADMIN)")
def test_nft_check_accepts_the_ruleset():
    # `nft --check` fully parses + semantically validates against the live ruleset cache.
    FW.check()  # raises RuntimeError on any rejection


@pytest.mark.skipif(not _NFT_USABLE, reason="nft cannot reach netlink here (needs CAP_NET_ADMIN)")
def test_nft_check_accepts_ipv6_ruleset():
    GatewayFirewall(
        sandbox_subnets=["fd00:5a11::/64"], gateway_ip="fd00:5a11::1", proxy_port=48081
    ).check()


def test_input_chain_governs_host_reachability():
    # The sandbox may reach only the proxy + DNS ports on the gateway host, nothing else.
    txt = FW.render()
    assert "chain input" in txt and "jump sandbox_ingress" in txt
    assert "chain sandbox_ingress" in txt
    ingress = txt.split("chain sandbox_ingress")[1].split("chain forward")[0]
    assert "tcp dport 48081 accept" in ingress
    assert "dport 53 accept" in ingress
    assert "drop" in ingress


def test_forward_hard_deny_covers_all_forwarded_traffic():
    # Nobody forwarded through this host — including the gateway container's own egress —
    # may reach a hard-deny range. That rule sits in the forward hook, before the jump.
    txt = FW.render()
    fwd_hook = txt.split("chain forward")[1].split("chain sandbox_egress")[0]
    assert "@hard_deny4" in fwd_hook


def test_iface_matching_is_spoof_proof_when_known():
    fw = GatewayFirewall(
        sandbox_subnets=["172.31.240.0/24"], gateway_ip="172.31.240.1",
        proxy_port=48081, sandbox_iface="br-abc123",
    )
    txt = fw.render()
    assert 'iifname "br-abc123" jump sandbox_egress' in txt
    assert 'iifname "br-abc123" jump sandbox_ingress' in txt
    # when the iface is known, NO source-subnet jump exists (that one a spoof could bypass)
    assert "ip saddr 172.31.240.0/24 jump" not in txt


@pytest.mark.skipif(
    not (shutil.which("unshare") and shutil.which("nft")), reason="needs nft + unshare"
)
def test_iface_ruleset_loads_in_netns(tmp_path):
    fw = GatewayFirewall(
        sandbox_subnets=["172.31.240.0/24"], gateway_ip="172.31.240.1",
        proxy_port=48081, sandbox_iface="br-abc123",
    )
    ruleset = tmp_path / "iface.nft"
    ruleset.write_text(fw.render())
    proc = subprocess.run(
        ["unshare", "-rn", "bash", "-c", f"nft -f {ruleset} && nft list ruleset"],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0 and "Operation not permitted" in proc.stderr:
        pytest.skip("no rootless netns here")
    assert proc.returncode == 0, proc.stderr
    assert 'iifname "br-abc123"' in proc.stdout
