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
    # gateway's own egress (output hook) hard-drops cloud metadata (backstop against a proxy
    # bug) — but ONLY metadata (A7), so host loopback/link-local keep working.
    assert "chain output" in txt
    out_hook = txt.split("chain output")[1]
    assert "@host_backstop4" in out_hook
    assert "@hard_deny4" not in out_hook   # NOT the full set (that would kill host loopback)


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


def test_forward_backstop_is_metadata_only_and_sandbox_gets_full_hard_deny():
    # A7: the GLOBAL forward hook drops ONLY the metadata backstop, so co-tenant containers
    # forwarded through this host keep loopback / link-local / RFC1918. The sandbox's FULL
    # hard-deny (which correctly includes those ranges) lives in sandbox_egress, not the hook.
    txt = FW.render()
    fwd_hook = txt.split("chain forward")[1].split("chain sandbox_egress")[0]
    assert "@host_backstop4" in fwd_hook
    assert "@hard_deny4" not in fwd_hook   # the full set is NOT dropped for co-tenants
    sb_egress = txt.split("chain sandbox_egress")[1].split("chain output")[0]
    assert "@hard_deny4" in sb_egress      # the sandbox itself stays fully constrained


def test_host_backstop_is_metadata_not_loopback():
    # The global forward/output backstop set contains the metadata endpoint but NOT loopback
    # (dropping 127.0.0.0/8 host-wide would break the host — the whole point of A7).
    txt = FW.render()
    backstop_set = txt.split("set host_backstop4")[1].split("}")[0]
    # BLOCK-3: IMDS + the ECS/EKS container-credential endpoints are all in the global backstop.
    for ep in ("169.254.169.254/32", "169.254.170.2/32", "169.254.170.23/32"):
        assert ep in backstop_set, ep
    assert "127.0.0.0/8" not in backstop_set
    # loopback IS still denied for the sandbox: it lives in the full hard_deny4 set.
    hard_set = txt.split("set hard_deny4")[1].split("}")[0]
    assert "127.0.0.0/8" in hard_set
    assert "169.254.0.0/16" in hard_set


def test_host_backstop_cidrs_covers_all_credential_endpoints():
    cidrs = denylist.host_backstop_cidrs()
    # BLOCK-3: the earlier set covered only IMDS and left ECS/EKS credential endpoints reachable.
    for ep in ("169.254.169.254/32", "169.254.170.2/32", "169.254.170.23/32"):
        assert ep in cidrs, ep
    # never the ranges the host/co-tenants legitimately use
    for forbidden in ("127.0.0.0/8", "::1/128", "fe80::/10", "224.0.0.0/4", "240.0.0.0/4",
                      "10.0.0.0/8"):
        assert forbidden not in cidrs, forbidden


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


# --------------------------- S3 backstop: apply() is idempotent (delete-then-load) ----------------------
# The one-shot firewall sidecar re-runs `apply-firewall` on every gateway bring-up. `nft -f` re-declaring
# an already-present table errors ("File exists") on the existing chains, so apply() MUST drop the table
# first — otherwise the second bring-up would fail closed with no real problem.

def test_apply_deletes_the_table_before_loading(monkeypatch):
    from vigil_gateway import nftables as nftmod

    calls: list[list[str]] = []

    def _fake_run(argv, *a, **kw):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(nftmod.GatewayFirewall, "_nft_bin", staticmethod(lambda: "/usr/sbin/nft"))
    monkeypatch.setattr(nftmod.subprocess, "run", _fake_run)

    FW.apply()

    # first a delete of the table, THEN the `nft -f -` load — in that order.
    assert any(c[:3] == ["/usr/sbin/nft", "delete", "table"] for c in calls), "apply() must delete first"
    load_idx = next(i for i, c in enumerate(calls) if c[:2] == ["/usr/sbin/nft", "-f"])
    del_idx = next(i for i, c in enumerate(calls) if c[:3] == ["/usr/sbin/nft", "delete", "table"])
    assert del_idx < load_idx, "the table delete must precede the ruleset load (idempotent re-apply)"


def test_apply_raises_when_the_load_is_rejected(monkeypatch):
    from vigil_gateway import nftables as nftmod

    def _fake_run(argv, *a, **kw):
        # the delete succeeds; the load fails — a rejected ruleset / no privilege must surface, not pass
        rc = 1 if argv[:2] == ["/usr/sbin/nft", "-f"] else 0
        return subprocess.CompletedProcess(argv, rc, stdout="", stderr="Operation not permitted")

    monkeypatch.setattr(nftmod.GatewayFirewall, "_nft_bin", staticmethod(lambda: "/usr/sbin/nft"))
    monkeypatch.setattr(nftmod.subprocess, "run", _fake_run)

    with pytest.raises(RuntimeError, match="nft -f failed"):
        FW.apply()


# ------------------ sx-s3 MEDIUM: apply() fails closed if the pinned sandbox bridge is absent ------------
# An interface-governed ruleset whose bridge interface does not exist in the netns matches NO sandbox
# traffic — the deny-default jump fires for nothing and the sandbox rides the forward `policy accept`
# ungoverned (a silent fail-OPEN). apply() must REFUSE before loading such a ruleset.

def _recording_nft(monkeypatch):
    from vigil_gateway import nftables as nftmod
    calls: list[list[str]] = []

    def _run(argv, *a, **kw):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(nftmod.GatewayFirewall, "_nft_bin", staticmethod(lambda: "/usr/sbin/nft"))
    monkeypatch.setattr(nftmod.subprocess, "run", _run)
    return calls


def test_apply_refuses_when_pinned_sandbox_iface_is_absent(monkeypatch):
    from vigil_gateway import nftables as nftmod
    fw = GatewayFirewall(sandbox_subnets=["172.31.240.0/24"], gateway_ip="172.31.240.1",
                         proxy_port=48081, sandbox_iface="vigil-nope0")
    monkeypatch.setattr(nftmod.os.path, "isdir", lambda p: False)   # the pinned bridge does NOT exist

    def _boom(*a, **k):
        raise AssertionError("apply() reached nft despite the pinned bridge being absent — not fail-closed")

    monkeypatch.setattr(nftmod.GatewayFirewall, "_nft_bin", staticmethod(lambda: "/usr/sbin/nft"))
    monkeypatch.setattr(nftmod.subprocess, "run", _boom)
    with pytest.raises(RuntimeError, match="does not exist"):
        fw.apply()


def test_apply_proceeds_when_pinned_iface_present(monkeypatch):
    from vigil_gateway import nftables as nftmod
    fw = GatewayFirewall(sandbox_subnets=["172.31.240.0/24"], gateway_ip="172.31.240.1",
                         proxy_port=48081, sandbox_iface="vigil-sbx0")
    monkeypatch.setattr(nftmod.os.path, "isdir", lambda p: p == "/sys/class/net/vigil-sbx0")
    calls = _recording_nft(monkeypatch)
    fw.apply()
    assert any(c[:2] == ["/usr/sbin/nft", "-f"] for c in calls), "the ruleset must load when the bridge exists"


def test_apply_without_iface_skips_the_bridge_check(monkeypatch):
    # source-subnet matching (no pinned iface) — the interface check is N/A and must not block apply()
    from vigil_gateway import nftables as nftmod
    monkeypatch.setattr(nftmod.os.path, "isdir", lambda p: False)   # even with NO interfaces present
    calls = _recording_nft(monkeypatch)
    FW.apply()   # FW is defined at module top WITHOUT a sandbox_iface
    assert any(c[:2] == ["/usr/sbin/nft", "-f"] for c in calls), "subnet-matched apply must still load"
