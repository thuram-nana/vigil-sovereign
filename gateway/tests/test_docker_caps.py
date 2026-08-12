"""The Strix sandbox no longer receives NET_ADMIN by default (P6 / FATAL-1).

Runs only where Strix's runtime deps (openai-agents, docker) are importable; skipped
otherwise. The behaviour under test is the env-driven capability policy in
``strix.runtime.docker_client._sandbox_net_caps``.
"""

from __future__ import annotations

import pathlib
import sys

import pytest


def _docker_client():
    strix = pathlib.Path(__file__).resolve().parents[2] / "vendor" / "strix"
    if str(strix) not in sys.path:
        sys.path.insert(0, str(strix))
    return pytest.importorskip(
        "strix.runtime.docker_client",
        reason="Strix runtime deps (openai-agents/docker) not installed",
    )


def test_net_admin_dropped_by_default(monkeypatch):
    dc = _docker_client()
    monkeypatch.delenv("STRIX_SANDBOX_NET_CAPS", raising=False)
    caps = dc._sandbox_net_caps()
    assert caps == ["NET_RAW"]
    assert "NET_ADMIN" not in caps


def test_override_can_restore_net_admin(monkeypatch):
    dc = _docker_client()
    monkeypatch.setenv("STRIX_SANDBOX_NET_CAPS", "NET_RAW,NET_ADMIN")
    assert dc._sandbox_net_caps() == ["NET_RAW", "NET_ADMIN"]


def test_empty_override_means_no_net_caps(monkeypatch):
    dc = _docker_client()
    monkeypatch.setenv("STRIX_SANDBOX_NET_CAPS", "")
    assert dc._sandbox_net_caps() == []


def test_whitespace_and_case_normalised(monkeypatch):
    dc = _docker_client()
    monkeypatch.setenv("STRIX_SANDBOX_NET_CAPS", " net_raw , net_admin ")
    assert dc._sandbox_net_caps() == ["NET_RAW", "NET_ADMIN"]


# --------------------------------- A7 compose topology ---------------------------------

def test_render_compose_binds_sandbox_ip_not_all_interfaces():
    # A7: the shipped compose must bind the proxy to the sandbox-net IP (not 0.0.0.0, which
    # bind_ok now refuses and which would expose the proxy on the world-facing egress net),
    # and wire the client-auth token into the topology.
    from vigil_gateway.docker import SandboxNetworking

    net = SandboxNetworking()
    bind_ip = net.sandbox_gateway_ip()
    assert bind_ip == "172.31.240.2"
    frag = net.render_compose()
    assert "0.0.0.0" not in frag
    assert f'"--host", "{bind_ip}"' in frag
    assert f"ipv4_address: {bind_ip}" in frag
    assert "VIGIL_GATEWAY_PROXY_TOKEN" in frag
