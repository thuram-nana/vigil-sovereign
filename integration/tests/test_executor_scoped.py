"""WS-A — the executor's SCOPED egress guard: engage owner-authorized REMOTE/LAN targets, still fail-closed.

When a signed-authority ``scope`` is threaded in (production, via wiring), the executor allows a target ONLY
if its host is in the owner-signed scope AND every resolved IP clears the never-liftable floor
(metadata/link-local/reserved), pinning the exact resolved IP (TOCTOU/DNS-rebind defence). Loopback is
reachable only when the scope authorizes it. With NO scope the guard is loopback-only (covered by
test_live_executor.py). Resolution is hermetic here via a fake getaddrinfo — nothing spawns or does DNS.

Run: PYTHONPATH=integration:gateway pytest integration/tests/test_executor_scoped.py -q
"""
from __future__ import annotations

import hashlib
import socket
from types import SimpleNamespace

import pytest

from vigil_gateway.scope_source import StaticScopeSource
from vigil_integration.agent.state import Phase
from vigil_integration.live.executor import execute


def _signer(data: bytes) -> str:
    return "sig-" + hashlib.sha256(data).hexdigest()[:24]


class _FakeRun:
    def __init__(self):
        self.calls: list[list[str]] = []

    def __call__(self, argv, *, timeout, output_cap):
        self.calls.append(list(argv))
        return SimpleNamespace(exit_code=0, stdout="OK", stderr="")


def _allow_gate(seen):
    def _g(tool_name, target, destructive):
        seen.append(target)          # capture the resolved_target the gate is scoped on (AUDIT-G4)
        return SimpleNamespace(outcome="allow", allowed=True, reason="ok")
    return _g


def _view():
    return {t: [p.value for p in Phase] for t in ("nmap", "httpx", "nuclei")}


def _fake_addrinfo(mapping):
    """host -> ip (IPv4). Unknown host raises gaierror. Value may be a LIST of ips (multi-answer)."""
    def _f(host, port, *a, **k):
        ips = mapping.get(host)
        if ips is None:
            raise socket.gaierror("name does not resolve")
        if isinstance(ips, str):
            ips = [ips]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0)) for ip in ips]
    return _f


def _run(target, *, scope_hosts, addrinfo, tool="httpx"):
    seen: list = []
    fr = _FakeRun()
    res = execute(tool, {"target": target}, Phase.INFORMATIONAL,
                  gate=_allow_gate(seen), view=_view(), destructive_view={tool: False},
                  run=fr, signer=_signer, seq=1, now=7,
                  scope=StaticScopeSource(list(scope_hosts)))
    return res, fr, seen


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch):
    # default: nothing resolves unless a test installs a mapping (fail-closed hermetic default)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_addrinfo({}))


def test_in_scope_remote_public_host_runs_pinned_to_the_resolved_ip(monkeypatch):
    # 93.184.216.34 is globally routable (not in any floor/private tier)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_addrinfo({"scanme.example.com": "93.184.216.34"}))
    res, fr, seen = _run("http://scanme.example.com/x", scope_hosts=["scanme.example.com"],
                         addrinfo=None)
    assert res.outcome == "ran"
    assert fr.calls and "93.184.216.34" in " ".join(fr.calls[0])          # pinned to the resolved IP
    assert seen == ["scanme.example.com"]                                 # gate scoped on the HOSTNAME (G4)


def test_out_of_scope_public_host_denies_before_spawn(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_addrinfo({"evil.example": "8.8.8.8"}))
    res, fr, _ = _run("http://evil.example/", scope_hosts=["scanme.example.com"], addrinfo=None)
    assert res.outcome == "deny" and "not in the signed authority scope" in res.reason
    assert fr.calls == []                                                 # never spawned


def test_metadata_denied_even_when_in_scope(monkeypatch):
    # a scoped hostname that (maliciously or by rebind) resolves to the cloud metadata IP → floor deny
    monkeypatch.setattr(socket, "getaddrinfo", _fake_addrinfo({"scanme.example.com": "169.254.169.254"}))
    res, fr, _ = _run("http://scanme.example.com/", scope_hosts=["scanme.example.com"], addrinfo=None)
    assert res.outcome == "deny" and "always-denied" in res.reason
    assert fr.calls == []


def test_lan_host_runs_only_for_the_exact_authorized_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_addrinfo({"10.0.0.5": "10.0.0.5", "10.0.0.6": "10.0.0.6"}))
    ok, fr_ok, _ = _run("http://10.0.0.5/", scope_hosts=["10.0.0.5"], addrinfo=None)
    assert ok.outcome == "ran" and fr_ok.calls                           # exact private IP lifted by scope
    bad, fr_bad, _ = _run("http://10.0.0.6/", scope_hosts=["10.0.0.5"], addrinfo=None)
    assert bad.outcome == "deny" and fr_bad.calls == []                # sibling not authorized


def test_loopback_still_runs_when_the_scope_authorizes_it(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_addrinfo({"127.0.0.1": "127.0.0.1"}))
    res, fr, seen = _run("http://127.0.0.1:18080/", scope_hosts=["127.0.0.1"], addrinfo=None)
    assert res.outcome == "ran" and fr.calls
    assert seen == ["127.0.0.1:18080"]                                   # loopback IP-literal == hostname


def test_toctou_multi_answer_with_a_denied_ip_is_rejected(monkeypatch):
    # the host resolves to a good in-scope IP AND the metadata IP — ANY denied resolved IP refuses the target
    monkeypatch.setattr(socket, "getaddrinfo",
                        _fake_addrinfo({"scanme.example.com": ["93.184.216.34", "169.254.169.254"]}))
    res, fr, _ = _run("http://scanme.example.com/", scope_hosts=["scanme.example.com"], addrinfo=None)
    assert res.outcome == "deny" and fr.calls == []


def test_no_scope_is_loopback_only_even_for_an_in_reach_public_ip(monkeypatch):
    # regression: without a scope threaded, the guard is loopback-only (fail-closed default) regardless of DNS
    monkeypatch.setattr(socket, "getaddrinfo", _fake_addrinfo({"scanme.example.com": "93.184.216.34"}))
    fr = _FakeRun()
    res = execute("httpx", {"target": "http://scanme.example.com/"}, Phase.INFORMATIONAL,
                  gate=_allow_gate([]), view=_view(), destructive_view={"httpx": False},
                  run=fr, signer=_signer, seq=1, now=7)   # scope=None
    assert res.outcome == "deny" and fr.calls == []
