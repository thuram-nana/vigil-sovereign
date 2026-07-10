"""
Tests for Wave 2.3 — the service-reachability oracle.

A scanner's "open port" is an OBSERVATION; it becomes a FACT only when a real transport handshake
reproduces. These cover the pure oracle (judge a retained handshake), the FindingContext carrier +
offline re-verification (the retained JSON-safe evidence re-confirms with no network), and the gated,
bounded active capture (injected connector, a real loopback socket, and every fail-closed refusal).
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from framework.v2.verify import (
    OracleVerifier,
    capture_handshake,
    confirm_reachable,
    reachable_context,
    service_reachability_oracle,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.reachability import _is_single_host
from framework.v2.verify.reverify import reverify_context


# ---- the pure oracle -------------------------------------------------------


def test_oracle_fires_on_a_completed_tcp_connect() -> None:
    sig = service_reachability_oracle(
        {"connected": True, "host": "10.0.0.5", "port": 443, "protocol": "tcp"})
    assert sig.fired and sig.confidence >= 0.7 and "10.0.0.5:443" in sig.evidence


def test_only_a_real_banner_raises_confidence_above_a_bare_connect() -> None:
    bare = service_reachability_oracle({"connected": True, "host": "h", "port": 22})
    bannered = service_reachability_oracle(
        {"connected": True, "host": "h", "port": 22, "banner": "SSH-2.0-OpenSSH_9.6"})
    # a real connect's captured peer port is ALWAYS the one we dialled (getpeername), so it is
    # self-referential and must NOT corroborate — only an application-layer banner does.
    peer_only = service_reachability_oracle(
        {"connected": True, "host": "h", "port": 22, "peer": "10.0.0.5:22"})
    assert bare.confidence == 0.90 and peer_only.confidence == 0.90
    assert bannered.confidence == 0.97


@pytest.mark.parametrize("hs", [
    {"connected": False, "host": "h", "port": 22, "error": "ConnectionRefusedError"},
    {"connected": True, "host": "", "port": 22},          # no concrete host
    {"connected": True, "host": "h"},                      # no port
    {"connected": "yes", "host": "h", "port": 22},         # not strictly True
    {"connected": True, "host": "h", "port": 53, "protocol": "udp"},  # udp w/o banner
    "not a mapping",
    {},
])
def test_oracle_does_not_fire_without_a_real_handshake(hs) -> None:
    assert service_reachability_oracle(hs).fired is False


def test_oracle_fires_on_udp_only_with_a_service_response() -> None:
    sig = service_reachability_oracle(
        {"connected": True, "host": "h", "port": 53, "protocol": "udp", "banner": "\x00\x01"})
    assert sig.fired


# ---- verifier routing + FindingContext carrier -----------------------------


def test_service_reachable_routes_to_the_reachability_oracle() -> None:
    res = OracleVerifier().confirm(
        {"bug_class": "service_reachable",
         "handshake": {"connected": True, "host": "10.0.0.5", "port": 443}})
    assert res.confirmed and res.bug_class == "service_reachable"


def test_finding_context_carries_the_handshake_through_to_the_verifier() -> None:
    ctx = FindingContext.from_handshake({"connected": True, "host": "h", "port": 8443})
    vctx = ctx.to_verifier_context()
    assert vctx["bug_class"] == "service_reachable" and vctx["handshake"]["port"] == 8443
    assert OracleVerifier().confirm(vctx).confirmed


def test_a_refused_handshake_does_not_confirm() -> None:
    res = confirm_reachable({"connected": False, "host": "h", "port": 22, "error": "timeout"})
    assert not res.confirmed


# ---- offline re-verification (prove-don't-guess: re-execute over retained evidence) ----


def test_confirmed_reachability_reverifies_offline_from_its_retained_context() -> None:
    hs = {"connected": True, "host": "10.0.0.5", "port": 443, "protocol": "tcp",
          "peer": "10.0.0.5:443", "banner": "HTTP/1.1 400"}
    oracle_context = reachable_context(hs)
    # no network, no trust in the capturer — re-run the pure oracle over the retained evidence
    r = reverify_context(oracle_context, bug_class="service_reachable")
    assert r.reproduced and r.ok
    # and the context is JSON-serialisable (the property that makes offline re-verify possible)
    import json
    json.dumps(oracle_context)


# ---- the gated, bounded active capture -------------------------------------


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def test_capture_handshake_with_an_injected_connector_confirms(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "10.0.0.5")
    hs = capture_handshake("10.0.0.5", 443, slug="alpha",
                           connect=lambda h, p, t, b: ("10.0.0.5:443", "hi"))
    assert hs["connected"] is True and hs["peer"] == "10.0.0.5:443"
    assert confirm_reachable(hs).confirmed


def test_capture_handshake_turns_a_connect_failure_into_a_clean_negative(monkeypatch, tmp_path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "10.0.0.5")

    def _refuse(h, p, t, b):
        raise ConnectionRefusedError("refused")

    hs = capture_handshake("10.0.0.5", 443, slug="alpha", connect=_refuse)
    assert hs["connected"] is False and "Refused" in hs["error"]
    assert not confirm_reachable(hs).confirmed


def test_capture_handshake_over_a_real_loopback_socket(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    # a real listening socket on an ephemeral loopback port — a genuine 3-way handshake, no mocks
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        hs = capture_handshake("127.0.0.1", port, slug="alpha", read_banner=False, timeout=2.0)
    finally:
        srv.close()
    assert hs["connected"] is True and hs["host"] == "127.0.0.1" and hs["port"] == port
    assert confirm_reachable(hs).confirmed


def test_capture_handshake_with_no_slug_is_refused_never_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    _grant_active_recon(monkeypatch)
    called = {"n": 0}
    hs = capture_handshake("10.0.0.5", 443, connect=lambda *a: (called.update(n=1) or ("x", "")))
    assert hs["connected"] is False and "slug" in hs["error"] and called["n"] == 0


def test_capture_handshake_kill_switch_refuses_and_never_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    _grant_active_recon(monkeypatch)
    from framework.v2.authority import KillSwitch
    KillSwitch("alpha").trip("halt")
    called = {"n": 0}

    def _spy(h, p, t, b):
        called["n"] += 1
        return ("x", "")

    hs = capture_handshake("10.0.0.5", 443, slug="alpha", connect=_spy)
    assert hs["connected"] is False and "kill-switch" in hs["error"] and called["n"] == 0


def test_capture_handshake_requires_the_active_recon_entitlement(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability",
                        lambda cap: (_ for _ in ()).throw(RuntimeError("not entitled")))
    hs = capture_handshake("10.0.0.5", 443, slug="alpha", connect=lambda *a: ("x", ""))
    assert hs["connected"] is False and "not entitled" in hs["error"]


def test_capture_handshake_out_of_scope_host_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "10.0.0.5")
    called = {"n": 0}
    hs = capture_handshake("8.8.8.8", 53, slug="alpha",
                           connect=lambda *a: (called.update(n=called["n"] + 1) or ("x", "")))
    assert hs["connected"] is False and "scope" in hs["error"] and called["n"] == 0


@pytest.mark.parametrize("bad", ["10.0.0.5/24", "10.0.0.1-50", "-oN", "a,b", "1.2.3.4 5.6.7.8",
                                 "fe80::1", "2001:db8::5", "::1"])
def test_capture_handshake_rejects_non_single_host_targets(monkeypatch, bad) -> None:
    # includes bare IPv6: the URL-shaped scope gate truncates it, so the gate would validate a
    # different string than the socket dials — reject until the scope layer supports bracketed IPv6.
    _grant_active_recon(monkeypatch)
    hs = capture_handshake(bad, 443, slug="alpha", connect=lambda *a: ("x", ""))
    assert hs["connected"] is False and "single host" in hs["error"]
    assert _is_single_host(bad) is False
