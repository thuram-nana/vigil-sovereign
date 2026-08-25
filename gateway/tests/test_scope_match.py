"""B2 — the stdlib-only scope MATCHER the gateway container falls back to when framework is absent.

This is the fix for the B2 red-pen BLOCK: the per-connection L7 check (`ScopeSource.matches`) used to import
``host_matches_scope`` from ``framework.v2.common.ethics``, which is NOT in the stdlib-only container — so it
raised and the proxy denied EVERY host (the injected scope was inert, the gateway was structurally deny-all).
``scope_match`` ports the matcher verbatim; ``scope_source._gate`` falls back to it when framework is genuinely
absent. These tests use ONLY ``vigil_gateway`` (no framework), mirroring the container.
"""
from __future__ import annotations

from vigil_gateway import scope_match, scope_source
from vigil_gateway.scope_source import StaticScopeSource


def test_local_matcher_literal_wildcard_ipv6_and_denies():
    hm = scope_match.host_matches_scope
    assert hm("acme.example.com", ["acme.example.com"]) is True
    assert hm("evil.example.com", ["acme.example.com"]) is False
    assert hm("a.b.example.com", ["*.example.com"]) is True
    assert hm("example.com", ["*.example.com"]) is True             # the apex matches its own wildcard
    assert hm("fe80::1", ["[fe80::1]"]) is True                     # canonical IPv6, bracketed entry
    assert hm("fe80:0:0:0:0:0:0:1", ["fe80::1"]) is True            # expanded == compressed
    assert hm("169.254.169.254", ["acme.example.com"]) is False     # unrelated IP denied
    assert hm("x", []) is False and hm("", ["a"]) is False          # empties deny (fail-closed)


def test_container_scope_matches_via_local_gate_without_framework(monkeypatch):
    """THE fix: with framework ABSENT (the stdlib-only container, simulated by forcing the local gate),
    StaticScopeSource still ENFORCES the injected scope — it matches in-scope hosts and denies others — instead
    of raising ModuleNotFoundError and denying everything (the red-pen BLOCK)."""
    monkeypatch.setattr(scope_source, "_GATE", scope_source._local_gate())
    s = StaticScopeSource(["acme.example.com", "*.corp.example"])
    assert s.matches("acme.example.com") is True
    assert s.matches("host.corp.example") is True
    assert s.matches("evil.example") is False
    assert s.matches_url("https://acme.example.com/path") is True
    assert s.matches_url("https://evil.example/path") is False
    # an EMPTY injected scope is still deny-all under the local matcher (fail-closed).
    assert StaticScopeSource([]).matches("acme.example.com") is False


def test_local_gate_parse_scope_is_unavailable_in_the_container():
    """Charter PARSING is the launcher's host-side job; the container only MATCHES an injected static scope.
    A container-side parse_scope call (which only a CharterScopeSource would make — never constructed there)
    refuses rather than silently mis-parsing."""
    import pytest
    parse_scope, _hm, _eh = scope_source._local_gate()
    with pytest.raises(RuntimeError, match="requires the CRUCIBLE ethics gate"):
        parse_scope("acme")
