"""scope_source — reuse of CRUCIBLE's matcher + hermetic resolution.

Runs where CRUCIBLE's framework + vigil_core are importable (the offense venv). The point
is that the gateway shares CRUCIBLE's exact scope semantics rather than a second copy.
"""

from __future__ import annotations

import socket

import pytest

from vigil_gateway import scope_source
from vigil_gateway.scope_source import StaticScopeSource


def test_reuses_crucible_matcher_semantics():
    s = StaticScopeSource(["example.com", "*.staging.example.com", "[2606:4700::1111]"])
    assert s.matches("example.com")
    assert s.matches("api.staging.example.com")   # wildcard subdomain
    assert s.matches("staging.example.com")        # wildcard apex
    assert s.matches("2606:4700::1111")            # canonical IPv6
    assert not s.matches("evil.com")
    assert not s.matches("example.com.evil.com")


def test_matches_url_ipv6_correct():
    s = StaticScopeSource(["example.com"])
    assert s.matches_url("https://example.com/path?q=1")
    assert not s.matches_url("https://evil.com/")
    assert not s.matches_url("not a url")


def _fake_resolver(mapping):
    def resolver(host, port):
        if host not in mapping:
            raise socket.gaierror(f"no such host {host}")
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port or 0))
            for ip in mapping[host]
        ]
    return resolver


def test_resolved_allowed_ips_skips_wildcards_and_failures():
    s = StaticScopeSource(["example.com", "*.wild.com", "unresolvable.test", "10.0.0.5"])
    resolver = _fake_resolver({"example.com": ["93.184.216.34"], "10.0.0.5": ["10.0.0.5"]})
    ips = s.resolved_allowed_ips(resolver=resolver)
    assert "93.184.216.34" in ips
    assert "10.0.0.5" in ips           # an IP literal resolves to itself
    # wildcard entry contributes nothing; the unresolvable name is silently skipped
    assert all(not ip.startswith("wild") for ip in ips)
    assert len(ips) == 2


def test_charter_source_wraps_parse_scope(monkeypatch):
    # Exercise CharterScopeSource without a charter on disk by injecting the gate tuple.
    _parse, hms, eh = scope_source._gate()
    monkeypatch.setattr(scope_source, "_GATE", (lambda slug: ["acme.example"], hms, eh))
    src = scope_source.CharterScopeSource("acme")
    assert src.hosts() == ["acme.example"]
    assert src.matches("acme.example")
    assert not src.matches("other.example")


def test_empty_host_never_matches():
    s = StaticScopeSource(["example.com"])
    assert not s.matches("")
    assert not s.matches_url("")
