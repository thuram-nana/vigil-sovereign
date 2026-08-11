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
    # Exercise CharterScopeSource without a charter on disk by injecting the gate tuple. A3: the signing
    # check runs first, so stub it to a noop here (its enforcement is tested separately below).
    _parse, hms, eh = scope_source._gate()
    monkeypatch.setattr(scope_source, "_GATE", (lambda slug: ["acme.example"], hms, eh))
    monkeypatch.setattr(scope_source, "_require_charter_signed", lambda slug: None)
    src = scope_source.CharterScopeSource("acme")
    assert src.hosts() == ["acme.example"]
    assert src.matches("acme.example")
    assert not src.matches("other.example")


def _write_charter(tmp_path, slug, signer):
    cp = tmp_path / f"{slug}.md"
    cp.write_text(
        f"# Engagement charter — {slug}\n\n"
        f"Signed: `{signer}`     Date: `2026-05-04`\n\n"
        "## 2. In-scope systems\n\n"
        "| Host |\n|---|\n| `acme.example` |\n",
        encoding="utf-8",
    )
    return cp


def test_charter_source_refuses_unsigned_charter(monkeypatch, tmp_path):
    # A3: the gateway must NOT authorize destinations from an UNSIGNED charter. An unsigned charter (the
    # placeholder `<name>` on the Signed: line) makes hosts() raise, fail-closed; a signed one returns scope.
    from framework.v2.common import paths as _paths
    from framework.v2.common.ethics import CharterNotSigned

    monkeypatch.setattr(_paths, "charter_path", lambda s: tmp_path / f"{s}.md")
    _write_charter(tmp_path, "unsigned", "<name>")     # placeholder => NOT signed
    with pytest.raises(CharterNotSigned):
        scope_source.CharterScopeSource("unsigned").hosts()
    # a genuinely signed charter is accepted and its scope is read.
    _write_charter(tmp_path, "signed", "tester")
    assert scope_source.CharterScopeSource("signed").hosts() == ["acme.example"]


def test_empty_host_never_matches():
    s = StaticScopeSource(["example.com"])
    assert not s.matches("")
    assert not s.matches_url("")
