"""B2 drift-guard — the gateway's stdlib-only scope matcher agrees with CRUCIBLE's original, ALWAYS.

``vigil_gateway.scope_match`` is a verbatim port of ``framework.v2.common.ethics``'s matching predicate so the
stdlib-only gateway container can enforce scope without framework. A port is only safe if it cannot drift from
the original: this test compares the two implementations over a corpus of hosts × scope-entry sets and URLs,
so any future edit to either side that changes matching behaviour fails here.

Offense leg only (imports framework to compare) → listed in the ci.yml offense run-list.
"""
from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.common.ethics", reason="CRUCIBLE not importable in this leg")

from framework.v2.common import ethics
from vigil_gateway import scope_match

_HOSTS = [
    "acme.example.com", "evil.example.com", "example.com", "a.b.example.com", "sub.corp.example",
    "corp.example", "ACME.Example.CoM", "acme.example.com.", "", "169.254.169.254",
    "fe80::1", "fe80:0:0:0:0:0:0:1", "[fe80::1]", "10.0.0.5", "2001:db8::1",
]
_SCOPES = [
    [], ["acme.example.com"], ["*.example.com"], ["*.corp.example", "acme.example.com"],
    ["[fe80::1]"], ["fe80::1"], ["N/A"], ["none", "acme.example.com"], ["10.0.0.5"],
    ["`acme.example.com`"], ["2001:db8::/32"], ["2001:db8::1"],
]
_URLS = [
    "https://acme.example.com/p?q=1", "acme.example.com", "http://[fe80::1]:8443/x",
    "https://user:pw@acme.example.com/x", "https://10.0.0.5", "fe80::1", "https://[2001:db8::1]/y",
    "not a url", "", "https://EXAMPLE.com",
]


def test_host_matches_scope_parity():
    for h in _HOSTS:
        for s in _SCOPES:
            assert scope_match.host_matches_scope(h, s) == ethics.host_matches_scope(h, s), (h, s)


def test_extract_hostname_parity():
    for u in _URLS:
        assert scope_match.extract_hostname(u) == ethics.extract_hostname(u), u


def test_bracket_bare_ipv6_parity():
    for u in _URLS + ["https://fe80::1/x", "https://fe80::1", "ssh://[::1]:22"]:
        assert scope_match.bracket_bare_ipv6(u) == ethics.bracket_bare_ipv6(u), u
