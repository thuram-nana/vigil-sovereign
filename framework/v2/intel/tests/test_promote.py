"""intel.promote — the asset→endpoint promotion projector (the DISCOVERER keystone).

These pin the single missing edge that turns recon roaming into a live test feed: an IN-SCOPE
recon/sensor asset (DOMAIN / HOST / web-ish SERVICE) becomes a url-bearing ENDPOINT node that the
autonomous loop's :func:`engage_autonomous._endpoint_probe_targets` can then read. The cardinal
properties asserted here: in-scope BY the charter predicate the live gate uses (out-of-scope never
promoted), a LEAD not a fact (intel:promote provenance), and deterministic + idempotent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.common import paths as _paths
from framework.v2.engage_autonomous import _endpoint_probe_targets
from framework.v2.intel.promote import promote_to_endpoints
from framework.v2.worldmodel import Edge, EdgeKind, Node, NodeKind, WorldModel

_CHARTER = """\
# Engagement charter — `{slug}`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
{rows}

## 3. Out of scope

- Anything not listed above.
"""


@pytest.fixture()
def charter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "targets"
    root.mkdir()

    def build(slug: str, hosts: list[str]) -> None:
        td = root / slug
        td.mkdir(parents=True, exist_ok=True)
        rows = "\n".join(f"| `{h}` | test | Yes |" for h in hosts)
        (td / "charter.md").write_text(_CHARTER.format(slug=slug, rows=rows), encoding="utf-8")

    monkeypatch.setattr(_paths, "charter_path", lambda s: root / s / "charter.md")
    return build


def _world() -> WorldModel:
    return WorldModel()


def _domain(w: WorldModel, host: str) -> None:
    w.add_node(Node(id=f"domain:{host}", kind=NodeKind.DOMAIN, attrs={},
                    provenance=f"intel:obs:{host}", confidence=0.8, first_seen=1, last_seen=1))


def _host(w: WorldModel, ip: str) -> None:
    w.add_node(Node(id=f"host:{ip}", kind=NodeKind.HOST, attrs={},
                    provenance=f"intel:obs:{ip}", confidence=0.8, first_seen=1, last_seen=1))


def _service(w: WorldModel, hostkey: str, port: int, *, service: str, proto: str = "tcp",
             with_host: bool = False) -> str:
    """Add a SERVICE node keyed like sensors mint it (``{hostkey}:{port}/{proto}``). When ``with_host``
    also add the HOST + a HOSTS edge (the robust host-resolution path)."""
    svc_id = f"service:{hostkey}:{port}/{proto}"
    w.add_node(Node(id=svc_id, kind=NodeKind.SERVICE,
                    attrs={"port": port, "protocol": proto, "service": service},
                    provenance="intel:obs:svc", confidence=0.7, first_seen=1, last_seen=1))
    if with_host:
        _host(w, hostkey)
        w.add_edge(Edge(src=f"host:{hostkey}", dst=svc_id, kind=EdgeKind.HOSTS,
                        provenance="intel:obs:svc", confidence=0.7, first_seen=1, last_seen=1))
    return svc_id


# ---------------------------------------------------------------------------
# in-scope assets are promoted to url-bearing ENDPOINTs; out-of-scope are not
# ---------------------------------------------------------------------------


def test_promotes_in_scope_domain_to_https_root(charter):
    charter("t", ["*.example.com"])
    w = _world()
    _domain(w, "api.example.com")       # in scope (wildcard)
    _domain(w, "evil.attacker.test")    # out of scope
    minted = promote_to_endpoints(w, "t")
    assert minted == [("endpoint:promoted:https://api.example.com/", "https://api.example.com/")]
    node = w.get_node("endpoint:promoted:https://api.example.com/")
    assert node is not None and node.kind is NodeKind.ENDPOINT
    assert node.attrs["url"] == "https://api.example.com/"
    assert node.attrs["host"] == "api.example.com"
    assert node.provenance == "intel:promote:domain:api.example.com"
    # a LEAD, never a fact — intel-grounded, not oracle-grounded
    assert node.grounding == "intel"


def test_promotes_in_scope_host(charter):
    charter("t", ["10.0.0.5"])
    w = _world()
    _host(w, "10.0.0.5")
    _host(w, "8.8.8.8")   # out of scope
    minted = promote_to_endpoints(w, "t")
    assert minted == [("endpoint:promoted:https://10.0.0.5/", "https://10.0.0.5/")]


def test_promotes_web_service_scheme_and_nondefault_port(charter):
    charter("t", ["10.0.0.9"])
    w = _world()
    # with_host=False isolates SERVICE promotion (no HOST node → the host-key-parse fallback resolves
    # the host); this keeps the assertion about scheme/port derivation, not host promotion.
    _service(w, "10.0.0.9", 8080, service="http")      # http:8080
    _service(w, "10.0.0.9", 8443, service="https")     # https:8443
    _service(w, "10.0.0.9", 22, service="ssh")         # NOT web -> skipped
    urls = sorted(u for _, u in promote_to_endpoints(w, "t"))
    assert urls == ["http://10.0.0.9:8080/", "https://10.0.0.9:8443/"]


def test_web_service_default_ports_omit_the_port(charter):
    charter("t", ["10.0.0.9"])
    w = _world()
    _service(w, "10.0.0.9", 80, service="http")     # default http port -> omitted
    _service(w, "10.0.0.9", 443, service="https")   # default https port -> omitted
    urls = sorted(u for _, u in promote_to_endpoints(w, "t"))
    assert urls == ["http://10.0.0.9/", "https://10.0.0.9/"]


def test_service_host_from_hosts_edge_is_robust(charter):
    charter("t", ["node1.example.com"])
    w = _world()
    # a SERVICE whose host is resolved via the incoming HOSTS edge (not key-parsing); the HOST node it
    # adds is ALSO in scope, so BOTH the service root and the host https-root are promoted.
    _service(w, "node1.example.com", 8080, service="http-alt", with_host=True)
    urls = sorted(u for _, u in promote_to_endpoints(w, "t"))
    assert urls == ["http://node1.example.com:8080/", "https://node1.example.com/"]


def test_out_of_scope_never_promoted(charter):
    charter("t", ["only.example.com"])
    w = _world()
    _domain(w, "other.test")
    _host(w, "1.2.3.4")
    _service(w, "1.2.3.4", 80, service="http")
    assert promote_to_endpoints(w, "t") == []


def test_non_web_service_never_promoted(charter):
    charter("t", ["10.0.0.9"])
    w = _world()
    _service(w, "10.0.0.9", 22, service="ssh")
    _service(w, "10.0.0.9", 3306, service="mysql")
    _service(w, "10.0.0.9", 53, service="domain")
    assert promote_to_endpoints(w, "t") == []


def test_ipv6_host_is_bracketed(charter):
    charter("t", ["fe80::1"])
    w = _world()
    _host(w, "fe80::1")
    minted = promote_to_endpoints(w, "t")
    assert minted == [("endpoint:promoted:https://[fe80::1]/", "https://[fe80::1]/")]


# ---------------------------------------------------------------------------
# deterministic + idempotent, and readable by the loop's probe-target reader
# ---------------------------------------------------------------------------


def test_idempotent_and_deterministic(charter):
    charter("t", ["*.example.com"])
    w = _world()
    _domain(w, "a.example.com")
    _domain(w, "b.example.com")
    first = promote_to_endpoints(w, "t")
    n_after_first = w.node_count
    second = promote_to_endpoints(w, "t")
    assert first == second                       # deterministic
    assert w.node_count == n_after_first         # idempotent upsert — no new nodes on re-run


def test_promoted_endpoints_are_read_by_endpoint_probe_targets(charter):
    """THE BRIDGE: after promotion, the loop's own probe-target reader returns the promoted urls — the
    single edge that lets a recon-discovered asset reach the test loop."""
    charter("t", ["*.example.com"])
    w = _world()
    _domain(w, "api.example.com")
    before = _endpoint_probe_targets(w, exclude=set())
    assert before == []                          # nothing testable yet (recon minted only a DOMAIN)
    promote_to_endpoints(w, "t")
    after = _endpoint_probe_targets(w, exclude=set())
    assert after == [("endpoint:promoted:https://api.example.com/", "https://api.example.com/")]


def test_wildcard_and_apex_both_match(charter):
    charter("t", ["*.example.com"])
    w = _world()
    _domain(w, "example.com")        # apex matches *.example.com
    _domain(w, "deep.sub.example.com")
    urls = sorted(u for _, u in promote_to_endpoints(w, "t"))
    assert urls == ["https://deep.sub.example.com/", "https://example.com/"]


# ---------------------------------------------------------------------------
# best-effort: no charter / no scope / no world → empty, never raises
# ---------------------------------------------------------------------------


def test_no_charter_returns_empty(charter):
    # slug with no charter file written
    w = _world()
    _domain(w, "api.example.com")
    assert promote_to_endpoints(w, "missing-slug") == []


def test_none_world_returns_empty(charter):
    charter("t", ["example.com"])
    assert promote_to_endpoints(None, "t") == []


def test_empty_scope_returns_empty(charter):
    charter("t", [])   # a charter with an empty scope table
    w = _world()
    _domain(w, "api.example.com")
    assert promote_to_endpoints(w, "t") == []
