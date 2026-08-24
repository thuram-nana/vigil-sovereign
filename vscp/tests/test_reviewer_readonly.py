"""VSCP-own reviewer-read-only suite (runs in vscp-ci.yml)."""
from __future__ import annotations

from vscp import rbac_routes as routes


def test_every_route_upholds_reviewer_read_only():
    assert routes.reviewer_readonly_report() == []


def test_reviewer_reads_but_cannot_write():
    assert routes.reviewer_can_route("GET", "/vscp/deployments") is True
    assert routes.reviewer_can_route("GET", "/vscp/trust-authorities") is True
    assert routes.reviewer_can_route("GET", "/vscp/reviewer/queue") is True
    for method, path in (
        ("POST", "/vscp/deployments"),
        ("POST", "/vscp/trust-authorities"),
        ("POST", "/vscp/authorizations"),
        ("POST", "/vscp/authorizations/a1/revoke"),
    ):
        assert routes.reviewer_can_route(method, path) is False, (method, path)


def test_default_deny_for_unmapped_route():
    assert routes.route_required_permission("POST", "/vscp/nope") is None
    assert routes.role_can_route("owner", "POST", "/vscp/nope") is False


def test_report_catches_a_bad_mapping(monkeypatch):
    bad = dict(routes.ROUTE_PERMISSIONS)
    bad[("POST", "/vscp/writable-by-reviewer")] = routes.READ
    monkeypatch.setattr(routes, "ROUTE_PERMISSIONS", bad)
    assert any("writable-by-reviewer" in e for e in routes.reviewer_readonly_report())
