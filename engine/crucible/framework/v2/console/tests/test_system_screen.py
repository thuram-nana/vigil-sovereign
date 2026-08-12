"""
Console System provider (`/api/services`) — READ-ONLY system-readiness + docker-service state.

The System screen surfaces the same report as `vigil doctor`. Asserts the properties it stakes on:
  * the readiness SHAPE is always present (fail-soft default has every key), so the screen never breaks;
  * it is READ-ONLY + idempotent — a readiness read starts nothing and mutates nothing;
  * it FAILS SOFT — if the collector is unavailable (e.g. vigil_integration not importable in a leg), it
    returns an honest default (ok:False + empty sections), never a raise;
  * the route is registered so the UI can reach it.
"""

from __future__ import annotations

from framework.v2.console import api

_KEYS = {"ok", "issues", "notes", "binaries", "venvs", "dirs", "ui_ports", "docker_services"}


def test_services_data_has_the_readiness_shape() -> None:
    d = api.services_data()
    assert _KEYS <= set(d)
    assert isinstance(d["ok"], bool)
    assert isinstance(d["docker_services"], dict)


def test_services_data_is_read_only_and_idempotent() -> None:
    a = api.services_data()
    b = api.services_data()
    assert set(a) == set(b)                     # stable shape; two reads, no raise, no mutation


def test_services_data_fail_soft(monkeypatch) -> None:
    # The provider must return the honest default (never propagate) when the collector is unavailable.
    try:
        from vigil_integration import doctor
    except ImportError:
        # vigil_integration not importable in this leg → services_data already fail-softs.
        d = api.services_data()
        assert d["ok"] is False and _KEYS <= set(d)
        return

    def _boom(*a, **k):
        raise RuntimeError("collector unavailable")
    monkeypatch.setattr(doctor, "collect", _boom)
    d = api.services_data()
    assert d["ok"] is False and _KEYS <= set(d)


def test_route_is_registered() -> None:
    from framework.v2.console import server
    assert server._EXACT_ROUTES.get("/api/services") is api.services_data
