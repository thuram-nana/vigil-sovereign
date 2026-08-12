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

import pytest

from framework.v2.console import actions, api

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


# --------------------------- the gated bring-up action (/api/services/up) ---------------------------
# NB every test here patches BOTH bring-up legs (RootServices + SandboxNetworking) so a test NEVER runs
# real `docker compose`/`build` (which would hang on an image pull). Needs vigil_integration → importorskip.

@pytest.fixture
def no_real_docker(monkeypatch):
    pytest.importorskip("vigil_integration.services")
    import vigil_integration.services as svc
    calls: dict = {}

    class _FakeRoot:
        def __init__(self, root):
            pass

        def up(self, svcs):
            calls["svcs"] = list(svcs)
            return {s: "running" for s in svcs}
    monkeypatch.setattr(svc, "RootServices", _FakeRoot)
    try:
        import vigil_gateway.docker as gw

        class _FakeGw:
            def compose_up(self, *a, **k):
                calls["gateway"] = True
                return {"gateway": "running"}
        monkeypatch.setattr(gw, "SandboxNetworking", _FakeGw)
    except ImportError:
        pass
    return calls


def test_services_up_is_bounded_to_the_closed_service_set(no_real_docker) -> None:
    # The request can NEVER choose the service/image/command: only the fixed `all` flag selects from a
    # CLOSED set. A body that tries to inject a service name is ignored, and it never raises.
    r = actions.services_up({"all": False, "services": ["evil"], "service": "x; rm -rf /"})
    assert r["ok"] is True
    assert no_real_docker.get("svcs") == ["qdrant"]                 # request names IGNORED — fixed default only

    actions.services_up({"all": True})
    assert no_real_docker.get("svcs") == ["qdrant", "neo4j", "otel-collector"]


def test_services_up_fail_soft_per_leg(no_real_docker, monkeypatch) -> None:
    # If a leg raises, the action reports it as an error and still returns ok — never a 500.
    import vigil_integration.services as svc

    class _Boom:
        def __init__(self, root):
            pass

        def up(self, svcs):
            raise RuntimeError("docker down")
    monkeypatch.setattr(svc, "RootServices", _Boom)   # gateway leg stays the fast fake from the fixture
    r = actions.services_up({"all": False})
    assert r["ok"] is True and "services_error" in r["result"]


def test_services_up_tolerates_a_non_dict_body(no_real_docker) -> None:
    # _read_body can return ANY JSON value; a non-dict body must NOT raise (the "never raises" contract).
    for bad in ([], None, "x", 123, True):
        r = actions.services_up(bad)
        assert isinstance(r, dict) and r["ok"] is True
