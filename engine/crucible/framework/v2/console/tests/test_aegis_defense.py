"""P5a — the console side of the AEGIS Defense dashboard: fail-closed gateway launch validation, an
honest empty status, and the route wiring. These paths never import the aegis package (the AegisConfig
parse-check is lazy and only reached AFTER the cheap validation), so they run in the minimal CI env
(no httpx) exactly like the rest of the console suite.
"""
from __future__ import annotations

import pytest

from framework.v2.console import actions, api, server


@pytest.fixture
def isolated_current(tmp_path, monkeypatch):
    """Point the single-gateway pointer at a temp file so the empty-state assertions are deterministic
    regardless of any real gateway an operator may have launched on this machine."""
    monkeypatch.setattr(actions, "_aegis_current_path", lambda: tmp_path / "aegis-current.json")
    return tmp_path


# --- fail-closed launch validation (NO spawn on bad input) --------------------

@pytest.mark.parametrize("body,needle", [
    ({}, "upstream"),
    ({"upstream": "not-a-url"}, "upstream"),
    ({"upstream": "ftp://x/y"}, "upstream"),
    ({"upstream": "http://app:3000", "deployment_secret": ""}, "deployment secret"),
    ({"upstream": "http://app:3000", "deployment_secret": "s", "mode": "evil"}, "mode"),
    ({"upstream": "http://app:3000", "deployment_secret": "s\nEVIL=1"}, "single line"),
    ({"upstream": "http://app:3000", "deployment_secret": "s", "port": "99999"}, "1–65535"),
    ({"upstream": "http://app:3000", "deployment_secret": "s", "port": "abc"}, "number"),
    # a honeypot path must be a URL path (leading "/"), so a "--flag"-looking value can never reach the
    # child argv, and a newline can't smuggle anything — rejected BEFORE any spawn.
    ({"upstream": "http://app:3000", "deployment_secret": "s", "honeypot_paths": ["--verdicts-out=/etc/x"]}, "honeypot path"),
    ({"upstream": "http://app:3000", "deployment_secret": "s", "honeypot_paths": ["/ok\ninject"]}, "honeypot path"),
    # P4 verdict sink: a non-http(s) URL or a bad sink format is refused BEFORE any spawn.
    ({"upstream": "http://app:3000", "deployment_secret": "s", "verdict_webhook": "ftp://x/y"}, "verdict_webhook"),
    ({"upstream": "http://app:3000", "deployment_secret": "s", "verdict_webhook": "http://s\nX"}, "verdict_webhook"),
    ({"upstream": "http://app:3000", "deployment_secret": "s", "verdict_webhook": "http://sink", "verdict_sink": "evil"}, "verdict_sink"),
])
def test_aegis_setup_refuses_bad_input(isolated_current, body, needle):
    r = actions.aegis_setup(body)
    assert "error" in r and needle in r["error"], (body, r)


def test_aegis_setup_threads_the_verdict_webhook_to_the_child(isolated_current, monkeypatch):
    import importlib.util

    import pytest as _pytest
    if importlib.util.find_spec("httpx") is None:
        _pytest.skip("the gateway spawn path needs httpx")

    captured: dict = {}

    class _FakeProc:
        pid = 4321

    def _fake_popen(cmd, **kw):
        captured["cmd"] = list(cmd)
        return _FakeProc()

    monkeypatch.setattr(actions, "run_dir", lambda rid, **kw: isolated_current / rid)
    monkeypatch.setattr(actions, "console_dir", lambda: isolated_current / ".console")
    monkeypatch.setattr(actions.subprocess, "Popen", _fake_popen)

    r = actions.aegis_setup({
        "upstream": "http://127.0.0.1:3000", "deployment_secret": "sekret",
        "verdict_webhook": "https://siem.example/hook", "verdict_sink": "slack",
    })
    assert r.get("status") == "running", r
    cmd = captured["cmd"]
    assert "--verdict-webhook" in cmd and "https://siem.example/hook" in cmd
    assert cmd[cmd.index("--verdict-sink") + 1] == "slack"
    assert r["verdict_webhook"] == "https://siem.example/hook" and r["verdict_sink"] == "slack"
    assert "--verdict-webhook" in r["production_command"]
    # the auth secret is NEVER on the argv (it rides the inherited env)
    assert "AEGIS_VERDICT_WEBHOOK_AUTHORIZATION" not in " ".join(cmd)


def test_aegis_setup_refusals_do_not_import_the_aegis_engine(isolated_current):
    import sys
    before = {m for m in sys.modules if m.startswith("framework.v2.aegis")}
    actions.aegis_setup({"upstream": "nope"})            # a refusal must not NEWLY pull the httpx-heavy pkg
    after = {m for m in sys.modules if m.startswith("framework.v2.aegis")}
    assert after == before, f"refusal path imported aegis: {after - before}"


# --- honest empty status + verdict path ---------------------------------------

def test_aegis_status_empty_is_honest(isolated_current):
    st = api.aegis_status()
    assert st["running"] is False and st["gateway"] is None
    assert st["actors"] == [] and st["actor_count"] == 0
    assert st["note"] and "No AEGIS gateway" in st["note"]   # honest empty state, never fabricated data


def test_aegis_verdicts_path_none_without_gateway(isolated_current):
    assert actions.aegis_verdicts_path() is None


def test_aegis_stop_is_idempotent_noop(isolated_current):
    r = actions.aegis_stop({})
    assert r.get("stopped") is False


# --- route wiring -------------------------------------------------------------

def test_status_route_registered():
    assert server._EXACT_ROUTES.get("/api/aegis/status") is api.aegis_status


def test_setup_stop_verdicts_wired():
    # the POST actions + the SSE verdicts source exist (the setup/stop POSTs ride the CSRF/rebind gate
    # in do_POST; the verdicts SSE resolves its path via api.aegis_verdicts_path).
    assert callable(actions.aegis_setup) and callable(actions.aegis_stop)
    assert callable(actions.aegis_verdicts_path)
