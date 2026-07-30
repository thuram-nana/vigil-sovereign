"""B5 — the recurring vuln-feed SIDECAR the console supervises (start / stop / status).

``run_feed_start`` spawns the SAME gated ``intel feed-daemon --live`` CLI a hand-run uses (argv LIST, no shell)
as a tracked background subprocess; ``run_feed_stop`` terminates + untracks it. Invariants under test:

  * OPT-IN + kill-switch gated — a tripped switch refuses and spawns NOTHING;
  * the spawned argv is the LEADS-only recurring daemon — never a one-shot pull, a promote/apply, or a target;
  * idempotent — a live sidecar for the slug is reported, never double-spawned;
  * the pids are tracked in a console-owned file and honestly surfaced by ``feed_sidecars`` / ``feed_status``
    with the live pid + chosen interval and NO fabricated next-run/last-run;
  * FATAL-2 — the console SUBPROCESSES the offense CLI (``python -m framework.v2 intel feed-daemon``); it never
    imports the integration package.

No real subprocess and no real signal are used: ``subprocess.Popen`` / ``_pid_alive`` / ``_feed_terminate`` are
faked, exactly as ``test_knowledge_actions`` fakes ``subprocess.run``.
"""

from __future__ import annotations

import json as _json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

from framework.v2.common import paths
from framework.v2.console import actions, api, server


class _FakePopen:
    def __init__(self, argv, **kw):
        self.argv = argv
        self.pid = 4242
        self._kw = kw


def _clear_killswitch(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")


def _trip_killswitch(monkeypatch, tmp_path, slug):
    from framework.v2.authority.killswitch import KillSwitch
    monkeypatch.setattr(paths, "killswitch_path", lambda s: tmp_path / f"{s}.halt")
    KillSwitch(slug).trip("stop")


def _capture_popen(monkeypatch):
    seen = {"argv": None, "count": 0}

    def fake(argv, **kw):
        seen["argv"] = argv
        seen["count"] += 1
        return _FakePopen(argv, **kw)

    monkeypatch.setattr(actions.subprocess, "Popen", fake)
    return seen


def _forbid_popen(monkeypatch):
    seen = {"called": False}

    def boom(argv, **kw):
        seen["called"] = True
        raise AssertionError(f"subprocess.Popen must not be called: {argv}")

    monkeypatch.setattr(actions.subprocess, "Popen", boom)
    return seen


# ---- run_feed_start ---------------------------------------------------------


def test_feed_start_requires_a_slug():
    assert actions.run_feed_start("")["ok"] is False


def test_feed_start_refused_under_killswitch_spawns_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    _trip_killswitch(monkeypatch, tmp_path, "acme")
    seen = _forbid_popen(monkeypatch)
    out = actions.run_feed_start("acme", interval=3600)
    assert out["ok"] is False and "kill-switch" in out.get("refused", "")
    assert seen["called"] is False                                # no recurring egress under STOP


def test_feed_start_spawns_gated_daemon_and_tracks_pid(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    _clear_killswitch(monkeypatch, tmp_path)
    monkeypatch.setattr(actions, "_pid_alive", lambda pid: True)  # our fake child is "alive"
    seen = _capture_popen(monkeypatch)
    out = actions.run_feed_start("acme", interval=3600)
    assert out["ok"] is True and out["running"] is True and out["pid"] == 4242
    argv = seen["argv"]
    # the gated OFFENSE-engine recurring daemon, argv LIST (no shell), --live opt-in
    assert argv[:6] == [actions.sys.executable, "-m", "framework.v2", "intel", "feed-daemon", "--live"]
    assert argv[argv.index("--slug") + 1] == "acme"
    assert argv[argv.index("--interval") + 1] == "3600"
    assert "--poll" in argv
    # never the one-shot pull, never a promote/apply/target
    for banned in ("refresh-vulnintel", "--promote", "--apply", "--record"):
        assert banned not in argv
    # tracked in the console-owned pids file + surfaced by feed_sidecars
    scs = actions.feed_sidecars()
    assert any(s["slug"] == "acme" and s["alive"] and s["interval"] == 3600 for s in scs)


def test_feed_start_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    _clear_killswitch(monkeypatch, tmp_path)
    monkeypatch.setattr(actions, "_pid_alive", lambda pid: True)
    seen = _capture_popen(monkeypatch)
    actions.run_feed_start("acme")
    out2 = actions.run_feed_start("acme")
    assert out2["ok"] is True and out2.get("already_running") is True
    assert seen["count"] == 1                                     # a live sidecar is never double-spawned


def test_feed_start_clamps_interval(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    _clear_killswitch(monkeypatch, tmp_path)
    monkeypatch.setattr(actions, "_pid_alive", lambda pid: False)
    seen = _capture_popen(monkeypatch)
    actions.run_feed_start("acme", interval=1)                    # below the floor → clamped up
    argv = seen["argv"]
    assert int(argv[argv.index("--interval") + 1]) == actions._FEED_INTERVAL_MIN
    actions.run_feed_start("acme2", interval=10 ** 9)            # above the ceiling → clamped down
    argv2 = seen["argv"]
    assert int(argv2[argv2.index("--interval") + 1]) == actions._FEED_INTERVAL_MAX


# ---- run_feed_stop ----------------------------------------------------------


def test_feed_stop_terminates_and_untracks(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    _clear_killswitch(monkeypatch, tmp_path)
    monkeypatch.setattr(actions, "_pid_alive", lambda pid: True)
    _capture_popen(monkeypatch)
    actions.run_feed_start("acme")
    killed = {"pid": None}
    monkeypatch.setattr(actions, "_feed_terminate",
                        lambda pid, **kw: (killed.__setitem__("pid", pid) or True))
    out = actions.run_feed_stop("acme")
    assert out["ok"] is True and out["stopped"] is True and out["pid"] == 4242
    assert killed["pid"] == 4242
    assert actions.feed_sidecars() == []                         # untracked after stop


def test_feed_stop_untracked_is_clean_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    out = actions.run_feed_stop("never-started")
    assert out["ok"] is True and out["stopped"] is False


# ---- feed_status projection -------------------------------------------------


def test_feed_status_lists_running_sidecar(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    _clear_killswitch(monkeypatch, tmp_path)
    monkeypatch.setattr(actions, "_pid_alive", lambda pid: True)
    _capture_popen(monkeypatch)
    actions.run_feed_start("acme", interval=1800)
    d = api.feed_status()
    assert d["recurring"]["managed_here"] is True
    scs = d["recurring"]["sidecars"]
    assert any(s["slug"] == "acme" and s["alive"] and s["interval"] == 1800 for s in scs)
    # HONEST: still no fabricated schedule state
    assert "next_run" not in d["recurring"] and "last_run" not in d["recurring"]


# ---- server routes (CSRF-gated, wired) --------------------------------------


@contextmanager
def _running():
    httpd = server.serve(host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _post(url, *, csrf=True, headers=None, data=b"{}"):
    req = urllib.request.Request(url, method="POST", data=data)
    if csrf:
        req.add_header("X-Requested-With", "vigil-ui")
    req.add_header("Sec-Fetch-Site", "same-origin")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_feed_start_stop_routes_are_csrf_gated_and_wired(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path))
    _clear_killswitch(monkeypatch, tmp_path)
    monkeypatch.setattr(actions, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(actions, "_feed_terminate", lambda pid, **kw: True)
    _capture_popen(monkeypatch)
    with _running() as base:
        # cross-site (no custom header) → refused by the shared guard BEFORE routing
        st, body = _post(base + "/api/feed/acme/start", csrf=False)
        assert st == 403 and b"X-Requested-With" in body
        # same-origin start → routes to the action + returns ok
        st, body = _post(base + "/api/feed/acme/start", data=b'{"interval":1800}')
        assert st == 200
        r = _json.loads(body)
        assert r["ok"] is True and r["slug"] == "acme"
        # stop routes too
        st, body = _post(base + "/api/feed/acme/stop")
        assert st == 200 and _json.loads(body)["ok"] is True
