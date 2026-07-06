"""
Ops Console — Phase 0 (spine + read API + SSE tail).

Pins the load-bearing guarantees: the server binds loopback ONLY, the read APIs are
resilient JSON, static serving blocks path traversal, and the event tailer does an
incremental read of the append-only log. A read-only console with no destructive
route is the whole safety story here.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from framework.v2.console import api, server
from framework.v2.console.sse import EventTailer


# ---------------------------------------------------------------------------
# read APIs — resilient JSON on any tree
# ---------------------------------------------------------------------------


def test_status_data_shape() -> None:
    d = api.status_data()
    assert set(d) == {"paths", "backends"}
    assert "crucible_root" in d["paths"] and "targets_root" in d["paths"]
    assert isinstance(d["backends"], list)
    for b in d["backends"]:
        assert set(b) == {"name", "available", "note"}


def test_list_engagements_is_resilient() -> None:
    d = api.list_engagements()
    assert "engagements" in d and isinstance(d["engagements"], list)
    for e in d["engagements"]:
        assert "slug" in e and "killswitch" in e
        assert "tripped" in e["killswitch"]  # fail-closed field always present


def test_engagement_detail_never_raises_on_unknown_slug() -> None:
    d = api.engagement_detail("no-such-engagement-xyz")
    assert d["slug"] == "no-such-engagement-xyz"
    assert d["killswitch"]["tripped"] in (True, False)


# ---------------------------------------------------------------------------
# loopback-only guard
# ---------------------------------------------------------------------------


def test_serve_refuses_non_loopback() -> None:
    for host in ("0.0.0.0", "192.168.1.10", "::"):
        with pytest.raises(ValueError, match="loopback only"):
            server.serve(host=host, port=0)


# ---------------------------------------------------------------------------
# event tailer — incremental read of an append-only JSONL
# ---------------------------------------------------------------------------


def test_event_tailer_reads_only_new_lines(tmp_path) -> None:
    log = tmp_path / ".crucible-v2.log"
    log.write_text('{"event":"old","level":"info"}\n', encoding="utf-8")
    t = EventTailer(log, from_end=True)  # start live -> ignores the pre-existing line
    assert t.read_new() == []
    with log.open("a", encoding="utf-8") as f:
        f.write('{"event":"a","status":200}\n{"event":"b"}\n')
    got = t.read_new()
    assert [e["event"] for e in got] == ["a", "b"]
    # partial line is buffered until its newline arrives
    with log.open("a", encoding="utf-8") as f:
        f.write('{"event":"c"')
    assert t.read_new() == []
    with log.open("a", encoding="utf-8") as f:
        f.write('}\n')
    assert [e["event"] for e in t.read_new()] == ["c"]


def test_event_tailer_skips_malformed_lines(tmp_path) -> None:
    log = tmp_path / "x.log"
    log.write_text("", encoding="utf-8")
    t = EventTailer(log, from_end=True)
    with log.open("a", encoding="utf-8") as f:
        f.write("not json\n{\"event\":\"ok\"}\n")
    assert [e["event"] for e in t.read_new()] == ["ok"]


# ---------------------------------------------------------------------------
# live server: serves the SPA + APIs, blocks traversal, has no destructive route
# ---------------------------------------------------------------------------


@contextmanager
def _running_server():
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


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 (loopback test)
        return r.status, r.headers.get_content_type(), r.read()


def test_server_serves_spa_and_apis() -> None:
    with _running_server() as base:
        st, ct, body = _get(base + "/")
        assert st == 200 and ct == "text/html" and b"CRUCIBLE" in body
        st, ct, body = _get(base + "/static/styles.css")
        assert st == 200 and ct == "text/css"
        st, ct, body = _get(base + "/api/status")
        assert st == 200 and "backends" in json.loads(body)
        st, ct, body = _get(base + "/api/engagements")
        assert st == 200 and "engagements" in json.loads(body)


def test_server_blocks_path_traversal_and_unknown_api() -> None:
    with _running_server() as base:
        for bad in ("/static/../server.py", "/static/../../__main__.py"):
            with pytest.raises(urllib.error.HTTPError) as ei:
                _get(base + bad)
            assert ei.value.code == 404
        with pytest.raises(urllib.error.HTTPError) as ei:
            _get(base + "/api/does-not-exist")
        assert ei.value.code == 404


def test_only_safe_actions_no_clear_or_destructive_route() -> None:
    # The console exposes exactly three SAFE POST actions (launch / reverify / trip).
    # It must NOT expose a kill-switch CLEAR, a scope/authority edit, or any other
    # mutating route — clearing/relaxing is a deliberate off-console act.
    with _running_server() as base:
        for bad in ("/api/killswitch/x/clear", "/api/scope/edit", "/api/authority/x/grant",
                    "/api/destroy", "/api/launch/engage-destructive"):
            req = urllib.request.Request(base + bad, method="POST", data=b"{}")
            with pytest.raises(urllib.error.HTTPError) as ei:
                urllib.request.urlopen(req, timeout=5)  # noqa: S310
            assert ei.value.code in (404, 501), f"{bad} should not be a route"


def test_launch_rejects_non_loopback_target() -> None:
    from framework.v2.console import actions

    d = actions.launch_scan("http://not-loopback.example/")
    assert "error" in d and "loopback" in d["error"]


def test_runs_report_and_reverify_read_saved_run(tmp_path, monkeypatch) -> None:
    from framework.v2.console import actions

    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    rd = tmp_path / "runs" / "r1"
    rd.mkdir(parents=True)
    (rd / "meta.json").write_text(json.dumps({"target": "http://127.0.0.1/", "status": "done"}), encoding="utf-8")
    (rd / "report.json").write_text(json.dumps({
        "summary": {"confirmed": 1}, "findings": [{"kind": "active", "bug_class": "xss"}], "attack_paths": [],
    }), encoding="utf-8")
    (rd / "reverifiable.json").write_text(json.dumps({
        "active_findings": [{"bug_class": "xss", "confirmed_by": "reflection_context",
                             "confidence": 0.9, "oracle_context": None}],
    }), encoding="utf-8")

    runs = api.list_runs()["runs"]
    assert runs and runs[0]["run_id"] == "r1" and runs[0]["findings"] == 1
    doc = api.run_report("r1")
    assert doc["run_id"] == "r1" and doc["summary"]["confirmed"] == 1
    rv = actions.reverify_run("r1")
    assert rv["total"] == 1  # the one finding was examined (cert-less here -> not reproduced)


# ---------------------------------------------------------------------------
# Phase 2 — benchmark + world-model reconstruction + coverage
# ---------------------------------------------------------------------------


def test_benchmark_data_reads_committed_results() -> None:
    d = api.benchmark_data()
    assert d["results"] is not None, "committed docs/benchmark-results.json should load"
    tools = [r["tool"] for r in d["results"]["results"]]
    assert "crucible" in tools
    assert d["baseline"] is not None  # eval/baselines/benchmark-app.json


def test_worldmodel_reconstructs_attack_paths(tmp_path, monkeypatch) -> None:
    from framework.v2.console import actions

    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    rd = tmp_path / "runs" / "r1"
    rd.mkdir(parents=True)
    # a ScanReport with chainable findings (IDOR fronts a datastore, deser on a host)
    report = {
        "target": "http://t/",
        "active_findings": [
            {"check_id": "idor", "bug_class": "idor", "insertion_point": "query:id", "param": "id",
             "endpoint": "http://t/account?id=1", "confidence": 0.9, "confirmed_by": "achieved_state",
             "rationale": "swap", "oracle_context": None},
            {"check_id": "deser", "bug_class": "deserialization", "insertion_point": "body:data", "param": "data",
             "endpoint": "http://t/import", "confidence": 0.9, "confirmed_by": "oob_callback",
             "rationale": "gadget", "oracle_context": None},
        ],
    }
    (rd / "reverifiable.json").write_text(json.dumps(report), encoding="utf-8")

    wm = api.worldmodel("r1")
    assert wm["node_count"] > 0 and wm["edge_count"] > 0
    assert len(wm["paths"]) >= 1  # attacker -> crown jewel chain
    kinds = {n["kind"] for n in wm["nodes"]}
    assert kinds & {"datastore", "host", "cloud_resource"}  # a crown-jewel node exists
    # every path step is technique-annotated (the reasoning, surfaced)
    assert all(s["technique"] for p in wm["paths"] for s in p["steps"])
