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


def _post(url: str, *, headers=None, data=b"{}", csrf=True):
    req = urllib.request.Request(url, method="POST", data=data)
    if csrf:                                    # the custom header the SPA's fetch sets
        req.add_header("X-Requested-With", "fetch")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_console_refuses_post_without_custom_header() -> None:
    # X6 (review survivor): a cross-site <form> POST that omits Origin + Sec-Fetch-Site (Safari
    # <16.4, in-app WebViews) but carries a legit loopback Host must STILL be refused — the guard
    # requires POSITIVE proof (a custom header a cross-site form cannot set), not mere absence.
    with _running_server() as base:
        st, body = _post(base + "/api/killswitch/victim/trip", csrf=False)
        assert st == 403 and b"X-Requested-With" in body


def test_console_refuses_cross_site_post() -> None:
    # X6: even WITH the custom header (a rebinding page could forge it), a cross-site Sec-Fetch,
    # a foreign Origin, or a rebinding Host is refused.
    with _running_server() as base:
        st, body = _post(base + "/api/launch/scan", headers={"Sec-Fetch-Site": "cross-site"})
        assert st == 403 and b"cross-site" in body                 # cross-site fetch metadata
        st, _ = _post(base + "/api/launch/scan", headers={"Origin": "http://evil.example"})
        assert st == 403                                           # foreign Origin
        st, _ = _post(base + "/api/launch/scan", headers={"Host": "evil.example"})
        assert st == 403                                           # DNS-rebinding Host


def test_console_refuses_malformed_host_cleanly() -> None:
    # X6 (2nd-pass review): a malformed Host must fail CLOSED as a clean 403, not raise an
    # unhandled ValueError — both a bad port (caught in _port_ok) and a malformed IPv6 authority
    # (which raises in urlsplit itself, before the port check) are guarded.
    with _running_server() as base:
        for bad in ("127.0.0.1:notaport", "127.0.0.1]", "[::1", "127.0.0.1:99999"):
            st, _ = _post(base + "/api/launch/scan", headers={"Host": bad})
            assert st == 403, f"malformed Host {bad!r} should be a clean 403, got {st}"


def test_console_allows_same_origin_post() -> None:
    # a same-origin POST (custom header + same-origin Sec-Fetch) passes the CSRF guard (it then
    # hits the action, which may itself refuse a bad target — but it is NOT blocked as cross-site).
    with _running_server() as base:
        st, _ = _post(base + "/api/launch/scan",
                      headers={"Sec-Fetch-Site": "same-origin"},
                      data=b'{"target":"http://127.0.0.1:9/"}')
        assert st != 403


def test_session_routes_create_list_rename_delete(tmp_path, monkeypatch) -> None:
    # F2: the permanent-session POST routes go through the SAME CSRF/rebind guard and drive only the
    # registry (which mints no fact). Isolate the live dir so the test never touches the repo's .vigil-live.
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    same = {"Sec-Fetch-Site": "same-origin"}
    with _running_server() as base:
        # a cross-site create (no custom header) is refused before it touches the registry
        st, _ = _post(base + "/api/session/create", csrf=False, data=b'{"name":"x"}')
        assert st == 403
        # same-origin create → ok, returns a session id
        st, body = _post(base + "/api/session/create", headers=same, data=b'{"name":"Audit A"}')
        assert st == 200
        sid = json.loads(body)["session"]["id"]
        # it lists (read route, no CSRF needed)
        _, _, lst = _get(base + "/api/sessions")
        assert any(s["id"] == sid for s in json.loads(lst)["sessions"])
        # F4: connect it to a second session (the POST is the consent), CSRF-guarded like the rest
        st, body = _post(base + "/api/session/create", headers=same, data=b'{"name":"Audit B"}')
        sid_b = json.loads(body)["session"]["id"]
        st, _ = _post(base + "/api/session/connect", csrf=False, data=json.dumps({"id": sid, "other": sid_b}).encode())
        assert st == 403                                            # cross-site connect refused
        st, body = _post(base + "/api/session/connect", headers=same,
                         data=json.dumps({"id": sid, "other": sid_b}).encode())
        assert st == 200 and json.loads(body)["session"]["connections"] == [sid_b]
        st, body = _post(base + "/api/session/disconnect", headers=same,
                         data=json.dumps({"id": sid, "other": sid_b}).encode())
        assert st == 200 and json.loads(body)["session"]["connections"] == []
        # rename + soft delete
        st, body = _post(base + "/api/session/rename", headers=same,
                         data=json.dumps({"id": sid, "name": "Audit A2"}).encode())
        assert st == 200 and json.loads(body)["session"]["name"] == "Audit A2"
        st, body = _post(base + "/api/session/delete", headers=same, data=json.dumps({"id": sid}).encode())
        assert st == 200 and json.loads(body)["deleted"] == "soft"
        # an unsafe id on a mutating route is a clean 404, never a 500/traversal
        st, _ = _post(base + "/api/session/rename", headers=same,
                      data=json.dumps({"id": "../etc", "name": "x"}).encode())
        assert st == 404


def test_only_safe_actions_no_clear_or_destructive_route() -> None:
    # The console exposes exactly three SAFE POST actions (launch / reverify / trip).
    # It must NOT expose a kill-switch CLEAR, a scope/authority edit, or any other
    # mutating route — clearing/relaxing is a deliberate off-console act.
    with _running_server() as base:
        for bad in ("/api/killswitch/x/clear", "/api/scope/edit", "/api/authority/x/grant",
                    "/api/destroy", "/api/launch/engage-destructive"):
            st, _ = _post(base + bad)      # passes the CSRF guard, then must not route
            assert st in (404, 501), f"{bad} should not be a route"


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


def test_worldmodel_reexecutes_stored_findings_at_the_boundary(tmp_path, monkeypatch) -> None:
    # TRUTHENOVATION T1: the console world-model handler re-projects a STORED report through
    # chain_findings(verify=True), so it RE-EXECUTES each finding's retained proof. A finding that
    # re-fires grants a grounded attacker capability; a recorded-confirmed finding whose retained
    # proof no longer reproduces (here: never retained → oracle_context None) grants NONE — no
    # grounded reach/topology/path — and is shown only as an UNGROUNDED demoted node.
    from framework.v2.console import actions
    from framework.v2.verify.adapter import FindingContext

    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    rd = tmp_path / "runs" / "r1"
    rd.mkdir(parents=True)
    # a genuinely RE-FIRING finding: a divergent boolean/differential context reverify re-confirms.
    refiring = FindingContext.from_http_responses(
        {"status": 200, "body": "No results."},
        {"status": 200, "body": "id=1 alice user\nid=2 bob admin\nid=3 carol user"},
        bug_class="boolean_sqli", discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump(mode="json")
    report = {
        "target": "http://t/",
        "active_findings": [
            {"check_id": "good", "bug_class": "boolean_sqli", "insertion_point": "query:q", "param": "q",
             "endpoint": "http://t/?q=1", "confidence": 0.9, "confirmed_by": "differential_response",
             "rationale": "divergent", "oracle_context": refiring},
            # recorded confirmed but NO retained proof → never re-fires → grants no grounded capability
            {"check_id": "stale", "bug_class": "idor", "insertion_point": "query:id", "param": "id",
             "endpoint": "http://t/account?id=1", "confidence": 0.9, "confirmed_by": "achieved_state",
             "rationale": "swap", "oracle_context": None},
        ],
    }
    (rd / "reverifiable.json").write_text(json.dumps(report), encoding="utf-8")

    wm = api.worldmodel("r1")
    assert wm["node_count"] > 0 and wm["edge_count"] > 0
    # the re-firing finding DOES grant a grounded attacker capability (no over-skip)
    grounded_edges = [e for e in wm["edges"]
                      if e["provenance"].startswith("finding:") and e["grounding"] == "grounded"]
    assert grounded_edges, "a re-firing stored finding must reconstruct a grounded capability"
    # the non-re-firing IDOR grants NO grounded crown-jewel topology (BLOCK-1 regression)
    grounded_topo = [n for n in wm["nodes"]
                     if n["kind"] in ("datastore", "host") and n["grounding"] == "grounded"]
    assert grounded_topo == [], "a non-re-firing finding must not spawn a grounded crown-jewel node"
    # the demoted IDOR finding is still shown — but as an UNGROUNDED node, never a grounded fact
    idor_nodes = [n for n in wm["nodes"] if n["id"].startswith("finding:idor")]
    assert idor_nodes and all(n["grounding"] != "grounded" for n in idor_nodes)
    # every path that IS reconstructed is technique-annotated (the reasoning, surfaced)
    assert all(s["technique"] for p in wm["paths"] for s in p["steps"])


# ---------------------------------------------------------------------------
# Phase 3-4 — the intelligence/governance readers are resilient
# ---------------------------------------------------------------------------


def test_phase34_readers_resilient() -> None:
    m = api.memory_data()
    assert "summary" in m and isinstance(m["priors"], list)
    k = api.kernel_data()
    assert isinstance(k["backends"], list) and k["cognitive_docs"]
    assert "note" in api.authority_full("")  # no slug -> guidance, never a crash
    a = api.authority_full("no-such-slug")
    assert a["killswitch"]["tripped"] in (True, False) and "gates" in a
    assert api.planner_data("no-such-slug")["present"] is False
    assert api.reports_data("no-such-slug")["reports"] == []
