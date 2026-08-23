"""S10 — the Strix control-state reader (`api.strix_control`) must reflect REAL runtime state.

The UI half of S10 surfaces the Strix runtime CONTROL STATE. This suite proves each surface reads the
TRUE datum and never fabricates one:

  * a down / absent gateway shows down; a running one shows up; a probe error is UNKNOWN (fail-closed);
  * a DEGRADED proof subsystem shows degraded and is NEVER read as CLEAN (invariant 12);
  * the FACT / LEAD / CLEAN / INCONCLUSIVE separation counts the real proof records, and a run that did
    not COMPLETE can never read CLEAN;
  * model locality is the recorded meta datum (local / cloud / unknown), never inferred;
  * resource consumption has NO live source on this build — it is declared unavailable with ONLY the
    configured limits, and carries no fabricated live number;
  * a container-level kill is honestly UNAVAILABLE (not wired), while the real host-pid stop is offered
    only for a running run;
  * only Strix (strix / codebase) runs are listed, and the engagement slug scopes the list;
  * the whole reader is resilient on an empty tree (honest empty state, never a crash).

Plus an end-to-end proof the `/api/strix/control` route is wired through the server, and a `node --check`
syntax gate on the SPA (skipped where node is unavailable).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from framework.v2.console import actions, api, server

from .conftest import AUTH_HEADERS


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _mk_run(console: Path, run_id: str, **meta) -> Path:
    rd = console / "runs" / run_id
    rd.mkdir(parents=True)
    (rd / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return rd


def _write_proof(rd: Path, name: str, **rec) -> None:
    (rd / "proofs").mkdir(exist_ok=True)
    (rd / "proofs" / name).write_text(json.dumps(rec), encoding="utf-8")


def _degrade(rd: Path, kind: str, count: int = 1) -> None:
    (rd / "proofs").mkdir(exist_ok=True)
    (rd / "proofs" / "_degraded.json").write_text(
        json.dumps({"degradations": [{"kind": kind, "count": count}]}), encoding="utf-8")


@pytest.fixture()
def console(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    (tmp_path / "runs").mkdir()
    # keep the gateway datum deterministic unless a test overrides it
    monkeypatch.setattr(api, "services_data", lambda: {"docker_services": {}})
    monkeypatch.delenv("STRIX_DOCKER_SANDBOX_NETWORK", raising=False)
    return tmp_path


# ---------------------------------------------------------------------------
# gateway — up / down / probe-error all read honestly
# ---------------------------------------------------------------------------

def test_gateway_running_and_pinned_is_egress_on(console, monkeypatch):
    monkeypatch.setattr(api, "services_data", lambda: {
        "docker_services": {"vigil-gateway": {"state": "running", "networks": {}, "image": True}}})
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "vigil_sandbox")
    gw = api.strix_control()["gateway"]
    assert gw["available"] is True and gw["running"] is True
    assert gw["sandbox_pinned"] is True and gw["egress"] == "ON"


def test_gateway_running_but_unpinned_is_egress_off(console, monkeypatch):
    monkeypatch.setattr(api, "services_data", lambda: {
        "docker_services": {"vigil-gateway": {"state": "running"}}})
    # no STRIX_DOCKER_SANDBOX_NETWORK -> the sandbox is not pinned onto the gated net
    gw = api.strix_control()["gateway"]
    assert gw["running"] is True and gw["sandbox_pinned"] is False and gw["egress"] == "OFF"


def test_gateway_absent_shows_down(console, monkeypatch):
    monkeypatch.setattr(api, "services_data", lambda: {
        "docker_services": {"vigil-gateway": {"state": "absent"}}})
    gw = api.strix_control()["gateway"]
    assert gw["available"] is True and gw["running"] is False
    assert gw["state"] == "absent" and gw["egress"] == "OFF"


def test_gateway_probe_error_is_unknown_failclosed(console, monkeypatch):
    monkeypatch.setattr(api, "services_data", lambda: {
        "docker_services": {"vigil-gateway": {"error": "docker daemon unreachable"}}})
    gw = api.strix_control()["gateway"]
    # a probe error must never read as up: fail-closed to UNKNOWN, running False
    assert gw["running"] is False and gw["egress"] == "UNKNOWN" and "error" in gw


def test_gateway_probe_missing_is_unavailable(console, monkeypatch):
    monkeypatch.setattr(api, "services_data", lambda: {"docker_services": {}})
    gw = api.strix_control()["gateway"]
    assert gw["available"] is False and gw["running"] is False and gw["egress"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# proof health — a degraded subsystem is degraded, never CLEAN
# ---------------------------------------------------------------------------

def test_degraded_proof_is_surfaced_and_not_clean(console):
    rd = _mk_run(console, "r-deg", run_kind="strix", target="http://t/", status="done", slug="e1")
    _degrade(rd, "proof_subsystem_unavailable")
    d = api.strix_control("r-deg")
    ph = d["proof_health"]
    assert ph["verification_degraded"] is True
    assert ph["disposition"] == "proof_subsystem_unavailable"
    v = d["verdicts"]
    assert v["clean"] is False and v["verification_degraded"] is True
    assert v["inconclusive"] >= 1 and v["clean_blocked_reason"]


def test_capture_failed_degradation_named(console):
    rd = _mk_run(console, "r-cap", run_kind="strix", target="http://t/", status="done", slug="e1")
    _degrade(rd, "capture_failed", 3)
    d = api.strix_control("r-cap")
    assert d["proof_health"]["disposition"] == "capture_failed"
    causes = {c["kind"]: c["count"] for c in d["proof_health"]["degraded_causes"]}
    assert causes.get("capture_failed") == 3


# ---------------------------------------------------------------------------
# FACT / LEAD / CLEAN / INCONCLUSIVE separation + the completion gate
# ---------------------------------------------------------------------------

def test_verdict_counts_reflect_real_proof_records(console):
    rd = _mk_run(console, "r-facts", run_kind="strix", target="http://u/", status="done", slug="e1")
    _write_proof(rd, "a.json", status="fact", bug_class="sqli", proof_id="1")
    _write_proof(rd, "b.json", status="lead", bug_class="xss", proof_id="2")
    _write_proof(rd, "c.json", status="denied", bug_class="rce", proof_id="3")
    v = api.strix_control("r-facts")["verdicts"]
    assert v["fact"] == 1 and v["lead"] == 1 and v["denied"] == 1
    assert v["clean"] is False  # a run with a FACT is not clean


def test_completed_empty_run_is_clean(console):
    _mk_run(console, "r-clean", run_kind="strix", target="http://t/", status="done", slug="e1")
    v = api.strix_control("r-clean")["verdicts"]
    assert v["fact"] == 0 and v["lead"] == 0
    assert v["clean"] is True and v["run_incomplete"] is False


def test_interrupted_empty_run_is_never_clean(console):
    # invariant 12: a run that did not complete must not read as an optimistic CLEAN
    _mk_run(console, "r-int", run_kind="codebase", target="/src", status="interrupted",
            slug="e2", resumable=True, interrupted_reason="host gone")
    v = api.strix_control("r-int")["verdicts"]
    assert v["clean"] is False and v["run_incomplete"] is True
    assert v["inconclusive"] >= 1 and "did not complete" in (v["clean_blocked_reason"] or "")


# ---------------------------------------------------------------------------
# model locality — the recorded meta datum, never inferred
# ---------------------------------------------------------------------------

def test_model_locality_local_from_backend(console):
    _mk_run(console, "r-l1", run_kind="strix", status="done", slug="e1", model_backend="local", model="m")
    m = api.strix_control("r-l1")["model"]
    assert m["locality"] == "local" and "this host" in m["residency"]


def test_model_locality_local_from_strix_llm(console):
    _mk_run(console, "r-l2", run_kind="strix", status="done", slug="e1", strix_llm="ollama/llama3")
    m = api.strix_control("r-l2")["model"]
    assert m["locality"] == "local" and m["endpoint"] == "ollama/llama3"


def test_model_locality_cloud(console):
    _mk_run(console, "r-c", run_kind="strix", status="done", slug="e1", model="claude-3")
    m = api.strix_control("r-c")["model"]
    assert m["locality"] == "cloud" and m["model"] == "claude-3" and "third-party" in m["residency"]


def test_model_locality_unknown_when_unrecorded(console):
    _mk_run(console, "r-u", run_kind="strix", status="done", slug="e1")
    m = api.strix_control("r-u")["model"]
    assert m["locality"] == "unknown" and m["model"] is None


# ---------------------------------------------------------------------------
# resource consumption — no live source, no fabricated number
# ---------------------------------------------------------------------------

def test_resources_declare_no_live_source_and_no_fake_numbers(console):
    r = api.strix_control()["resources"]
    assert r["live_usage_available"] is False
    assert "no docker-stats reader" in r["note"].lower()
    lim = r["configured_limits"]
    # only CONFIGURED limits, as strings; no live cpu/mem/pids numeric usage anywhere in the block
    assert set(lim) == {"mem_limit", "cpus", "pids_limit", "shm_size"}
    # no fabricated LIVE-usage figures: none of the docker-stats field names may appear (a real
    # docker-stats reader would emit these; this build has none, so they must be absent).
    blob = json.dumps(r)
    for fabricated in ("cpu_percent", "mem_usage", "mem_percent", "pids_current", "cpu_usage",
                       "memory_stats", "blkio"):
        assert fabricated not in blob


def test_resources_read_configured_env_limits(console, monkeypatch):
    monkeypatch.setenv("STRIX_SANDBOX_MEM_LIMIT", "2g")
    monkeypatch.setenv("STRIX_SANDBOX_CPUS", "1.5")
    r = api.strix_control()["resources"]
    assert r["configured_limits"]["mem_limit"] == "2g"
    assert r["configured_limits"]["cpus"] == "1.5"
    # unset ones stay honest defaults, never a fabricated live figure
    assert "default" in r["configured_limits"]["pids_limit"]


# ---------------------------------------------------------------------------
# kill controls — container kill unavailable; host-pid stop real & gated on running
# ---------------------------------------------------------------------------

def test_container_kill_is_unavailable(console):
    _mk_run(console, "r-k", run_kind="strix", status="running", slug="e1", pid=12345)
    ks = api.strix_control("r-k")["killswitch"]
    assert ks["container_kill"]["available"] is False
    assert "not wired" in ks["container_kill"]["note"].lower()


def test_process_stop_available_only_for_a_running_run(console):
    _mk_run(console, "r-run", run_kind="strix", status="running", slug="e1", pid=999)
    _mk_run(console, "r-done", run_kind="strix", status="done", slug="e1", pid=888)
    assert api.strix_control("r-run")["killswitch"]["process_stop"]["available"] is True
    assert api.strix_control("r-done")["killswitch"]["process_stop"]["available"] is False


def test_engagement_killswitch_state_present(console):
    _mk_run(console, "r-e", run_kind="strix", status="running", slug="e1", pid=1)
    eng = api.strix_control("r-e")["killswitch"]["engagement"]
    assert eng["slug"] == "e1" and eng["tripped"] in (True, False)
    assert eng["trip_via"] == "/api/killswitch/e1/trip"


# ---------------------------------------------------------------------------
# run listing — only Strix runs, engagement-scoped
# ---------------------------------------------------------------------------

def test_only_strix_runs_are_listed(console):
    _mk_run(console, "url1", run_kind="url", mode="url", status="done", slug="e1", started=1.0)
    _mk_run(console, "strix1", run_kind="strix", mode="strix", status="done", slug="e1", started=2.0)
    _mk_run(console, "code1", run_kind="codebase", mode="codebase", status="done", slug="e2", started=3.0)
    ids = {r["run_id"] for r in api.strix_control()["runs"]}
    assert ids == {"strix1", "code1"} and "url1" not in ids


def test_slug_scopes_the_run_list(console):
    _mk_run(console, "s-a", run_kind="strix", mode="strix", status="done", slug="e1", started=1.0)
    _mk_run(console, "s-b", run_kind="codebase", mode="codebase", status="done", slug="e2", started=2.0)
    ids = {r["run_id"] for r in api.strix_control(slug="e2")["runs"]}
    assert ids == {"s-b"}


def test_foreign_run_id_falls_back_to_newest_strix_run(console):
    _mk_run(console, "s-new", run_kind="strix", mode="strix", status="done", slug="e1", started=9.0)
    d = api.strix_control("does-not-exist")
    assert d["run_id"] == "s-new"  # never a 500, never a fabricated run


# ---------------------------------------------------------------------------
# resilience + honest empty state
# ---------------------------------------------------------------------------

def test_empty_tree_is_honest_not_a_crash(console):
    d = api.strix_control()
    assert d["run_id"] == "" and d["runs"] == [] and d["selected"] is None
    assert d["verdicts"]["has_run"] is False
    assert d["sandbox"]["container_status_available"] is False
    assert d["activity"]["live_tool_feed_available"] is False
    assert d["recovery"]["present"] is False


def test_resume_state_reflects_resumable_flag(console):
    _mk_run(console, "res", run_kind="strix", status="interrupted", slug="e1", resumable=True)
    _mk_run(console, "nores", run_kind="strix", status="error", slug="e1", resumable=False, started=2.0)
    assert api.strix_control("res")["recovery"]["action"] == "resume"
    assert api.strix_control("nores")["recovery"]["action"] == "restart"


# ---------------------------------------------------------------------------
# end-to-end: the /api/strix/control route is wired through the server
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
    req = urllib.request.Request(url, method="GET")
    for k, v in AUTH_HEADERS.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
        return r.status, r.read()


def test_route_is_served_and_returns_the_control_shape():
    with _running_server() as base:
        st, body = _get(base + "/api/strix/control")
        assert st == 200
        d = json.loads(body)
        for key in ("gateway", "sandbox", "approvals", "proof_health", "verdicts",
                    "activity", "resources", "killswitch", "recovery", "model", "runs", "doctrine"):
            assert key in d, f"missing control-state key {key!r}"


# ---------------------------------------------------------------------------
# the SPA parses (node --check) — the surface this slice adds is in app.js
# ---------------------------------------------------------------------------

def test_app_js_node_check():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    app_js = Path(__file__).resolve().parents[6] / "packages" / "vigil-ui" / "app.js"
    assert app_js.is_file(), f"app.js not found at {app_js}"
    proc = subprocess.run([node, "--check", str(app_js)], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"node --check failed:\n{proc.stderr}"
