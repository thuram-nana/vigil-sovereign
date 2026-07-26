"""
Ops Console — P2 (New-Assessment launch + blackboard live stream).

Pins the load-bearing P2 guarantees:

  * ``launch_assessment`` routes each wizard mode to the RIGHT already-gated CLI (scan /
    engage / engage --autonomous / strix / aegis) — proven from the recorded command,
    with the subprocess spawn STUBBED so no real tool runs;
  * it REFUSES cleanly (a JSON error, never a traceback) for a remote engage without a
    signed charter, a non-existent codebase path, a CIDR scope, and an unknown mode;
  * APPROVE-THEN-RUN is preserved: a launched engage never carries ``--approve-offense``
    (the console cannot pre-authorize offense) and never passes ``--scope`` (the console
    cannot relax the charter-signed scope);
  * the blackboard SSE tailer streams the 14 kinds with a DURABLE cursor (seeded over a
    temp blackboard) and preserves the ``verified_by_oracle`` FACT signal.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from framework.v2.console import actions, api, server
from framework.v2.console.blackboard_sse import BlackboardTailer


# ---------------------------------------------------------------------------
# launch_assessment — each mode routes to the right gated CLI (spawn stubbed)
# ---------------------------------------------------------------------------


@pytest.fixture()
def stub_launch(tmp_path, monkeypatch):
    """Redirect the run registry to tmp and NO-OP the subprocess spawn, so a launch is
    fully deterministic and touches no real tool. The command is read back from meta.json,
    which ``launch_assessment`` writes synchronously before it would spawn."""
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_spawn_background", lambda *a, **k: None)
    def _cmd(run_id):
        meta = json.loads((tmp_path / "runs" / run_id / "meta.json").read_text(encoding="utf-8"))
        return meta["cmd"], meta
    return _cmd


def test_loopback_url_routes_to_scan(stub_launch):
    r = actions.launch_assessment({"mode": "url", "target": "http://127.0.0.1:8000/", "scan_mode": "quick"})
    assert r["status"] == "running" and r["stream"] == "progress"
    cmd, meta = stub_launch(r["run_id"])
    assert "scan" in cmd and "http://127.0.0.1:8000/" in cmd
    assert "--progress-log" in cmd and "--targeted" in cmd  # quick depth
    assert "engage" not in cmd


def test_remote_url_needs_charter_then_routes_to_engage(stub_launch, monkeypatch):
    # no charter for this slug → clean refusal (not a traceback)
    r = actions.launch_assessment({"mode": "url", "target": "https://app.example.com/"})
    assert "error" in r and "charter" in r["error"].lower()

    # with a charter present → the gated engage, mirrored onto the spine via --spine
    monkeypatch.setattr(actions, "_has_charter", lambda slug: True)
    r = actions.launch_assessment({"mode": "url", "target": "https://app.example.com/", "slug": "acme"})
    assert r["stream"] == "blackboard" and r["slug"] == "acme"
    cmd, meta = stub_launch(r["run_id"])
    assert cmd[:5] == [cmd[0], "-m", "framework.v2", "engage", "acme"]
    assert "https://app.example.com/" in cmd and "--spine" in cmd


def test_suite_routes_to_autonomous_engage(stub_launch):
    r = actions.launch_assessment({"mode": "suite", "target": "http://127.0.0.1/", "scan_mode": "deep"})
    cmd, _ = stub_launch(r["run_id"])
    assert "engage" in cmd and "--autonomous" in cmd and "--spine" in cmd
    assert "--autonomous-cycles" in cmd  # deep depth adds a second cycle


def test_tool_mode_maps_one_capability_to_its_gated_flag(stub_launch):
    r = actions.launch_assessment({"mode": "tool", "target": "http://127.0.0.1/", "tools": ["recon"]})
    cmd, _ = stub_launch(r["run_id"])
    assert "engage" in cmd and "--recon" in cmd
    # exactly one capability flag, even if the caller sent more
    r2 = actions.launch_assessment({"mode": "tool", "target": "http://127.0.0.1/", "tools": ["recon", "sso"]})
    cmd2, _ = stub_launch(r2["run_id"])
    assert "--recon" in cmd2 and "--sso" not in cmd2


def test_tool_mode_drops_unknown_capability_ids(stub_launch):
    # a capability id NOT in the whitelist must be DROPPED — never passed through as an argv or a flag
    # (defends the `_CAP_BY_ID.get` whitelist against a future regression that lets arbitrary ids through).
    r = actions.launch_assessment({"mode": "tool", "target": "http://127.0.0.1/",
                                   "tools": ["recon", "totally-unknown", "--approve-offense", "x;rm -rf /"]})
    cmd, _ = stub_launch(r["run_id"])
    assert "--recon" in cmd                       # the one known capability still maps to its gated flag
    joined = " ".join(cmd)
    for bad in ("totally-unknown", "approve-offense", "rm -rf", "x;rm"):
        assert bad not in joined, f"unknown/bogus tool id leaked into argv: {bad!r}"


def test_codebase_routes_to_strix_and_validates_path(stub_launch, tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    r = actions.launch_assessment({"mode": "codebase", "target": str(src), "authorized": True,
                                   "objective": "auth review"})
    assert r["stream"] == "none"
    cmd, _ = stub_launch(r["run_id"])
    assert cmd[0].endswith("strix") and "--target" in cmd and str(src) in cmd
    assert "--instruction" in cmd  # objective threaded through
    # a non-existent path is refused cleanly
    bad = actions.launch_assessment({"mode": "codebase", "target": str(tmp_path / "nope"), "authorized": True})
    assert "error" in bad and "does not exist" in bad["error"]


def test_codebase_mount_flag(stub_launch, tmp_path):
    src = tmp_path / "mono"
    src.mkdir()
    r = actions.launch_assessment({"mode": "codebase", "target": str(src), "mount": True})
    cmd, _ = stub_launch(r["run_id"])
    assert "--mount" in cmd and "--target" not in cmd


def test_aegis_detect_routes_and_needs_a_file(stub_launch, tmp_path):
    env = tmp_path / "telemetry.json"
    env.write_text("{}", encoding="utf-8")
    r = actions.launch_assessment({"mode": "aegis", "target": str(env)})
    cmd, _ = stub_launch(r["run_id"])
    assert "aegis" in cmd and "detect" in cmd and str(env) in cmd
    missing = actions.launch_assessment({"mode": "aegis", "target": str(tmp_path / "gone.json")})
    assert "error" in missing


def test_refuses_cidr_scope_and_unknown_mode_and_empty_target(stub_launch):
    assert "error" in actions.launch_assessment({"mode": "url", "target": "https://x/", "scope": ["10.0.0.0/8"]})
    assert "error" in actions.launch_assessment({"mode": "nonsense", "target": "http://127.0.0.1/"})
    assert "error" in actions.launch_assessment({"mode": "url", "target": ""})


def test_approve_then_run_preserved_no_offense_preauth_no_scope_relax(stub_launch, monkeypatch):
    """The console spawns only the gated CLI; it can neither pre-authorize offense
    (--approve-offense) nor pass a scope (which would relax the charter-signed scope)."""
    monkeypatch.setattr(actions, "_has_charter", lambda slug: True)
    r = actions.launch_assessment({"mode": "suite", "target": "https://app.example.com/", "slug": "acme",
                                   "scope": ["app.example.com", "*.example.com"]})
    cmd, meta = stub_launch(r["run_id"])
    assert "--approve-offense" not in cmd     # cannot stand-in for the owner's approval
    assert "--scope" not in cmd               # scope is charter-signed; never passed here
    assert "--discover-autotest" not in cmd   # never silently auto-fires discovered probes
    assert meta["scope"] == ["app.example.com", "*.example.com"]  # recorded for display only


# ---------------------------------------------------------------------------
# capabilities catalog — real data, id is the contract, no flag leaked
# ---------------------------------------------------------------------------


def test_capabilities_catalog_is_real_and_flag_free():
    d = api.capabilities_data()
    ids = {c["id"] for c in d["capabilities"]}
    assert {"recon", "arsenal", "sso"} <= ids
    for c in d["capabilities"]:
        assert set(c) == {"id", "label", "tier", "purpose"}  # the flag stays server-side
    assert [m["id"] for m in d["scan_modes"]] == ["quick", "standard", "deep"]


# ---------------------------------------------------------------------------
# blackboard SSE tailer — streams the 14 kinds with a durable cursor
# ---------------------------------------------------------------------------


def _seed_blackboard(db_path, slug="eng"):
    from framework.v2.agents.blackboard import Blackboard
    bb = Blackboard(db_path=db_path)
    ids = []
    ids.append(bb.post(engagement=slug, kind="observation", agent_name="recon",
                       payload={"source": "recon", "surface": "/login", "summary": "form seen"}))
    ids.append(bb.post(engagement=slug, kind="tool_call", agent_name="exploit",
                       payload={"tool": "curl", "tier": "T2", "target": "http://t/login"}))
    ids.append(bb.post(engagement=slug, kind="finding", agent_name="exploit",
                       payload={"finding_slug": "001-xss", "title": "reflected xss", "severity": "High",
                                "bug_class": "xss", "surface": "query:q", "summary": "reflect",
                                "verified_by_oracle": True, "oracle_kind": "sanitizer_signal"}))
    ids.append(bb.post(engagement=slug, kind="refusal", agent_name="gate",
                       payload={"gate": "scope", "action_refused": "reach evil.example", "fatal": False}))
    bb.close()
    return ids


def test_blackboard_tailer_durable_cursor_and_fact_signal(tmp_path):
    db = tmp_path / "bb.sqlite"
    ids = _seed_blackboard(db)

    t = BlackboardTailer("eng", since_id=0, db_path=db)
    got = t.read_new()
    assert [eid for eid, _ in got] == ids            # every kind, in id order
    kinds = [ev["kind"] for _, ev in got]
    assert kinds == ["observation", "tool_call", "finding", "refusal"]
    # the FACT signal survives the wire
    fnd = next(ev for _, ev in got if ev["kind"] == "finding")
    assert fnd["payload"]["verified_by_oracle"] is True and fnd["payload"]["oracle_kind"] == "sanitizer_signal"

    # durable cursor: a second poll with no new events yields nothing (no replay)
    assert t.read_new() == []

    # append one more; the SAME tailer resumes from its cursor
    from framework.v2.agents.blackboard import Blackboard
    bb = Blackboard(db_path=db)
    newid = bb.post(engagement="eng", kind="decision", agent_name="coord",
                    payload={"question": "next?", "choice": "pivot"})
    bb.close()
    got2 = t.read_new()
    assert [eid for eid, _ in got2] == [newid]

    # a FRESH tailer resuming from the 3rd id (mid-stream Last-Event-ID) sees only later events
    t2 = BlackboardTailer("eng", since_id=ids[2], db_path=db)
    assert [eid for eid, _ in t2.read_new()] == [ids[3], newid]


def test_blackboard_tailer_resilient_on_unknown_engagement(tmp_path):
    db = tmp_path / "bb.sqlite"
    _seed_blackboard(db)
    # a not-yet-started engagement (unregistered slug) yields nothing, never raises
    assert BlackboardTailer("no-such-engagement", db_path=db).read_new() == []
    # an empty slug is a no-op
    assert BlackboardTailer("", db_path=db).read_new() == []


# ---------------------------------------------------------------------------
# server routes — the POST is CSRF-gated; capabilities is a read route
# ---------------------------------------------------------------------------


@contextmanager
def _running_server(monkeypatch, tmp_path):
    # stub the spawn so a launched assessment over HTTP never runs a real tool
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    monkeypatch.setattr(actions, "_spawn_background", lambda *a, **k: None)
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


def _post(url, *, headers=None, data=b"{}", csrf=True):
    req = urllib.request.Request(url, method="POST", data=data)
    if csrf:
        req.add_header("X-Requested-With", "vigil-ui")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_launch_assessment_route_is_csrf_gated_and_routes(monkeypatch, tmp_path):
    with _running_server(monkeypatch, tmp_path) as base:
        # cross-site form (no custom header) is refused
        st, _ = _post(base + "/api/launch/assessment", csrf=False)
        assert st == 403
        # same-origin launch of a loopback scan succeeds
        st, body = _post(base + "/api/launch/assessment",
                         headers={"Sec-Fetch-Site": "same-origin"},
                         data=json.dumps({"mode": "url", "target": "http://127.0.0.1:8000/"}).encode())
        assert st == 200
        out = json.loads(body)
        assert out["status"] == "running" and out["mode"] == "url"


def test_capabilities_route_serves_catalog(monkeypatch, tmp_path):
    with _running_server(monkeypatch, tmp_path) as base:
        with urllib.request.urlopen(base + "/api/capabilities", timeout=5) as r:  # noqa: S310
            d = json.loads(r.read())
        assert any(c["id"] == "recon" for c in d["capabilities"])
