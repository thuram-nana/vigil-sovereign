"""Customer LIVE AGENT-GRAPH — the read-only, tenant-scoped, money-safe graph + rich-activity surface end to end
through the sovereign plane, plus the customer-app #/live graph view's honesty / CSP scans.

The feature: a customer watches a LIVE graph of the real sub-agents (recon / exploit / critique / grounding / …)
and streams their reasoning + tool activity WHILE their engagement runs, and can steer a selected node —
advisory-only. Invariants a false-green would break:
  * tenant isolation — a customer sees ONLY a host their org has ownership-proven; another tenant's engagement
    (and an unproven host) is structurally unreachable (the slug is resolved server-side from the org's own set);
  * the graph + transcript are a projection of REAL recorded rows (the seam drops anything off its allowlist);
  * money-safe — viewing mints / charges / launches nothing; node steering reuses the ADVISORY
    live_control.submit_instruction (fires no tool, relaxes no scope, mints no fact);
  * STRICT default-OFF — the provisioner actions + edge routes are absent (404 / refused) unless
    VIGIL_CUSTOMER_LIVE_GRAPH is on, and the #/live page is byte-identical otherwise;
  * the customer-app graph view invents nothing (no Math.random / placeholder) and is CSP-clean (no inline
    handlers).
"""
from __future__ import annotations

import itertools
import os
import re
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))   # sibling test helpers (_prov pattern, _page_and_build)

_iss = itertools.count(1)
_APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
_APP_JS = (_APP / "app.js").read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())            # the shared seam base (where the engine emits)
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_LIVE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", "1")               # the new graph surface ON for most tests
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_CONTROL", "1")


def _store():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    ensure_owner_keypair()
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _prove(store, org, host):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=1e9, ttl_seconds=1e12)


def _slug(org, host):
    from sigil.ui.target_authorization import _customer_slug
    return _customer_slug(org, host)


def _seed_seam(slug):
    """Emit a small, real customer-safe graph trail for ``slug`` the way the offense projector would."""
    from vigil_core import live_graph as lg
    from vigil_core.seam_base import resolve_seam_base
    base = resolve_seam_base()
    lg.emit(base, slug, "phase:scan", "phase", ts=1.0, ref=1, status="started")
    lg.emit(base, slug, "agent:recon", "observation", ts=1.5, ref=5, from_node="phase:scan", edge="attach")
    lg.emit(base, slug, "agent:exploit", "finding", ts=2.0, ref=9, from_node="agent:recon",
            edge="delegation", verified=True)


# --- the sovereign adapter: live_control.agent_graph / graph_activity -----------------------------------------
def test_agent_graph_reads_the_proven_host_as_a_fold_over_real_rows():
    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    slug = _slug("org_a", "api.example.com")
    _seed_seam(slug)
    g = live_control.agent_graph(s, "org_a", "api.example.com")
    assert g["ok"] and g["slug"] == slug
    ids = {n["id"] for n in g["nodes"]}
    assert ids == {"phase:scan", "agent:recon", "agent:exploit"}
    assert any(e["kind"] == "delegation" for e in g["edges"])
    ex = [n for n in g["nodes"] if n["id"] == "agent:exploit"][0]
    assert ex["verified"] == 1


def test_graph_activity_streams_rows_with_cursor_and_node_filter():
    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    slug = _slug("org_a", "api.example.com")
    _seed_seam(slug)
    out = live_control.graph_activity(s, "org_a", "api.example.com")
    assert out["ok"] and out["slug"] == slug and out["cursor"] == 2
    assert [r["node"] for r in out["rows"]] == ["phase:scan", "agent:recon", "agent:exploit"]
    # incremental: polling with since=cursor returns nothing new
    assert live_control.graph_activity(s, "org_a", "api.example.com", since=out["cursor"])["rows"] == []
    # node filter (what the UI does on node selection)
    only = live_control.graph_activity(s, "org_a", "api.example.com", node="agent:exploit")
    assert [r["node"] for r in only["rows"]] == ["agent:exploit"]


def test_graph_endpoints_surface_the_generation_epoch_and_it_changes_on_relaunch():
    # Finding 2 end-to-end through the sovereign reader: both graph endpoints return a RUN/GENERATION epoch, and a
    # relaunch of the reused (org, host) slug changes it — the signal the client uses to resync from seq 0 rather
    # than append a suffix of the new run onto the prior run (which would splice two engagements, AS-4a).
    from vigil_core import live_graph as lg
    from vigil_core.seam_base import resolve_seam_base

    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    slug = _slug("org_a", "api.example.com")
    _seed_seam(slug)
    g = live_control.agent_graph(s, "org_a", "api.example.com")
    a = live_control.graph_activity(s, "org_a", "api.example.com")
    assert "epoch" in g and "epoch" in a and g["epoch"] == a["epoch"]   # both endpoints agree on the generation
    e0, old_cursor = a["epoch"], a["cursor"]
    # a NEW launch on the SAME slug resets the trail and writes a run; the epoch MUST move so a stale cursor resyncs
    base = resolve_seam_base()
    lg.reset(base, slug)
    for i in range(4):
        lg.emit(base, slug, "phase:preflight" if i == 0 else "agent:recon",
                "phase" if i == 0 else "observation", ts=float(10 + i), ref=i + 1,
                status="started" if i == 0 else "")
    a2 = live_control.graph_activity(s, "org_a", "api.example.com", since=old_cursor)
    assert a2["epoch"] != e0                                            # a new generation -> client resyncs from 0
    assert live_control.agent_graph(s, "org_a", "api.example.com")["epoch"] == a2["epoch"]


def test_tenant_isolation_an_unproven_or_other_org_host_is_refused():
    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    with pytest.raises(ValueError):
        live_control.agent_graph(s, "org_a", "other.example.com")      # not proven by org_a
    with pytest.raises(ValueError):
        live_control.agent_graph(s, "org_b", "api.example.com")        # cross-tenant
    with pytest.raises(ValueError):
        live_control.graph_activity(s, "org_b", "api.example.com")     # cross-tenant


def test_no_cross_org_event_leak_each_org_sees_only_its_own_slug():
    from sigil.ui import live_control
    s = _store()
    _prove(s, "org_a", "api.example.com")
    _prove(s, "org_b", "api.example.com")                              # a DIFFERENT org proved the SAME hostname
    _seed_seam(_slug("org_a", "api.example.com"))                      # only org_a's engagement has a trail
    # org_a sees its graph; org_b (its slug is org-namespaced + distinct) sees an EMPTY graph — never org_a's events
    assert _slug("org_a", "api.example.com") != _slug("org_b", "api.example.com")
    assert {n["id"] for n in live_control.agent_graph(s, "org_a", "api.example.com")["nodes"]}
    assert live_control.agent_graph(s, "org_b", "api.example.com")["nodes"] == []
    assert live_control.graph_activity(s, "org_b", "api.example.com")["rows"] == []


# --- the provisioner actions: flag + admit_customer(run_engagement) + tenant ----------------------------------
def _prov(store):
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    orgs = OrgRegistry(store)
    if orgs.org("org_a") is None:
        orgs.create_org("org_a", "org_a", owner="alice", issued_at=float(next(_iss)))
    orgs.grant_membership("org_a", "alice", "operator", issued_at=float(next(_iss)))
    return Provisioner(store, customers=CustomerRegistry(store), orgs=orgs, wallet=WalletRegistry(store),
                       email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                       rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4,
                                                     base_lock_s=1.0),
                       email_sender=NullEmailSender(), now_fn=lambda: float(next(_iss)))


def test_provisioner_graph_reads_then_is_flag_and_admit_gated(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    s = _store()
    _prove(s, "org_a", "api.example.com")
    _seed_seam(_slug("org_a", "api.example.com"))
    p = _prov(s)
    g = p.launch_graph("alice", "org_a", host="api.example.com")
    assert g["slug"] == _slug("org_a", "api.example.com") and g["nodes"]
    a = p.launch_graph_activity("alice", "org_a", host="api.example.com")
    assert [r["node"] for r in a["rows"]][:1] == ["phase:scan"]
    # a non-member cannot view another's graph (admit gating / tenant isolation)
    with pytest.raises(ProvisionDenied):
        p.launch_graph("mallory", "org_a", host="api.example.com")
    with pytest.raises(ProvisionDenied):
        p.launch_graph_activity("mallory", "org_a", host="api.example.com")
    # flag FORCED OFF (strict default) -> both actions refused (the whole surface is inert)
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", "0")
    with pytest.raises(ProvisionDenied):
        p.launch_graph("alice", "org_a", host="api.example.com")
    with pytest.raises(ProvisionDenied):
        p.launch_graph_activity("alice", "org_a", host="api.example.com")


def test_graph_default_off_without_the_flag(monkeypatch):
    from sigil import config
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.delenv("VIGIL_CUSTOMER_LIVE_GRAPH", raising=False)
    assert config.customer_live_graph_enabled() is False               # STRICT default-OFF (unset => off)
    s = _store()
    _prove(s, "org_a", "api.example.com")
    p = _prov(s)
    with pytest.raises(ProvisionDenied):
        p.launch_graph("alice", "org_a", host="api.example.com")


def test_node_steer_reuses_the_advisory_instruct_path_even_with_live_control_off(monkeypatch):
    # the graph's node-steer reuses live_control.submit_instruction. It must work when ONLY the graph flag is on.
    from vigil_integration.live import instructions

    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_CONTROL", "0")             # coarse feed OFF; graph ON
    s = _store()
    _prove(s, "org_a", "api.example.com")
    p = _prov(s)
    r = p.launch_instruct("alice", "org_a", host="api.example.com", text="[focus: Exploitation agent] check admin API")
    assert r["slug"] == _slug("org_a", "api.example.com")
    (one,) = instructions.drain(r["slug"])
    assert one.startswith("[focus: Exploitation agent]")               # advisory text landed on the engine's queue
    # with BOTH flags off, the advisory path is absent (refused) — byte-identical to the surface not existing
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", "0")
    with pytest.raises(ProvisionDenied):
        p.launch_instruct("alice", "org_a", host="api.example.com", text="x")


# --- the edge flag: the page reflects the flag; OFF is byte-identical bar the flag value + build id ------------
def test_the_edge_writes_the_live_graph_flag_into_the_page(tmp_path, monkeypatch):
    from test_customer_onboarding import _page_and_build
    monkeypatch.delenv("VIGIL_CUSTOMER_LIVE_GRAPH", raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-live-graph="0"' in off and "__VIGIL_LIVE_GRAPH__" not in off
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_GRAPH", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-live-graph="1"' in on and build_on != build_off
    # the ONLY difference the flag makes to the page is its own value + the build id (byte-identical otherwise)
    assert on.replace('data-live-graph="1"', 'data-live-graph="0"').replace(build_on, build_off) == off


# --- the customer-app #/live graph view: HONEST (no fabrication) + CSP-clean (no inline handlers) -------------
def _graph_js_section() -> str:
    start = _APP_JS.index("Live agent-GRAPH view (LIVE_GRAPH_ON)")
    end = _APP_JS.index("function viewLiveControl()", start)
    return _APP_JS[start:end]


def test_the_graph_view_fabricates_no_data():
    section = _graph_js_section()
    # no fabricated data: no Math.random, no placeholder/fake/sample agent/node generation in the graph code
    assert "Math.random" not in section
    for bad in ("Math.random", "placeholder(", "fakeNode", "sampleNode", "demoAgent", "dummyNode"):
        assert bad not in section, bad
    # the graph is rendered from SERVER data only: the render reads lg.nodes / lg.edges / lg.all (the fetched rows)
    assert "lg.nodes" in section and "lg.edges" in section and "lg.all" in section
    # honest states: fixed empty / could-not-load copy (never a fake heartbeat)
    assert "No agent activity has been recorded yet" in section
    assert "Could not load the live graph" in section


def test_the_graph_view_resyncs_the_transcript_on_a_generation_epoch_change():
    # Finding 2 (client): the graph view tracks the run/generation epoch and, when it changes, resyncs the
    # transcript from seq 0 instead of appending a suffix of a new run onto the prior run.
    section = _graph_js_section()
    assert "lg.epoch" in section                                       # the client holds the epoch its cursor belongs to
    assert "epoch !== lg.epoch" in section                             # and resyncs when the seam's epoch moves
    # on a detected epoch change the cursor is reset to -1 so the next read re-reads the new run from the start
    assert "lg.cursor = -1" in section


def test_the_graph_view_is_csp_clean_no_inline_handlers():
    section = _graph_js_section()
    # events are attached (addEventListener via onClick / .addEventListener), never inline on*= attribute strings
    assert "addEventListener" in section or "onClick" in section
    assert not re.search(r'["\']\s*on[a-z]+\s*=', section)             # no inline  on...=  handler written into markup
    assert ".innerHTML" not in section                                # no innerHTML sink in the graph view
    # the fetches are the read-only graph endpoints (no mutation on view)
    assert "/live/graph" in section and "/live/graph/activity" in section


def test_the_poll_is_tightened_for_the_graph_view():
    # near-real-time: the graph view polls faster than the coarse phase feed (tightened delta poll).
    assert "GRAPH_POLL_MS" in _APP_JS
    m_graph = re.search(r"GRAPH_POLL_MS\s*=\s*(\d+)", _APP_JS)
    m_live = re.search(r"LIVE_POLL_MS\s*=\s*(\d+)", _APP_JS)
    assert m_graph and m_live and int(m_graph.group(1)) < int(m_live.group(1))
