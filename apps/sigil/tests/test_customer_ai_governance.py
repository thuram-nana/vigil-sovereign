"""Legal/governance S5 — the customer AI / human-in-the-loop GOVERNANCE disclosure (``ui/ai_governance``) and its
provisioner / edge gating, behind ``VIGIL_CUSTOMER_AI_GOVERNANCE`` (default OFF).

Load-bearing invariants (each mutation-verified — the named test reds when its guard is broken):
  * DEFAULT OFF / FAIL-CLOSED: flag off -> the provisioner refuses, the cockpit action is absent (None -> 404) and the
    edge route is absent (404) — byte-identical to a build without the screen
    (test_flag_off_the_disclosure_is_absent_everywhere, test_the_edge_route_is_absent_when_off).
  * ORG FROM THE SESSION, NEVER A CLAIM: the disclosure is read for the SESSION org only; a member of one org can never
    read another's, and only a role that reads assessments may read it at all
    (test_only_members_who_read_assessments_get_it, test_never_another_org).
  * READ-ONLY, GROUNDED, NO FABRICATION: the payload mutates nothing and every statement carries a citation to an
    existing canonical source — the Terms, the README or the Safety & Authorization briefing — whose exact words appear
    verbatim in the repo (test_every_statement_is_grounded_in_an_existing_source, test_the_disclosure_mints_nothing).
  * THE SCREEN SHOWS THE SERVER'S WORDS: flag on, #/ai-governance renders the AI-use and human-oversight statements and
    their sources, and offers no control (test_the_screen_shows_the_ai_use_and_human_oversight_statements).

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:packages/core/vigil_core:integration python -m pytest -q \
     apps/sigil/tests/test_customer_ai_governance.py
"""
from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path

import pytest

from sigil.governor.identity import ensure_owner_keypair
from sigil.ui import ai_governance as aig
from sigil.ui.custui import build_customer_server
from sigil.ui.provision import ProvisionDenied
# the shared Area-6 fixtures build an org with a proven host + member in exactly the shape a customer read needs
from test_compliance_rollup import _member, _prov, _prove, _store
from test_customer_monitoring_screen import _DOM, _fn, _var
from test_customer_onboarding import _line, _need_node

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS, APP_JS = APP / "ui.js", APP / "app.js"
_REPO = Path(__file__).resolve().parents[3]
FLAG = "VIGIL_CUSTOMER_AI_GOVERNANCE"


@pytest.fixture(autouse=True)
def _flag_off(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    monkeypatch.setenv("VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED", "1")   # the founder role is admitted as founder


# ---- the disclosure module (grounded, read-only) -----------------------------------------------------------------
def test_the_statement_negates_ai_authority():
    """The fixed statement frames the screen and denies AI authority — nothing else on the screen claims it."""
    assert "never as an authority" in aig.STATEMENT
    d = aig.disclosure("acme")
    assert d["ok"] is True and d["org_id"] == "acme" and d["statement"] == aig.STATEMENT
    assert [s["title"] for s in d["sections"]] == ["What AI does", "What AI never does",
                                                   "Human in the loop — AI proposes, the oracle disposes",
                                                   "Where your data goes"]


def test_every_statement_is_grounded_in_an_existing_source():
    """Every point carries a citation, and its load-bearing sentences are the EXISTING canonical words — the Terms, the
    README and the Safety & Authorization briefing — so nothing here is a reworded or invented copy."""
    terms = (_REPO / "apps/sigil/sigil/ui/public_site/terms/index.html").read_text(encoding="utf-8")
    readme = (_REPO / "README.md").read_text(encoding="utf-8")
    # the HTML wraps lines; compare on collapsed whitespace so a verbatim quote matches the rendered text
    terms_flat = " ".join(terms.split())
    for s in aig.disclosure("acme")["sections"]:
        for pt in s["points"]:
            assert pt["source"] and pt["text"], s["title"]
    # a sample of the verbatim canonical sentences the screen must carry, each present in its cited source as-is
    assert "AI never decides what you are charged or which hosts you may test." in terms_flat
    assert ("Parts of the Service use AI models: to plan and prioritise testing, to propose what might be a "
            "vulnerability, to summarise results and to answer questions in the assistant.") in terms_flat
    assert "You keep all rights in your Customer Data." in terms_flat
    assert ("The AI and every tool only PROPOSE. Only a deterministic oracle mints a signed FACT. Only the conjunctive "
            "gate authorizes an action. Only the egress gate lets a packet leave.") in readme
    assert "The AI proposes; the oracle disposes." in readme
    blob = json.dumps(aig.disclosure("acme"))
    for sentence in ("AI never decides what you are charged or which hosts you may test.",
                     "The AI proposes; the oracle disposes.",
                     "You keep all rights in your Customer Data."):
        assert sentence in blob, sentence


def test_the_disclosure_mints_nothing():
    """A pure read: calling it writes no spine record (it takes no store at all) and returns a fresh structure each
    time (module state is never handed out to mutate)."""
    a, b = aig.disclosure("acme"), aig.disclosure("acme")
    assert a == b and a is not b and a["sections"] is not b["sections"]
    a["sections"][0]["points"][0]["text"] = "mutated"
    assert aig.disclosure("acme")["sections"][0]["points"][0]["text"] != "mutated"   # module state untouched


# ---- the provisioner + cockpit gating ----------------------------------------------------------------------------
def test_flag_off_the_disclosure_is_absent_everywhere(monkeypatch):
    from sigil.ui.server import Handler
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    _prove(store, "acme", "acme.example", it)
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.customer_ai_governance("alice", "acme")
    h = Handler.__new__(Handler)
    assert h._provision_dispatch(p, "ai_governance_disclosure", "alice", {"org_id": "acme"}) is None   # -> 404
    monkeypatch.setenv(FLAG, "1")
    out = h._provision_dispatch(p, "ai_governance_disclosure", "alice", {"org_id": "acme"})
    assert out["ok"] is True and out["org_id"] == "acme" and out["statement"] == aig.STATEMENT


@pytest.mark.parametrize("role,ok", [("founder", True), ("operator", True), ("org_admin", False),
                                     ("analyst", False), ("viewer", False)])
def test_only_members_who_read_assessments_get_it(monkeypatch, role, ok):
    monkeypatch.setenv(FLAG, "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", role, it)
    _prove(store, "acme", "acme.example", it)
    if ok:
        assert p.customer_ai_governance("alice", "acme")["org_id"] == "acme"
    else:
        with pytest.raises(ProvisionDenied, match="view_assessments"):
            p.customer_ai_governance("alice", "acme")


def test_never_another_org(monkeypatch):
    """The org is the SESSION's: a founder of acme can read acme, never globex — whatever a body might claim."""
    monkeypatch.setenv(FLAG, "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    _prove(store, "acme", "acme.example", it)
    assert p.customer_ai_governance("alice", "acme")["org_id"] == "acme"
    with pytest.raises(ProvisionDenied):
        p.customer_ai_governance("alice", "globex")


# ---- the edge (the page + the route gate) ------------------------------------------------------------------------
def _page_and_build(tmp_path):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "s"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
        r = c.getresponse()
        return r.read().decode(), r.getheader("X-Vigil-Build")
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_edge_writes_the_flag_into_the_page(tmp_path, monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-ai-governance="0"' in off and "__VIGIL_AI_GOVERNANCE__" not in off
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-ai-governance="1"' in on and build_on != build_off
    # only its own value changed between the two pages (plus the build id it counts in)
    assert on.replace('data-ai-governance="1"', 'data-ai-governance="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv(FLAG, v)
        assert 'data-ai-governance="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v


def test_the_edge_route_is_absent_when_off(tmp_path, monkeypatch):
    """Fail-closed at the edge: with the flag off GET /api/customer/ai-governance is the edge's OWN unknown-route 404,
    and with it on the route is present (401 "sign in first" with no session) — never 404."""
    from test_custui import _get, _opener, _stack
    monkeypatch.delenv(FLAG, raising=False)
    sov, edge, ep, _sp = _stack(tmp_path, monkeypatch)
    try:
        assert _get(_opener(), ep, "/api/customer/ai-governance")[0] == 404
    finally:
        sov.shutdown(); edge.shutdown()
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _sp = _stack(tmp_path / "on", monkeypatch)
    try:
        assert _get(_opener(), ep, "/api/customer/ai-governance")[0] == 401   # present, needs a session
    finally:
        sov.shutdown(); edge.shutdown()


# ---- the screen, under node --------------------------------------------------------------------------------------
_WORLD = r"""
Object.assign(document.body.dataset, {aiGovernance: "1"});
let who = { authenticated: true, username: "ana", org_id: "org_x" };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: "#/ai-governance" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
var GUIDE = null, GUIDE_ON = false;
const VUI = window.VUI;
const calls = [];
let server = {};
async function answer(key) {
  const r = server[key];
  if (!r) { const e = new Error("404"); e.status = 404; e.data = { error: "not found" }; throw e; }
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data; throw e; }
  return r.data;
}
VUI.getJSON = async p => { calls.push(["GET", p]); return answer("GET " + p); };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); return answer("POST " + p); };
const tick = () => new Promise(r => setTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
const out = {};
"""


def _node(script: str) -> dict:
    import subprocess
    src = APP_JS.read_text(encoding="utf-8")
    prog = "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", "const h = window.VUI.h;", _WORLD,
                      _fn(src, "pageFlag"), _line(src, r"^  function here\(\) \{.*\}$"), _fn(src, "loadingHolder"),
                      _var(src, "API"), _var(src, "AI_GOVERNANCE_ON"),
                      _fn(src, "area6View"), _fn(src, "viewAiGovernance"), _fn(src, "aiGovernanceBody"),
                      "(async () => {\n" + script + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
                      " e => { console.error(e && e.stack || e); process.exit(3); });"])
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


_SERVER_OK = {
    "ok": True, "org_id": "org_x",
    "statement": "VIGIL uses AI to assist and advise — never as an authority.",
    "sections": [
        {"title": "What AI does",
         "points": [{"text": "Parts of the Service use AI models to plan and prioritise testing.",
                     "source": "Terms of Service, §11"}]},
        {"title": "What AI never does",
         "points": [{"text": "AI never decides what you are charged or which hosts you may test.",
                     "source": "Terms of Service, §11"},
                    {"text": "Four separate authorities run the system, and none of them is the AI.",
                     "source": "README"}]},
    ],
}


def test_the_screen_shows_the_ai_use_and_human_oversight_statements():
    _need_node()
    out = _node(r"""
server = { "GET api/customer/ai-governance": { data: %s } };
const view = viewAiGovernance(); document.body.appendChild(view); await flush();
out.title = text(view.querySelector("h2"));
out.calls = calls;
out.statement = text(view.querySelector(".cust-aig-statement"));
out.cards = view.querySelectorAll("div.card").map(c => (c.querySelectorAll("h3")[0] || {}).textContent);
out.points = view.querySelectorAll(".cust-aig-point").map(p => text(p));
out.cites = view.querySelectorAll(".cust-aig-cite").map(p => text(p));
out.buttons = buttons(view);
out.whole = text(view);
""" % json.dumps(_SERVER_OK))
    assert out["title"] == "How VIGIL uses AI"
    assert out["calls"] == [["GET", "api/customer/ai-governance"]]           # one read, no org id in the request
    assert "never as an authority" in out["statement"]
    assert out["cards"] == ["What AI does", "What AI never does"]
    # the AI-use statement and the human-oversight (what AI never does) statement both on the page, verbatim
    assert "Parts of the Service use AI models to plan and prioritise testing." in out["points"]
    assert "AI never decides what you are charged or which hosts you may test." in out["points"]
    assert "Four separate authorities run the system, and none of them is the AI." in out["points"]
    # every point shows its source, and the screen offers NO control (a pure display)
    assert out["cites"] == ["Source: Terms of Service, §11", "Source: Terms of Service, §11", "Source: README"]
    assert out["buttons"] == []


def test_a_read_that_fails_is_told_honestly_without_inventing_words():
    _need_node()
    out = _node(r"""
server = { "GET api/customer/ai-governance": { status: 403, data: { error: "forbidden" } } };
const view = viewAiGovernance(); document.body.appendChild(view); await flush();
out.soon = text(view.querySelector(".cust-soon"));
out.points = view.querySelectorAll(".cust-aig-point").length;
""")
    assert "Only members who can see this workspace's assessments" in out["soon"] and out["points"] == 0
