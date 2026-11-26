"""PR-G (Area 6) — the customer app's Plans and Reports screens (app.js, executed under node) and their edge routes
(over the REAL edge -> cockpit hop).

* The edge writes data-plans / data-report-export / data-compliance into the page — "0" for every off value, "1" only
  with its flag — and the ONLY difference a flag makes to the page is its own value + the build id.
* With every flag off the app is unchanged: no Plans / Reports tab, #/plans and #/reports are the home screen exactly as
  an unknown route, the guide offers no "Go to" for them, and no call is made; the edge 404s every route.
* Plans: the tiers come from the one session-scoped read; Choose goes through the EXISTING checkout with the plan's
  price_id only; Upgrade / Downgrade / Cancel plan are asked first in the page and sent through the step-up with only
  {price_id} or {cancel: true}; refusals are told in fixed words (or the server's customer-written reason).
* Reports: Download report saves exactly the server's document; a PDF that is not available, a locked trial and a role
  without assessments get fixed words; the standards mapping never says a control is met — its statement is the
  server's own (ui/compliance_view.STATEMENT), and OWASP shows the whole Top 10 while PCI DSS / SOC 2 show only what a
  proven weakness implicates.
* The edge carries the SESSION org and only the plan choice to the cockpit — a body org_id never travels.

Mutation-verify targets (each neuter reds a NAMED test here):
  * a tab or route shown with the flag off              -> test_with_every_flag_off_the_app_is_unchanged
  * Choose sends more than the price_id                 -> test_choose_uses_the_existing_checkout_with_the_price_only
  * a switch sent without asking first / without step-up -> test_a_switch_is_asked_first_and_sent_through_the_step_up
  * the mapping claims a control is met                 -> test_the_mapping_screen_never_says_a_control_is_met
  * the page always writes "1"                          -> test_the_edge_writes_the_area6_flags_into_the_page
  * a body org_id reaches the cockpit                   -> test_the_edge_sends_only_the_session_org_and_the_choice
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_monitoring_screen import _DOM, _fn, _var
from test_customer_onboarding import _guide, _line, _need_node, _page_and_build

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
UI_JS, APP_JS = APP / "ui.js", APP / "app.js"
_AREA6_FLAGS = ("VIGIL_CUSTOMER_PLANS", "VIGIL_CUSTOMER_PLAN_CHANGE", "VIGIL_CUSTOMER_PDF_REPORT",
                "VIGIL_CUSTOMER_COMPLIANCE_MAP")


@pytest.fixture(autouse=True)
def _flags_off(monkeypatch):
    for k in _AREA6_FLAGS + ("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED"):
        monkeypatch.delenv(k, raising=False)


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _block(src: str) -> str:
    i = src.index("  // ---- Plans, Reports and the standards mapping (PR-G, Area 6)")
    return src[i:src.index("  // ---- end of Plans, Reports and the standards mapping (PR-G)", i)]


# ---- the screens, under node ----------------------------------------------------------------------------------------
_WORLD = r"""
Object.assign(document.body.dataset, %(flags)s);
let who = { authenticated: true, username: "ana", org_id: "org_x" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
globalThis.location = { hash: %(hash)s, pathname: "/", search: "" };
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let renders = 0; function render() { renders++; }
let whoRefreshes = 0; async function refreshWho() { whoRefreshes++; }
function shell(inner, current) { return h("div.shell", { dataset: { current: current } }, inner); }
var GUIDE_ON = false;
const VUI = window.VUI;
const calls = [], toasts = [], errs = [], stepUps = [], checkouts = [];
let server = {};            // "GET <path>" / "POST <path>" -> {data} | {status, data}
async function answer(key) {
  const r = server[key];
  if (!r) { const e = new Error("404"); e.status = 404; e.data = { error: "not found" }; throw e; }
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data; throw e; }
  return r.data;
}
VUI.getJSON = async p => { calls.push(["GET", p]); return answer("GET " + p); };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); return answer("POST " + p); };
VUI.toast = m => toasts.push(String(m));
VUI.errorBanner = m => errs.push(String(m));
VUI.clearErrorBanner = () => {};
async function withStepUp(action, where) { stepUps.push(!!where); return action(); }
async function startCheckout(o, btn) { checkouts.push(JSON.parse(JSON.stringify(o))); }
const saved = [];
globalThis.URL = { createObjectURL: b => { saved.push(b); return "blob:vigil-test"; }, revokeObjectURL: () => {} };
const _realSetTimeout = setTimeout;
globalThis.setTimeout = (f, ms) => (ms >= 1000 ? 0 : _realSetTimeout(f, ms));
const anchors = [];
const _append = body.appendChild.bind(body);
body.appendChild = c => { if (c.tagName === "A") anchors.push({ href: c.getAttribute("href"),
                                                                 download: c.getAttribute("download") });
                          return _append(c); };
const tick = () => new Promise(r => _realSetTimeout(r, 0));
const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
const out = {};
"""

_FUNCS = ("pageFlag", "here", "loadingHolder", "kv", "err", "clearErr", "money", "fmtDate", "groupInt",
          "area6Label", "plansButton", "plansDays", "area6View", "viewPlans", "plansBody", "plansCurrentCard",
          "plansTrialCard", "plansPaygCard", "plansTierCard", "plansAction", "plansConfirm", "plansConfirmCancel",
          "plansChange", "plansFailed", "viewReports", "reportsDownloadCard", "reportsBlob", "reportsSave",
          "reportsDownload", "reportsFailed", "complianceSection", "complianceBody", "complianceCard")
_VARS = ("API", "PLANS_ON", "REPORT_EXPORT_ON", "COMPLIANCE_ON", "REPORTS_ON", "COMPLIANCE_STATEMENT",
         "COMPLIANCE_STATUS")


def _node(script: str, *, flags: "dict | None" = None, hash_: str = "#/plans") -> dict:
    src = _src()
    flags = {"plans": "1", "reportExport": "1", "compliance": "1"} if flags is None else flags
    prog = "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", "const h = window.VUI.h;",
                      _WORLD % {"flags": json.dumps(flags), "hash": json.dumps(hash_)}]
                     + [_fn(src, n) for n in _FUNCS] + [_var(src, n) for n in _VARS]
                     + ["(async () => {\n" + script + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
                        " e => { console.error(e && e.stack || e); process.exit(3); });"])
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


_PLANS_NONE = {
    "org_id": "org_x", "can_manage": True, "current": None, "scheduled_change": None,
    "trial": {"credits": 100, "had_trial": True, "preview_locked": True, "rules": ["One trial per workspace."]},
    "pay_as_you_go": {"packs": [{"price_id": "vigil_topup_1k", "name": "1,000 credit top-up", "credits": 1000,
                                 "amount_minor": 1000, "currency": "USD"}], "rules": ["Bought credits never expire."]},
    "depths": [{"run_tier": "quick", "name": "Quick scan"}, {"run_tier": "deep", "name": "Deep scan"}],
    "tiers": [{"id": "vigil_pro_monthly", "price_id": "vigil_pro_monthly", "name": "Pro (monthly)",
               "amount_minor": 9900, "currency": "USD", "credits_per_period": 6000, "period_days": 30.0,
               "current": False, "scheduled": False, "action": "checkout", "rules": ["A rule."]}],
    "actions": {"checkout": True, "change": False, "cancel": False, "change_unavailable_reason": "",
                "plan_checkout_pending": False},
}
_PLANS_PRO = {
    **_PLANS_NONE,
    "trial": {"credits": 100, "had_trial": True, "preview_locked": False, "rules": []},
    "current": {"plan_id": "pro", "status": "active", "period_end": 1800000000, "credits_per_period": 6000,
                "active": True, "price_id": "vigil_pro_monthly", "name": "Pro (monthly)", "amount_minor": 9900,
                "currency": "USD", "period_days": 30.0, "retired": False},
    "tiers": [{"id": "vigil_research_monthly", "price_id": "vigil_research_monthly", "name": "Research (monthly)",
               "amount_minor": 2900, "currency": "USD", "credits_per_period": 2000, "period_days": 30.0,
               "current": False, "scheduled": False, "action": "downgrade", "rules": []},
              {"id": "vigil_pro_monthly", "price_id": "vigil_pro_monthly", "name": "Pro (monthly)",
               "amount_minor": 9900, "currency": "USD", "credits_per_period": 6000, "period_days": 30.0,
               "current": True, "scheduled": False, "action": "current", "rules": []},
              {"id": "vigil_team_monthly", "price_id": "vigil_team_monthly", "name": "Team (monthly)",
               "amount_minor": 29900, "currency": "USD", "credits_per_period": 20000, "period_days": 30.0,
               "current": False, "scheduled": False, "action": "upgrade", "rules": []}],
    "actions": {"checkout": False, "change": True, "cancel": True, "change_unavailable_reason": "",
                "plan_checkout_pending": False},
}

_CARD = """
const cardOf = t => document.querySelectorAll("div.card").filter(c => ((c.querySelectorAll("h3")[0] || {}).textContent) === t)[0];
const btn = (t, label) => button(cardOf(t), label);
"""


def test_the_plans_screen_compares_the_tiers_from_the_one_read():
    out = _node(_CARD + r"""
server = { "GET api/customer/billing/plans": { data: %s } };
const view = viewPlans(); document.body.appendChild(view); await flush();
out.cards = document.querySelectorAll("div.card").map(c => (c.querySelectorAll("h3")[0] || {}).textContent);
out.pro = text(cardOf("Pro (monthly)"));
out.trial = text(cardOf("Trial")); out.payg = text(cardOf("Pay as you go"));
out.buttons = buttons(view); out.calls = calls; out.depths = text(view).indexOf("Quick scan, Deep scan") >= 0;
""" % json.dumps(_PLANS_NONE))
    assert out["calls"] == [["GET", "api/customer/billing/plans"]]            # one read, no org id
    assert out["cards"] == ["Your plan", "Trial", "Pay as you go", "Pro (monthly)"]
    assert "99.00 USD per month" in out["pro"] and "Credits each period6,000" in out["pro"]
    assert "Trial credits100" in out["trial"] and "1,000 credits10.00 USD" in out["payg"]
    assert out["buttons"] == ["Buy credits on Billing", "Choose Pro (monthly)"] and out["depths"] is True


def test_choose_uses_the_existing_checkout_with_the_price_only():
    out = _node(_CARD + r"""
server = { "GET api/customer/billing/plans": { data: %s } };
document.body.appendChild(viewPlans()); await flush();
btn("Pro (monthly)", "Choose Pro (monthly)").click(); await flush();
btn("Pay as you go", "Buy credits on Billing").click();
out.checkouts = checkouts; out.posts = calls.filter(c => c[0] === "POST"); out.navs = navs;
""" % json.dumps(_PLANS_NONE))
    assert out["checkouts"] == [{"price_id": "vigil_pro_monthly"}]            # nothing but the catalog id
    assert out["posts"] == [] and out["navs"] == ["#/billing"]


def test_a_switch_is_asked_first_and_sent_through_the_step_up():
    out = _node(_CARD + r"""
server = { "GET api/customer/billing/plans": { data: %s },
           "POST api/customer/billing/plan-change": { data: { kind: "change", effective_at: 1800000000,
                                                              name: "Team (monthly)", price_id: "vigil_team_monthly" } } };
document.body.appendChild(viewPlans()); await flush();
out.pro = buttons(cardOf("Pro (monthly)")); out.research = buttons(cardOf("Research (monthly)"));
out.current = buttons(cardOf("Your plan"));
btn("Team (monthly)", "Upgrade").click();
out.asked = text(cardOf("Team (monthly)").querySelector("div.cust-mon-confirm"));
out.before = calls.filter(c => c[0] === "POST").length;
btn("Team (monthly)", "Not now").click();
out.restored = buttons(cardOf("Team (monthly)"));
btn("Team (monthly)", "Upgrade").click(); btn("Team (monthly)", "Yes, switch at renewal").click(); await flush();
out.posts = calls.filter(c => c[0] === "POST"); out.stepUps = stepUps; out.toasts = toasts; out.renders = renders;
""" % json.dumps(_PLANS_PRO))
    assert out["pro"] == [] and out["research"] == ["Downgrade"]              # the current plan offers no action
    assert out["current"] == ["Cancel plan"]
    assert "Switch to Team (monthly) at your next renewal, on 2027-01-15?" in out["asked"]
    assert "Nothing is charged today." in out["asked"] and "299.00 USD per month" in out["asked"]
    assert "Need more credits before then? Buy a credit pack on Billing" in out["asked"]   # an upgrade waits: say so
    assert out["before"] == 0 and out["restored"] == ["Upgrade"]               # nothing sent until confirmed
    assert out["posts"] == [["POST", "api/customer/billing/plan-change", {"price_id": "vigil_team_monthly"}]]
    assert out["stepUps"] == [True] and out["renders"] == 1
    assert out["toasts"] == ["Your plan changes to Team (monthly) on 2027-01-15. Nothing was charged today."]


def test_cancel_and_keep_send_only_the_choice():
    sched = {**_PLANS_PRO, "scheduled_change": {"kind": "change", "effective_at": 1800000000,
                                                "price_id": "vigil_team_monthly", "name": "Team (monthly)"}}
    out = _node(_CARD + r"""
server = { "GET api/customer/billing/plans": { data: %s },
           "POST api/customer/billing/plan-change": { data: { kind: "keep", effective_at: 1800000000 } } };
document.body.appendChild(viewPlans()); await flush();
out.note = text(cardOf("Your plan").querySelector("div.cust-launch-note"));
btn("Your plan", "Keep my current plan").click(); await flush();
btn("Your plan", "Cancel plan").click();
out.asked = text(cardOf("Your plan").querySelector("div.cust-mon-confirm"));
btn("Your plan", "Yes, cancel").click(); await flush();
out.posts = calls.filter(c => c[0] === "POST").map(c => c[2]);
""" % json.dumps(sched))
    assert out["note"] == "Your plan changes to Team (monthly) on 2027-01-15."
    assert out["posts"] == [{"price_id": "vigil_pro_monthly"}, {"cancel": True}]
    assert out["asked"].startswith("End your plan on 2027-01-15? It will not renew")


def test_a_downgrade_is_asked_without_the_top_up_hint_and_an_ended_plan_says_so():
    ended = {**_PLANS_PRO, "current": {**_PLANS_PRO["current"], "active": False},
             "actions": {**_PLANS_PRO["actions"], "change": False, "cancel": False, "checkout": True}}
    past_due = {**_PLANS_PRO, "current": {**_PLANS_PRO["current"], "active": False, "status": "past_due"},
                "actions": {**_PLANS_PRO["actions"], "change": False, "cancel": False}}
    out = _node(_CARD + r"""
server = { "GET api/customer/billing/plans": { data: %s } };
document.body.appendChild(viewPlans()); await flush();
btn("Research (monthly)", "Downgrade").click();
out.asked = text(cardOf("Research (monthly)").querySelector("div.cust-mon-confirm"));
document.body.children.length = 0;
server = { "GET api/customer/billing/plans": { data: %s } };
document.body.appendChild(viewPlans()); await flush();
out.ended = text(cardOf("Your plan")); out.endedButtons = buttons(cardOf("Your plan"));
document.body.children.length = 0;
server = { "GET api/customer/billing/plans": { data: %s } };
document.body.appendChild(viewPlans()); await flush();
out.pastDue = text(cardOf("Your plan"));
""" % (json.dumps(_PLANS_PRO), json.dumps(ended), json.dumps(past_due)))
    assert "Switch to Research (monthly) at your next renewal" in out["asked"]
    assert "Need more credits" not in out["asked"]
    assert "StatusEnded" in out["ended"] and "Ended on2027-01-15" in out["ended"] and out["endedButtons"] == []
    assert "Renews on" not in out["ended"]
    assert "StatusPayment past due" in out["pastDue"] and "Period ends on2027-01-15" in out["pastDue"]


@pytest.mark.parametrize("status,data,expect,rerender", [
    (404, {"error": "not found"}, "Changing plans is not available on this deployment. Nothing was changed.", 0),
    (429, {"error": "rate limited"}, "Too many attempts — wait a moment and try again. Nothing was changed.", 0),
    (403, {"error": "denied: this plan renews within a day; change it after the renewal"},
     "The plan was not changed: this plan renews within a day; change it after the renewal.", 0),
    (403, {"error": ("denied: the payment processor did not confirm the change; check your plan in a minute before "
                     "trying again, or contact support")},
     ("VIGIL could not confirm the change: the payment processor did not confirm the change; check your plan in a "
      "minute before trying again, or contact support. This screen now shows your plan as it is."), 1),
    (502, {"error": "provisioner unreachable"}, ("VIGIL could not confirm the change: provisioner unreachable. This "
                                                 "screen now shows your plan as it is."), 1),
])
def test_a_refused_switch_is_told_honestly(status, data, expect, rerender):
    out = _node(_CARD + r"""
server = { "GET api/customer/billing/plans": { data: %s },
           "POST api/customer/billing/plan-change": { status: %d, data: %s } };
document.body.appendChild(viewPlans()); await flush();
btn("Team (monthly)", "Upgrade").click(); btn("Team (monthly)", "Yes, switch at renewal").click(); await flush();
out.errs = errs; out.renders = renders; out.toasts = toasts;
""" % (json.dumps(_PLANS_PRO), status, json.dumps(data)))
    assert out["errs"] == [expect] and out["renders"] == rerender and out["toasts"] == []


def test_a_role_that_cannot_see_billing_gets_the_honest_card():
    out = _node(r"""
server = { "GET api/customer/billing/plans": { status: 403, data: { error: "denied: requester may not read" } } };
const view = viewPlans(); document.body.appendChild(view); await flush();
out.text = text(view);
""")
    assert "Only members who can see billing — the founder or an admin — can compare plans." in out["text"]
    assert "requester may not read" not in out["text"]                      # never the server's words


_REPORT = {"format": "html", "filename": "vigil-report-org_x-20270115.html", "html": "<!doctype html><p>r</p>",
           "fingerprint": "sha256:ab"}
_COMPLIANCE = {
    "findings_total": 2,
    "statement": "x",
    "frameworks": [
        {"framework": "owasp", "label": "OWASP Top 10", "version": "OWASP Top 10:2021", "summary": {},
         "controls": [{"id": "A01:2021", "name": "Broken Access Control", "status": "no_proven_weakness",
                       "findings": []},
                      {"id": "A03:2021", "name": "Injection", "status": "weakness_proven",
                       "findings": [{"finding_ref": "f1", "title": "SQL injection", "host": "a.example",
                                     "retest": None}]},
                      {"id": "A09:2021", "name": "Security Logging and Monitoring Failures",
                       "status": "not_mapped", "findings": []}]},
        {"framework": "pci_dss", "label": "PCI DSS", "version": "PCI DSS v4.0", "summary": {},
         "controls": [{"id": "6.2.4", "name": "", "status": "weakness_fixed",
                       "findings": [{"finding_ref": "f2", "title": "Open redirect", "host": "a.example",
                                     "retest": "fixed"}]},
                      {"id": "10.2.1", "name": "", "status": "no_proven_weakness", "findings": []}]},
    ],
}


def test_the_reports_screen_saves_exactly_the_servers_document():
    out = _node(r"""
server = { "GET api/customer/report": { data: %s }, "GET api/customer/compliance": { data: { frameworks: [] } } };
const view = viewReports(); document.body.appendChild(view); await flush();
button(view, "Download report").click(); await flush();
out.anchors = anchors; out.saved = saved.length; out.blob = await saved[0].text(); out.type = saved[0].type;
out.note = text(view.querySelectorAll("div.card")[0]);
out.calls = calls;
""" % json.dumps({**_REPORT, "filename": "../../etc/passwd x.html"}), hash_="#/reports")
    assert out["blob"] == _REPORT["html"] and out["type"] == "text/html;charset=utf-8" and out["saved"] == 1
    assert out["anchors"] == [{"href": "blob:vigil-test", "download": "..-..-etc-passwd-x.html"}]   # a safe name
    assert "Saved ..-..-etc-passwd-x.html." in out["note"]
    assert ["GET", "api/customer/report"] in out["calls"]


def test_a_pdf_is_saved_from_its_bytes():
    pdf = "%PDF-1.4 test %%EOF"
    import base64
    out = _node(r"""
server = { "GET api/customer/report/pdf": { data: { format: "pdf", filename: "r.pdf", pdf_b64: %s } } };
const view = viewReports(); document.body.appendChild(view); await flush();
button(view, "Download PDF").click(); await flush();
out.type = saved[0].type; out.bytes = Buffer.from(await saved[0].arrayBuffer()).toString("latin1");
""" % json.dumps(base64.b64encode(pdf.encode()).decode()), flags={"reportExport": "1"}, hash_="#/reports")
    assert out["type"] == "application/pdf" and out["bytes"] == pdf


@pytest.mark.parametrize("path,status,error,expect", [
    ("/pdf", 403, "denied: PDF export is not set up on this deployment — download the HTML report instead",
     "A PDF is not available on this deployment right now."),
    ("", 403, "denied: the full report unlocks with your first purchase: buy credits to download it",
     "The full report unlocks with your first purchase. Buy credits in Billing to download it."),
    ("", 403, "denied: requester may not read this org (view_assessments)",
     "Only members who can read assessments — the founder, or an Operator VIGIL has added — can download"),
    ("", 429, "rate limited; retry after 3600s", "Too many reports in a short time — try again later."),
    ("", 404, "not found", "Downloading a report is not available right now."),
])
def test_a_refused_download_is_told_in_fixed_words(path, status, error, expect):
    label = "Download PDF" if path else "Download report"
    out = _node(r"""
server = { "GET api/customer/report%s": { status: %d, data: { error: %s } } };
const view = viewReports(); document.body.appendChild(view); await flush();
button(view, %s).click(); await flush();
out.note = text(view.querySelectorAll("div.card")[0]); out.buttons = buttons(view); out.saved = saved.length;
""" % (path, status, json.dumps(error), json.dumps(label)), flags={"reportExport": "1"}, hash_="#/reports")
    assert expect in out["note"] and out["saved"] == 0
    assert error.split(": ", 1)[-1] not in out["note"]                        # never the server's own words
    assert ("Go to Billing" in out["buttons"]) == ("unlocks" in error)


def test_the_mapping_screen_never_says_a_control_is_met():
    out = _node(r"""
server = { "GET api/customer/compliance": { data: %s } };
const view = viewReports(); document.body.appendChild(view); await flush();
out.cards = document.querySelectorAll("div.card").map(c => text(c));
out.text = text(view);
""" % json.dumps(_COMPLIANCE), flags={"compliance": "1"}, hash_="#/reports")
    owasp, pci = out["cards"]
    assert "A01:2021 — Broken Access ControlNo proven weakness" in owasp                  # OWASP: the whole Top 10
    assert "A03:2021 — InjectionProven weakness · 1 finding(s)" in owasp and "SQL injection on a.example" in owasp
    assert "Not mapped by VIGIL's checks" in owasp
    assert "6.2.4Fixed (retest) · 1 finding(s)" in pci and "Open redirect on a.example (fixed)" in pci
    assert "10.2.1" not in pci and "1 other control(s) VIGIL's checks map have no proven weakness here." in pci
    from sigil.ui.compliance_view import STATEMENT
    assert STATEMENT in out["text"]                                           # the server's own sentence, verbatim
    rest = out["text"].replace(STATEMENT, "")
    assert not re.search(r"(?i)\b(compliant|compliance|covered|coverage|satisf\w*|passe[sd]|passing)\b", rest)
    assert re.findall(r"(?i)\bmet\b", rest) == ["met"]                       # only "not an assessment that they are met"
    assert "That is not an assessment that they are met." in rest


def test_the_app_statement_is_the_servers():
    from sigil.ui.compliance_view import STATEMENT
    out = _node("out.s = COMPLIANCE_STATEMENT;")
    assert out["s"] == STATEMENT


# ---- the top bar, the routes and the guide (flag-gated) -----------------------------------------------------------
_VIEWS = ("viewDashboard", "viewLogin", "viewSignup", "viewRecover", "viewGoogleCode", "viewBilling",
          "viewBillingReturn", "viewInvoices", "viewAssets", "viewAssessments", "viewTeam", "viewMonitoring",
          "viewCode", "viewGuideScreen", "viewSecurityScreen", "viewPlans", "viewReports", "viewConnect")


def _wiring(flags: dict, script: str) -> dict:
    src = _src()
    i = src.index("  var ROUTES = {")
    world = "\n".join([
        f"Object.assign(document.body.dataset, {json.dumps(flags)});",
        'globalThis.location = { hash: "#/plans" };',
        'let who = { authenticated: true, username: "ana" };',
        "const state = { get: () => ({ who }) };",
        "function authed() { return !!(who && who.authenticated); }",
        "const calls = []; const VUI = window.VUI;",
        "VUI.getJSON = async p => { calls.push(['GET', p]); return {}; };",
        "function nav(r) { location.hash = r; }",
        "function ntfWidget() { return null; }\nasync function doLogout() {}",
        'function viewSoon(t) { return "viewSoon:" + t; }',
        ("var GUIDE = null, GUIDE_ON = false, SECURITY_ON = false, TEAM_ON = false, MONITORING_ON = false, "
         "LAUNCH_ON = false, CODE_ON = false, CONNECT_ON = false, SETTINGS_ON = false, PRIVACY_CENTER_ON = false;")]
        + [f"function {v}() {{ return {json.dumps(v)}; }}" for v in _VIEWS])
    # PR-L (Area 11): the shell also reads ATTACK_PATH_ON, so app.js's own flag line rides in beside PR-G's (read from
    # the page dataset like theirs: none of these flag sets names attackPath, so the shell shows no Attack-path link).
    prog = "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", world, _line(src, r"^  function h\(\) \{.*\}$"),
                      _fn(src, "pageFlag"), _var(src, "PLANS_ON"), _var(src, "REPORT_EXPORT_ON"),
                      _var(src, "COMPLIANCE_ON"), _var(src, "REPORTS_ON"), _var(src, "ATTACK_PATH_ON"),
                      _fn(src, "navLink"), _fn(src, "shell"),
                      _line(src, r"^  function routeShown\(route\) \{.*\}$"), src[i:src.index("\n  };", i) + 5],
                      "const out = {};\n(async () => {\n" + script + "\n})().then(() => "
                      "process.stdout.write(JSON.stringify(out)), e => { console.error(e && e.stack || e); "
                      "process.exit(3); });"])
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


_WIRE = r"""
out.links = shell(h("div"), "#/").querySelectorAll("button.cust-nav-link").map(b => text(b));
out.plans = ROUTES["#/plans"](); out.reports = ROUTES["#/reports"](); out.home = ROUTES["#/"]();
who = { authenticated: false }; out.signedOut = [ROUTES["#/plans"](), ROUTES["#/reports"]()];
who = { authenticated: true, username: "ana" };
out.shown = [routeShown("#/plans"), routeShown("#/reports"), routeShown("#/billing")];
await new Promise(r => setTimeout(r, 0));
out.calls = calls;
"""
_BASE_LINKS = ["Overview", "Billing", "Invoices", "Assets", "Assessments", "Team"]


def test_with_every_flag_off_the_app_is_unchanged():
    for v in ("0", "", "__VIGIL_PLANS__"):
        off = _wiring({"plans": v, "reportExport": v, "compliance": v}, _WIRE)
        assert off["links"] == _BASE_LINKS + ["Sign out (ana)"], v
        assert off["plans"] == off["reports"] == off["home"] == "viewDashboard", v
        assert off["signedOut"] == ["viewLogin", "viewLogin"] and off["shown"] == [False, False, True], v
        assert off["calls"] == [], v


def test_each_flag_brings_its_own_tab():
    on = _wiring({"plans": "1", "reportExport": "1", "compliance": "1"}, _WIRE)
    assert on["links"] == _BASE_LINKS + ["Plans", "Reports", "Sign out (ana)"]
    assert on["plans"] == "viewPlans" and on["reports"] == "viewReports" and on["shown"] == [True, True, True]
    for flags, links in (({"plans": "1"}, ["Plans"]), ({"reportExport": "1"}, ["Reports"]),
                         ({"compliance": "1"}, ["Reports"])):
        out = _wiring(flags, _WIRE)
        assert out["links"] == _BASE_LINKS + links + ["Sign out (ana)"], flags


def test_reports_shows_only_the_parts_whose_flag_is_on():
    only_map = _node("const v = viewReports(); out.h = v.querySelectorAll('h3').map(x => text(x));",
                     flags={"compliance": "1"}, hash_="#/reports")
    only_dl = _node("const v = viewReports(); out.h = v.querySelectorAll('h3').map(x => text(x));",
                    flags={"reportExport": "1"}, hash_="#/reports")
    assert only_map["h"] == ["Standards mapping"] and only_dl["h"] == ["Download a report"]


def test_the_guide_walks_through_plans_and_reports():
    out = _guide()
    steps = {(ch["id"], st["id"]): st for ch in out["chapters"] for st in ch["steps"]}
    assert steps[("credits", "compare")]["route"] == "#/plans" and steps[("credits", "compare")]["when"] == "plans"
    assert any("Yes, switch at renewal" in c for c in steps[("credits", "compare")]["clicks"])
    assert steps[("assess", "report")]["route"] == steps[("assess", "standards")]["route"] == "#/reports"
    assert (steps[("assess", "report")]["when"], steps[("assess", "standards")]["when"]) == ("reportExport",
                                                                                           "compliance")
    assert any("never states that a control is met" in c for c in steps[("assess", "standards")]["clicks"])
    faq = [f for f in out["faq"] if "Download report" in f["a"]]
    assert len(faq) == 1 and faq[0]["when"] == "reportExport"
    # every PR-G addition — and nothing else — is gated on a page switch (so with them off the guide is unchanged);
    # the other gated entries are PR-B's (#1198) Fix-first step, on its own switch (data-posture), legal/governance
    # S1's Settings step (data-settings), legal/governance S2's Privacy centre step (data-privacy-center) and
    # legal/governance S3's Data rights step (data-data-rights)
    gated = sorted([f"{ch['id']}/{st['id']}" for ch in out["chapters"] for st in ch["steps"] if st.get("when")]
                   + [f"faq/{f['q']}" for f in out["faq"] if f.get("when")]
                   + [f"{ch['id']}/{st['id']}:alt" for ch in out["chapters"] for st in ch["steps"] if st.get("alt")])
    assert gated == ["assess/fixfirst", "assess/report", "assess/standards", "credits/compare", "credits/plans:alt",
                     "faq/Can I give our results to an auditor or a customer?", "workspace/datarights",
                     "workspace/organization", "workspace/organization:alt", "workspace/privacy"]
    assert steps[("workspace", "privacy")]["when"] == "privacyCenter"             # lgS2's step, never a PR-G switch
    assert steps[("workspace", "datarights")]["when"] == "dataRights"            # lgS3's step, never a PR-G switch
    assert steps[("assess", "fixfirst")]["when"] == "posture"                     # PR-B's step, never a PR-G switch
    assert steps[("workspace", "organization")]["when"] == "settings"            # lgS1's step, never a PR-G switch
    assert steps[("workspace", "organization")]["alt"]["when"] == "security"     # its Account-security clicks
    plans = steps[("credits", "plans")]
    assert plans["clicks"][-1] == "A workspace has one plan at a time. To change plans, contact VIGIL."   # as before
    assert plans["alt"]["when"] == "plans" and plans["alt"]["clicks"][:-1] == plans["clicks"][:-1]
    assert plans["alt"]["clicks"][-1] == "A workspace has one plan at a time. To change it, use Plans in the top bar."


# The whole Guide screen (every chapter tab, then Questions) as text, over app.js's OWN pageFlag + routeShown (verbatim)
# with the page switches in `flags`. With `strip`, the PR-G entries are removed from the guide's data first — the guide
# as it was before them — so the two renders can be compared.
_GUIDE_RENDER = r"""
Object.assign(document.body.dataset, %(flags)s);
var MONITORING_ON = false, CODE_ON = false, CONNECT_ON = false, SETTINGS_ON = false, PRIVACY_CENTER_ON = false;
%(page_flag)s
%(route_shown)s
const G = window.VIGIL_GUIDE;
if (%(strip)s) {
  G.CHAPTERS.forEach(ch => { ch.steps = ch.steps.filter(s => !s.when); ch.steps.forEach(s => { delete s.alt; }); });
  const keep = G.FAQ.filter(f => !f.when); G.FAQ.length = 0; keep.forEach(f => G.FAQ.push(f));
}
const navs = [];
const g = G.viewGuide({ h: window.VUI.h, username: "ana", storage: { getItem: () => null, setItem: () => {},
                        removeItem: () => {} }, nav: r => navs.push(r), shown: routeShown, flag: pageFlag });
document.body.appendChild(g);
const tabs = () => g.querySelectorAll(".cust-guide-tab");
const pages = [];
tabs().map(b => b.textContent).forEach(name => {
  tabs().filter(b => b.textContent === name)[0].click();
  g.querySelectorAll(".cust-guide-step-head").forEach(t => t.click());          // open every step
  pages.push(name + "\n" + text(g) + "\n" + g.querySelectorAll("button").map(b => b.textContent).join("|"));
  g.querySelectorAll("button").filter(b => b.textContent.indexOf("Go to ") === 0).forEach(b => b.click());
});
process.stdout.write(JSON.stringify({ pages, navs }));
"""


def _guide_render(flags: dict, *, strip: bool = False) -> dict:
    src = _src()
    guide_js = APP / "guide.js"
    prog = "\n".join([_DOM, f"require({json.dumps(str(UI_JS))});", f"require({json.dumps(str(guide_js))});",
                      _GUIDE_RENDER % {"flags": json.dumps(flags), "strip": json.dumps(strip),
                                       "page_flag": _fn(src, "pageFlag"),
                                       "route_shown": _line(src, r"^  function routeShown\(route\) \{.*\}$")}])
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_with_the_flags_off_the_guide_renders_exactly_as_before():
    for off in ({}, {"plans": "0", "reportExport": "0", "compliance": "0"}, {"plans": "", "compliance": "__X__"}):
        now, before = _guide_render(off), _guide_render(off, strip=True)
        assert now == before, off
        blob = "\n".join(now["pages"])
        for s in ("Compare plans", "Plans in the top bar", "Download a report", "Download report", "Standards mapping",
                  "auditor", "Go to Plans", "Go to Reports"):
            assert s not in blob, (off, s)
        assert "A workspace has one plan at a time. To change plans, contact VIGIL." in blob


def test_each_switch_brings_only_its_own_guide_steps():
    on = _guide_render({"plans": "1", "reportExport": "1", "compliance": "1"})
    blob = "\n".join(on["pages"])
    for s in ("Compare plans and change yours", "Download a report", "See the standards your findings touch",
              "Can I give our results to an auditor or a customer?", "Go to Plans", "Go to Reports",
              "A workspace has one plan at a time. To change it, use Plans in the top bar."):
        assert s in blob, s
    assert "To change plans, contact VIGIL." not in blob
    assert "#/plans" in on["navs"] and "#/reports" in on["navs"]
    only_map = "\n".join(_guide_render({"compliance": "1"})["pages"])
    assert "See the standards your findings touch" in only_map and "Go to Reports" in only_map
    assert "Download a report" not in only_map and "auditor" not in only_map and "Compare plans" not in only_map
    only_dl = "\n".join(_guide_render({"reportExport": "1"})["pages"])
    assert "Download a report" in only_dl and "auditor" in only_dl and "See the standards" not in only_dl
    only_plans = "\n".join(_guide_render({"plans": "1"})["pages"])
    assert "Compare plans and change yours" in only_plans and "Go to Plans" in only_plans
    assert "Go to Reports" not in only_plans and "Download a report" not in only_plans


def test_the_new_copy_has_no_estimate_or_engine_name():
    block = _block(_src())
    strings = " ".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    for word in ("estimat", "quote", "predict", "claude", "anthropic", "strix", "nyx", "opus", "sonnet", "gpt",
                 "llm", "margin", "markup"):
        assert word not in strings.lower(), word


# ---- the edge ---------------------------------------------------------------------------------------------------------
def test_the_edge_writes_the_area6_flags_into_the_page(tmp_path, monkeypatch):
    off, build_off = _page_and_build(tmp_path / "a")
    for attr, ph in (("data-plans", "__VIGIL_PLANS__"), ("data-report-export", "__VIGIL_REPORT_EXPORT__"),
                     ("data-compliance", "__VIGIL_COMPLIANCE__")):
        assert f'{attr}="0"' in off and ph not in off
    for env, attr in (("VIGIL_CUSTOMER_PLANS", "data-plans"), ("VIGIL_CUSTOMER_PDF_REPORT", "data-report-export"),
                      ("VIGIL_CUSTOMER_COMPLIANCE_MAP", "data-compliance")):
        monkeypatch.setenv(env, "1")
        on, build_on = _page_and_build(tmp_path / env)
        assert f'{attr}="1"' in on and build_on != build_off
        assert on.replace(f'{attr}="1"', f'{attr}="0"').replace(build_on, build_off) == off   # only its own value
        for v in ("0", "", "no", "maybe"):
            monkeypatch.setenv(env, v)
            assert f'{attr}="0"' in _page_and_build(tmp_path / f"{env}{v or 'empty'}")[0], (env, v)
        monkeypatch.delenv(env)


_ROUTES = ("/api/customer/billing/plans", "/api/customer/report", "/api/customer/report/pdf",
           "/api/customer/compliance")


def _signup(op, ep, email="a@acme.com"):
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    return _post(op, ep, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1",
                                                          "org_name": "Acme"})[1]


def test_flags_off_the_edge_answers_404(tmp_path, monkeypatch):
    """Off, each route is the EDGE's own unknown-route answer (status AND body) — it never hops to the cockpit, whose
    own refusal ("unknown provision action") would otherwise mask an edge that served the route (two independent
    refusals, each checked on its own: the cockpit leg is test_flags_off_the_plans_surface_is_absent & co)."""
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        _signup(op, ep)
        unknown_get = _get(op, ep, "/api/customer/no-such-read")
        unknown_post = _post(op, ep, "/api/customer/no-such-action", {"price_id": "vigil_pro_monthly"})
        assert unknown_get[0] == 404 and unknown_post[0] == 404
        for path in _ROUTES:
            assert _get(op, ep, path) == unknown_get, path
        assert _post(op, ep, "/api/customer/billing/plan-change", {"price_id": "vigil_pro_monthly"}) == unknown_post
        monkeypatch.setenv("VIGIL_CUSTOMER_PLANS", "1")              # Plans alone: the change route stays absent
        assert _post(op, ep, "/api/customer/billing/plan-change", {"price_id": "vigil_pro_monthly"}) == unknown_post
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_routes_relay_the_session_read_role_scoped(tmp_path, monkeypatch):
    for k in _AREA6_FLAGS:
        monkeypatch.setenv(k, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        conf = _signup(op, ep)
        c, plans = _get(op, ep, "/api/customer/billing/plans")
        assert c == 200 and plans["org_id"] == conf["org_id"] and plans["tiers"]         # org_admin sees billing
        for path in ("/api/customer/compliance", "/api/customer/report", "/api/customer/report/pdf"):
            c, body = _get(op, ep, path)
            assert c == 403 and "view_assessments" in body["error"], path                # billing is not testing
        assert _get(_opener(), ep, "/api/customer/billing/plans")[0] == 401               # no session: refused
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_edge_sends_only_the_session_org_and_the_choice(tmp_path, monkeypatch):
    from sigil.ui.provision import Provisioner
    seen: list = []

    def fake(self, requester, org, *, price_id="", cancel=False, ip="", mfa_at=0.0, now=None):
        seen.append({"requester": requester, "org": org, "price_id": price_id, "cancel": cancel})
        return {"org_id": org, "kind": "cancel" if cancel else "change", "effective_at": 1.0}
    monkeypatch.setattr(Provisioner, "billing_plan_change", fake)
    for k in _AREA6_FLAGS:
        monkeypatch.setenv(k, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        conf = _signup(op, ep)
        c, _r = _post(op, ep, "/api/customer/billing/plan-change",
                      {"price_id": "vigil_pro_monthly", "org_id": "org_evil", "requester": "x", "amount_minor": 1})
        assert c == 200
        c, _r = _post(op, ep, "/api/customer/billing/plan-change", {"cancel": "yes"})   # not a real true
        c, _r = _post(op, ep, "/api/customer/billing/plan-change", {"cancel": True})
        assert seen == [{"requester": conf["username"], "org": conf["org_id"], "price_id": "vigil_pro_monthly",
                         "cancel": False},
                        {"requester": conf["username"], "org": conf["org_id"], "price_id": "", "cancel": False},
                        {"requester": conf["username"], "org": conf["org_id"], "price_id": "", "cancel": True}]
    finally:
        sov.shutdown(); edge.shutdown()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
