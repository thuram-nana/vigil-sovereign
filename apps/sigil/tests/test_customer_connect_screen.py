"""Consumer PR-C — the customer app's Connect screen (app.js under node), its top-bar wiring and its guide step.

* The edge writes data-connect="1" into the page only while VIGIL_CUSTOMER_CONNECT is on, and data-cloud-connect="1" only
  while the cloud leg is ALSO on (VIGIL_CUSTOMER_CLOUD_CONNECT alone turns nothing on) — the switches that also serve
  api/customer/connect and api/customer/connect/* — and "0" otherwise: the same bytes for every off value, and each value
  counts in the build id.
* Off, the app is unchanged: no Connect tab, #/connect is the home screen exactly as an unknown route, routeShown hides
  it, the guide does not even LIST its Connect step (a flag-off deployment sees the guide it always had), and nothing is
  fetched or timed.
* On, the screen shows only what the server sent and offers only flows this deployment can finish (`available`):
    - WEBSITE: the server's pre-selected method, the values to publish shown verbatim with Copy, NO check until the
      person confirms they are authorized to test the site; then automatic re-checking on the server's cadence that
      flips the site to Verified with no reload, and stops on Verified, on any refusal, when the screen is left and
      after its cap (then "Check again"), and waits — uncounted — while the page is hidden;
    - CODE REPOSITORY: the Code screen's own GitHub install, offered only to someone the server says may manage code;
    - CLOUD ACCOUNT (only with the cloud leg on): a provider picker (AWS / GCP / Azure / Cloudflare, offered per
      available.cloud_providers), the chosen provider's account-id input pre-validated with the backend's own rule, and
      the provider's own placement verbatim (AWS a trust policy; GCP a service-account id + email + gcloud; Azure an
      admin-consent link + binding tag; Cloudflare a read-only token name + the token pasted ONCE as a SECRET). Verify
      sends only the provider, the account and the role_ref; a connection started earlier is "Not finished" with
      Continue (the server's resumed steps for THAT provider) and Cancel; an expired one offers Connect again;
      Disconnect and Cancel ask first and label by provider.
* The copy follows the product rules: no model or engine name, no price, no estimate.

app.js's own code is extracted verbatim and run on the customer UI kit (ui.js) and the guide (guide.js) with a minimal
DOM; every other page flag the extracted code can reference is stubbed off.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the edge always writes "1" / the cloud flag works alone   -> test_the_edge_writes_both_connect_flags_into_the_page
  * the tab, the route, routeShown or the guide step not gated -> test_with_the_flag_off_the_app_is_unchanged
  * the screen fetches with the flag off                      -> test_with_the_flag_off_the_connect_screen_fetches_nothing
  * the cloud tile shown without the cloud leg                -> test_the_screen_shows_the_three_tiles_from_the_server
  * a flow offered that this deployment cannot finish         -> test_only_flows_this_deployment_can_finish_are_offered
  * the server's method ignored / a value re-worded           -> test_the_proof_preselects_the_servers_method_and_copies_verbatim
  * a check sent before the authorization is confirmed        -> test_no_check_runs_until_the_person_confirms_they_are_authorized
  * the re-check ignores the server's cadence / never flips   -> test_the_recheck_follows_the_servers_cadence_and_flips_to_verified
  * the re-check survives a refusal, leaving, hiding or its cap
                                                              -> test_the_recheck_stops_on_a_refusal_when_left_and_after_its_cap
  * Verify sends more than it names / the trust policy re-worded
                                                              -> test_the_cloud_steps_show_the_exact_policy_and_verify_sends_only_its_fields
  * a half-finished connection cannot be continued            -> test_a_half_finished_cloud_connection_continues_with_the_same_steps
  * Disconnect / Cancel sends without asking                  -> test_disconnect_and_cancel_ask_first_and_keep_it_sends_nothing
  * the picker offers a provider the deployment cannot finish  -> test_the_cloud_picker_offers_every_available_provider
  * a non-AWS flow posts "aws" / renders AWS-shaped fields     -> test_connecting_{gcp,azure,cloudflare}_*
  * the Cloudflare token is echoed back or not sent as secret  -> test_connecting_cloudflare_posts_cloudflare_and_pastes_the_secret_token_once
  * a connected non-AWS row mislabels its provider / reference -> test_a_connected_non_aws_row_labels_and_renders_by_its_provider
  * resuming a non-AWS connection falls back to AWS steps      -> test_resuming_a_non_aws_connection_shows_that_providers_steps
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from test_customer_onboarding import _FORBIDDEN as _COPY_FORBIDDEN
from test_customer_team import _fn, _line, _node, _page_and_build

APP_JS = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app" / "app.js"
_FLAGS = ("VIGIL_CUSTOMER_CONNECT", "VIGIL_CUSTOMER_CLOUD_CONNECT", "VIGIL_CUSTOMER_STEPUP_REQUIRED")


@pytest.fixture(autouse=True)
def _no_flags(monkeypatch):
    for var in _FLAGS:
        monkeypatch.delenv(var, raising=False)


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _connect_block(src: str) -> str:
    """The Connect screen's own section of app.js, verbatim (the harness runs what ships, not a copy of it)."""
    i = src.index("  // ---- Connect (VIGIL_CUSTOMER_CONNECT)")
    return src[i:src.index("  // ---- Team (VIGIL_CUSTOMER_TEAM_UI)", i)]


def _last_fn(src: str, name: str) -> str:
    """The LAST top-level definition of a function app.js declares more than once (the one the browser keeps)."""
    i = src.rindex(f"\n  function {name}(") + 1
    return src[i:src.index("\n  }\n", i) + 4]


# --- the edge flags ------------------------------------------------------------------------------------------------------
def test_the_edge_writes_both_connect_flags_into_the_page(tmp_path, monkeypatch):
    # VIGIL_CUSTOMER_CONNECT is now DEFAULT-ON, so the off baseline FORCES it off with the explicit =0 override;
    # the loop below re-checks that every non-affirmative value (and the cloud flag alone) serves that same page.
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "0")
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-connect="0"' in off and 'data-cloud-connect="0"' in off
    assert "__VIGIL_CONNECT__" not in off and "__VIGIL_CLOUD_CONNECT__" not in off
    for n, (var, v) in enumerate((("VIGIL_CUSTOMER_CONNECT", "0"), ("VIGIL_CUSTOMER_CONNECT", ""),
                                  ("VIGIL_CUSTOMER_CONNECT", "maybe"), ("VIGIL_CUSTOMER_CLOUD_CONNECT", "1"))):
        monkeypatch.setenv(var, v)                    # every off value — and the cloud flag ALONE — serve the same page
        assert _page_and_build(tmp_path / f"c{n}") == (off, build_off), (var, v)
    monkeypatch.delenv("VIGIL_CUSTOMER_CLOUD_CONNECT")
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-connect="1"' in on and 'data-cloud-connect="0"' in on and build_on != build_off
    assert on.replace('data-connect="1"', 'data-connect="0"').replace(build_on, build_off) == off
    monkeypatch.setenv("VIGIL_CUSTOMER_CLOUD_CONNECT", "1")
    both, build_both = _page_and_build(tmp_path / "d")
    assert 'data-connect="1"' in both and 'data-cloud-connect="1"' in both
    assert build_both not in (build_off, build_on)
    assert both.replace('data-cloud-connect="1"', 'data-cloud-connect="0"').replace(build_both, build_on) == on


# --- with the flag off, the app is exactly what it was -------------------------------------------------------------------
_VIEWS = ("viewDashboard", "viewLogin", "viewSignup", "viewRecover", "viewGoogleCode", "viewBilling", "viewBillingReturn",
          "viewInvoices", "viewAssets", "viewAssessments", "viewGuideScreen", "viewMonitoring", "viewTeam", "viewCode",
          "viewSecurityScreen", "viewConnect")
# Every OTHER page flag the extracted code may reference, off. CONNECT_ON is read from the page by app.js's own line.
# ATTACK_PATH_ON / BLIND_VULN_ON are PR-L's (Area 11) flags: the extracted shell + route table read ATTACK_PATH_ON.
_OTHER_FLAGS_OFF = ("var GUIDE = null, GUIDE_ON = false, SECURITY_ON = false, TEAM_ON = false, MONITORING_ON = false, "
                    "LAUNCH_ON = false, CODE_ON = false, ATTACK_PATH_ON = false, BLIND_VULN_ON = false, "
                    "SETTINGS_ON = false, PRIVACY_CENTER_ON = false, SELLER_IDENTITY_ON = false, LIVE_ON = false;")


def _wiring(flag: str, script: str) -> dict:
    """app.js's own top bar (shell + navLink), routeShown and route table, verbatim, over stub screens — plus the real
    guide (guide.js) asked which steps it lists, with app.js's own routeShown as its `shown`."""
    src = _src()
    i = src.index("  var ROUTES = {")
    world = "\n".join([
        f"document.body.dataset.connect = {json.dumps(flag)};",
        'globalThis.location = { hash: "#/connect" };',
        'let who = { authenticated: true, username: "ana" };',
        "const state = { get: () => ({ who }) };",
        "function authed() { return !!(who && who.authenticated); }",
        "const calls = []; const VUI = window.VUI;",
        "VUI.getJSON = async p => { calls.push(['GET', p]); return {}; };",
        "VUI.postJSON = async (p, b) => { calls.push(['POST', p, b]); return {}; };",
        "const navs = []; function nav(r) { navs.push(r); location.hash = r; }",
        "function ntfWidget() { return null; }\nasync function doLogout() {}",
        'function viewSoon(t) { return "viewSoon:" + t; }',
        "const mem = {}; const storage = { getItem: k => (k in mem ? mem[k] : null), setItem: (k, v) => { mem[k] = v; },"
        " removeItem: k => { delete mem[k]; } };",
        _OTHER_FLAGS_OFF] + [f"function {v}() {{ return {json.dumps(v)}; }}" for v in _VIEWS])
    return _node("\n".join([world, _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                            _line(src, r'^  var CONNECT_ON = pageFlag\("connect"\);$'), _fn(src, "navLink"),
                            _fn(src, "shell"), _line(src, r"^  function routeShown\(route\) \{.*\}$"),
                            src[i:src.index("\n  };", i) + 5], script]))


_WIRING_SCRIPT = r"""
out.links = shell(h("div"), "#/").querySelectorAll("button.cust-nav-link").map(b => text(b));
out.route = ROUTES["#/connect"](); out.home = ROUTES["#/"]();
who = { authenticated: false }; out.signedOut = ROUTES["#/connect"](); who = { authenticated: true, username: "ana" };
out.shown = [routeShown("#/connect"), routeShown("#/billing"), routeShown("#/assets")];
const steps = env => window.VIGIL_GUIDE.viewGuide(Object.assign({ h, username: "ana", storage, nav, chapter: "hosts" }, env))
  .querySelectorAll(".cust-guide-step").map(s => [text(s.querySelector(".cust-guide-step-title")),
    s.querySelectorAll("button").filter(b => !b.classList.contains("cust-guide-step-head")).map(b => b.textContent)]);
out.guide = steps({ shown: routeShown });
out.guideSaysNothing = steps({});
await tick();
out.calls = calls;
"""


def test_with_the_flag_off_the_app_is_unchanged():
    for flag in ("0", "", "__VIGIL_CONNECT__"):
        off = _wiring(flag, _WIRING_SCRIPT)
        assert off["links"] == ["Overview", "Billing", "Invoices", "Assets", "Assessments", "Team", "Sign out (ana)"], flag
        assert off["route"] == off["home"] == "viewDashboard" and off["signedOut"] == "viewLogin", flag
        assert off["shown"] == [False, True, True] and off["calls"] == [], flag
        # the guide's Connect step is not even LISTED: the hosts chapter is exactly the four steps it always was
        assert [t for t, _ in off["guide"]] == ["Register the host", "Publish one proof", "Confirm and verify",
                                                "Keep the proof current"], flag
    on = _wiring("1", _WIRING_SCRIPT)
    assert on["links"] == ["Overview", "Billing", "Invoices", "Assets", "Assessments", "Team", "Connect",
                           "Sign out (ana)"]
    assert on["route"] == "viewConnect" and on["signedOut"] == "viewLogin" and on["shown"] == [True, True, True]
    assert on["guide"][-1] == ["Or connect everything in one place", ["Go to Connect", "Mark as done"]]
    # a caller that does not say which screens are shown never gets the step (the guide cannot vouch for the screen)
    assert [t for t, _ in on["guideSaysNothing"]] == [t for t, _ in on["guide"][:-1]]
    src = _src()
    assert '.concat(CONNECT_ON ? [navLink("Connect", "#/connect")] : [])' in src
    assert '"#/connect": function () { return authed() ? (CONNECT_ON ? viewConnect() : viewDashboard()) : viewLogin(); },' in src


# --- the screen (app.js under node) -----------------------------------------------------------------------------------------
_WORLD = r"""
document.body.dataset.connect = __FLAG__;
document.body.dataset.cloudConnect = __CLOUD__;
globalThis.location = { hash: "#/connect", pathname: "/", search: "" };
let who = { authenticated: true, username: "cust_fo" };
const state = { get: () => ({ who }) };
function authed() { return !!(who && who.authenticated); }
const navs = []; function nav(r) { navs.push(r); location.hash = r; }
let renders = 0; function render() { renders++; }
let refreshed = 0; async function refreshWho() { refreshed++; }
function shell(inner, current) { return h("div.cust-shell", { dataset: { current: current } }, inner); }
function viewLogin() { return h("div.cust-login"); }
function viewDashboard() { return h("div.cust-home"); }
var GUIDE = null, GUIDE_ON = false;
var CODE_ON = __CODE_ON__;
const githubs = []; async function codeConnect(btn) { githubs.push(btn.textContent); }
const VUI = window.VUI;
const calls = [], toasts = [], errs = [];
let server = {};            // "GET <path>" / "POST <path>" -> {data} | {status, data} | [answer, answer, ...] in turn
function answer(key) {
  let r = server[key];
  if (Array.isArray(r)) r = r.length > 1 ? r.shift() : r[0];
  if (!r) { const e = new Error("404"); e.status = 404; e.data = { error: "not found" }; throw e; }
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data; throw e; }
  return JSON.parse(JSON.stringify(r.data));
}
VUI.getJSON = async p => { calls.push(["GET", p]); return answer("GET " + p); };
VUI.postJSON = async (p, b) => { calls.push(["POST", p, b]); return answer("POST " + p); };
VUI.toast = m => toasts.push(String(m));
VUI.errorBanner = m => errs.push(String(m));
VUI.clearErrorBanner = () => {};
// Timers: a zero delay passes straight through (it is how the harness lets promises settle); any other delay is
// RECORDED and run only when the test says so (fire), so the automatic re-check runs on the test's clock.
const realSetTimeout = globalThis.setTimeout;
const timers = []; let timerSeq = 0;
globalThis.setTimeout = (fn, ms) => {
  if (!ms) return realSetTimeout(fn, 0);
  timerSeq++; timers.push({ id: timerSeq, fn, ms }); return timerSeq;
};
globalThis.clearTimeout = id => { const i = timers.findIndex(t => t.id === id); if (i >= 0) timers.splice(i, 1); };
const flush = async () => { for (let i = 0; i < 12; i++) await tick(); };
const pollTimers = () => timers.filter(t => t.ms !== 1500);          // 1500 ms = the Copy button's "Copied" revert
async function fire() { const t = pollTimers()[0]; if (!t) return null; timers.splice(timers.indexOf(t), 1); t.fn();
                        await flush(); return t.ms; }
const copied = [];
Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async v => { copied.push(v); } } },
                                                 configurable: true, writable: true });
const root = new El("div"); document.body.appendChild(root);
async function show() { location.hash = "#/connect"; VUI.mount(root, ROUTES["#/connect"]()); await flush(); return root; }
function posts() { return calls.filter(c => c[0] === "POST"); }
function tile(title) { return root.querySelectorAll("div.cust-connect-tile").filter(t => text(t.querySelector("h3")) === title)[0]; }
function rows(t) { return t.querySelectorAll("div.cust-asset-head").map(r => [text(r.querySelector("span.host")),
  text(r.querySelector("span.cust-badge")), buttons(r)]); }
function flowBox() { return root.querySelector("#connect-flow"); }
function status() { return text(root.querySelector("p.cust-connect-status")); }
async function press(where, label) { button(where, label).click(); await flush(); }
"""


def _screen_app(flag: str, cloud: str, code_on: bool) -> str:
    """The stubbed world plus app.js's own Connect screen and the helpers it calls, extracted verbatim."""
    src = _src()
    world = (_WORLD.replace("__FLAG__", json.dumps(flag)).replace("__CLOUD__", json.dumps(cloud))
             .replace("__CODE_ON__", "true" if code_on else "false"))
    return "\n".join([world, _line(src, r"^  function h\(\) \{.*\}$"), _fn(src, "pageFlag"),
                      _line(src, r'^  var API = "[^"]*";'), _fn(src, "kv"), _fn(src, "fmtDate"), _fn(src, "loadingHolder"),
                      _line(src, r"^  function here\(\) \{.*\}$"), _line(src, r"^  function err\(msg\) \{.*$"),
                      _line(src, r"^  function clearErr\(\) \{.*$"), _last_fn(src, "own"), _fn(src, "statusBadge"),
                      _connect_block(src),
                      "const ROUTES = {\n" + _line(src, r'^    "#/connect": function .*,$') + "\n};"])


_AV = {"site_check": True, "site_auto_recheck": True, "repos": True, "repo_connect": True, "cloud_connect": True,
       "cloud_providers": {"aws": True, "gcp": True, "azure": True, "cloudflare": True}}
_POLICY = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:role/vigil-connector"},
     "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:ExternalId": "EXT-abc_123"}}}]}, indent=2)
_OVERVIEW = {
    "org_id": "org_a", "available": _AV,
    "sites": [{"host": "app.acme.io", "status": "verified"}, {"host": "acme.io", "status": "pending"},
              {"host": "old.acme.io", "status": "expired"}],
    "repos": [{"repo": "github.com/acme/api"}],
    "cloud": [{"provider": "aws", "account_id": "111111111111", "role_ref": "arn:aws:iam::111111111111:role/V",
               "verified_at": 1.79e9, "expires_at": 1.8e9, "access": "read-only", "status": "connected"},
              {"provider": "aws", "account_id": "222222222222", "role_ref": "arn:aws:iam::222222222222:role/V",
               "verified_at": 1.6e9, "expires_at": 1.65e9, "access": "read-only", "status": "expired"},
              {"provider": "aws", "account_id": "333333333333", "access": "read-only", "status": "pending"}]}
_PENDING = {"org_id": "org_a", "host": "acme.io", "status": "pending", "selected_method": "dns-txt",
            "marker": "vigil-site-verification=TOK",
            "methods": {"meta-tag": {"meta_tag": '<meta name="vigil-site-verification" content="TOK">'},
                        "dns-txt": {"dns_name": "_vigil-challenge.acme.io", "dns_value": "vigil-site-verification=TOK"},
                        "well-known": {"well_known_url": "https://acme.io/.well-known/vigil-site-verification.txt",
                                       "well_known_body": "vigil-site-verification=TOK"}},
            "recheck": {"due": True}}
_CHALLENGE = {"provider": "aws", "account_id": "123456789012", "external_id": "EXT-abc_123", "resumed": False,
              "principal_arn": "arn:aws:iam::111122223333:role/vigil-connector", "trust_policy": _POLICY,
              "permissions_policy_arn": "arn:aws:iam::aws:policy/SecurityAudit", "role_name_hint": "VigilSecurityAudit"}
# The other three providers' challenge shapes, exactly as provision.cloud_connect_challenge returns them (the common
# {provider, account_id, external_id, resumed} merged with the provider's placement — gcp_placement / azure_placement /
# cloudflare_placement). The SA email / Object ID / token the customer pastes back is the provider's role_ref.
_GCP_PROJECT = "my-company-prod"
_GCP_SA_ID = "vgl-0123456789abcdef0123"
_GCP_SA_EMAIL = _GCP_SA_ID + "@" + _GCP_PROJECT + ".iam.gserviceaccount.com"
_GCP_CONNECTOR_SA = "vigil-connect@vigil-prod.iam.gserviceaccount.com"
_GCP_CHALLENGE = {
    "provider": "gcp", "account_id": _GCP_PROJECT, "external_id": "EXT-gcp_1", "resumed": False,
    "connector_sa": _GCP_CONNECTOR_SA, "token_creator_role": "roles/iam.serviceAccountTokenCreator",
    "sa_id": _GCP_SA_ID, "sa_email": _GCP_SA_EMAIL,
    "steps": [("In GCP project " + _GCP_PROJECT + ", create a service account with EXACTLY this id (its name encodes "
               "your connection — do not change it): " + _GCP_SA_ID),
              ("Grant VIGIL's connector service account the Service Account Token Creator role ON that service account "
               "(resource-scoped; a project-wide grant also works but is broader than needed).")],
    "gcloud": [('gcloud iam service-accounts create ' + _GCP_SA_ID + ' --project=' + _GCP_PROJECT
                + ' --display-name="VIGIL connect"'),
               ('gcloud iam service-accounts add-iam-policy-binding ' + _GCP_SA_EMAIL + ' --project=' + _GCP_PROJECT
                + ' --member="serviceAccount:' + _GCP_CONNECTOR_SA + '" --role="roles/iam.serviceAccountTokenCreator"')]}
_AZURE_TENANT = "00000000-0000-0000-0000-000000000000"
_AZURE_CLIENT = "11111111-2222-3333-4444-555555555555"
_AZURE_OBJECT_ID = "99999999-8888-7777-6666-555555555555"
_AZURE_CHALLENGE = {
    "provider": "azure", "account_id": _AZURE_TENANT, "external_id": "EXT-az_1", "resumed": False,
    "client_id": _AZURE_CLIENT,
    "admin_consent_url": "https://login.microsoftonline.com/" + _AZURE_TENANT + "/adminconsent?client_id=" + _AZURE_CLIENT,
    "binding_tag": "EXT-az_1",
    "graph_read": ("GET https://graph.microsoft.com/v1.0/servicePrincipals(appId='" + _AZURE_CLIENT
                   + "')?$select=appId,id,tags"),
    "steps": [("As a Global Administrator of tenant " + _AZURE_TENANT + ", open the admin-consent URL and grant VIGIL's "
               "app admin consent (read-only application permissions)."),
              ("In Microsoft Entra ID -> Enterprise applications -> VIGIL -> Properties, add the binding tag shown (the "
               "external id) as a tag, then Save."),
              ("Return here and verify: VIGIL reads its own service principal back over Microsoft Graph and confirms "
               "the tag equals the external id.")]}
_CF_ACCOUNT = "0123456789abcdef0123456789abcdef"
_CF_TOKEN_NAME = "vigil-verify-EXT-cf_1"
_CF_GROUPS = ["Account Settings Read", "Zone Read", "User API Tokens Read"]
_CF_CHALLENGE = {
    "provider": "cloudflare", "account_id": _CF_ACCOUNT, "external_id": "EXT-cf_1", "resumed": False,
    "token_name": _CF_TOKEN_NAME, "permission_groups": _CF_GROUPS, "account_scope": _CF_ACCOUNT, "read_only": True,
    "steps": ["In the Cloudflare dashboard open My Profile -> API Tokens -> Create Token -> Create Custom Token.",
              ("Name the token EXACTLY " + _CF_TOKEN_NAME + " — the name proves this request is yours; a different name "
               "is rejected."),
              ("Under Permissions add ONLY Read permissions (set each to Read, never Edit/Write): "
               + ", ".join(_CF_GROUPS) + ". A token carrying any write/edit permission is refused."),
              ("Under Account Resources choose Include -> a specific account -> " + _CF_ACCOUNT + " (NOT 'All "
               "accounts'); keep any Zone Resources scoped within that same account only. A token that can reach more "
               "than this one account is refused."),
              "Leave Client IP Address Filtering and TTL at their defaults, create the token, and copy it.",
              ("Paste the token into the connect screen once. VIGIL verifies it and does NOT store it — only the "
               "token's public id and a sha256 are kept.")]}


def _screen(server: "dict | None" = None, then: str = "", *, flag: str = "1", cloud: str = "1", code_on: bool = True,
            overview: "dict | None" = None, before: str = "") -> dict:
    srv = {"GET api/customer/connect": {"data": overview if overview is not None else _OVERVIEW}}
    srv.update(server or {})
    return _node(_screen_app(flag, cloud, code_on) + f"\nserver = {json.dumps(srv)};\n{before}\nawait show();\n" + then)


def test_with_the_flag_off_the_connect_screen_fetches_nothing():
    for flag in ("0", "", "__VIGIL_CONNECT__"):
        out = _screen(flag=flag, then="out.calls = calls; out.home = !!root.querySelector('div.cust-home'); "
                                      "out.on = [CONNECT_ON, CLOUD_CONNECT_ON]; out.timers = timers.length;")
        assert out == {"calls": [], "home": True, "on": [False, False], "timers": 0}, flag
    # the cloud flag alone turns nothing on in the page either
    out = _screen(flag="0", cloud="1", then="out.on = [CONNECT_ON, CLOUD_CONNECT_ON]; out.calls = calls;")
    assert out == {"on": [False, False], "calls": []}


def test_the_screen_shows_the_three_tiles_from_the_server():
    then = r"""
out.calls = calls;
out.tiles = root.querySelectorAll("div.cust-connect-tile").map(t => text(t.querySelector("h3")));
out.sites = rows(tile("Website"));
out.siteActs = buttons(tile("Website").querySelector("div.cust-mon-actions"));
out.repos = rows(tile("Code repository"));
out.repoActs = buttons(tile("Code repository").querySelector("div.cust-mon-actions"));
out.cloud = tile("Cloud account") ? tile("Cloud account").querySelectorAll("div.cust-connect-acct").map(a => [
  text(a.querySelector("span.host")), text(a.querySelector("span.cust-badge")), buttons(a)]) : null;
out.cloudText = tile("Cloud account") ? text(tile("Cloud account")) : null;
"""
    out = _screen(then=then)
    assert out["calls"] == [["GET", "api/customer/connect"]]
    assert out["tiles"] == ["Website", "Code repository", "Cloud account"]
    assert out["sites"] == [["app.acme.io", "✓ Verified", []], ["acme.io", "… Pending", ["Continue"]],
                            ["old.acme.io", "⚠ Expired", ["Prove again"]]]
    assert out["siteActs"] == ["Connect a website"]
    assert out["repos"] == [["github.com/acme/api", "Connected", []]]
    assert out["repoActs"] == ["Connect GitHub", "Open Code"]
    assert out["cloud"] == [["AWS 111111111111", "✓ Connected (read-only)", ["Disconnect"]],
                            ["AWS 222222222222", "⚠ Expired — connect again", ["Connect again", "Disconnect"]],
                            ["AWS 333333333333", "… Not finished", ["Continue", "Cancel"]]]
    assert "Valid until2027-01-15" in out["cloudText"]
    # without the cloud leg there is no cloud tile, whatever the answer carries
    out = _screen(cloud="0", then=then)
    assert out["tiles"] == ["Website", "Code repository"] and out["cloud"] is None


def test_only_flows_this_deployment_can_finish_are_offered():
    none = dict(_OVERVIEW, available={k: False for k in _AV}, repos=[])
    then = r"""
out.texts = root.querySelectorAll("div.cust-connect-tile").map(t => text(t));
out.buttons = root.querySelectorAll("div.cust-connect-tile").map(t => buttons(t));
"""
    out = _screen(overview=none, then=then)
    site, repo, cloud = out["texts"]
    assert "Proving a website is not available on this deployment yet" in site
    assert out["buttons"][0] == []                                   # no Continue / Prove again / Connect a website
    assert "Only the founder of this workspace, or an Operator VIGIL has added, can connect repositories." in repo
    assert out["buttons"][1] == []
    assert "Connecting a cloud account is not available on this deployment yet" in cloud
    assert out["buttons"][2] == ["Disconnect", "Disconnect", "Cancel"]   # what exists can still be removed
    out = _screen(overview=none, code_on=False, then=then)
    assert "Connecting repositories is not available on this deployment yet." in out["texts"][1]
    # the code review is reachable but GitHub cannot be connected here: Open Code, never a dead Connect GitHub
    partial = dict(_OVERVIEW, available=dict(_AV, repo_connect=False))
    out = _screen(overview=partial, then=then)
    assert out["buttons"][1] == ["Open Code"]
    assert "Connecting GitHub is not available on this deployment yet." in out["texts"][1]


def test_the_proof_preselects_the_servers_method_and_copies_verbatim():
    out = _screen({"POST api/customer/connect/ownership": {"data": _PENDING}}, r"""
await press(tile("Website"), "Continue");
out.read = posts();
const tabs = () => flowBox().querySelector("div.cust-connect-methods").querySelectorAll("button").map(b => [
  b.textContent, b.getAttribute("aria-pressed")]);
out.tabs = tabs();
const values = () => flowBox().querySelectorAll("div.cust-connect-copy").map(r => [text(r.querySelector("span.k")),
  text(r.querySelector("code"))]);
out.dns = values();
await press(flowBox().querySelectorAll("div.cust-connect-copy")[1], "Copy");
out.copied = copied.slice();
await press(flowBox(), "HTML meta tag");
out.metaTabs = tabs(); out.meta = values();
await press(flowBox(), "File on your site");
out.file = values();
out.posts = posts().length;
""")
    assert out["read"] == [["POST", "api/customer/connect/ownership", {"host": "acme.io"}]]   # a read: no re-check asked
    assert out["tabs"] == [["HTML meta tag", "false"], ["DNS TXT record", "true"], ["File on your site", "false"]]
    assert out["dns"] == [["Name", "_vigil-challenge.acme.io"], ["Value", "vigil-site-verification=TOK"]]
    assert out["copied"] == ["vigil-site-verification=TOK"]
    assert out["metaTabs"][0] == ["HTML meta tag", "true"]
    assert out["meta"] == [["Tag", '<meta name="vigil-site-verification" content="TOK">']]
    assert out["file"] == [["URL", "https://acme.io/.well-known/vigil-site-verification.txt"],
                           ["Contents", "vigil-site-verification=TOK"]]
    assert out["posts"] == 1                                         # switching method sends nothing


def test_no_check_runs_until_the_person_confirms_they_are_authorized():
    out = _screen({"POST api/customer/connect/ownership": [{"data": _PENDING}, {"data": dict(
        _PENDING, checked={"ran": True, "ok": False, "method": "dns-txt", "reason": "not found yet"},
        recheck={"due": True, "next_in": 10.0})}]}, r"""
await press(tile("Website"), "Continue");
await press(flowBox(), "Check now");
out.unconfirmed = [status(), posts().length, pollTimers().length];
flowBox().querySelector("#connect-authz").checked = true;
await press(flowBox(), "Check now");
out.sent = posts().slice(1);
""")
    assert out["unconfirmed"] == ["Please confirm you are authorized to test this site first.", 1, 0]
    assert out["sent"] == [["POST", "api/customer/connect/ownership",
                            {"host": "acme.io", "method": "dns-txt", "recheck": True, "authorized": True}]]


def _checked(reason="could not read the published token: no TXT record yet", next_in=10.0):
    return {"data": dict(_PENDING, checked={"ran": True, "ok": False, "method": "dns-txt", "reason": reason},
                         recheck={"due": True, "next_in": next_in})}


_START_CHECKING = r"""
await press(tile("Website"), "Continue");
flowBox().querySelector("#connect-authz").checked = true;
await press(flowBox(), "Check now");
"""


def test_the_recheck_follows_the_servers_cadence_and_flips_to_verified():
    deferred = {"data": dict(_PENDING, checked={"ran": False, "deferred": True}, recheck={"due": True, "next_in": 3.2})}
    verified = {"data": {"org_id": "org_a", "host": "acme.io", "status": "verified", "method": "dns-txt",
                         "checked": {"ran": True, "ok": True, "method": "dns-txt"}}}
    out = _screen({"POST api/customer/connect/ownership": [{"data": _PENDING}, _checked(), deferred, verified]},
                  _START_CHECKING + r"""
out.first = [status(), pollTimers().map(t => t.ms)];
out.fired1 = await fire();
out.second = [status(), pollTimers().map(t => t.ms)];
out.fired2 = await fire();
out.third = [status(), pollTimers().map(t => t.ms), toasts.slice(), renders];
out.checks = posts().filter(p => p[2] && p[2].recheck === true).length;
""")
    assert out["first"] == ["Not found yet: could not read the published token: no TXT record yet. Checking again in "
                            "10 s.", [10000]]
    assert out["fired1"] == 10000
    assert out["second"] == ["Waiting for your change to appear. Checking again in 3 s.", [3200]]   # the server's cadence
    assert out["fired2"] == 3200
    assert out["third"] == ["Verified — acme.io is connected.", [], ["Ownership verified for acme.io"], 1]
    assert out["checks"] == 3                                        # one request per step, none after Verified


def test_the_recheck_stops_on_a_refusal_when_left_and_after_its_cap():
    # a refusal (here: the per-workspace ceiling) stops it, says why, and offers Check again
    out = _screen({"POST api/customer/connect/ownership": [{"data": _PENDING}, _checked(),
                                                           {"status": 429, "data": {"error": "rate limited"}}]},
                  _START_CHECKING + r"""
await fire();
out.refused = [status(), pollTimers().length, errs.slice(), button(flowBox(), "Check again").hidden];
""")
    assert out["refused"] == ["Automatic checking stopped.", 0,
                              ["Checking stopped: too many checks just now. Wait a few minutes, then try again."], False]
    # leaving the screen ends the chain at its next step: nothing more is sent
    out = _screen({"POST api/customer/connect/ownership": [{"data": _PENDING}, _checked()]}, _START_CHECKING + r"""
location.hash = "#/billing";
const sent = posts().length;
await fire();
out.left = [posts().length - sent, pollTimers().length];
""")
    assert out["left"] == [0, 0]
    # while the page is hidden it waits — no request, and the wait is not counted against the cap
    out = _screen({"POST api/customer/connect/ownership": [{"data": _PENDING}, _checked()]}, _START_CHECKING + r"""
document.hidden = true;
const sent = posts().length;
for (let i = 0; i < 40; i++) await fire();
out.hidden = [posts().length - sent, pollTimers().map(t => t.ms)];
document.hidden = false;
await fire();
out.visible = posts().length - sent;
""")
    assert out["hidden"] == [0, [10000]] and out["visible"] == 1
    # after about five minutes of "not yet" it pauses (30 checks), and Check again starts it afresh
    out = _screen({"POST api/customer/connect/ownership": [{"data": _PENDING}, _checked()]}, _START_CHECKING + r"""
while (pollTimers().length) await fire();
out.capped = [posts().filter(p => p[2] && p[2].recheck).length, status(), button(flowBox(), "Check again").hidden];
await press(flowBox(), "Check again");
out.again = [posts().filter(p => p[2] && p[2].recheck).length, pollTimers().length];
""")
    assert out["capped"][0] == 30 and out["capped"][2] is False
    assert out["capped"][1].startswith("Not found yet (could not read the published token: no TXT record yet). "
                                       "Automatic checking paused")
    assert out["again"] == [31, 1]


def test_a_fresh_second_factor_is_asked_for_honestly():
    step_up = {"status": 401, "data": {"error": "a fresh second-factor (step-up) is required for this operation",
                                       "step_up_required": True}}
    out = _screen({"POST api/customer/connect/ownership": [{"data": _PENDING}, step_up]}, _START_CHECKING + r"""
out.said = errs.slice(); out.navs = navs.slice(); out.timers = pollTimers().length;
""")
    assert out["said"] == ["For your security, this needs a fresh second-factor check. Verify with your authenticator, "
                           "then try again."]
    assert out["navs"] == [] and out["timers"] == 0                 # not treated as a sign-out; checking stopped
    # with the account-security step-up in this build, the request goes through it (sent once more after the check)
    out = _screen({"POST api/customer/connect/ownership": [{"data": _PENDING}, _checked()]},
                  "const wheres = []; globalThis.withStepUp = (action, where) => { wheres.push(where && where.className); "
                  "return action(); };" + _START_CHECKING + "out.wheres = wheres;")
    assert out["wheres"] == ["card cust-connect-proof"]                 # the step-up opens inside the proof card


def test_the_cloud_steps_show_the_exact_policy_and_verify_sends_only_its_fields():
    out = _screen({"POST api/customer/connect/cloud/challenge": {"data": _CHALLENGE},
                   "POST api/customer/connect/cloud/verify": {"data": {"provider": "aws", "account_id": "123456789012",
                                                                       "access": "read-only"}}}, r"""
await press(tile("Cloud account"), "Connect a cloud account");
flowBox().querySelector("#connect-cloud-provider").value = "aws";
flowBox().querySelector("#connect-cloud-account").value = "12345";
await press(flowBox(), "Continue");
out.bad = [errs.slice(), posts().length];
flowBox().querySelector("#connect-cloud-account").value = " 1234-5678 9012 ";
await press(flowBox(), "Continue");
out.challenge = posts().slice();
out.policy = text(flowBox().querySelector("pre.cust-connect-policy"));
await press(flowBox().querySelector("li"), "Copy");
out.copied = copied.slice();
out.rows = flowBox().querySelectorAll("div.cust-connect-copy").map(r => text(r.querySelector("code")));
out.text = text(flowBox());
await press(flowBox(), "Verify connection");
out.empty = errs.slice(-1);
flowBox().querySelector("#connect-aws-role").value = "  arn:aws:iam::123456789012:role/VigilSecurityAudit ";
await press(flowBox(), "Verify connection");
out.verify = posts().slice(1);
out.after = [toasts.slice(), renders];
""")
    assert out["bad"] == [["An AWS account ID is 12 digits."], 0]          # refused here, nothing sent
    assert out["challenge"] == [["POST", "api/customer/connect/cloud/challenge",
                                 {"provider": "aws", "account_id": "123456789012"}]]
    assert out["policy"] == _POLICY and out["copied"] == [_POLICY]          # verbatim, never re-worded
    assert out["rows"] == ["arn:aws:iam::aws:policy/SecurityAudit"]
    assert "refuses any other external ID" in out["text"] and "CloudTrail shows as denied" in out["text"]
    assert "Continuing the connection you started" not in out["text"]
    assert out["empty"] == ["Paste the role's ARN."]
    assert out["verify"] == [["POST", "api/customer/connect/cloud/verify", {
        "provider": "aws", "account_id": "123456789012", "role_ref": "arn:aws:iam::123456789012:role/VigilSecurityAudit"}]]
    assert out["after"] == [["AWS account 123456789012 connected (read-only)"], 1]


def test_a_half_finished_cloud_connection_continues_with_the_same_steps():
    resumed = dict(_CHALLENGE, account_id="333333333333", resumed=True)
    out = _screen({"POST api/customer/connect/cloud/challenge": {"data": resumed}}, r"""
const acct = n => tile("Cloud account").querySelectorAll("div.cust-connect-acct")
  .filter(a => text(a.querySelector("span.host")) === "AWS " + n)[0];
await press(acct("333333333333"), "Continue");
out.sent = posts();
out.text = text(flowBox());
out.policy = text(flowBox().querySelector("pre.cust-connect-policy"));
await press(acct("222222222222"), "Connect again");
out.again = posts().slice(1);
""")
    assert out["sent"] == [["POST", "api/customer/connect/cloud/challenge",
                            {"provider": "aws", "account_id": "333333333333"}]]
    assert "Continuing the connection you started: the trust policy and external ID are unchanged." in out["text"]
    assert out["policy"] == _POLICY
    assert out["again"] == [["POST", "api/customer/connect/cloud/challenge",
                             {"provider": "aws", "account_id": "222222222222"}]]


def test_disconnect_and_cancel_ask_first_and_keep_it_sends_nothing():
    out = _screen({"POST api/customer/connect/cloud/disconnect": {"data": {"disconnected": True}}}, r"""
const acct = n => tile("Cloud account").querySelectorAll("div.cust-connect-acct")
  .filter(a => text(a.querySelector("span.host")) === "AWS " + n)[0];
await press(acct("111111111111"), "Disconnect");
out.ask = [buttons(acct("111111111111")), text(acct("111111111111").querySelector("div.cust-mon-actions"))];
await press(acct("111111111111"), "Keep it");
out.kept = [buttons(acct("111111111111")), posts().length];
await press(acct("111111111111"), "Disconnect");
await press(acct("111111111111"), "Disconnect");
out.sent = posts();
await press(acct("333333333333"), "Cancel");
out.cancelAsk = [buttons(acct("333333333333")), text(acct("333333333333").querySelector("div.cust-mon-actions"))];
await press(acct("333333333333"), "Cancel connection");
out.cancelSent = posts().slice(1);
out.toasts = toasts;
""")
    assert out["ask"][0] == ["Disconnect", "Keep it"] and "Disconnect AWS 111111111111?" in out["ask"][1]
    assert out["kept"] == [["Disconnect"], 0]
    assert out["sent"] == [["POST", "api/customer/connect/cloud/disconnect",
                            {"provider": "aws", "account_id": "111111111111"}]]
    assert out["cancelAsk"][0] == ["Cancel connection", "Keep it"]
    assert "The external ID VIGIL gave you stops working" in out["cancelAsk"][1]
    assert out["cancelSent"] == [["POST", "api/customer/connect/cloud/disconnect",
                                  {"provider": "aws", "account_id": "333333333333"}]]
    assert out["toasts"] == ["AWS account 111111111111 disconnected", "AWS account 333333333333: connection cancelled"]


# --- the provider picker and the three non-AWS flows (AWS stays exactly as above) ------------------------------------
def test_the_cloud_picker_offers_every_available_provider():
    opts = r"""
await press(tile("Cloud account"), "Connect a cloud account");
out.options = flowBox().querySelector("select#connect-cloud-provider").querySelectorAll("option")
  .map(o => [o.value, o.textContent]);
"""
    out = _screen(then=opts)
    assert out["options"] == [["aws", "AWS"], ["gcp", "GCP"], ["azure", "Azure"], ["cloudflare", "Cloudflare"]]
    # only the providers the server marks ready in available.cloud_providers are offered
    some = dict(_OVERVIEW, available=dict(_AV, cloud_providers={"aws": True, "gcp": False, "azure": True,
                                                                "cloudflare": False}))
    out = _screen(overview=some, then=opts)
    assert out["options"] == [["aws", "AWS"], ["azure", "Azure"]]
    # with no per-provider map at all the picker falls back to offering all four (the server still refuses an
    # unprovisioned provider with its own error, so the picker is never a dead end)
    nomap = dict(_OVERVIEW, available={k: v for k, v in _AV.items() if k != "cloud_providers"})
    out = _screen(overview=nomap, then=opts)
    assert out["options"] == [["aws", "AWS"], ["gcp", "GCP"], ["azure", "Azure"], ["cloudflare", "Cloudflare"]]


def test_connecting_gcp_posts_gcp_and_renders_the_service_account_fields():
    out = _screen({"POST api/customer/connect/cloud/challenge": {"data": _GCP_CHALLENGE},
                   "POST api/customer/connect/cloud/verify": {"data": {"provider": "gcp", "account_id": _GCP_PROJECT,
                                                                       "access": "read-only"}}}, r"""
await press(tile("Cloud account"), "Connect a cloud account");
const prov = flowBox().querySelector("#connect-cloud-provider"); prov.value = "gcp"; prov.dispatch("change");
out.label = flowBox().querySelectorAll("label").map(l => text(l));
flowBox().querySelector("#connect-cloud-account").value = "sh0rt";
await press(flowBox(), "Continue");
out.bad = [errs.slice(), posts().length];
flowBox().querySelector("#connect-cloud-account").value = "  my-company-prod  ";
await press(flowBox(), "Continue");
out.challenge = posts().slice();
out.header = text(flowBox().querySelector("h3"));
out.steps = flowBox().querySelector("ol.cust-connect-steps").querySelectorAll("li").map(li => text(li));
out.values = flowBox().querySelectorAll("div.cust-connect-copy").map(r => [text(r.querySelector("span.k")),
  r.querySelector("code") ? text(r.querySelector("code")) : null]);
flowBox().querySelector("#connect-cloud-role").value = "  " + __SA__ + "  ";
await press(flowBox(), "Verify connection");
out.verify = posts().slice(1);
out.after = [toasts.slice(), renders];
""".replace("__SA__", json.dumps(_GCP_SA_EMAIL)))
    assert out["label"] == ["Cloud provider", "GCP project ID"]
    assert out["bad"] == [[("A GCP project ID is 6 to 30 characters: a lowercase letter, then lowercase letters, digits "
                            "or hyphens, with no trailing hyphen.")], 0]
    assert out["challenge"] == [["POST", "api/customer/connect/cloud/challenge",
                                 {"provider": "gcp", "account_id": "my-company-prod"}]]
    assert out["header"] == "Connect Google Cloud project my-company-prod"
    assert out["steps"] == _GCP_CHALLENGE["steps"]                      # the server's own steps, verbatim
    vals = {k: v for k, v in out["values"]}
    assert vals["Service account id"] == _GCP_SA_ID and vals["Service account email"] == _GCP_SA_EMAIL
    assert vals["Connector"] == _GCP_CONNECTOR_SA and vals["Role"] == "roles/iam.serviceAccountTokenCreator"
    assert [v for k, v in out["values"] if k == "gcloud"] == _GCP_CHALLENGE["gcloud"]
    assert out["verify"] == [["POST", "api/customer/connect/cloud/verify",
                              {"provider": "gcp", "account_id": "my-company-prod", "role_ref": _GCP_SA_EMAIL}]]
    assert out["after"] == [["GCP account my-company-prod connected (read-only)"], 1]


def test_connecting_azure_posts_azure_and_renders_the_consent_fields():
    out = _screen({"POST api/customer/connect/cloud/challenge": {"data": _AZURE_CHALLENGE},
                   "POST api/customer/connect/cloud/verify": {"data": {"provider": "azure", "account_id": _AZURE_TENANT,
                                                                       "access": "read-only"}}}, r"""
await press(tile("Cloud account"), "Connect a cloud account");
const prov = flowBox().querySelector("#connect-cloud-provider"); prov.value = "azure"; prov.dispatch("change");
out.label = flowBox().querySelectorAll("label").map(l => text(l));
flowBox().querySelector("#connect-cloud-account").value = "not-a-guid";
await press(flowBox(), "Continue");
out.bad = [errs.slice(), posts().length];
flowBox().querySelector("#connect-cloud-account").value = "  " + __T__ + "  ";
await press(flowBox(), "Continue");
out.challenge = posts().slice();
out.header = text(flowBox().querySelector("h3"));
out.steps = flowBox().querySelector("ol.cust-connect-steps").querySelectorAll("li").map(li => text(li));
out.href = flowBox().querySelector("a.cust-connect-link").getAttribute("href");
out.linkText = text(flowBox().querySelector("a.cust-connect-link"));
out.values = flowBox().querySelectorAll("div.cust-connect-copy").map(r => [text(r.querySelector("span.k")),
  r.querySelector("code") ? text(r.querySelector("code")) : null]);
flowBox().querySelector("#connect-cloud-role").value = "  " + __OID__ + "  ";
await press(flowBox(), "Verify connection");
out.verify = posts().slice(1);
out.after = [toasts.slice(), renders];
""".replace("__T__", json.dumps(_AZURE_TENANT)).replace("__OID__", json.dumps(_AZURE_OBJECT_ID)))
    assert out["label"] == ["Cloud provider", "Azure tenant ID (a GUID)"]
    assert out["bad"] == [[("An Azure tenant ID is a lowercase GUID, for example "
                            "00000000-0000-0000-0000-000000000000.")], 0]
    assert out["challenge"] == [["POST", "api/customer/connect/cloud/challenge",
                                 {"provider": "azure", "account_id": _AZURE_TENANT}]]
    assert out["header"] == "Connect Azure tenant " + _AZURE_TENANT
    assert out["steps"] == _AZURE_CHALLENGE["steps"]
    assert out["href"] == _AZURE_CHALLENGE["admin_consent_url"]         # admin_consent_url rendered as a link
    assert out["linkText"] == "Open the admin-consent page"
    vals = {k: v for k, v in out["values"] if v is not None}
    assert vals["Binding tag"] == "EXT-az_1" and vals["Application (client) ID"] == _AZURE_CLIENT
    assert vals["VIGIL reads"] == _AZURE_CHALLENGE["graph_read"]
    assert out["verify"] == [["POST", "api/customer/connect/cloud/verify",
                              {"provider": "azure", "account_id": _AZURE_TENANT, "role_ref": _AZURE_OBJECT_ID}]]
    assert out["after"] == [["Azure account " + _AZURE_TENANT + " connected (read-only)"], 1]


def test_connecting_cloudflare_posts_cloudflare_and_pastes_the_secret_token_once():
    secret = "cf-SECRET-tokenvalue-never-echoed-0001"
    out = _screen({"POST api/customer/connect/cloud/challenge": {"data": _CF_CHALLENGE},
                   "POST api/customer/connect/cloud/verify": {"data": {"provider": "cloudflare",
                                                                       "account_id": _CF_ACCOUNT,
                                                                       "access": "read-only"}}}, r"""
await press(tile("Cloud account"), "Connect a cloud account");
const prov = flowBox().querySelector("#connect-cloud-provider"); prov.value = "cloudflare"; prov.dispatch("change");
out.label = flowBox().querySelectorAll("label").map(l => text(l));
flowBox().querySelector("#connect-cloud-account").value = "NOTHEX";
await press(flowBox(), "Continue");
out.bad = [errs.slice(), posts().length];
flowBox().querySelector("#connect-cloud-account").value = "  " + __ACCT__ + "  ";
await press(flowBox(), "Continue");
out.challenge = posts().slice();
out.header = text(flowBox().querySelector("h3"));
out.steps = flowBox().querySelector("ol.cust-connect-steps").querySelectorAll("li").map(li => text(li));
const role = flowBox().querySelector("#connect-cloud-role");
out.inputType = role.getAttribute("type"); out.placeholder = role.getAttribute("placeholder");
out.copyRows = flowBox().querySelectorAll("div.cust-connect-copy").map(r => [text(r.querySelector("span.k")),
  text(r.querySelector("code"))]);
out.perm = flowBox().querySelector("div.cust-kv").querySelectorAll("span").map(text);
role.value = __SECRET__;
await press(flowBox(), "Verify connection");
out.verify = posts().slice(1);
out.after = [toasts.slice(), renders];
out.codes = flowBox().querySelectorAll("code").map(text);
""".replace("__ACCT__", json.dumps(_CF_ACCOUNT)).replace("__SECRET__", json.dumps(secret)))
    assert out["label"] == ["Cloud provider", "Cloudflare account ID (32 hex characters)"]
    assert out["bad"] == [["A Cloudflare account ID is 32 lowercase hexadecimal characters."], 0]
    assert out["challenge"] == [["POST", "api/customer/connect/cloud/challenge",
                                 {"provider": "cloudflare", "account_id": _CF_ACCOUNT}]]
    assert out["header"] == "Connect Cloudflare account " + _CF_ACCOUNT
    assert out["steps"] == _CF_CHALLENGE["steps"]
    assert out["inputType"] == "password" and out["placeholder"] is None   # a secret: masked, never pre-filled
    cr = {k: v for k, v in out["copyRows"]}
    assert cr["Token name"] == _CF_TOKEN_NAME and cr["Account"] == _CF_ACCOUNT
    assert out["perm"] == ["Permissions (read-only)", ", ".join(_CF_GROUPS)]
    # the SECRET token is submitted once through the existing connect POST as role_ref
    assert out["verify"] == [["POST", "api/customer/connect/cloud/verify",
                              {"provider": "cloudflare", "account_id": _CF_ACCOUNT, "role_ref": secret}]]
    assert out["after"] == [["Cloudflare account " + _CF_ACCOUNT + " connected (read-only)"], 1]
    # and NEVER echoed back: not in a toast, not in a rendered code cell
    assert secret not in " ".join(out["after"][0]) and secret not in " ".join(out["codes"])


_MULTI_OVERVIEW = {
    "org_id": "org_a", "available": _AV, "sites": [], "repos": [],
    "cloud": [{"provider": "gcp", "account_id": _GCP_PROJECT, "role_ref": _GCP_SA_EMAIL,
               "verified_at": 1.79e9, "expires_at": 1.8e9, "access": "read-only", "status": "connected"},
              {"provider": "azure", "account_id": _AZURE_TENANT, "role_ref": _AZURE_OBJECT_ID,
               "verified_at": 1.79e9, "expires_at": 1.8e9, "access": "read-only", "status": "connected"},
              {"provider": "cloudflare", "account_id": _CF_ACCOUNT, "role_ref": "fedcba9876543210fedcba9876543210",
               "verified_at": 1.6e9, "expires_at": 1.65e9, "access": "read-only", "status": "expired"}]}


def test_a_connected_non_aws_row_labels_and_renders_by_its_provider():
    out = _screen(server={"POST api/customer/connect/cloud/disconnect": {"data": {"disconnected": True}}},
                  overview=_MULTI_OVERVIEW, then=r"""
const acct = host => tile("Cloud account").querySelectorAll("div.cust-connect-acct")
  .filter(a => text(a.querySelector("span.host")) === host)[0];
out.rows = tile("Cloud account").querySelectorAll("div.cust-connect-acct").map(a => [
  text(a.querySelector("span.host")), text(a.querySelector("span.cust-badge")),
  a.querySelectorAll("div.cust-kv").map(k => k.querySelectorAll("span").map(text)), buttons(a)]);
await press(acct("GCP " + __P__), "Disconnect");
out.confirm = text(acct("GCP " + __P__).querySelector("div.cust-mon-actions"));
await press(acct("GCP " + __P__), "Disconnect");
out.sent = posts();
out.toasts = toasts.slice();
""".replace("__P__", json.dumps(_GCP_PROJECT)))
    assert out["rows"][0] == ["GCP " + _GCP_PROJECT, "✓ Connected (read-only)",
                              [["Service account", _GCP_SA_EMAIL], ["Valid until", "2027-01-15"]], ["Disconnect"]]
    assert out["rows"][1] == ["Azure " + _AZURE_TENANT, "✓ Connected (read-only)",
                              [["Enterprise app (Object ID)", _AZURE_OBJECT_ID], ["Valid until", "2027-01-15"]],
                              ["Disconnect"]]
    assert out["rows"][2] == ["Cloudflare " + _CF_ACCOUNT, "⚠ Expired — connect again",
                              [["API token ID", "fedcba9876543210fedcba9876543210"], ["Expired", "2022-04-15"]],
                              ["Connect again", "Disconnect"]]
    assert "Disconnect GCP " + _GCP_PROJECT + "?" in out["confirm"] and "remove it in GCP" in out["confirm"]
    assert out["sent"] == [["POST", "api/customer/connect/cloud/disconnect",
                            {"provider": "gcp", "account_id": _GCP_PROJECT}]]
    assert out["toasts"] == ["GCP account " + _GCP_PROJECT + " disconnected"]


@pytest.mark.parametrize("challenge, header, note, field", [
    (_GCP_CHALLENGE, "Connect Google Cloud project " + _GCP_PROJECT, "service-account id and external", _GCP_SA_ID),
    (_AZURE_CHALLENGE, "Connect Azure tenant " + _AZURE_TENANT, "admin-consent URL and the", _AZURE_CLIENT),
    (_CF_CHALLENGE, "Connect Cloudflare account " + _CF_ACCOUNT, "token name and account scope", _CF_TOKEN_NAME)])
def test_resuming_a_non_aws_connection_shows_that_providers_steps(challenge, header, note, field):
    resumed = dict(challenge, resumed=True)
    pending = {"org_id": "org_a", "available": _AV, "sites": [], "repos": [],
               "cloud": [{"provider": challenge["provider"], "account_id": challenge["account_id"],
                          "access": "read-only", "status": "pending"}]}
    out = _screen(server={"POST api/customer/connect/cloud/challenge": {"data": resumed}}, overview=pending, then=r"""
await press(tile("Cloud account").querySelectorAll("div.cust-connect-acct")[0], "Continue");
out.sent = posts();
out.header = text(flowBox().querySelector("h3"));
out.text = text(flowBox());
out.steps = flowBox().querySelector("ol.cust-connect-steps").querySelectorAll("li").length;
""")
    assert out["sent"] == [["POST", "api/customer/connect/cloud/challenge",
                            {"provider": challenge["provider"], "account_id": challenge["account_id"]}]]
    assert out["header"] == header                                      # the resumed steps label by provider
    assert note in out["text"] and field in out["text"]                # the resumed note + a real provider field
    assert out["steps"] == len(challenge["steps"])


def test_the_repo_tile_uses_the_code_screens_own_install():
    out = _screen(then=r"""
await press(tile("Code repository"), "Connect GitHub");
out.githubs = githubs; out.posts = posts().length;
await press(tile("Code repository"), "Open Code");
out.navs = navs;
""")
    assert out == {"githubs": ["Connect GitHub"], "posts": 0, "navs": ["#/code"]}


def test_a_refused_read_says_who_can_connect_and_a_sign_out_goes_to_sign_in():
    forbidden = {"status": 403, "data": {"error": "denied: requester may not view"}}
    out = _screen({"GET api/customer/connect": forbidden}, "out.text = text(root.querySelector('#connect-body'));")
    assert out["text"].startswith("Connecting assets is for the people who test in this workspace")
    out = _screen({"GET api/customer/connect": {"status": 401, "data": {"error": "login required"}}},
                  "out.navs = navs; out.refreshed = refreshed;")
    assert out == {"navs": ["#/login"], "refreshed": 1}


def test_the_connect_screens_copy_follows_the_product_rules():
    block = _connect_block(_src())
    blob = " ".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert not _COPY_FORBIDDEN.search(blob), _COPY_FORBIDDEN.search(blob).group(0)
    for sentence in re.split(r"(?<=[.!?])\s+", blob):            # an estimate is only ever mentioned to rule it out
        if re.search(r"estimat|quote|predict|price|cost", sentence, re.IGNORECASE):
            assert re.search(r"\bnever\b|\bno\b|\bnot\b", sentence, re.IGNORECASE), sentence
