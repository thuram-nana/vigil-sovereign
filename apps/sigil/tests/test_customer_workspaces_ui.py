"""C-WS — the per-engagement WORKSPACES provisioner actions, the DEFAULT-OFF strict flag, the real edge→provisioner
hop (flag-off 404 + one flag-on happy path), the page-flag injection, and the SPA's screen gating.

Load-bearing, proven here (a false-green is a product defect — a workspace is the one place a run's work lives,
reachable only by its own tenant):

  * the flag is DEFAULT-OFF and STRICT (only an affirmative turns it on); with it off the provisioner actions
    refuse and the edge routes 404; the page is byte-identical to a build without the feature;
  * create-on-start is IDEMPOTENT, and the requester/org are the hop-bound SESSION (never a body field);
  * every action is admit_customer-gated: a billing-only org_admin is denied create (run_engagement) and read
    (view_assessments); an operator may create / list / get / rename / archive / export;
  * TENANT ISOLATION — a member of org A naming org B is refused (admit binds requester→org), and a workspace id
    of another org reads as not found within one's own org scope;
  * EXPORT is a portable owner-signed bundle that re-verifies;
  * the SPA shows the Workspaces screen (route + nav) ONLY while the flag is on, and the added code is CSP-clean.

The admit-gated / CRUD / isolation proofs run against a Provisioner built with an INJECTED owner keypair (the
deterministic pattern test_customer_knowledge uses) — not the shared-SIGIL_HOME edge stack, which carries a known
cross-test owner-key flake (test_customer_launch_ui / test_customer_monitoring_hop). Two SMALL edge tests still
exercise the real hop: the flag-off 404 (needs no session, so it does not flake) and one flag-on happy path.
"""
from __future__ import annotations

import itertools
import re
import tempfile
import time
from pathlib import Path

import pytest
from test_custui import _opener, _post, _scrub_shared_owner_state, _stack  # noqa: F401 (autouse scrub)
from test_customer_onboarding import _page_and_build

from sigil import config
from sigil.governor.customers import CustomerRegistry
from sigil.governor.engagement_workspaces import verify_export
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionError, Provisioner

FLAG = "VIGIL_CUSTOMER_WORKSPACES"
APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
INDEX_HTML = APP / "index.html"
_ISSUED = itertools.count(1)


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _prov(store, owner):
    """A Provisioner over ``store`` with an INJECTED owner keypair (deterministic — no shared-home key)."""
    return Provisioner(
        store, customers=CustomerRegistry(store, owner_key=owner), orgs=OrgRegistry(store, owner_key=owner),
        wallet=WalletRegistry(store, owner_key=owner), email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100)


def _org(p, org, members):
    p.orgs.create_org(org, org.upper(), owner="owner", issued_at=float(next(_ISSUED)))
    for user, role in members.items():
        p.orgs.grant_membership(org, user, role, issued_at=float(next(_ISSUED)))


# ============================================================================ the DEFAULT-OFF strict flag ===

def test_flag_is_off_by_default_when_unset(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    assert config.customer_workspaces_enabled() is False


def test_flag_is_strict_affirmative_only(monkeypatch):
    for v in ("1", "true", "TRUE", "yes", "on", "enabled"):
        monkeypatch.setenv(FLAG, v)
        assert config.customer_workspaces_enabled() is True, v
    for v in ("0", "false", "no", "off", "disabled", "", "garbage", "maybe"):
        monkeypatch.setenv(FLAG, v)
        assert config.customer_workspaces_enabled() is False, v


def test_cap_falls_back_to_the_default_on_junk(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_WORKSPACES_MAX_PER_ORG", raising=False)
    assert config.customer_workspaces_max_per_org() == 100
    monkeypatch.setenv("VIGIL_CUSTOMER_WORKSPACES_MAX_PER_ORG", "7")
    assert config.customer_workspaces_max_per_org() == 7
    for v in ("0", "-1", "nope", "99999999"):
        monkeypatch.setenv("VIGIL_CUSTOMER_WORKSPACES_MAX_PER_ORG", v)
        assert config.customer_workspaces_max_per_org() == 100, v


# ========================================================== the provisioner actions (deterministic, injected key) ===

def test_actions_refuse_when_the_flag_is_off(monkeypatch):
    monkeypatch.setenv(FLAG, "0")                            # explicit off
    p = _prov(_store(), ensure_owner_keypair())
    _org(p, "acme", {"olive": "operator"})
    for call in (
        lambda: p.customer_workspace_ensure("olive", "acme", "e1", "t"),
        lambda: p.customer_workspaces_list("olive", "acme"),
        lambda: p.customer_workspace_get("olive", "acme", "ws_" + "0" * 40),
        lambda: p.customer_workspace_rename("olive", "acme", "ws_" + "0" * 40, "t"),
        lambda: p.customer_workspace_archive("olive", "acme", "ws_" + "0" * 40),
        lambda: p.customer_workspace_export("olive", "acme", "ws_" + "0" * 40),
    ):
        with pytest.raises(ProvisionDenied, match="not enabled"):
            call()


def test_create_on_start_is_idempotent(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    s = _store()
    p = _prov(s, ensure_owner_keypair())
    _org(p, "acme", {"olive": "operator"})
    from sigil.governor.engagement_workspaces import WORKSPACE_SIGNAL

    def _ws_records():
        return sum(1 for r in s.iter_records()
                   if isinstance(r.payload, dict) and r.payload.get("signal") == WORKSPACE_SIGNAL)
    r1 = p.customer_workspace_ensure("olive", "acme", "scan.example.com", "Acme scan")
    assert r1["created"] is True and r1["announcement"] == "Created workspace: Acme scan"
    wid = r1["workspace"]["workspace_id"]
    n = _ws_records()
    r2 = p.customer_workspace_ensure("olive", "acme", "scan.example.com", "A DIFFERENT TITLE")
    assert r2["created"] is False and r2["workspace"]["workspace_id"] == wid
    assert r2["workspace"]["title"] == "Acme scan"                        # not re-titled
    assert _ws_records() == n                                             # and NO new workspace grant appended
    assert p.customer_workspaces_list("olive", "acme")["workspaces"][0]["workspace_id"] == wid


def test_ensure_rename_archive_require_run_engagement_reads_require_view_assessments(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    p = _prov(_store(), ensure_owner_keypair())
    _org(p, "acme", {"adam": "org_admin", "olive": "operator"})       # org_admin = billing only
    with pytest.raises(ProvisionDenied, match="run_engagement"):
        p.customer_workspace_ensure("adam", "acme", "e1", "t")
    with pytest.raises(ProvisionDenied, match="view_assessments"):
        p.customer_workspaces_list("adam", "acme")
    # a non-member holds nothing
    with pytest.raises(ProvisionDenied):
        p.customer_workspaces_list("nobody", "acme")
    # the operator can create, then a billing admin cannot rename/archive it
    wid = p.customer_workspace_ensure("olive", "acme", "e1", "t")["workspace"]["workspace_id"]
    with pytest.raises(ProvisionDenied, match="run_engagement"):
        p.customer_workspace_rename("adam", "acme", wid, "x")
    with pytest.raises(ProvisionDenied, match="run_engagement"):
        p.customer_workspace_archive("adam", "acme", wid)
    with pytest.raises(ProvisionDenied, match="view_assessments"):
        p.customer_workspace_export("adam", "acme", wid)


def test_get_rename_archive_export_round_trip(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    owner = ensure_owner_keypair()
    p = _prov(_store(), owner)
    _org(p, "acme", {"olive": "operator"})
    wid = p.customer_workspace_ensure("olive", "acme", "e1", "WS one")["workspace"]["workspace_id"]
    got = p.customer_workspace_get("olive", "acme", wid)
    assert got["workspace"]["workspace_id"] == wid
    assert {ref["kind"] for ref in got["references"]} >= {"transcript", "findings", "evidence", "launch"}
    assert p.customer_workspace_rename("olive", "acme", wid, "WS renamed")["workspace"]["title"] == "WS renamed"
    # export: owner-signed, re-verifies under the deployment owner key, tamper fails
    bundle = p.customer_workspace_export("olive", "acme", wid)["bundle"]
    assert verify_export(bundle, owner.public_key_b64) is True
    bundle["manifest"]["workspace"]["title"] = "TAMPERED"
    assert verify_export(bundle, owner.public_key_b64) is False
    # archive: still listed + gettable, status archived; rename then refused
    assert p.customer_workspace_archive("olive", "acme", wid)["workspace"]["status"] == "archived"
    assert p.customer_workspace_get("olive", "acme", wid)["workspace"]["status"] == "archived"
    with pytest.raises(ProvisionDenied, match="archived"):
        p.customer_workspace_rename("olive", "acme", wid, "x")


def test_tenant_isolation_a_member_of_a_cannot_touch_b(monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    p = _prov(_store(), ensure_owner_keypair())
    _org(p, "acme", {"olive": "operator"})
    _org(p, "globex", {"greg": "operator"})
    wid_a = p.customer_workspace_ensure("olive", "acme", "e1", "Acme WS")["workspace"]["workspace_id"]
    p.customer_workspace_ensure("greg", "globex", "e9", "Globex WS")
    # olive naming globex is refused outright (admit binds requester->org, no cross-tenant read)
    with pytest.raises(ProvisionDenied):
        p.customer_workspaces_list("olive", "globex")
    # greg (globex) cannot get/rename/export acme's workspace id within his OWN org scope — it reads as not found
    with pytest.raises(ProvisionError, match="no such workspace"):
        p.customer_workspace_get("greg", "globex", wid_a)
    with pytest.raises(ProvisionDenied, match="no such workspace"):
        p.customer_workspace_rename("greg", "globex", wid_a, "pwn")
    # each org's list shows only its own
    assert [w["title"] for w in p.customer_workspaces_list("olive", "acme")["workspaces"]] == ["Acme WS"]
    assert [w["title"] for w in p.customer_workspaces_list("greg", "globex")["workspaces"]] == ["Globex WS"]
    # acme's workspace is untouched
    assert p.customer_workspace_get("olive", "acme", wid_a)["workspace"]["status"] == "active"


def test_body_org_is_never_trusted_the_requester_org_is_authoritative(monkeypatch):
    """The provisioner takes requester + org as positional args from the hop-bound session; there is no body
    org field here at all. A member of acme can only ever act on acme (admit binds the pair)."""
    monkeypatch.setenv(FLAG, "1")
    p = _prov(_store(), ensure_owner_keypair())
    _org(p, "acme", {"olive": "operator"})
    out = p.customer_workspace_ensure("olive", "acme", "e1", "WS")
    assert out["org_id"] == "acme"


# ================================================================================= the page-flag injection ===

def test_the_edge_writes_the_workspaces_flag_into_the_page(tmp_path, monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-workspaces="0"' in off and "__VIGIL_WORKSPACES__" not in off
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-workspaces="1"' in on and build_on != build_off
    # flag OFF is byte-identical to flag ON but for the one attribute value and the build id (nothing else moves)
    assert on.replace('data-workspaces="1"', 'data-workspaces="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv(FLAG, v)
        assert 'data-workspaces="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v


def test_index_html_carries_the_workspaces_dataset():
    assert 'data-workspaces="__VIGIL_WORKSPACES__"' in INDEX_HTML.read_text(encoding="utf-8")


# =============================================================== the real edge hop: flag-off 404 + happy path ===

def _get(opener, port, path):
    import json
    import urllib.error
    import urllib.request
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    try:
        with opener.open(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except ValueError:
            return e.code, None


def test_flag_off_routes_are_absent_over_the_edge(tmp_path, monkeypatch):
    """Flag OFF (default): every workspace route/action is an unknown route/action -> 404, with NO session needed
    (so this edge test does not touch the flaky signup path)."""
    monkeypatch.delenv(FLAG, raising=False)
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        assert _get(op, ep, "/api/customer/workspaces")[0] == 404
        assert _get(op, ep, "/api/customer/workspace?id=ws_" + "0" * 40)[0] == 404
        for action in ("ensure", "rename", "archive", "export"):
            assert _post(op, ep, f"/api/customer/workspace/{action}", {"workspace_id": "x"})[0] == 404
    finally:
        sov.shutdown(); edge.shutdown()


def test_flag_on_happy_path_over_the_edge(tmp_path, monkeypatch):
    """One end-to-end pass over the real custui->server->provisioner hop: a signed-in operator creates a workspace
    (idempotent) and lists it, the org coming from the SESSION. Shares the documented shared-SIGIL_HOME owner-key
    flake with test_customer_launch_ui; re-run once if it flakes (the deterministic proofs are the provisioner
    tests above)."""
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "ws@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        OrgRegistry(sov.store()).grant_membership(conf["org_id"], conf["username"], "operator",
                                                  issued_at=time.time() + 1e6)
        c, r = _post(op, ep, "/api/customer/workspace/ensure", {"engagement_id": "e1", "title": "WS", "org_id": "EVIL"})
        assert c == 200 and r["created"] is True and r["org_id"] != "EVIL"      # body org ignored; session org wins
        wid = r["workspace"]["workspace_id"]
        assert _post(op, ep, "/api/customer/workspace/ensure", {"engagement_id": "e1"})[1]["created"] is False
        c, lst = _get(op, ep, "/api/customer/workspaces")
        assert c == 200 and [w["workspace_id"] for w in lst["workspaces"]] == [wid]
        # no-session is refused before the hop
        assert _get(_opener(), ep, "/api/customer/workspaces")[0] == 401
    finally:
        sov.shutdown(); edge.shutdown()


# ========================================================================= the SPA: gated screen, CSP-clean ===

def test_app_js_gates_the_workspaces_screen_on_the_flag():
    src = _src()
    assert 'var WORKSPACES_ON = pageFlag("workspaces");' in src
    assert "function viewWorkspaces(" in src
    # dispatched by the render() hook (NOT a ROUTES entry / navLink / routeShown clause — so the guide census and the
    # shared route+nav structures stay byte-identical), gated on the flag, login-guarded, home-screening when off.
    assert 'WORKSPACES_ON && key === "#/workspaces"' in src
    assert "? (authed() ? viewWorkspaces : viewLogin)" in src


def test_app_js_leaves_the_shared_route_and_nav_structures_untouched():
    """C-WS must NOT add a ROUTES entry, a navLink, or a routeShown clause for #/workspaces — those feed the guide
    census and the flag-stubbed node tests that the parallel chat-continuity build owns. The screen is reached only
    via the render() hook, so these shared structures stay byte-identical (no collision, census intact)."""
    src = _src()
    assert '"#/workspaces": function' not in src                      # no ROUTES-table entry
    assert 'navLink("Workspaces"' not in src                          # no sidebar nav link
    assert '"#/workspaces" || WORKSPACES_ON' not in src               # no routeShown clause


# The same banned-token set the repo's canonical CSP scan uses (test_customer_security_ui): inline handlers, HTML
# string sinks, eval-family, inline styles and per-viewer storage. The added code must contain none of them.
_BANNED = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "html:",
           'setAttribute("on', "setAttribute('on", ".onclick", "onclick=", 'setAttribute("style"', "style:",
           "cssText", "localStorage", "sessionStorage", "indexedDB", "document.cookie")


def test_workspaces_additions_are_csp_clean_no_inline_handlers():
    """The added code wires every handler with addEventListener (CSP-safe) — NEVER an inline handler, HTML string
    sink, eval, inline style or per-viewer storage. Scanned against the repo's banned-token set over the block."""
    src = _src()
    start = src.index("function wsStatusLabel(")
    end = src.index("// ---- router", start)
    block = src[start:end]
    for banned in _BANNED:
        assert banned not in block, banned
    assert 'addEventListener("click"' in block                            # the buttons ARE wired, the allowed way
    assert "http://" not in block and "https://" not in block             # only its own relative API
