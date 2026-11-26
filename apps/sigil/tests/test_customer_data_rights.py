"""Legal/governance S3 — the customer Data-rights screen, behind VIGIL_CUSTOMER_DATA_RIGHTS (default OFF).

The Data-rights screen is a #/data-rights settings sub-screen that states the customer's data rights in the EXISTING
published words of the Privacy notice and Terms of Service, names the owner-decided 30-day response SLA and the
data-subject contact (info@sigilsovereign.com), lets a customer EXPORT their OWN org's non-secret records (the same
tenant-scoped, redacted invoices / usage / findings reads the other screens use — no new authority, no mutation), and
RECORD a close-account / deletion request (one owner-signed append-only row in ui/data_rights_store, idempotent per
request_id; it does NOT auto-wipe the immutable spine — that is the owner-gated hard-prune / VAULT-PRUNE path).

Each test here is one S3 acceptance bullet:
  * Flag OFF: export/delete routes unregistered, byte-identical       -> test_1_flag_off_routes_404_page_byte_identical
  * Flag OFF: the EDGE's own 404, nothing relayed                     -> test_1b_flag_off_edge_answers_own_404
  * Flag ON, export assembles ONLY the requesting org's own data,
    tenant-scoped, IDOR-safe (another org's rows structurally absent) -> test_2_export_is_tenant_scoped_and_idor_safe
  * Export excludes all secret material; a role that may not read a
    section degrades honestly (never another role's data)            -> test_3_export_excludes_secrets_and_degrades_honestly
  * Delete/close request writes an owner-signed append-only record,
    idempotent per request_id; it does NOT auto-wipe the spine        -> test_4_request_is_signed_append_only_idempotent_off_spine
  * email_channel notify OFF by default; recorded regardless of send  -> test_5_email_notify_off_by_default_recorded_regardless
  * A request carries no role/money/authority, unlocks nothing        -> test_6_request_carries_no_authority
  * Request identity = session principal; a body account/org ignored  -> test_7_identity_is_session_principal_body_ignored
  * Export is rate-limited (the login/checkout limiter)               -> test_8_export_is_rate_limited
  * Flag ON over the real edge: the screen's reads resolve 401 (no
    session), the request route needs a session                      -> test_9_flag_on_routes_present_over_the_real_edge
  * The screen renders the rights + 30-day SLA + contact + actions,
    fires ONE read on arrival and writes nothing                     -> test_10_screen_renders_rights_sla_contact_and_actions
  * app.js / index.html wire the flag, route and screen script        -> test_11_app_wires_flag_route_and_screen_script
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from test_custui import _get, _opener, _post, _scrub_shared_owner_state, _stack  # noqa: F401 (autouse scrub)
from test_customer_team import _DOM, _need_node

from sigil import config
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair, owner_keypair, owner_pubkey
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import data_rights_store as store
from sigil.ui.custui import CustomerHandler, build_customer_server
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import Provisioner, ProvisionRateLimited, build_provisioner

FLAG = "VIGIL_CUSTOMER_DATA_RIGHTS"
APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
INDEX_HTML = APP / "index.html"
DATA_RIGHTS_JS = APP / "data_rights.js"
UI_JS = APP / "ui.js"
OWNER = generate_keypair()
OP = OWNER.public_key_b64


@pytest.fixture(autouse=True)
def _no_flag(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)


@pytest.fixture
def home(tmp_path, monkeypatch):
    d = tmp_path / "customer_data_rights"
    monkeypatch.setattr(config, "CUSTOMER_DATA_RIGHTS_DIR", d)
    return d


_iss = iter(range(1, 10_000_000))


# --- the full-stack signup helper (mirrors the settings-shell harness) ----------------------------------------------
def _signed_up(tmp_path, monkeypatch, email, org_name="Acme"):
    sov, edge, ep, sp = _stack(tmp_path, monkeypatch)
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    conf = _post(op, ep, "/api/customer/signup/confirm",
                 {"token": t, "password": "customer-pw-1", "org_name": org_name})
    assert conf[0] == 200, conf
    return sov, edge, ep, op, conf[1]


def _page_and_build(tmp_path):
    import http.client
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


def _edge_stub(session):
    """The edge's OWN handler, I/O stubbed: the session it sees and every hop RECORDED (an ``action`` in ``sent`` means
    the edge relayed)."""
    h = object.__new__(CustomerHandler)
    sent = {}
    h._session = lambda: session
    h._ip = lambda: "1.2.3.4"
    h._provision = lambda action, principal, body: (sent.update(action=action, principal=principal, body=body)
                                                     or (200, {"ok": True}))
    h._json = lambda obj, code=200: sent.update(code=code, out=obj)
    h._deny = lambda code=403, msg="forbidden": sent.update(code=code, out={"error": msg})
    return h, sent


# --- a provisioner over a real store, with two orgs + a distinguishable invoice each ---------------------------------
def _two_org_provisioner(monkeypatch, tmp_path, *, role_a="operator", role_b="operator"):
    monkeypatch.setattr(config, "LOGIN_RATELIMIT_DIR", tmp_path / "rl")   # isolate the shared lockout markers
    st = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    ensure_owner_keypair()
    orgs = OrgRegistry(st)
    orgs.create_org("org_a", "org_a", owner="u_a", issued_at=float(next(_iss)))
    orgs.grant_membership("org_a", "u_a", role_a, issued_at=float(next(_iss)))
    orgs.create_org("org_b", "org_b", owner="u_b", issued_at=float(next(_iss)))
    orgs.grant_membership("org_b", "u_b", role_b, issued_at=float(next(_iss)))
    inv = InvoiceRegistry(st, owner_key=owner_keypair(), trusted_pubkey=owner_pubkey())
    inv.record("org_a", invoice_id="INV-A", kind="topup", price_id="price_A", amount_minor=500, currency="usd",
               credits=50, issued_at=1700000000.0)
    inv.record("org_b", invoice_id="INV-B", kind="topup", price_id="price_B", amount_minor=900, currency="usd",
               credits=90, issued_at=1700000000.0)
    return build_provisioner(st), st


def _account_prov(sender=None, now=1.0):
    """A provisioner whose registries AND signed data-rights rows use the SAME (SIGIL_HOME) owner key — so a recorded
    row verifies under ``orgs.trusted_pubkey`` exactly as it does in production (``build_provisioner``). Returns
    ``(provisioner, trusted_pubkey, store)`` with one active customer ``cust_ana``."""
    ensure_owner_keypair()
    kp, pub = owner_keypair(), owner_pubkey()
    st = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(st, owner_key=kp, trusted_pubkey=pub)
    custs.create("a@acme.io", issued_at=1.0, password="password-xyz", username="cust_ana")
    p = Provisioner(
        st, customers=custs, orgs=OrgRegistry(st, owner_key=kp, trusted_pubkey=pub),
        wallet=WalletRegistry(st, owner_key=kp, trusted_pubkey=pub),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=sender if sender is not None else NullEmailSender(), trial_credits=100, now_fn=lambda: now)
    return p, pub, st


# =====================================================================================================================
# 1. Flag OFF: the three routes are unregistered (404), and the page is byte-identical bar the flag + build id
# =====================================================================================================================
def test_1_flag_off_routes_404_page_byte_identical(tmp_path, monkeypatch, home):
    sov, edge, ep, op, conf = _signed_up(tmp_path, monkeypatch, "off@acme.io")
    try:
        for who in (op, _opener()):
            assert _get(who, ep, "/api/customer/data-rights") == (404, {"error": "not found"})
            assert _get(who, ep, "/api/customer/data-rights/export") == (404, {"error": "not found"})
            assert _post(who, ep, "/api/customer/data-rights/request",
                         {"kind": "close_account", "request_id": "r1"}) == (404, {"error": "unknown action"})
        assert not home.exists()                                       # no store dir created with the flag off
    finally:
        sov.shutdown()
        edge.shutdown()
    off, build_off = _page_and_build(tmp_path / "a")
    assert 'data-data-rights="0"' in off and "__VIGIL_DATA_RIGHTS__" not in off
    monkeypatch.setenv(FLAG, "1")
    on, build_on = _page_and_build(tmp_path / "b")
    assert 'data-data-rights="1"' in on and build_on != build_off
    assert on.replace('data-data-rights="1"', 'data-data-rights="0"').replace(build_on, build_off) == off
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv(FLAG, v)
        assert 'data-data-rights="0"' in _page_and_build(tmp_path / f"c{v or 'empty'}")[0], v
    assert 'data-data-rights="__VIGIL_DATA_RIGHTS__"' in INDEX_HTML.read_text(encoding="utf-8")


# =====================================================================================================================
# 1b. Flag OFF: the EDGE itself refuses each verb and relays NOTHING (its own 404, independent of the cockpit gate)
# =====================================================================================================================
def test_1b_flag_off_edge_answers_own_404(monkeypatch):
    session = {"username": "cust_ana", "org_id": "org_a"}
    for value in (None, "0", "", "no", "off", "maybe"):
        if value is None:
            monkeypatch.delenv(FLAG, raising=False)
        else:
            monkeypatch.setenv(FLAG, value)
        h, sent = _edge_stub(session)
        h._dispatch("data-rights/request", {"kind": "close_account", "request_id": "r1", "username": "cust_eve"})
        assert sent == {"code": 404, "out": {"error": "unknown action"}}, value     # nothing relayed
        for path in ("/api/customer/data-rights", "/api/customer/data-rights/export"):
            h, sent = _edge_stub(session)
            h.path = path
            h.do_GET()
            assert sent == {"code": 404, "out": {"error": "not found"}}, (value, path)
    monkeypatch.setenv(FLAG, "1")                                       # positive control: flag on relays each verb
    h, sent = _edge_stub(session)
    h._dispatch("data-rights/request", {"kind": "close_account", "request_id": "r1"})
    assert (sent["action"], sent["principal"], sent["code"]) == ("data_rights_request", "cust_ana", 200)
    h, sent = _edge_stub(session)
    h.path = "/api/customer/data-rights"
    h.do_GET()
    assert (sent["action"], sent["principal"], sent["code"]) == ("data_rights_overview", "cust_ana", 200)


# =====================================================================================================================
# 2. Flag ON, export: assembles ONLY the requesting org's own records (tenant-scoped, IDOR-safe)
# =====================================================================================================================
def test_2_export_is_tenant_scoped_and_idor_safe(monkeypatch, tmp_path):
    monkeypatch.setenv(FLAG, "1")
    p, _st = _two_org_provisioner(monkeypatch, tmp_path)
    # u_a exports org_a: the invoices section carries org_a's OWN invoice, never org_b's
    ea = p.data_rights_export("u_a", "org_a")
    assert ea["ok"] is True and ea["org_id"] == "org_a"
    assert set(ea["export"]) == {"invoices", "usage", "findings"}
    blob = json.dumps(ea["export"])
    assert "INV-A" in blob and "price_A" in blob
    assert "INV-B" not in blob and "price_B" not in blob and "org_b" not in blob    # another org's rows absent
    # u_b exports org_b: mirror image
    eb = p.data_rights_export("u_b", "org_b")
    blobb = json.dumps(eb["export"])
    assert "INV-B" in blobb and "INV-A" not in blobb and "org_a" not in blobb
    # IDOR: u_a asking for org_b (not a member) gets EVERY section restricted — never another org's rows
    cross = p.data_rights_export("u_a", "org_b")
    assert cross["org_id"] == "org_b"
    assert all(sec == {"restricted": True} for sec in cross["export"].values()), cross["export"]
    assert "INV-B" not in json.dumps(cross["export"])


# =====================================================================================================================
# 3. Export excludes all secret material; a role that may not read a section degrades honestly
# =====================================================================================================================
def test_3_export_excludes_secrets_and_degrades_honestly(monkeypatch, tmp_path):
    monkeypatch.setenv(FLAG, "1")
    # org_admin may read invoices + usage (view_billing) but NOT findings (view_assessments): the findings section is an
    # honest {"restricted": true} marker, never another role's data.
    p, _st = _two_org_provisioner(monkeypatch, tmp_path, role_a="org_admin")
    ea = p.data_rights_export("u_a", "org_a")
    # org_admin may read invoices (view_billing/view_invoices) but NOT findings (view_assessments): the findings section
    # is an honest {"restricted": true} marker — never another role's data.
    assert ea["export"]["invoices"].get("restricted") is None and "INV-A" in json.dumps(ea["export"]["invoices"])
    assert ea["export"]["findings"] == {"restricted": True}
    # no secret material of any kind leaked into the export (mirrors the settings / report redaction); the signature
    # material of the invoice ledger is projected away by the customer-safe reads
    blob = json.dumps(ea["export"]).lower()        # scan the exported sections, not the screen's own note
    for secret in ("cred_hash", "cred_salt", "password", "api_key", "apikey", "fingerprint", "private_key",
                   "\"sig\"", "pubkey", "secret"):
        assert secret not in blob, secret
    assert "note" in ea and "no secret material" in ea["note"].lower()


# =====================================================================================================================
# 4. Delete/close request writes an owner-signed append-only record, idempotent per request_id, OFF the signed spine
# =====================================================================================================================
def test_4_request_is_signed_append_only_idempotent_off_spine(monkeypatch, tmp_path, home):
    monkeypatch.setenv(FLAG, "1")
    p, pub, st = _account_prov(now=1234.0)
    spine_before = st.count()
    r1 = p.data_rights_request("cust_ana", "org_a", kind="close_account", request_id="rid-1")
    assert r1["ok"] is True and r1["recorded"] is True and r1["sla_days"] == 30
    assert r1["request"]["kind"] == "close_account" and r1["request"]["request_id"] == "rid-1"
    assert "VAULT-PRUNE" in r1["note"] and "30 days" in r1["note"]
    # idempotent replay of the SAME request_id: a no-op, not a second row
    r2 = p.data_rights_request("cust_ana", "org_a", kind="close_account", request_id="rid-1")
    assert r2["recorded"] is False and r2["request"]["request_id"] == "rid-1"
    # the record is one owner-signed row, verifiable under the trusted owner pubkey, and NOT on the signed spine
    rows = store.list_requests("cust_ana", trusted_pubkey=pub)
    assert [x["request_id"] for x in rows] == ["rid-1"]
    assert store.list_requests("cust_ana", trusted_pubkey=generate_keypair().public_key_b64) == []   # verify-on-read
    assert st.count() == spine_before                                  # the hot signed spine is untouched (no audit row)


# =====================================================================================================================
# 5. email_channel notify is OFF by default (NullEmailSender); the request is recorded regardless of send success
# =====================================================================================================================
def test_5_email_notify_off_by_default_recorded_regardless(monkeypatch, tmp_path, home):
    monkeypatch.setenv(FLAG, "1")

    class _CapturingSender:
        def __init__(self, fail=False):
            self.sent = []
            self.fail = fail

        def send(self, to, subject, body):
            if self.fail:
                raise RuntimeError("smtp down")
            self.sent.append((to, subject, body))
            return True

    # default sender (NullEmailSender) sends nothing, yet the request is recorded
    p, pub, _st = _account_prov(NullEmailSender())
    assert p.data_rights_request("cust_ana", "org_a", kind="close_account", request_id="r1")["recorded"] is True
    assert store.list_requests("cust_ana", trusted_pubkey=pub)[0]["request_id"] == "r1"
    # a sender that RAISES does not undo the recorded request (best-effort notify)
    monkeypatch.setattr(config, "CUSTOMER_DATA_RIGHTS_DIR", tmp_path / "b")
    p2, pub2, _st2 = _account_prov(_CapturingSender(fail=True))
    assert p2.data_rights_request("cust_ana", "org_a", kind="close_account", request_id="r2")["recorded"] is True
    assert store.list_requests("cust_ana", trusted_pubkey=pub2)[0]["request_id"] == "r2"
    # an opted-in sender IS notified at the published contact, with the SLA in the message
    monkeypatch.setattr(config, "CUSTOMER_DATA_RIGHTS_DIR", tmp_path / "c")
    cap = _CapturingSender()
    p3, _pub3, _st3 = _account_prov(cap)
    p3.data_rights_request("cust_ana", "org_a", kind="close_account", request_id="r3")
    assert len(cap.sent) == 1 and cap.sent[0][0] == config.CUSTOMER_DATA_RIGHTS_CONTACT
    assert "30 days" in cap.sent[0][2]


# =====================================================================================================================
# 6. A data-rights request carries no role/money/authority and unlocks nothing by itself
# =====================================================================================================================
def test_6_request_carries_no_authority(monkeypatch, tmp_path, home):
    monkeypatch.setenv(FLAG, "1")
    p, pub, _st = _account_prov()
    r = p.data_rights_request("cust_ana", "org_a", kind="close_account", request_id="r1")
    # the answer names no role, credit, grant or authority — only the request, SLA and contact
    assert set(r) == {"ok", "recorded", "request", "sla_days", "contact", "note"}
    blob = json.dumps(r).lower()
    for forbidden in ("role", "grant", "credits", "token", "authority", "permission"):
        assert forbidden not in blob, forbidden
    # a bad kind is a plain refusal, nothing recorded
    from sigil.ui.provision import ProvisionError
    with pytest.raises(ProvisionError):
        p.data_rights_request("cust_ana", "org_a", kind="make_me_admin", request_id="r2")
    assert [x["request_id"] for x in store.list_requests("cust_ana", trusted_pubkey=pub)] == ["r1"]


# =====================================================================================================================
# 7. Request identity = session principal; a request-field account/org is ignored (end to end, over the real edge)
# =====================================================================================================================
def test_7_identity_is_session_principal_body_ignored(tmp_path, monkeypatch, home):
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setattr(config, "CUSTOMER_DATA_RIGHTS_DIR", home)
    sov, edge, ep, op, conf = _signed_up(tmp_path, monkeypatch, "own@acme.io")
    try:
        # a body that names ANOTHER account/org is ignored: the row is recorded for the SESSION principal + org
        c, r = _post(op, ep, "/api/customer/data-rights/request",
                     {"kind": "close_account", "request_id": "rid-1", "username": "cust_eve", "org_id": "org_evil"})
        assert c == 200 and r["recorded"] is True, (c, r)
        assert r["request"]["org_id"] == conf["org_id"]                 # the SESSION org, never the body's
        rows = store.list_requests(conf["username"], trusted_pubkey=owner_pubkey())
        assert [x["request_id"] for x in rows] == ["rid-1"]
        assert store.list_requests("cust_eve", trusted_pubkey=owner_pubkey()) == []   # nothing for the body's account
        # no session -> the request route needs sign-in (401), never records
        anon = _opener()
        assert _post(anon, ep, "/api/customer/data-rights/request",
                     {"kind": "close_account", "request_id": "rid-2"})[0] == 401
    finally:
        sov.shutdown()
        edge.shutdown()


# =====================================================================================================================
# 8. Export is rate-limited (reuses the existing login/checkout limiter)
# =====================================================================================================================
def test_8_export_is_rate_limited(monkeypatch, tmp_path, home):
    monkeypatch.setenv(FLAG, "1")
    st = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    p = Provisioner(
        st, customers=CustomerRegistry(st, owner_key=OWNER, trusted_pubkey=OP),
        orgs=OrgRegistry(st, owner_key=OWNER, trusted_pubkey=OP),
        wallet=WalletRegistry(st, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=3, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: 1.0)
    # the first three exports are admitted (the org is empty / not a member, so each section is restricted — the
    # rate-limit counts the ATTEMPT regardless); the fourth is locked out
    for _ in range(3):
        assert p.data_rights_export("u_x", "org_x", now=1.0)["ok"] is True
    with pytest.raises(ProvisionRateLimited):
        p.data_rights_export("u_x", "org_x", now=1.0)


# =====================================================================================================================
# 9. Flag ON over the REAL edge: the routes are PRESENT (401 without a session), never 404; off, they are absent
# =====================================================================================================================
def test_9_flag_on_routes_present_over_the_real_edge(tmp_path, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    sov, edge, ep, _sp = _stack(tmp_path / "on", monkeypatch)
    try:
        anon = _opener()
        for p in ("data-rights", "data-rights/export"):
            assert _get(anon, ep, "/api/customer/" + p)[0] == 401, p            # present, needs sign-in
        assert _post(anon, ep, "/api/customer/data-rights/request",
                     {"kind": "close_account", "request_id": "r"})[0] == 401
    finally:
        sov.shutdown()
        edge.shutdown()
    monkeypatch.delenv(FLAG, raising=False)
    sov, edge, ep, _sp = _stack(tmp_path / "off", monkeypatch)
    try:
        anon = _opener()
        for p in ("data-rights", "data-rights/export"):
            assert _get(anon, ep, "/api/customer/" + p)[0] == 404, p            # absent with the flag off
    finally:
        sov.shutdown()
        edge.shutdown()


# =====================================================================================================================
# 10. The screen renders the rights + 30-day SLA + contact + actions, fires ONE read on arrival and writes nothing
# =====================================================================================================================
def _node_render() -> dict:
    prog = _DOM + f"""
require({json.dumps(str(UI_JS))});
require({json.dumps(str(DATA_RIGHTS_JS))});
const calls = [];
const VUI = window.VUI;
VUI.getJSON = async p => {{ calls.push(["GET", p]);
  return {{ ok: true, sla_days: 30, contact: "info@sigilsovereign.com", requests: [] }}; }};
VUI.postJSON = async (p, b) => {{ calls.push(["POST", p, b]); return {{ ok: true }}; }};
VUI.toast = () => {{}};
const navs = []; function nav(r) {{ navs.push(r); }}
const root = new El("div"); document.body.appendChild(root);
const node = window.VIGIL_DATA_RIGHTS.viewDataRights({{ h: VUI.h, VUI: VUI, api: "api/customer", nav: nav,
  loading: t => VUI.h("p", {{ text: t }}) }});
VUI.mount(root, node);
await tick(); await tick();
out.calls = calls;
out.text = root.textContent;
out.buttons = buttons(root);
const exp = button(root, "Export my data"), del = button(root, "Request account deletion");
out.exportWired = !!(exp && exp.listeners.click && exp.listeners.click.length);
out.deleteWired = !!(del && del.listeners.click && del.listeners.click.length);
"""
    wrapped = ("const out = {};\n(async () => {\n" + prog + "\n})().then(() => process.stdout.write(JSON.stringify(out)),"
               " e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", wrapped], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_10_screen_renders_rights_sla_contact_and_actions():
    _need_node()
    out = _node_render()
    # it fires EXACTLY one read (the overview) on arrival, and writes nothing
    assert out["calls"] == [["GET", "api/customer/data-rights"]], out["calls"]
    # the rights are the EXISTING published words, quoted verbatim (never a reworded restatement)
    assert "You can ask us for access to, correction of, or deletion of your personal data" in out["text"]
    assert "you may ask us to close your account by contacting" in out["text"]
    assert "Your other data is not deleted automatically when the workspace closes" in out["text"]
    # the owner-decided SLA and the published contact
    assert "within 30 days" in out["text"] and "info@sigilsovereign.com" in out["text"]
    # the honest note about the immutable spine, not an instant erase
    assert "VAULT-PRUNE" in out["text"]
    # the two live action controls
    assert "Export my data" in out["buttons"] and "Request account deletion" in out["buttons"]
    assert out["exportWired"] is True and out["deleteWired"] is True


# =====================================================================================================================
# 11. app.js / index.html wire the flag, the route and the screen script (flag-guarded, so OFF adds no screen)
# =====================================================================================================================
def test_11_app_wires_flag_route_and_screen_script():
    html = INDEX_HTML.read_text(encoding="utf-8")
    assert 'data-data-rights="__VIGIL_DATA_RIGHTS__"' in html
    assert '<script src="data_rights.js"></script>' in html
    src = APP_JS.read_text(encoding="utf-8")
    assert 'var DATA_RIGHTS = window.VIGIL_DATA_RIGHTS;' in src
    assert 'var DATA_RIGHTS_ON = !!(DATA_RIGHTS && pageFlag("dataRights"));' in src
    assert ('(route !== "#/data-rights" || pageFlag("dataRights"))') in src
    assert ('    "#/data-rights": function () { return authed() ? (DATA_RIGHTS_ON ? viewDataRightsScreen()'
            ' : viewDashboard()) : viewLogin(); },') in src
    assert 'settingsLink("Data rights", "#/data-rights")' in src
    assert DATA_RIGHTS_JS.exists() and "window.VIGIL_DATA_RIGHTS" in DATA_RIGHTS_JS.read_text(encoding="utf-8")
