"""C1a — launching and controlling an assessment from the customer app: the read, its gates, and the SPA.

What this pins:
  * KEPT RESERVATIONS: ``launch_reserve`` keeps the signed lease (flag on) so the app can start / cancel it after a
    reload; ``launch_start`` and ``launch_cancel`` forget it. Off: nothing is kept.
  * THE READ (``customer_launches`` / ``ui.customer_launches.launches``): a reserved launch, a running one, a paused
    one (over the real seam, real reserve → start → pause → resume → cancel), with the actions the server would accept
    and the signed lease only for a member who may run assessments; a settled launch is never active; finished
    launches come from the settle-drain outcomes; the depth and the launch choices never carry a credit / unit amount.
  * IDOR: the read is the SESSION org's only — another org's seam lease and another org's kept file are structurally
    unreachable, and a lease that does not verify under the owner key is dropped.
  * FLAG-GATED: the edge route, the cockpit dispatch and the provisioner read are all absent while the flag is off.
  * THE SPA (executed under node): the depth picker shows no number, the buttons match the server's actions per state,
    Cancel confirms in the page, the step-up message is shown, the poll stops when the screen is left or hidden, every
    refusal is mapped to fixed copy — and with the flag off the Assessments view is byte-identical to the base build.
  * THE GUIDE's launch / follow steps name the real labels.

The provisioner-level tests run with the integration PYTHONPATH (the seam + add_customer_target live across it),
mirroring ``test_launch_pause_resume_actions.py``; the edge tests use the real hop (``test_custui`` helpers).
"""
from __future__ import annotations

import itertools
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME owner state pristine)

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
APP_JS = APP / "app.js"
GUIDE_JS = APP / "guide.js"
UI_JS = APP / "ui.js"
BASE_REF = "427e4909"            # the base of this branch: the pre-C1a Assessments view, for the byte-identical proof

_iss = itertools.count(1)
_RESERVED_AT = 2000.0
_IN_WINDOW = 2500.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    from sigil import config
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    # CUSTOMER_LAUNCHES_DIR is bound at import, so isolate it per test (the slug is a deterministic hash of
    # (org, host), so tests reusing org_a/apme.cm would otherwise share one kept-launch file).
    monkeypatch.setattr(config, "CUSTOMER_LAUNCHES_DIR", Path(tempfile.mkdtemp()) / "launches")
    monkeypatch.setenv("VIGIL_CUSTOMER_LAUNCH_UI", "1")
    # VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED is now DEFAULT-ON, so FORCE it off here (the explicit =0 override) to keep
    # this file's pause-off baseline; the tests that exercise pause/resume set it to "1" themselves afterward.
    monkeypatch.setenv("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED", "0")
    for v in ("VIGIL_TIERED_PRODUCTS", "VIGIL_TRIAL_PRODUCT_ID",
              "VIGIL_TRIAL_PREVIEW_ENABLED", "VIGIL_METERED_BILLING", "VIGIL_ONE_LAUNCH_PER_HOST"):
        monkeypatch.delenv(v, raising=False)


# --------------------------------------------------------------------------- the provisioner + the seam ----
def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _setup(store, org, host, *, role="operator", credits=100, now=1000.0):
    """Seat a member + wallet credits + ownership proof + a minted EngagementAuthority (copied from
    test_launch_pause_resume_actions) — enough for reserve_launch to mint a verifiable lease on ``host``."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.target_authorization import add_customer_target
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    if orgs.org(org) is None:
        orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", role, issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}:{next(_iss)}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=now)["ok"]


def _prov(store):
    from sigil.ui.provision import build_provisioner
    return build_provisioner(store)


def _reserve(p, org="org_a", host="apme.cm"):
    r = p.launch_reserve("u", org, host, now=_RESERVED_AT)
    return r["lease"], r["slug"], r["nonce"]


def _launches(p, org="org_a", requester="u", now=_IN_WINDOW):
    return p.customer_launches(requester, org, now=now)


def test_reserve_keeps_the_lease_start_and_cancel_forget_it(monkeypatch):
    from sigil.ui import customer_launches as cl
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    lease, slug, nonce = _reserve(p)
    # kept: the read lists it as reserved with Start + Cancel and the signed lease to present
    row = next(l for l in _launches(p)["launches"] if l["slug"] == slug)
    assert row["state"] == "reserved" and row["actions"] == ["start", "cancel"] and row["launch"] == nonce
    assert row["lease"]["document"]["nonce"] == nonce
    assert cl._load("org_a", slug), "the lease was kept for the app"
    # start: forgotten (the seam holds it now) and the read shows it running
    assert p.launch_start("u", "org_a", lease, now=_IN_WINDOW)["slug"] == slug
    assert not cl._load("org_a", slug)
    run = next(l for l in _launches(p)["launches"] if l["slug"] == slug)
    assert run["state"] == "running"
    # a second reserve (cancel it) is kept then forgotten on cancel
    lease2, slug2, _n2 = _reserve(p, host="apme.cm")           # same host → same slug, new nonce
    assert cl._load("org_a", slug2)
    assert p.launch_cancel("u", "org_a", lease2)["refunded"] >= 0
    assert not any(cl._load("org_a", slug2))


def test_reserve_keeps_nothing_when_the_flag_is_off(monkeypatch):
    from sigil.ui import customer_launches as cl
    monkeypatch.setenv("VIGIL_CUSTOMER_LAUNCH_UI", "0")
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    _lease, slug, _n = _reserve(p)
    assert cl._load("org_a", slug) == []                        # nothing kept
    from sigil.ui.provision import ProvisionDenied
    with pytest.raises(ProvisionDenied, match="not enabled"):   # and the read is absent
        _launches(p)


def test_reserve_start_pause_resume_cancel_over_the_seam(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED", "1")
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    lease, slug, nonce = _reserve(p)
    assert p.launch_start("u", "org_a", lease, now=_IN_WINDOW)["slug"] == slug
    assert [l["actions"] for l in _launches(p)["launches"] if l["slug"] == slug] == [["pause"]]
    assert p.launch_pause("u", "org_a", lease, now=_IN_WINDOW) == {"slug": slug, "nonce": nonce}
    paused = next(l for l in _launches(p)["launches"] if l["slug"] == slug)
    assert paused["state"] == "paused" and paused["actions"] == ["resume"]
    assert p.launch_resume("u", "org_a", lease, now=_IN_WINDOW)["slug"] == slug
    assert next(l for l in _launches(p)["launches"] if l["slug"] == slug)["state"] == "running"
    # a settled launch is never active (a started launch settles through its completion, not a customer cancel —
    # settle it directly here to prove the read drops it once the seam settlement marker is written)
    from sigil.ui.launch_gate import LaunchGate
    assert LaunchGate(s).settle_launch(signed_lease=lease, consumed_units=0, now=3000.0, expect_org_id="org_a")["ok"]
    assert not any(l["slug"] == slug for l in _launches(p)["launches"])


def test_pause_resume_actions_absent_until_the_flag_is_on(monkeypatch):
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    lease, slug, _n = _reserve(p)
    assert p.launch_start("u", "org_a", lease, now=_IN_WINDOW)["slug"] == slug
    d = _launches(p)
    assert d["pause_resume"] is False
    assert next(l for l in d["launches"] if l["slug"] == slug)["actions"] == []   # running, but no pause offered


def test_finished_launches_come_from_the_settle_outcomes():
    from sigil.ui.target_authorization import _customer_slug
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    slug = _customer_slug("org_a", "apme.cm")
    s.append(kind="assessment_outcome", source="settle", actor="X",
             payload={"engagement_slug": slug, "org_id": "org_a", "outcome": "completed", "nonce": "n9", "ts": 50.0})
    fin = _launches(p)["finished"]
    assert fin and fin[0]["slug"] == slug and fin[0]["state"] == "completed" and fin[0]["host"] == "apme.cm"


def test_a_lapsed_proof_still_lists_a_running_launch(monkeypatch):
    # a proof can expire WHILE an assessment runs; the launch stays controllable (ever_proven_hosts).
    from sigil.governor.asset_ownership import AssetOwnershipRegistry
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    lease, slug, _n = _reserve(p)
    assert p.launch_start("u", "org_a", lease, now=_IN_WINDOW)["slug"] == slug
    AssetOwnershipRegistry(s).revoke_proof("org_a", "apme.cm")      # the proof lapses mid-run
    assert "apme.cm" not in AssetOwnershipRegistry(s).proven_hosts("org_a", now=_IN_WINDOW)
    assert next(l for l in _launches(p)["launches"] if l["slug"] == slug)["state"] == "running"


def _pub(store):
    from sigil.governor.orgs import OrgRegistry
    return OrgRegistry(store).trusted_pubkey


def test_the_read_is_denied_to_a_billing_role(monkeypatch):
    # the read is gated on view_assessments (testing-domain): a demoted member cannot read it at all.
    from sigil.governor.orgs import OrgRegistry
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    _reserve(p)
    assert _launches(p)["launches"]                                  # operator: readable
    OrgRegistry(s).grant_membership("org_a", "u", "analyst", issued_at=float(next(_iss)))
    from sigil.ui.provision import ProvisionDenied
    with pytest.raises(ProvisionDenied):
        _launches(p)


def test_the_projector_gates_actions_choices_and_lease_on_control(monkeypatch):
    # The projector itself: without run_engagement (control=False) a launch carries NO actions and NO signed lease,
    # and NO launch choices are offered — even though the read was permitted (defense-in-depth: the read gate is
    # view_assessments, the control gate is run_engagement). With control=True they are all present.
    from sigil.ui import customer_launches as cl
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    _reserve(p)
    kw = dict(now=_IN_WINDOW, trusted_pubkey=_pub(s), pause_resume=False,
              choices=[{"product_id": "", "depth": None}])
    no = cl.launches(s, "org_a", control=False, **kw)
    yes = cl.launches(s, "org_a", control=True, **kw)
    assert no["launches"] and no["choices"] == []
    row = no["launches"][0]
    assert row["actions"] == [] and "lease" not in row and row["state"] == "reserved"
    ctrl = yes["launches"][0]
    assert ctrl["actions"] == ["start", "cancel"] and "lease" in ctrl and yes["choices"]


def test_a_reserved_launch_past_its_window_offers_only_cancel(monkeypatch):
    # read past not_after: a reserved launch can no longer start (Cancel only), and says so.
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    _lease, slug, _n = _reserve(p)                                   # 8h window from 2000 → not_after 30800
    row = next(l for l in _launches(p, now=40000.0)["launches"] if l["slug"] == slug)
    assert row["state"] == "reserved" and row["expired"] is True and row["actions"] == ["cancel"]
    # in-window it still offers start
    assert next(l for l in _launches(p, now=_IN_WINDOW)["launches"] if l["slug"] == slug)["actions"] == ["start", "cancel"]


def test_a_settled_lease_still_on_the_seam_is_not_active(monkeypatch):
    # the is_lease_settled guard is the belt-and-braces for a settled launch whose lease is still on the seam (its
    # settlement marker was written before the tombstone; a crash between leaves the lease there). Simulate it: start
    # (lease on the seam) then write the settlement marker WITHOUT settling (no tombstone) — the read must drop it.
    from vigil_integration.live.credit_lease_broker import read_credit_lease, record_lease_settlement
    from vigil_core.seam_base import resolve_seam_base
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    lease, slug, nonce = _reserve(p)
    assert p.launch_start("u", "org_a", lease, now=_IN_WINDOW)["slug"] == slug
    base = resolve_seam_base()
    assert read_credit_lease(base, slug) is not None                # the lease is on the seam
    record_lease_settlement(base, slug, nonce)                      # marker set, lease NOT tombstoned
    assert read_credit_lease(base, slug) is not None                # still on the seam
    assert not any(l["slug"] == slug for l in _launches(p)["launches"])   # yet never shown active


def test_choices_never_carry_a_number(monkeypatch):
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    _reserve(p)
    d = _launches(p)
    ids = {c["product_id"] for c in d["choices"]}
    assert ids == {"vigil_launch_quick", "vigil_launch_deep"}
    for c in d["choices"]:
        assert set(c) == {"product_id", "depth"} and c["depth"] in ("quick", "deep")   # product + depth, NO units
        assert "units" not in c and "credits" not in c
    # flat (no tiered products): one default choice with no depth
    monkeypatch.delenv("VIGIL_TIERED_PRODUCTS")
    assert _launches(p)["choices"] == [{"product_id": "", "depth": None}]


def test_a_locked_trial_org_is_offered_only_the_trial_product(monkeypatch):
    # a trial-preview org that has not bought credits is offered ONLY the trial product (every other launch is refused
    # by _trial_launch_check), so Launch must not show the others.
    from sigil.governor.wallet import WalletRegistry
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")
    monkeypatch.setenv("VIGIL_TRIAL_PRODUCT_ID", "vigil_launch_quick")
    s = _store()
    _setup(s, "org_a", "apme.cm")
    WalletRegistry(s).grant("org_a", 450, "trial", entry_id="trial-preview:org_a", issued_at=float(next(_iss)))
    p = _prov(s)
    assert p._preview_locked("org_a")
    assert p._launch_choices("org_a") == [{"product_id": "vigil_launch_quick", "depth": "quick"}]
    # unlocked (a purchase): both depths return
    WalletRegistry(s).grant("org_a", 50, "topup", entry_id="topup:org_a", source_ref="pay", issued_at=float(next(_iss)))
    from sigil.governor.report_unlock import ReportUnlockRegistry
    ReportUnlockRegistry(s).unlock("org_a", "topup", source_ref="pay", issued_at=float(next(_iss)))
    assert {c["product_id"] for c in p._launch_choices("org_a")} == {"vigil_launch_quick", "vigil_launch_deep"}


def test_the_read_is_the_session_orgs_only_idor(monkeypatch):
    # org A's read never shows org B's launch — not its seam lease, not a file planted for A under B's slug.
    s = _store()
    _setup(s, "org_a", "apme.cm")
    _setup(s, "org_b", "bpme.cm")
    p = _prov(s)
    la, sa, _na = _reserve(p, org="org_a", host="apme.cm")
    lb, sb, _nb = _reserve(p, org="org_b", host="bpme.cm")
    assert p.launch_start("u", "org_b", lb, now=_IN_WINDOW)["slug"] == sb        # B's launch is running on the seam
    slugs_a = {l["slug"] for l in _launches(p, org="org_a")["launches"]}
    assert sa in slugs_a and sb not in slugs_a                                   # A sees only A's
    # plant B's signed lease into A's OWN kept file (under A's own slug sa): the read loads it for A, re-binds it and
    # drops it — B's launch (nonce _nb) never surfaces for A.
    from sigil.ui import customer_launches as cl
    nb = lb["document"]["nonce"]
    cl._save("org_a", sa, [{"lease": lb, "at": 1.0}])
    assert nb not in {l["launch"] for l in _launches(p, org="org_a")["launches"]}


def test_a_lease_that_does_not_verify_is_dropped(monkeypatch):
    # a kept file whose lease is for this org+slug but signed by a DIFFERENT owner key is not surfaced.
    from sigil.ui import customer_launches as cl
    from sigil.ui.target_authorization import _customer_slug
    from vigil_core import CreditLaunchLease, sign_credit_launch_lease
    from sigil.reuse import generate_keypair
    from datetime import datetime, timedelta, timezone
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    slug = _customer_slug("org_a", "apme.cm")
    t = datetime.fromtimestamp(_RESERVED_AT, tz=timezone.utc)
    forged = CreditLaunchLease(engagement_slug=slug, org_id="org_a", scope_host="apme.cm", units_reserved=5,
                               not_before=t, not_after=t + timedelta(hours=8), nonce="forged", issued_at=_RESERVED_AT)
    signed = sign_credit_launch_lease(forged, {"owner": generate_keypair().private_key_b64}).model_dump(mode="json")
    cl._save("org_a", slug, [{"lease": signed, "at": 1.0}])
    assert not any(l["launch"] == "forged" for l in _launches(p)["launches"])


# --------------------------------------------------------------------------- the edge route + the hop ----
def _need_node() -> str:
    node = shutil.which("node")
    if node is None:
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                or (os.environ.get("VIGIL_REQUIRE_NODE") or "").strip().lower() in {"1", "true", "yes", "on"}):
            pytest.fail("node is required here (CI or VIGIL_REQUIRE_NODE) but is not on PATH")
        pytest.skip("node not installed")
    return node


def test_the_launches_route_is_flag_gated_and_session_scoped():
    from sigil.ui import custui, server
    import inspect
    esrc = inspect.getsource(custui)
    assert 'if path == "/api/customer/launches" and _launch_ui_on():' in esrc
    assert '_customer_read_relay("launch_list")' in esrc           # org from the SERVER-side session, never a query
    ssrc = inspect.getsource(server)
    i = ssrc.index('if action == "launch_list":')
    assert "customer_launch_ui_enabled()" in ssrc[i:i + 300] and "return None" in ssrc[i:i + 300]


def test_launches_route_requires_a_session_and_is_404_when_off(tmp_path, monkeypatch):
    from test_custui import _get, _opener, _post, _stack
    monkeypatch.setenv("VIGIL_CUSTOMER_LAUNCH_UI", "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        assert _get(_opener(), ep, "/api/customer/launches")[0] == 401     # flag on, no session → refused before the hop
    finally:
        sov.shutdown(); edge.shutdown()
    monkeypatch.setenv("VIGIL_CUSTOMER_LAUNCH_UI", "0")
    sov2, edge2, ep2, _2 = _stack(tmp_path / "off", monkeypatch)
    try:
        # flag OFF: the edge route is ABSENT, so it 404s for an unauthenticated request (an open route would 401 for
        # no session) AND for a signed-in customer (an unknown route, never a relay).
        assert _get(_opener(), ep2, "/api/customer/launches")[0] == 404    # no session, route absent → 404 not 401
        op = _opener()
        t = _post(op, ep2, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        _post(op, ep2, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "Acme"})
        assert _get(op, ep2, "/api/customer/launches")[0] == 404           # signed in, flag off → unknown route
    finally:
        sov2.shutdown(); edge2.shutdown()


def test_the_edge_writes_the_launch_flag_into_the_page(tmp_path, monkeypatch):
    import http.client
    import threading
    from sigil.ui.custui import build_customer_server

    def page_and_build(home):
        srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                    sessions_dir=str(home / "s"))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            c.request("GET", "/", headers={"Host": f"127.0.0.1:{srv.server_address[1]}"})
            r = c.getresponse()
            return r.read().decode(), r.getheader("X-Vigil-Build")
        finally:
            srv.shutdown(); srv.server_close()

    monkeypatch.setenv("VIGIL_CUSTOMER_LAUNCH_UI", "0")
    off, build_off = page_and_build(tmp_path / "a")
    assert 'data-launch-ui="0"' in off and "__VIGIL_LAUNCH_UI__" not in off
    monkeypatch.setenv("VIGIL_CUSTOMER_LAUNCH_UI", "1")
    on, build_on = page_and_build(tmp_path / "b")
    assert 'data-launch-ui="1"' in on and build_on != build_off            # the value counts in the build id
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv("VIGIL_CUSTOMER_LAUNCH_UI", v)
        assert 'data-launch-ui="0"' in page_and_build(tmp_path / f"c{v or 'e'}")[0], v


def test_the_launches_read_over_the_edge(tmp_path, monkeypatch):
    from test_custui import _get, _opener, _post, _stack
    from sigil.governor.orgs import OrgRegistry
    monkeypatch.setenv("VIGIL_CUSTOMER_LAUNCH_UI", "1")
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        oid, u = conf["org_id"], conf["username"]
        # a billing org_admin may NOT read launches (billing != testing)
        assert _get(op, ep, "/api/customer/launches")[0] == 403
        OrgRegistry(sov.store()).grant_membership(oid, u, "operator", issued_at=1e12)
        c, d = _get(op, ep, "/api/customer/launches")
        assert c == 200 and d["org_id"] == oid and d["launches"] == [] and d["choices"] == [{"product_id": "", "depth": None}]
    finally:
        sov.shutdown(); edge.shutdown()


# --------------------------------------------------------------------------- the SPA (executed under node) ----
def _dom() -> str:
    from test_customer_onboarding import _DOM
    return _DOM


def _slice(src: str, start: str, end: str) -> str:
    i = src.index(start)
    j = src.index(end)
    return src[i:j]


def _fn(src: str, name: str) -> str:
    i = src.index(f"function {name}(")
    i = src.rindex("\n", 0, i) + 1
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


_PRELUDE = r"""
document.body.dataset.launchUi = %(flag)s;
var API = "api/customer";          // app.js's own constant, above the extracted C1a block
const calls = [];
const toasts = [];
let scheduled = 0, cleared = 0;
globalThis.setTimeout = function (fn, ms) { scheduled++; return { fn: fn, ms: ms }; };
globalThis.clearTimeout = function () { cleared++; };
let hashPath = "#/assessments";
function here() { return hashPath; }
function dataView(c, t, p, ok) { return ok; }   // the base view's shell: return its renderOk, to call with the data
const navs = []; function nav(r) { navs.push(r); }
function clearErr() {}
async function refreshWho() {}
function fmtDate(ts) { return "d"; }
function loadFindings() {}
function pageFlag(name) { var ds = (document.body && document.body.dataset) || {}; return ds[name] === "1"; }
const VUI = window.VUI;
const h = VUI.h;
let server = %(server)s;              // { launches: {...}, usage: {...}, post: {url: {status, data, body}} }
VUI.getJSON = async function (p) {
  calls.push(["GET", p]);
  if (p.indexOf("/launches") >= 0) { if (server.launchesErr) { const e = new Error("x"); e.status = server.launchesErr; throw e; } return server.launches; }
  if (p.indexOf("/billing/usage") >= 0) return server.usage || { scans: [] };
  return {};
};
VUI.postJSON = async function (p, b) {
  calls.push(["POST", p, b]);
  const r = (server.post && server.post[p]) || { ok: true };
  if (r.status) { const e = new Error("x"); e.status = r.status; e.data = r.data || {}; throw e; }
  return r;
};
VUI.toast = function (m) { toasts.push(m); };
"""


def _harness(flag="1", *, server="{}", real=()):
    """app.js's own C1a block (verbatim) + viewAssessments + pageFlag, with the app's world stubbed. ``real`` names
    functions to keep from app.js instead of a stub (none by default)."""
    src = APP_JS.read_text(encoding="utf-8")
    block = _slice(src, '  var LAUNCH_ON = pageFlag("launchUi");',
                   "  // ---- end of launching and controlling assessments (C1a)")
    view = _fn(src, "viewAssessments")
    env = _PRELUDE % {"flag": json.dumps(flag), "server": server}
    return _dom() + f"\nrequire({json.dumps(str(UI_JS))});\nconst out = {{}};\n" + env + "\n" + block + "\n" + view


def _run(script: str, *, flag="1", server="{}") -> dict:
    prog = (_harness(flag, server=server)
            + "\nconst tick = () => new Promise(r => setTimeout(r, 0));\n"      # note: setTimeout is stubbed
            + "(async () => {\n" + script
            + "\n})().then(() => process.stdout.write(JSON.stringify(out)), e => { console.error(e && e.stack || e); process.exit(3); });")
    r = subprocess.run([_need_node(), "-e", prog], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _ser() -> str:
    # serialise the minimal-DOM tree the onboarding harness builds
    return r"""
function ser(e) {
  if (e == null) return "";
  if (!(e instanceof Node)) return String(e);
  if (e.children === undefined) return JSON.stringify(e.textContent);
  return e.tagName + (e.id ? "#" + e.id : "") + (e.className ? "." + e.className.split(" ").join(".") : "")
    + JSON.stringify(e.attrs) + "[" + e.children.map(ser).join(",") + "]";
}
"""


def test_the_depth_picker_shows_no_number():
    out = _run(_ser() + r"""
var choices = { choices: [{ product_id: "vigil_launch_quick", depth: "quick" },
                          { product_id: "vigil_launch_deep", depth: "deep" }], launches: [], finished: [] };
launchUi.data = choices; launchUi.picker = "cust_a";
var picker = launchPicker({ slug: "cust_a", host: "a.example" });
out.html = ser(picker);
out.labels = picker.querySelectorAll("button").map(function (b) { return b.textContent; });
""")
    # a digit never appears in the picker, and the labels are exactly Quick / Deep / Not now
    assert not re.search(r"[0-9]", out["html"]), out["html"]
    assert out["labels"] == ["Quick", "Deep", "Not now"]
    assert "Quick" in out["html"] and "Deep" in out["html"] and "never estimates" in out["html"]


def test_the_buttons_match_the_server_actions_per_state():
    out = _run(_ser() + r"""
function btns(l) { return ser(launchRow(l)); }
out.reserved = btns({ slug: "s", launch: "n", state: "reserved", depth: "quick", actions: ["start", "cancel"], lease: {} });
out.running = btns({ slug: "s", launch: "n", state: "running", actions: ["pause"], lease: {} });
out.paused = btns({ slug: "s", launch: "n", state: "paused", actions: ["resume"], lease: {} });
out.noctrl = btns({ slug: "s", launch: "n", state: "running", actions: [], lease: {} });
out.expired = btns({ slug: "s", launch: "n", state: "reserved", expired: true, actions: ["cancel"], lease: {} });
""")
    def labels(html):
        return re.findall(r'"button"\}\["([^"]+)"\]', html)
    assert labels(out["reserved"]) == ["Start", "Cancel"]
    assert labels(out["running"]) == ["Pause"]
    assert labels(out["paused"]) == ["Resume"]
    assert labels(out["noctrl"]) == []                              # no actions → no buttons
    assert labels(out["expired"]) == ["Cancel"] and "no longer start" in out["expired"]


def test_cancel_confirms_in_the_page_before_it_posts():
    out = _run(_ser() + r"""
launchUi.hosts = [{ slug: "s", host: "a.example" }];
launchUi.slots = {}; launchUi.other = h("div", {}); launchUi.done = h("div", {});
launchUi.data = { launches: [{ slug: "s", launch: "n", state: "reserved", actions: ["start", "cancel"], lease: { x: 1 } }],
                  finished: [], choices: [] };
var row = launchRow(launchUi.data.launches[0]);
var cancel = row.querySelectorAll("button").filter(function (b) { return b.textContent === "Cancel"; })[0];
cancel.click();                                                    // opens the in-page confirm, posts nothing
out.afterClick = calls.length;
out.confirm = launchUi.confirm;
""")
    assert out["afterClick"] == 0 and out["confirm"] == "s:n"       # a confirm step, no POST yet (no confirm() dialog)


def test_the_step_up_refusal_shows_the_authenticator_message():
    out = _run(_ser() + r"""
var e = { status: 401, data: { step_up_required: true } };
out.reserve = launchMessage("reserve", e).text;
out.pause = launchMessage("pause", e).text;
out.credits = launchMessage("reserve", { status: 403, data: { error: "insufficient credits: need 8, have 2" } });
out.proof = launchMessage("start", { status: 403, data: { error: "no current ownership proof for a.example" } }).go;
out.role = launchMessage("reserve", { status: 403, data: { error: "requester may not launch assessments for this org" } }).text;
""")
    assert "second-factor" in out["reserve"] and "authenticator" in out["reserve"]
    assert "Nothing was charged" in out["reserve"] and "Nothing changed" in out["pause"]
    assert "Add credits in Billing" in out["credits"]["text"] and out["credits"]["go"] == "#/billing"
    assert not re.search(r"[0-9]", out["credits"]["text"])          # the server's "need 8, have 2" never leaks
    assert out["proof"] == "#/assets" and "founder" in out["role"]


def test_the_poll_runs_only_while_a_launch_is_live_and_the_screen_is_shown():
    out = _run(_ser() + r"""
launchUi.data = { launches: [{ slug: "s", launch: "n", state: "running", actions: [], lease: {} }], finished: [], choices: [] };
scheduleLaunchPoll(); out.liveShown = !!launchUi.timer;             // live + visible → scheduled
stopLaunchPoll(); out.stopped = !!launchUi.timer;
document.hidden = true; scheduleLaunchPoll(); out.hidden = !!launchUi.timer;   // hidden → not scheduled
document.hidden = false;
launchUi.data = { launches: [{ slug: "s", launch: "n", state: "reserved", actions: ["start"], lease: {} }], finished: [], choices: [] };
scheduleLaunchPoll(); out.notLive = !!launchUi.timer;              // nothing running → not scheduled
launchUi.data = { launches: [{ slug: "s", launch: "n", state: "running", actions: [], lease: {} }], finished: [], choices: [] };
scheduleLaunchPoll(); out.again = !!launchUi.timer;
hashPath = "#/billing"; onLaunchRoute(); out.left = !!launchUi.timer;   // leaving the screen stops it
hashPath = "#/assessments"; scheduleLaunchPoll(); document.hidden = true; onLaunchVisibility(); out.hid = !!launchUi.timer;
""")
    assert out["liveShown"] is True and out["stopped"] is False and out["hidden"] is False
    assert out["notLive"] is False and out["again"] is True and out["left"] is False and out["hid"] is False


def test_used_credits_show_only_for_a_completed_launch_from_the_statement():
    out = _run(_ser() + r"""
launchUi.hosts = []; launchUi.slots = {}; launchUi.other = h("div", {}); launchUi.done = h("div", {});
launchUi.used["s3:n3"] = "7.000";                                     // a FAILED launch with a (stale) used figure
launchUi.data = { launches: [], choices: [], finished: [
  { slug: "s1", launch: "n1", state: "completed", ended_at: 10 },     // priced: shows its credits
  { slug: "s2", launch: "n2", state: "completed", ended_at: 11 },     // completed but UNPRICED (requests 0): no figure
  { slug: "s3", launch: "n3", state: "failed", ended_at: 12 } ] };    // failed: never a used figure
await loadUsage();
out.calls = calls.map(function (c) { return c[0] + " " + c[1]; });
out.used = { s1: launchUi.used["s1:n1"], s2: launchUi.used["s2:n2"] };
out.html = ser(finishedLaunches());
""", server=json.dumps({"usage": {"scans": [
        {"scan": "s1", "launch": "n1", "status": "ok", "requests": 3, "credits": "12.500"},
        {"scan": "s2", "launch": "n2", "status": "ok", "requests": 0, "credits": "0.000"}]}}))
    assert out["calls"] == ["GET api/customer/billing/usage"]          # asked once, only for the new completions
    assert out["used"]["s1"] == "12.500"                              # the statement's own figure, verbatim
    assert out["used"]["s2"] == ""                                    # completed but unpriced (0 requests): no figure
    assert "used 12.500 credits" in out["html"]
    assert "7.000" not in out["html"] and "0.000" not in out["html"]  # the failed launch's stale figure never shows


#: The pre-C1a `viewAssessments`, captured verbatim from the branch base (BASE_REF) as a committed golden so this
#: byte-identical proof needs no git history (CI checks out shallow — `git show <BASE_REF>` is not available there).
#: If a legitimate change to viewAssessments lands on the base, re-capture this with
#: `git show <base>:apps/sigil/sigil/ui/customer_app/app.js` + the _fn extractor.
_BASE_VIEWASSESSMENTS = r"""  function viewAssessments() {
    return dataView("#/assessments", "Assessments", API + "/assessments", function (d) {
      var items = (d && d.assessments) || [];
      var note = h("p.cust-muted", { text: "Your authorized assessments and their oracle-confirmed findings. "
        + "Launching a new assessment arrives with the run driver." });
      if (!items.length) {
        return h("div", {}, [note, h("div.card.cust-soon", { text: "No authorized assessments yet — register and "
          + "verify an asset, then the owner authorizes the target." })]);
      }
      var rows = items.map(function (a) {
        return h("div.card", {}, [
          h("div.cust-kv", {}, [h("span.k", { text: a.host }), h("span", { text: (a.findings || 0) + " finding(s)" })]),
          h("div.row", {}, [h("button.btn", { type: "button", text: "View findings",
            onClick: function () { loadFindings(a.slug, a.host); } })]),
        ]);
      });
      return h("div", {}, [note, h("div.cust-grid", {}, rows), h("div#assess-findings")]);
    });
  }"""


def test_with_the_flag_off_the_assessments_view_is_byte_identical():
    # viewAssessments with LAUNCH_ON false must render exactly what the pre-C1a build renders for the same inputs:
    # the current view is run with the flag off and its output compared, node-for-node, to the golden base view.
    base_view = _BASE_VIEWASSESSMENTS
    cur_view = _fn(APP_JS.read_text(encoding="utf-8"), "viewAssessments")
    inputs = r"""
var cases = [{ assessments: [{ slug: "cust_a", host: "a.example", findings: 2 }, { slug: "cust_b", host: "b.example" }] },
             { assessments: [] }, null];
"""
    harness = _dom() + f"\nrequire({json.dumps(str(UI_JS))});\n" + _ser() + r"""
document.body.dataset.launchUi = "0";
function pageFlag(name) { return (document.body.dataset || {})[name] === "1"; }
var LAUNCH_ON = pageFlag("launchUi");            // the real decision, with the flag off: false
function dataView(c, t, p, ok) { return ok; }    // return the renderOk so we can call it with each case
function loadFindings() {}
function assessmentsLaunchView() { throw new Error("must not run with the flag off"); }
var API = "api/customer";
const h = window.VUI.h;
"""
    prog_base = harness + base_view + inputs + "console.log(JSON.stringify(cases.map(function (c) { return ser(viewAssessments()(c)); })));"
    prog_cur = harness + cur_view + inputs + "console.log(JSON.stringify(cases.map(function (c) { return ser(viewAssessments()(c)); })));"
    rb = subprocess.run([_need_node(), "-e", prog_base], capture_output=True, text=True, timeout=60)
    rc = subprocess.run([_need_node(), "-e", prog_cur], capture_output=True, text=True, timeout=60)
    assert rb.returncode == 0, rb.stderr
    assert rc.returncode == 0, rc.stderr
    assert rb.stdout == rc.stdout, "flag OFF must render the Assessments view byte-identically to the base build"


def test_the_flag_off_app_renders_the_base_view_and_makes_no_call():
    # app.js's OWN `var LAUNCH_ON = pageFlag("launchUi")` line, with the flag off: viewAssessments never calls
    # assessmentsLaunchView — it renders the pre-C1a note and makes no launches read.
    out = _run(_ser() + r"""
out.on = LAUNCH_ON;
var node = viewAssessments()({ assessments: [{ slug: "cust_a", host: "a.example", findings: 1 }] });
out.html = ser(node);
out.calls = calls;                               // the base view is synchronous; it makes no launches read
""", flag="0")
    assert out["on"] is False
    assert "Launching a new assessment arrives with the run driver" in out["html"]   # the base note, unchanged
    assert "cust-launch" not in out["html"]          # assessmentsLaunchView (which adds div.cust-launch) never ran
    assert "Launch an assessment" not in out["html"] and "Choose a depth" not in out["html"]
    assert out["calls"] == []                        # no api/customer/launches read


def test_flag_off_registers_no_launch_listener_and_makes_no_call():
    # the two C1a listeners and the read are behind LAUNCH_ON; with the flag off the block never runs.
    src = APP_JS.read_text(encoding="utf-8")
    assert "if (LAUNCH_ON) {                                   // C1a" in src
    assert "window.addEventListener(\"hashchange\", onLaunchRoute);" in src
    assert "document.addEventListener(\"visibilitychange\", onLaunchVisibility);" in src
    assert 'if (LAUNCH_ON) return assessmentsLaunchView(items);' in src


# --------------------------------------------------------------------------- the guide ----
def test_the_guide_launch_and_follow_steps_name_the_real_labels():
    from test_customer_onboarding import _node
    out = _node("out.chapters = window.VIGIL_GUIDE.CHAPTERS;")
    steps = {(ch["id"], st["id"]): st for ch in out["chapters"] for st in ch["steps"]}
    launch = steps[("assess", "launch")]["clicks"]
    assert any("select Launch" in c for c in launch)
    assert any("Quick" in c and "Deep" in c for c in launch)
    assert any("never estimates" in c for c in launch)
    follow = steps[("assess", "follow")]["clicks"]
    for label in ("Pause", "Resume", "Cancel"):
        assert any(label in c for c in follow), label
    assert any("Yes, cancel" in c for c in follow)
    assert any("Running" in c and "Paused" in c for c in follow)
    # Retest is left as is (a later slice)
    retest = steps[("assess", "retest")]["clicks"]
    assert any("Retest" in c for c in retest)


# --------------------------------------------------------------------------- PR-F: "queued" (VIGIL_CUSTOMER_FAIR_QUEUE) ----
def _job_file(org, slug, nonce, seq, *, running=False):
    """One engine job-queue file, exactly as `vigil launch-drain` → EngagementScheduler writes it for a customer
    launch (a SecurityJob: tenant_id = the lease's org, engagement_slug = its slug, extra.nonce = its nonce), under
    the default queue root <VIGIL_BASE_DIR>/jobs."""
    from vigil_core.seam_base import resolve_seam_base
    d = Path(resolve_seam_base()) / "jobs" / ("running" if running else "queue")
    d.mkdir(parents=True, exist_ok=True)
    doc = {"slug": slug, "seed_url": f"https://{slug}/", "job_id": f"job{seq}", "seq": seq,
           "params": {"tenant_id": org, "source": "api", "engagement_slug": slug,
                      "extra": {"nonce": nonce, "org_id": org}}}
    (d / f"{seq:015d}.json").write_text(json.dumps(doc), encoding="utf-8")


def _started(p, org, host):
    lease, slug, nonce = _reserve(p, org=org, host=host)
    assert p.launch_start("u", org, lease, now=_IN_WINDOW)["slug"] == slug
    return slug, nonce


def test_a_started_launch_still_in_the_job_queue_shows_how_many_go_first(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_FAIR_QUEUE", "1")
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    slug, nonce = _started(p, "org_a", "apme.cm")
    # another tenant queued two jobs FIRST (seq 1, 2); org_a's job is third in arrival order. The fair claim serves
    # org_other's oldest, then org_a (never served, nothing running) — so ONE job goes before org_a's, not two.
    _job_file("org_other", "cust_other1", "o1", 1)
    _job_file("org_other", "cust_other2", "o2", 2)
    _job_file("org_a", slug, nonce, 3)
    row = next(l for l in _launches(p)["launches"] if l["slug"] == slug)
    assert row["state"] == "running" and row["queued"] == {"ahead": 1}


def test_queued_carries_a_count_and_never_another_tenants_identity(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_FAIR_QUEUE", "1")
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    slug, nonce = _started(p, "org_a", "apme.cm")
    _job_file("org_other", "cust_secretslug", "secretnonce", 1)
    _job_file("org_a", slug, nonce, 2)
    blob = json.dumps(_launches(p))
    for leaked in ("org_other", "cust_secretslug", "secretnonce", "job1"):
        assert leaked not in blob, f"{leaked!r} reached another tenant's launches read"


def test_queued_idor_each_org_sees_only_its_own_launches_position(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_FAIR_QUEUE", "1")
    s = _store()
    _setup(s, "org_a", "apme.cm")
    _setup(s, "org_b", "bpme.cm")
    p = _prov(s)
    sa, na = _started(p, "org_a", "apme.cm")
    sb, nb = _started(p, "org_b", "bpme.cm")
    _job_file("org_a", sa, na, 1)
    _job_file("org_b", sb, nb, 2)
    a = _launches(p, org="org_a")["launches"]
    b = _launches(p, org="org_b")["launches"]
    assert [(l["slug"], l["queued"]) for l in a] == [(sa, {"ahead": 0})]
    assert [(l["slug"], l["queued"]) for l in b] == [(sb, {"ahead": 1})]
    # a job file claiming to be org_b's but naming org_a's slug + nonce gives org_b nothing: org_b's read only
    # annotates org_b's own verified leases, and org_a's row keys on (slug, nonce) of ITS tenant only.
    _job_file("org_b", sa, na, 0)
    assert [l["slug"] for l in _launches(p, org="org_b")["launches"]] == [sb]


def test_a_launch_whose_job_is_running_or_paused_is_not_marked_queued(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_FAIR_QUEUE", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED", "1")
    s = _store()
    _setup(s, "org_a", "apme.cm")
    _setup(s, "org_a", "cpme.cm")
    p = _prov(s)
    s1, n1 = _started(p, "org_a", "apme.cm")
    _job_file("org_a", s1, n1, 1, running=True)                    # claimed by a worker: running, not queued
    lease2, s2, n2 = _reserve(p, org="org_a", host="cpme.cm")
    assert p.launch_start("u", "org_a", lease2, now=_IN_WINDOW)["slug"] == s2
    _job_file("org_a", s2, n2, 2)
    assert p.launch_pause("u", "org_a", lease2, now=_IN_WINDOW)["slug"] == s2   # paused: its state says so
    rows = {l["slug"]: l for l in _launches(p)["launches"]}
    assert "queued" not in rows[s1] and rows[s1]["state"] == "running"
    assert "queued" not in rows[s2] and rows[s2]["state"] == "paused"


def test_with_the_fair_queue_flag_off_the_read_never_touches_the_queue(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_FAIR_QUEUE", raising=False)
    import sigil.governor.fair_queue as fq
    s = _store()
    _setup(s, "org_a", "apme.cm")
    p = _prov(s)
    slug, nonce = _started(p, "org_a", "apme.cm")
    before = _launches(p)
    _job_file("org_a", slug, nonce, 1)

    def _boom(*_a, **_k):
        raise AssertionError("flag OFF read the job queue")

    monkeypatch.setattr(fq, "read_launch_positions", _boom)
    after = _launches(p)
    assert after == before and all("queued" not in l for l in after["launches"])   # byte-identical to no queue


def test_the_spa_shows_a_queued_launch_with_its_position_and_otherwise_renders_as_before():
    out = _run(_ser() + r"""
out.q0 = ser(launchRow({ slug: "s", launch: "n", state: "running", queued: { ahead: 0 }, actions: [], lease: {} }));
out.q3 = ser(launchRow({ slug: "s", launch: "n", state: "running", depth: "deep", queued: { ahead: 3 },
                         actions: ["pause"], lease: {} }));
out.plain = ser(launchRow({ slug: "s", launch: "n", state: "running", actions: ["pause"], lease: {} }));
out.junk = ser(launchRow({ slug: "s", launch: "n", state: "running", queued: { ahead: "3" }, actions: [], lease: {} }));
out.pausedq = ser(launchRow({ slug: "s", launch: "n", state: "paused", queued: { ahead: 2 }, actions: [], lease: {} }));
""")
    assert "Queued" in out["q0"] and "queued at position 1" in out["q0"] and "next to start" in out["q0"]
    assert "Queued · Deep" in out["q3"] and "queued at position 4" in out["q3"] and "3 ahead of it" in out["q3"]
    assert "Pause" in out["q3"]                                    # the server's actions still render
    for plain in (out["plain"], out["junk"]):                      # no / malformed `queued`: exactly as before
        assert "Running" in plain and "Queued" not in plain and "queued at position" not in plain
    assert "Paused" in out["pausedq"] and "Queued" not in out["pausedq"]
