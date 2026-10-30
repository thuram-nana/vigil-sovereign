"""Slice B — the SaaS billing READ API over the cockpit HTTP surface (owner billing-admin view).

Load-bearing invariants (a false-green would leak one tenant's money data to another, or expose billing to an
unauthenticated/under-privileged caller):
  * tenant-scoped: /api/billing/overview?org=X authorizes via the Slice-A COMPOSED gate (OrgRegistry.admit) —
    the global owner reads ANY org (keyholder never locked out); a per-org member reads ONLY an org they hold
    view_billing in; a non-member / wrong-org / under-privileged caller gets 403;
  * read-only: the endpoint mints nothing and surfaces no secret — purely a spine projection;
  * fail-closed input: a missing/invalid org id is a 400 before any lookup;
  * the tenant picker (/api/billing/orgs) is owner-only (manage_org);
  * every read still requires an authenticated principal (401 otherwise).
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.metering import PlanCreditLedger, refill_active_subscription
from sigil.governor.orgs import OrgRegistry
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-xyz789"


def _seed():
    """A spine with two orgs; acme funded (wallet top-up + an active subscription + plan tranche) and a per-org
    member alice(operator@acme); other empty. Grants are owner-signed by the persisted identity the server reads."""
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    owner = ensure_owner_keypair()
    store = SpineStore(path)
    orgs = OrgRegistry(store, owner_key=owner)
    wallet = WalletRegistry(store, owner_key=owner)
    subs = SubscriptionRegistry(store, owner_key=owner)
    plan = PlanCreditLedger(store, owner_key=owner)
    it = iter(range(1, 10_000))
    orgs.create_org("acme", "Acme Corp", owner="owner", issued_at=float(next(it)))
    orgs.create_org("other", "Other Inc", owner="owner", issued_at=float(next(it)))
    orgs.grant_membership("acme", "alice", "operator", issued_at=float(next(it)))
    wallet.grant("acme", 200, "topup", issued_at=float(next(it)))
    # period_end must be FAR in the future vs the server's wall-clock `now` (the overview reads at time.time()),
    # else the subscription correctly reads as lapsed and plan credits drop to 0.
    subs.subscribe("acme", "pro", 6000, period_start=0.0, period_end=2_000_000_000.0, issued_at=float(next(it)))
    refill_active_subscription(subs, plan, "acme", issued_at=float(next(it)))
    return path


def _serve(spine_path):
    srv = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _get(port, path, *, token=TOKEN):
    h = {"X-SIGIL-Token": token} if token is not None else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _post(port, path, body, *, token=TOKEN):
    h = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}",
         "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _bearer(port, username, role):
    code, body = _post(port, "/api/action", {"action": "create_account", "username": username, "role": role})
    assert code == 200, (code, body)
    return body["bearer_token"]


def test_owner_reads_any_tenant_billing_overview():
    srv, port = _serve(_seed())
    try:
        code, body = _get(port, "/api/billing/overview?org=acme")
        assert code == 200, (code, body)
        assert body["org_id"] == "acme"
        assert body["credits"]["available"] == 6200          # 200 persistent + 6000 live plan
        assert body["credits"]["persistent"] == 200 and body["credits"]["plan_live"] == 6000
        assert body["wallet"]["granted"] == 200 and body["wallet"]["available"] == 200
        assert body["subscription"]["plan_id"] == "pro" and body["active"] is True
        # a funded-elsewhere owner read of an empty tenant is allowed and shows zero (no cross-tenant bleed).
        code, other = _get(port, "/api/billing/overview?org=other")
        assert code == 200 and other["credits"]["available"] == 0 and other["subscription"] is None
    finally:
        srv.shutdown()


def test_missing_or_invalid_org_is_400():
    srv, port = _serve(_seed())
    try:
        assert _get(port, "/api/billing/overview")[0] == 400
        assert _get(port, "/api/billing/overview?org=")[0] == 400
        assert _get(port, "/api/billing/overview?org=bad%2Fslash")[0] == 400     # not a valid tenant id
    finally:
        srv.shutdown()


def test_unauthenticated_read_is_401():
    srv, port = _serve(_seed())
    try:
        assert _get(port, "/api/billing/overview?org=acme", token=None)[0] == 401
        assert _get(port, "/api/billing/orgs", token=None)[0] == 401
    finally:
        srv.shutdown()


def test_per_org_member_reads_only_their_tenant():
    srv, port = _serve(_seed())
    try:
        # alice is global viewer (no view_billing globally) but operator in acme via the seeded membership.
        alice = _bearer(port, "alice", "viewer")
        code, body = _get(port, "/api/billing/overview?org=acme", token=alice)
        assert code == 200 and body["credits"]["available"] == 6200, (code, body)   # her own tenant: allowed
        assert _get(port, "/api/billing/overview?org=other", token=alice)[0] == 403  # cross-tenant: denied
        # bob is a global viewer with NO org membership anywhere -> denied even on acme.
        bob = _bearer(port, "bob", "viewer")
        assert _get(port, "/api/billing/overview?org=acme", token=bob)[0] == 403
    finally:
        srv.shutdown()


def test_billing_plans_lists_the_catalog():
    # the pricing catalog projection — any authenticated principal (viewer+) may read it; it is global (not
    # tenant-scoped), carries no secret, and unauth is refused.
    srv, port = _serve(_seed())
    try:
        code, body = _get(port, "/api/billing/plans")
        assert code == 200 and isinstance(body.get("plans"), list) and len(body["plans"]) >= 1, (code, body)
        assert all({"price_id", "kind", "name", "amount_minor", "currency"} <= set(p) for p in body["plans"])
        assert all("cred_hash" not in p and "salt" not in p for p in body["plans"])   # no secret in a plan row
        assert _get(port, "/api/billing/plans", token=None)[0] == 401                  # auth required
    finally:
        srv.shutdown()


def test_org_list_is_owner_only():
    srv, port = _serve(_seed())
    try:
        code, body = _get(port, "/api/billing/orgs")
        assert code == 200 and {o["org_id"] for o in body["orgs"]} == {"acme", "other"}
        # a per-user operator (global) is NOT the owner keyholder -> the tenant enumerator is owner-only.
        op = _bearer(port, "carol", "operator")
        assert _get(port, "/api/billing/orgs", token=op)[0] == 403
    finally:
        srv.shutdown()


def _seed_one(org, *, period_end, past_due=False, topup=200):
    """A spine with ONE funded org whose subscription period_end / dunning state is controllable, so the
    now-passed liveness projection can be asserted (a lapsed / past_due plan reads as NOT live)."""
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    owner = ensure_owner_keypair()
    store = SpineStore(path)
    orgs = OrgRegistry(store, owner_key=owner)
    wallet = WalletRegistry(store, owner_key=owner)
    subs = SubscriptionRegistry(store, owner_key=owner)
    plan = PlanCreditLedger(store, owner_key=owner)
    it = iter(range(1, 10_000))
    orgs.create_org(org, org.upper(), owner="owner", issued_at=float(next(it)))
    wallet.grant(org, topup, "topup", issued_at=float(next(it)))
    subs.subscribe(org, "pro", 6000, period_start=0.0, period_end=period_end, issued_at=float(next(it)))
    refill_active_subscription(subs, plan, org, issued_at=float(next(it)))   # a tranche for this period
    if past_due:
        subs.mark_past_due(org)
    return path


def test_lapsed_period_reads_not_live_plan_zero():
    # SOUND PROJECTION (red-pen B/A1): a subscription whose period has ELAPSED vs the server wall-clock must read
    # active:false with plan_live 0 (the now-passed liveness) — the persistent wallet still shows. A regression
    # that dropped `now` from billing_overview would over-report the lapsed tenant's live plan credits.
    srv, port = _serve(_seed_one("lapsed", period_end=1.0))        # period_end=1.0 is far in the PAST vs now
    try:
        code, body = _get(port, "/api/billing/overview?org=lapsed")
        assert code == 200, (code, body)
        assert body["active"] is False
        assert body["credits"]["plan_live"] == 0
        assert body["credits"]["persistent"] == 200 and body["credits"]["available"] == 200
    finally:
        srv.shutdown()


def test_dunning_past_due_reads_not_live_plan_zero():
    # a past_due (dunning) subscription — even inside its period window — reads not-live: plan credits gone,
    # persistent stays. The display subscription still reports status past_due.
    srv, port = _serve(_seed_one("dun", period_end=2_000_000_000.0, past_due=True))
    try:
        code, body = _get(port, "/api/billing/overview?org=dun")
        assert code == 200, (code, body)
        assert body["active"] is False and body["credits"]["plan_live"] == 0
        assert body["credits"]["available"] == 200
        assert body["subscription"]["status"] == "past_due"
    finally:
        srv.shutdown()
