"""The customer notification centre — provision.customer_notifications aggregation.

Load-bearing invariants (a false-green either leaks one tenant's security findings to another, or shows a
billing-only admin assessment findings they must not see):
  * PER-SOURCE RBAC: findings require `view_assessments` (operator-tier); billing requires `view_billing`
    (org_admin+). A billing-only admin sees billing notices but NEVER assessment findings
    (billing-authz != testing-authz), and each source is skip-on-deny (never a 403 for the whole centre).
  * TENANT ISOLATION: org_id is the hop-bound session principal; a member reads ONLY their own org's
    notifications, and a forged/other org_id yields an EMPTY list (admit_customer has no global leg, and the
    findings projector is scoped to the org's OWN server-derived slug set — the IDOR class).
  * MONEY DOCTRINE: billing notices derive from owner-signed STATES only (past_due / canceled subscription
    statuses; zero-credit floor) — NO invented threshold decides a notification.
  * MONITORING: AEGIS alerts appear ONLY when the default-OFF flag is on AND the member may read (confirmed =
    high, lead = low); off ⇒ byte-identical (no monitoring notices even with events on the spine).
  * STABLE IDS + ordering: finding:<ref> / billing:<state> / monitor:<report_id>, most-severe-first, capped.
"""
from __future__ import annotations

import tempfile

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import _NOTIF_MAX, Provisioner
from sigil.ui.target_authorization import _customer_slug

NOW = 1000.0


def _store():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return s


def _prov(store, owner):
    """A Provisioner over `store`, every registry signed by the PERSISTED owner so the projectors'
    internal owner_key=None readers (billing_overview / assessment_findings) verify against the same root."""
    return Provisioner(
        store,
        customers=CustomerRegistry(store, owner_key=owner),
        orgs=OrgRegistry(store, owner_key=owner),
        wallet=WalletRegistry(store, owner_key=owner),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: NOW)


def _member(orgs, org, user, role, it):
    orgs.create_org(org, org.upper(), owner="owner", issued_at=float(next(it)))
    orgs.grant_membership(org, user, role, issued_at=float(next(it)))


def _prove(store, org, host, it):
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(it)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0, ttl_seconds=1e12)
    return _customer_slug(org, host)


def _finding(store, slug, ref, *, severity="high", bug_class="xss", title=None, summary=None):
    cert = {"engagement_slug": slug, "finding_ref": ref, "bug_class": bug_class,
            "surface": "https://x/" + ref, "confidence": "high", "severity": severity,
            "title": title or ("Finding " + ref), "summary": summary or ("summary " + ref)}
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": cert, "finding_ref": ref,
                          "signatures": [{"key_id": "gov", "signature_b64": "x"}]})


def _monitor(store, org, rid, *, decision="confirmed", host="acme.example", attack_class="prompt_injection",
             action="block"):
    store.append(kind="event", source="aegis", actor="AEGIS", payload={
        "signal": "aegis.monitoring_event", "org_id": org, "host": host, "ts": 500.0, "decision": decision,
        "attack_class": attack_class, "action": action, "confidence": "high", "provenance_tier": 1,
        "certificate_sha256": "c" + rid, "report_id": rid})


def _ids(out):
    return [n["id"] for n in out["notifications"]]


def _by_id(out, id_):
    return next((n for n in out["notifications"] if n["id"] == id_), None)


# -- findings + billing aggregate for an operator; severity-ranked -----------------------------------
def test_operator_gets_findings_and_billing():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    _finding(store, slug, "F1", severity="high")
    _finding(store, slug, "F2", severity="critical")
    # no wallet grant + no subscription -> available 0 -> billing:no_credits (and NO past_due/canceled)
    out = p.customer_notifications("alice", "acme", now=NOW)
    assert out["org_id"] == "acme"
    ids = _ids(out)
    assert set(ids) == {"finding:F1", "finding:F2", "billing:no_credits"}
    assert out["count"] == 3
    # most-severe first: the critical finding precedes the high finding precedes the medium billing notice
    assert ids == ["finding:F2", "finding:F1", "billing:no_credits"]
    assert _by_id(out, "finding:F2")["kind"] == "finding" and _by_id(out, "finding:F2")["severity"] == "critical"
    assert _by_id(out, "finding:F1")["title"] == "Finding F1"


# -- PER-SOURCE RBAC: an org_admin (billing, no view_assessments) sees billing but NEVER findings ----
def test_org_admin_sees_billing_not_findings():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "bob", "org_admin", it)          # org_admin: view_billing, NOT view_assessments
    slug = _prove(store, "acme", "acme.example", it)
    _finding(store, slug, "F1", severity="critical")
    out = p.customer_notifications("bob", "acme", now=NOW)
    ids = _ids(out)
    assert "finding:F1" not in ids                           # billing != testing: no security findings leak
    assert not any(i.startswith("finding:") for i in ids)
    assert "billing:no_credits" in ids                       # but billing notices DO show


# -- TENANT ISOLATION: a member reads only their own org; a forged/other org_id -> empty -------------
def test_tenant_isolation_cross_org_is_empty():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    _member(p.orgs, "other", "mallory", "operator", it)
    acme_slug = _prove(store, "acme", "acme.example", it)
    other_slug = _prove(store, "other", "beta.example", it)
    _finding(store, acme_slug, "FA", severity="high")
    _finding(store, other_slug, "FB", severity="high")       # a DIFFERENT tenant's finding — must never leak
    # alice reads acme: sees FA, never FB
    mine = p.customer_notifications("alice", "acme", now=NOW)
    assert "finding:FA" in _ids(mine) and "finding:FB" not in _ids(mine)
    # alice points her session at "other" (a forged org): NOT a member -> every source skips -> empty list
    forged = p.customer_notifications("alice", "other", now=NOW)
    assert forged["notifications"] == [] and forged["count"] == 0


def test_non_member_gets_empty_never_raises():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    out = p.customer_notifications("nobody", "acme", now=NOW)   # no membership anywhere
    assert out == {"org_id": "acme", "notifications": [], "count": 0}


# -- BILLING states derive from owner-signed states only --------------------------------------------
def test_billing_past_due_is_high_and_suppresses_only_when_credited():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "bob", "org_admin", it)
    WalletRegistry(store, owner_key=owner).grant("acme", 100, "trial", issued_at=float(next(it)))  # avail>0
    subs = SubscriptionRegistry(store, owner_key=owner)
    subs.subscribe("acme", "pro", 6000, period_start=1.0, period_end=1e9, issued_at=float(next(it)))
    subs.mark_past_due("acme", issued_at=float(next(it)))
    out = p.customer_notifications("bob", "acme", now=NOW)
    ids = _ids(out)
    assert "billing:past_due" in ids and _by_id(out, "billing:past_due")["severity"] == "high"
    assert "billing:no_credits" not in ids                   # credited, so no exhaustion notice


def test_billing_canceled_is_medium():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "bob", "org_admin", it)
    WalletRegistry(store, owner_key=owner).grant("acme", 100, "trial", issued_at=float(next(it)))
    subs = SubscriptionRegistry(store, owner_key=owner)
    subs.subscribe("acme", "pro", 6000, period_start=1.0, period_end=1e9, issued_at=float(next(it)))
    subs.cancel("acme")
    out = p.customer_notifications("bob", "acme", now=NOW)
    ids = _ids(out)
    assert "billing:canceled" in ids and _by_id(out, "billing:canceled")["severity"] == "medium"
    assert "billing:past_due" not in ids


def test_healthy_billing_is_silent():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "bob", "org_admin", it)
    WalletRegistry(store, owner_key=owner).grant("acme", 100, "trial", issued_at=float(next(it)))
    subs = SubscriptionRegistry(store, owner_key=owner)
    subs.subscribe("acme", "pro", 6000, period_start=1.0, period_end=1e9, issued_at=float(next(it)))
    out = p.customer_notifications("bob", "acme", now=NOW)
    assert out["notifications"] == [] and out["count"] == 0   # active + credited -> nothing to nag about


# -- MONITORING alerts: gated by the default-OFF flag ------------------------------------------------
def test_monitoring_absent_when_flag_off(monkeypatch):
    monkeypatch.delenv("VIGIL_CUSTOMER_MONITORING_ENABLED", raising=False)
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    _monitor(store, "acme", "R1", decision="confirmed")
    out = p.customer_notifications("alice", "acme", now=NOW)
    assert not any(i.startswith("monitor:") for i in _ids(out))   # byte-identical to a build without monitoring


def test_monitoring_alerts_when_enabled(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    _monitor(store, "acme", "R1", decision="confirmed")
    _monitor(store, "acme", "R2", decision="lead")
    out = p.customer_notifications("alice", "acme", now=NOW)
    conf, lead = _by_id(out, "monitor:R1"), _by_id(out, "monitor:R2")
    assert conf and conf["severity"] == "high" and conf["kind"] == "monitoring"
    assert lead and lead["severity"] == "low"
    # a monitoring event for ANOTHER org never appears for this one
    _monitor(store, "other", "R9", decision="confirmed")
    out2 = p.customer_notifications("alice", "acme", now=NOW)
    assert "monitor:R9" not in _ids(out2)


# -- severity ranking + cap --------------------------------------------------------------------------
def test_severity_ranking_order():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    WalletRegistry(store, owner_key=owner).grant("acme", 100, "trial", issued_at=float(next(it)))  # silence billing
    for ref, sev in (("Flow", "low"), ("Fcrit", "critical"), ("Fmed", "medium"), ("Fhigh", "high")):
        _finding(store, slug, ref, severity=sev)
    out = p.customer_notifications("alice", "acme", now=NOW)
    assert _ids(out) == ["finding:Fcrit", "finding:Fhigh", "finding:Fmed", "finding:Flow"]


def test_cap_bounds_list_but_count_is_true_total():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    WalletRegistry(store, owner_key=owner).grant("acme", 100, "trial", issued_at=float(next(it)))
    n = _NOTIF_MAX + 15
    for i in range(n):
        _finding(store, slug, "F%04d" % i, severity="medium")
    out = p.customer_notifications("alice", "acme", now=NOW)
    assert len(out["notifications"]) == _NOTIF_MAX
    assert out["count"] == n                                  # honest true total for the badge
    assert all(x["id"].startswith("finding:") for x in out["notifications"])
