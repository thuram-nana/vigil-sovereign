"""NTF-3 (read leg) — the tenant-scoped ``assessment_outcomes`` projector + the 4th notification-centre source.

Load-bearing invariants (a false-green either leaks one tenant's assessment outcomes to another, or shows a
billing-only admin assessment data they must not see, or re-silences the gap this slice closes):
  * TENANT ISOLATION (the IDOR class): ``assessment_outcomes`` keeps ONLY records whose ``engagement_slug`` is
    in the org's OWN server-derived slug set (``proven_hosts -> _customer_slug``). Because ``_customer_slug`` is
    a one-way hash of ``org_id\\x00host``, another tenant's outcome can never collide into this org's set — it
    is STRUCTURALLY unreachable, exactly as ``assessment_findings`` is. Dropping that membership filter REDS
    the cross-tenant test (the mutation-verify).
  * PER-SOURCE RBAC: the outcome source is behind ``view_assessments`` (operator-tier, NOT org_admin) and
    skip-on-deny — a billing-only admin sees billing notices but NEVER assessment outcomes.
  * THE GAP CLOSED: a COMPLETED run with ZERO findings AND a FAILED run (credits refunded) BOTH now produce a
    notification (previously both were silent). failed → high / canceled → medium / completed → info.
  * MONEY DOCTRINE: the outcome record carries NO amount; the projector allowlists inert fields only.
"""
from __future__ import annotations

import tempfile

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import assessments as _assess
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import Provisioner
from sigil.ui.target_authorization import _customer_slug

NOW = 1000.0


def _store():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return s


def _prov(store, owner):
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


def _outcome(store, slug, nonce, *, outcome="completed", ts=900.0, org_id="unused-by-projector"):
    """Append a synthetic kind='assessment_outcome' record (what the settle drain lands). The projector scopes
    by slug membership, NOT by the record's org_id field (that is the structural IDOR defense), so org_id here
    is deliberately a placeholder — only the slug decides which tenant may read it."""
    store.append(kind="assessment_outcome", source="sigil", actor="settle-drain",
                 payload={"engagement_slug": slug, "org_id": org_id, "outcome": outcome,
                          "nonce": nonce, "ts": ts})


def _finding(store, slug, ref, *, severity="high"):
    cert = {"engagement_slug": slug, "finding_ref": ref, "bug_class": "xss", "surface": "https://x/" + ref,
            "confidence": "high", "severity": severity, "title": "Finding " + ref, "summary": "s " + ref}
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": cert, "finding_ref": ref,
                          "signatures": [{"key_id": "gov", "signature_b64": "x"}]})


def _ids(out):
    return [n["id"] for n in out["notifications"]]


def _by_id(out, id_):
    return next((n for n in out["notifications"] if n["id"] == id_), None)


# -- projector + 4th source surface an org's own outcome ---------------------------------------------
def test_outcome_appears_in_projector_and_notifications():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    WalletRegistry(store, owner_key=owner).grant("acme", 100, "trial", issued_at=float(next(it)))  # silence billing
    _outcome(store, slug, "n1", outcome="completed", ts=900.0)
    # projector
    proj = _assess.assessment_outcomes(store, "acme", now=NOW)
    assert proj["org_id"] == "acme" and proj["count"] == 1
    o = proj["outcomes"][0]
    assert o["engagement_slug"] == slug and o["outcome"] == "completed" and o["nonce"] == "n1" and o["ts"] == 900.0
    # the allowlist never leaks the record's internal org_id field
    assert "org_id" not in o
    # 4th notification source
    out = p.customer_notifications("alice", "acme", now=NOW)
    nid = "outcome:" + slug + ":n1"
    assert nid in _ids(out)
    n = _by_id(out, nid)
    assert n["kind"] == "assessment" and n["severity"] == "info" and n["title"] == "Assessment completed"
    assert n["ts"] == 900.0


# -- THE IDOR CLASS: another tenant's outcome is structurally unreachable -----------------------------
def test_cross_tenant_outcome_is_structurally_unreachable():
    # Mirrors the findings-IDOR test. Dropping the _org_slug_set membership filter in assessment_outcomes REDS
    # this test (the mutation-verify): org A's projector would then surface org B's outcome.
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    _member(p.orgs, "other", "mallory", "operator", it)
    acme_slug = _prove(store, "acme", "acme.example", it)
    other_slug = _prove(store, "other", "beta.example", it)
    _outcome(store, acme_slug, "OA", outcome="completed")
    _outcome(store, other_slug, "OB", outcome="failed")      # a DIFFERENT tenant's outcome — must never leak
    # projector: acme sees ONLY acme_slug; other_slug is never returned
    a = _assess.assessment_outcomes(store, "acme", now=NOW)
    assert a["count"] == 1 and {o["engagement_slug"] for o in a["outcomes"]} == {acme_slug}
    assert all(o["engagement_slug"] != other_slug for o in a["outcomes"])
    b = _assess.assessment_outcomes(store, "other", now=NOW)
    assert b["count"] == 1 and b["outcomes"][0]["engagement_slug"] == other_slug
    # notification centre: alice@acme sees her outcome, never org B's
    mine = p.customer_notifications("alice", "acme", now=NOW)
    assert ("outcome:" + acme_slug + ":OA") in _ids(mine)
    assert ("outcome:" + other_slug + ":OB") not in _ids(mine)
    assert not any(i.endswith(":OB") for i in _ids(mine))
    # alice points her session at "other" (a forged org): NOT a member -> every source skips -> empty
    forged = p.customer_notifications("alice", "other", now=NOW)
    assert forged["notifications"] == [] and forged["count"] == 0


# -- the gap closed: zero-findings COMPLETED and FAILED both produce a notification -------------------
def test_clean_complete_and_failed_both_notify():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    WalletRegistry(store, owner_key=owner).grant("acme", 100, "trial", issued_at=float(next(it)))  # silence billing
    # a COMPLETED run with ZERO findings (no _finding appended) + a FAILED run
    _outcome(store, slug, "done1", outcome="completed")
    _outcome(store, slug, "fail1", outcome="failed")
    out = p.customer_notifications("alice", "acme", now=NOW)
    comp, fail = _by_id(out, "outcome:" + slug + ":done1"), _by_id(out, "outcome:" + slug + ":fail1")
    # the zero-findings completed run is NO LONGER silent
    assert comp and comp["severity"] == "info" and comp["kind"] == "assessment"
    assert not any(i.startswith("finding:") for i in _ids(out)), "no findings exist — only the outcome notifies"
    # the failed run is NO LONGER silent, and ranks as needs-attention (high)
    assert fail and fail["severity"] == "high" and fail["title"] == "Assessment failed"
    # most-severe-first ordering: the failed (high) precedes the completed (info)
    ids = _ids(out)
    assert ids.index("outcome:" + slug + ":fail1") < ids.index("outcome:" + slug + ":done1")


def test_canceled_outcome_is_medium():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    WalletRegistry(store, owner_key=owner).grant("acme", 100, "trial", issued_at=float(next(it)))
    _outcome(store, slug, "c1", outcome="canceled")
    out = p.customer_notifications("alice", "acme", now=NOW)
    n = _by_id(out, "outcome:" + slug + ":c1")
    assert n and n["severity"] == "medium" and n["title"] == "Assessment canceled"


# -- MONEY-WORDING: the failed/canceled body is billing-model-neutral (no false "refund" claim) -------
def test_outcome_body_is_billing_model_neutral_no_false_refund_claim():
    # Red-pen L4-01 fold: a POSTPAID/invoice tenant holds no prepaid credit wallet — a failed run reverses the
    # arrears draw (the run is simply not invoiced), so no credit refund occurs. The failed/canceled bodies
    # must NOT assert "credits were refunded" (false for that billing model); they say "you were not charged",
    # which is true for both prepaid (full refund) and postpaid (draw reversed / not invoiced).
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    WalletRegistry(store, owner_key=owner).grant("acme", 100, "trial", issued_at=float(next(it)))
    _outcome(store, slug, "f1", outcome="failed")
    _outcome(store, slug, "x1", outcome="canceled")
    out = p.customer_notifications("alice", "acme", now=NOW)
    for nid in ("outcome:" + slug + ":f1", "outcome:" + slug + ":x1"):
        n = _by_id(out, nid)
        assert n is not None, nid
        low = n["body"].lower()
        assert "not charged" in low            # billing-model-neutral: true for prepaid AND postpaid
        assert "refund" not in low             # never promise a credit refund a postpaid tenant never got


# -- PER-SOURCE RBAC: a billing-only admin never sees assessment outcomes ----------------------------
def test_without_view_assessments_no_outcome_source():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "bob", "org_admin", it)          # org_admin: view_billing, NOT view_assessments
    slug = _prove(store, "acme", "acme.example", it)
    _outcome(store, slug, "n1", outcome="completed")
    out = p.customer_notifications("bob", "acme", now=NOW)
    ids = _ids(out)
    assert not any(i.startswith("outcome:") for i in ids)     # billing != testing: no assessment outcomes leak
    assert "billing:no_credits" in ids                        # but billing notices DO show (source unaffected)


def test_non_member_gets_empty_never_raises():
    store = _store()
    owner = ensure_owner_keypair()
    p = _prov(store, owner)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(store, "acme", "acme.example", it)
    _outcome(store, slug, "n1", outcome="completed")
    out = p.customer_notifications("nobody", "acme", now=NOW)   # no membership anywhere
    assert out == {"org_id": "acme", "notifications": [], "count": 0}
