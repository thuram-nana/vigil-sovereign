"""The founder role (owner-approved): the signing-up customer may self-serve scans on hosts the org proves.

Load-bearing invariants (each a mutation target):
  * flag OFF (code default): both sign-up paths grant `org_admin` exactly as before — no testing;
  * flag ON (with the trial preview on, the production pair): both sign-up paths grant `founder` (server-set, read
    at the committing attempt); with the preview off they grant `org_admin`, so a sign-up trial that can fund a
    scan is always the rule-bound preview trial. The founder can request a challenge, verify ONLY with the inline
    authorization affirmation, and reserve a launch on a host the org proved and the owner key authorized. No
    proof / no authority is still refused. A trial-preview org stays limited to the trial product and one
    registrable domain;
  * changing or revoking a founder is owner-only: customer member management refuses a founder target (the
    founder included, on themself), never grants `founder`/`operator`, and counts the founder as an
    administrator for the last-admin rule; every member verb canonicalises the target name once and uses only
    that value, so surrounding whitespace never reaches a different membership than the one it writes;
  * the kill switch: flag OFF admits an existing founder as `org_admin` (no testing, billing kept), with no spine
    write; flag ON restores it. A reserved launch that has not started stays releasable for a full refund by any
    org member holding `run_engagement` or `manage_billing` (so a founder whose testing was withdrawn can still
    cancel it); a started launch is never cancelled;
  * the owner verbs (`sigil org set-member-role`, `sigil org demote-founders`) change a founder with a critical
    audit row first; demote-founders is idempotent and is the rollback procedure;
  * payment and trial grants never write a membership record;
  * `founder` is never a global role (account create/assign refuse it; a record carrying it lists no
    permission and the admission gate's global leg admits nothing).
"""
from __future__ import annotations

import itertools
import os
import tempfile

import pytest

from sigil.governor.orgs import MEMBERSHIP_SIGNAL
from sigil.ui.email_channel import PURPOSE_VERIFY

FLAG = "VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED"
PREVIEW = "VIGIL_TRIAL_PREVIEW_ENABLED"
_clock = itertools.count(1)
_PW = "customer-pw-123"


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared authority seam
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    for var in (FLAG, "VIGIL_CUSTOMER_STEPUP_REQUIRED", PREVIEW, "VIGIL_TIERED_PRODUCTS",
                "VIGIL_TRIAL_PRODUCT_ID", "VIGIL_ONE_LAUNCH_PER_HOST"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def flag_on(monkeypatch):
    """The production pair: a sign-up grants `founder` only while the trial preview is on as well."""
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv(PREVIEW, "1")


class _Fetcher:
    """What a resolver+GET of the customer's well-known would have seen: the marker it published."""

    def __init__(self):
        self.body = ""

    def fetch(self, method, host, *, now=None):
        return self.body


class _StubIdP:
    """A verified Google identity (the crypto is tested elsewhere); the provisioner's tail is under test."""

    def __init__(self, sub="g-founder", email="g.founder@gmail.com"):
        from sigil.ui.customer_identity import METHOD_GOOGLE_OIDC, CustomerIdentity
        self.method = METHOD_GOOGLE_OIDC
        self.identity = CustomerIdentity(method=METHOD_GOOGLE_OIDC, email=email, email_verified=True,
                                         federated_iss="https://accounts.google.com", federated_sub=sub)

    def verify(self, **_ctx):
        return self.identity


def _prov(*, store=None, idp=None, trial=False):
    """A vault-backed Provisioner: every registry signs/verifies under the ONE persisted owner key, so the proof,
    the memberships and the authority mint all agree (as in production)."""
    from sigil.governor.customer_credentials import CustomerCredentialRegistry
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.trial_claim import TrialClaimRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    ensure_owner_keypair()
    s = store or SpineStore(tempfile.mktemp(suffix=".jsonl"))
    extra = {}
    if trial:
        extra = {"trial_claims": TrialClaimRegistry(s),
                 "trial_launch_limiter": LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=86400.0,
                                                          base_lock_s=86400.0, max_lock_s=86400.0)}
    p = Provisioner(s, customers=CustomerRegistry(s), orgs=OrgRegistry(s), wallet=WalletRegistry(s),
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e9),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4,
                                                  base_lock_s=1.0),
                    customer_credentials=CustomerCredentialRegistry(s), oidc_provider=idp,
                    email_sender=NullEmailSender(), target_fetcher=_Fetcher(), trial_credits=100,
                    now_fn=lambda: 1000.0 + float(next(_clock)), **extra)
    return p, s


def _fund(p, org, credits=100):
    """Bought credits for `org`: an owner-signed top-up grant, as a verified payment mints (not a trial)."""
    p.wallet.grant(org, credits, "topup", entry_id=f"topup:{org}:{next(_clock)}", source_ref="test-payment",
                   issued_at=1000.0 + float(next(_clock)))


def _signup(p, email="founder@acme-founder.io", org="Acme"):
    tok = p.email_tokens.issue(email, PURPOSE_VERIFY)
    return p.confirm_signup(tok, password=_PW, org_name=org)


def _prove(p, user, org, host):
    """Challenge + publish + verify WITH the affirmation (records the proof and mints the authority)."""
    ch = p.target_challenge(user, org, host)
    p.target_fetcher.body = ch["well_known_body"]
    return p.target_verify(user, org, host, "well-known", authorized=True)


def _memberships(s):
    return [r.payload for r in s.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == MEMBERSHIP_SIGNAL]


def _audits(s, action):
    return [r.payload for r in s.iter_records() if isinstance(r.payload, dict)
            and r.payload.get("signal") == "provision.audit" and r.payload.get("action") == action]


# --- flag OFF: the sign-up is exactly as before ---------------------------------------------------------------

def test_flag_off_both_signup_paths_grant_org_admin_with_no_testing():
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov(idp=_StubIdP())
    a = _signup(p)
    g = p.oidc_finish(code="c", code_verifier="v", nonce="n", ip="1.2.3.4")
    for user, org in ((a["username"], a["org_id"]), (g["username"], g["orgs"][0])):
        assert p.orgs.membership_role(user, org) == "org_admin"
        with pytest.raises(ProvisionDenied):                       # billing admin: no testing
            p.target_challenge(user, org, "acme-founder.io")
        assert p.orgs.admit_customer(username=user, org_id=org, permission="manage_billing") is True
    # the membership records carry role org_admin, shaped exactly like a plain owner grant of org_admin
    recs = _memberships(s)
    assert [r["role"] for r in recs] == ["org_admin", "org_admin"]
    p.orgs.create_org("org_control", "control", owner="owner", issued_at=9e9)
    p.orgs.grant_membership("org_control", "control", "org_admin", issued_at=9e9)
    control = _memberships(s)[-1]
    assert all(set(r) == set(control) for r in recs)
    assert [r.get("role") for r in _audits(s, "signup")] == ["org_admin", "org_admin"]


# --- flag ON: the founder self-serves a scan on a host it proves --------------------------------------------

def test_flag_on_email_signup_founder_proves_a_host_and_reserves_a_launch(flag_on):
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    a = _signup(p)
    u, org = a["username"], a["org_id"]
    _fund(p, org)
    assert p.orgs.membership_role(u, org) == "founder"
    assert [r.get("role") for r in _audits(s, "signup")] == ["founder"]
    # the challenge is allowed; verify WITHOUT the affirmation is refused and mints nothing
    ch = p.target_challenge(u, org, "acme-founder.io")
    p.target_fetcher.body = ch["well_known_body"]
    with pytest.raises(ProvisionDenied, match="authorized to test this asset"):
        p.target_verify(u, org, "acme-founder.io", "well-known", authorized=False)
    with pytest.raises(ProvisionDenied):                            # no authority yet: launch refused
        p.launch_reserve(u, org, "acme-founder.io")
    r = p.target_verify(u, org, "acme-founder.io", "well-known", authorized=True)
    assert r["scope"] == ["acme-founder.io"]
    lease = p.launch_reserve(u, org, "acme-founder.io")
    assert lease["host"] == "acme-founder.io" and lease["units_reserved"] > 0
    # the founder reads its own results surface (testing domain)
    assert p.customer_assets(u, org)["assets"][0]["host"] == "acme-founder.io"


def test_flag_on_founder_launch_still_needs_proof_and_authority(flag_on):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    a = _signup(p)
    u, org = a["username"], a["org_id"]
    _fund(p, org)                                                   # credits are never the reason for a refusal
    with pytest.raises(ProvisionDenied):                            # no proof at all
        p.launch_reserve(u, org, "unproven-founder.io")
    reg = AssetOwnershipRegistry(s)                                 # a proof with NO minted authority
    ch = reg.issue_challenge(org, "proof-only-founder.io", issued_at=5000.0)
    reg.verify_and_record(org, "proof-only-founder.io", method=METHOD_DNS_TXT, observed=[ch.marker],
                          now=5001.0, ttl_seconds=1e12)
    with pytest.raises(ProvisionDenied):
        p.launch_reserve(u, org, "proof-only-founder.io")
    # another org's founder cannot use this org's proof
    b = _signup(p, email="other@beta-founder.io", org="Beta")
    _fund(p, b["org_id"])
    _prove(p, u, org, "acme-founder.io")
    with pytest.raises(ProvisionDenied):
        p.launch_reserve(b["username"], b["org_id"], "acme-founder.io")


def test_flag_on_google_signup_grants_founder(flag_on):
    p, s = _prov(idp=_StubIdP())
    g = p.oidc_finish(code="c", code_verifier="v", nonce="n", ip="1.2.3.4")
    u, org = g["username"], g["orgs"][0]
    assert p.orgs.membership_role(u, org) == "founder"
    assert p.target_challenge(u, org, "acme-founder.io")["dns_name"] == "_vigil-challenge.acme-founder.io"
    assert [r.get("role") for r in _audits(s, "signup")] == ["founder"]


def test_the_founder_flag_without_the_trial_preview_signs_up_an_org_admin(monkeypatch):
    # The founder role needs the preview trial on: with the founder flag on and the preview off, both sign-up paths
    # grant `org_admin`, so the sign-up trial cannot fund a scan (no trial product, domain or daily-cap rule would
    # hold it otherwise).
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setenv(FLAG, "1")
    p, s = _prov(idp=_StubIdP(), trial=True)
    a = _signup(p)
    g = p.oidc_finish(code="c", code_verifier="v", nonce="n", ip="1.2.3.4")
    for user, org in ((a["username"], a["org_id"]), (g["username"], g["orgs"][0])):
        assert p.orgs.membership_role(user, org) == "org_admin"
        assert p.wallet.has_grant_entry(org, f"trial:{org}") and p.wallet.available(org) == 100
        with pytest.raises(ProvisionDenied):
            p.target_challenge(user, org, "acme-founder.io")
        with pytest.raises(ProvisionDenied):
            p.launch_reserve(user, org, "acme-founder.io")
    assert [r.get("role") for r in _audits(s, "signup")] == ["org_admin", "org_admin"]
    # the same sign-up with the preview on as well is a founder held to the trial rules
    monkeypatch.setenv(PREVIEW, "1")
    f = _signup(p, email="pair@pair-founder.io", org="Pair")
    assert p.orgs.membership_role(f["username"], f["org_id"]) == "founder" and p._preview_locked(f["org_id"])


def test_a_locked_trial_founder_keeps_the_trial_product_and_one_domain(flag_on, monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    monkeypatch.setenv("VIGIL_TRIAL_PRODUCT_ID", "vigil_launch_quick")
    p, s = _prov(trial=True)
    a = _signup(p, email="trial.founder@acme-founder.io")
    u, org = a["username"], a["org_id"]
    assert p.orgs.membership_role(u, org) == "founder" and p._preview_locked(org)
    _prove(p, u, org, "acme-founder.io")
    _prove(p, u, org, "second-founder.io")
    with pytest.raises(ProvisionDenied, match="trial scan only"):
        p.launch_reserve(u, org, "acme-founder.io", product_id="vigil_launch_deep")
    assert p.launch_reserve(u, org, "acme-founder.io", product_id="vigil_launch_quick")["host"] == "acme-founder.io"
    with pytest.raises(ProvisionDenied, match="one domain"):
        p.launch_reserve(u, org, "second-founder.io", product_id="vigil_launch_quick")
    # the founder reads its results through the PREVIEW projection while the org is locked (the role does not
    # unlock reports; buying credits does)
    assert "preview" in p.customer_assessment_findings(u, org)


# --- member management: a founder is owner-only ----------------------------------------------------------------

def _founder_and_mate(p):
    a = _signup(p)
    m = _signup(p, email="mate@mate-founder.io", org="Mate")
    return a["username"], a["org_id"], m["username"]


def test_the_founder_cannot_grant_founder_or_operator(flag_on):
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    u, org, mate = _founder_and_mate(p)
    for bad in ("founder", "operator", "owner"):
        with pytest.raises(ProvisionDenied):
            p.grant_member(u, org, mate, bad)
    assert p.orgs.membership_role(mate, org) is None
    assert p.grant_member(u, org, mate, "org_admin")["role"] == "org_admin"     # an admin teammate is fine


def test_no_customer_can_change_or_revoke_a_founder(flag_on):
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    u, org, mate = _founder_and_mate(p)
    p.grant_member(u, org, mate, "org_admin")
    for requester in (mate, u):                                     # an org_admin teammate, and the founder itself
        for role in ("viewer", "analyst", "org_admin"):
            with pytest.raises(ProvisionDenied, match="service owner"):
                p.grant_member(requester, org, u, role)
        with pytest.raises(ProvisionDenied, match="service owner"):
            p.revoke_member(requester, org, u)
    assert p.orgs.membership_role(u, org) == "founder"
    denied = [a for a in _audits(s, "grant_member") + _audits(s, "revoke_member")
              if a.get("reason") == "founder_owner_only"]
    assert len(denied) == 8


def test_the_founder_counts_as_an_administrator_for_the_last_admin_rule(flag_on):
    p, s = _prov()
    u, org, mate = _founder_and_mate(p)
    p.grant_member(u, org, mate, "org_admin")
    # the teammate admin may step down and leave, because the founder remains an administrator
    assert p.grant_member(mate, org, mate, "viewer")["role"] == "viewer"
    p.grant_member(u, org, mate, "org_admin")
    p.revoke_member(mate, org, mate)
    assert p.orgs.membership_role(mate, org) is None and p.orgs.membership_role(u, org) == "founder"


_PADS = (" {}", "{} ", "\t{}", "{}\n", " {}\t")


@pytest.mark.parametrize("pad", _PADS)
def test_every_member_verb_reads_a_padded_target_as_the_same_member(flag_on, pad):
    # Every member verb canonicalises the target ONCE and uses only that value, so surrounding whitespace never
    # names a different membership than the one the write would change: the founder refusal holds for both
    # customer verbs, from a teammate admin and from the founder itself, and the audit names the real member.
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    u, org, mate = _founder_and_mate(p)
    p.grant_member(u, org, mate, "org_admin")
    for requester in (mate, u):
        for role in ("viewer", "analyst", "org_admin"):
            with pytest.raises(ProvisionDenied, match="service owner"):
                p.grant_member(requester, org, pad.format(u), role)
        with pytest.raises(ProvisionDenied, match="service owner"):
            p.revoke_member(requester, org, pad.format(u))
    assert p.orgs.membership_role(u, org) == "founder"
    denied = [a for a in _audits(s, "grant_member") + _audits(s, "revoke_member")
              if a.get("reason") == "founder_owner_only"]
    assert len(denied) == 8 and {a["target"] for a in denied} == {u}
    # a padded teammate name is that teammate: the change lands on the real membership and is audited as such
    assert p.grant_member(u, org, pad.format(mate), "viewer")["username"] == mate
    assert p.orgs.membership_role(mate, org) == "viewer"
    assert p.revoke_member(u, org, pad.format(mate))["username"] == mate
    assert p.orgs.membership_role(mate, org) is None
    assert _audits(s, "grant_member")[-1]["target"] == mate and _audits(s, "revoke_member")[-1]["target"] == mate


@pytest.mark.parametrize("pad", _PADS)
def test_a_padded_target_never_removes_the_last_administrator(monkeypatch, pad):
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    a = _signup(p)                                                  # flag off: the sole admin is an org_admin
    u, org = a["username"], a["org_id"]
    with pytest.raises(ProvisionDenied, match="last administrator"):
        p.revoke_member(u, org, pad.format(u))
    with pytest.raises(ProvisionDenied, match="last administrator"):
        p.grant_member(u, org, pad.format(u), "viewer")
    assert p.orgs.membership_role(u, org) == "org_admin"
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv(PREVIEW, "1")
    f = _signup(p, email="sole@sole-founder.io", org="Sole")       # flags on: the sole admin is the founder
    with pytest.raises(ProvisionDenied, match="service owner"):
        p.revoke_member(f["username"], f["org_id"], pad.format(f["username"]))
    assert p.orgs.membership_role(f["username"], f["org_id"]) == "founder"
    assert [m.username for m in p.orgs.memberships(f["org_id"])] == [f["username"]]


@pytest.mark.parametrize("pad", _PADS)
def test_the_owner_verb_reads_a_padded_target_as_the_same_member(flag_on, pad):
    from sigil.ui.provision import owner_set_member_role
    p, s = _prov()
    a = _signup(p)
    u, org = a["username"], a["org_id"]
    r = owner_set_member_role(s, org, pad.format(u), "org_admin", reason="support", issued_at=9e9)
    assert r["username"] == u and r["previous_role"] == "founder"
    assert p.orgs.membership_role(u, org) == "org_admin"
    assert _audits(s, "owner_set_member_role")[-1]["target"] == u


def test_last_admin_rule_still_holds_without_a_founder():
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()                                                  # flag off: plain org_admin sign-ups
    u, org, mate = _founder_and_mate(p)
    assert p.orgs.membership_role(u, org) == "org_admin"
    with pytest.raises(ProvisionDenied, match="last administrator"):
        p.grant_member(u, org, u, "viewer")
    with pytest.raises(ProvisionDenied, match="last administrator"):
        p.revoke_member(u, org, u)


# --- the kill switch ------------------------------------------------------------------------------------------

def test_kill_switch_turns_founder_testing_off_and_back_on_with_no_spine_write(flag_on, monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    a = _signup(p)
    u, org = a["username"], a["org_id"]

    def can(perm):
        return p.orgs.admit_customer(username=u, org_id=org, permission=perm)

    assert can("run_engagement") and can("view_assessments") and can("manage_billing")
    n = sum(1 for _ in s.iter_records())
    monkeypatch.setenv(FLAG, "0")
    assert not can("run_engagement") and not can("view_assessments")
    assert can("manage_billing") and can("manage_members") and can("view_billing")
    assert p.orgs.membership_role(u, org) == "founder"              # the stored role is unchanged
    with pytest.raises(ProvisionDenied):
        p.target_challenge(u, org, "acme-founder.io")
    assert sum(1 for r in s.iter_records() if r.payload.get("signal") == MEMBERSHIP_SIGNAL) == 1
    assert sum(1 for _ in s.iter_records()) == n + 1                # only the refusal's audit row
    monkeypatch.setenv(FLAG, "1")
    assert can("run_engagement") and can("view_assessments")


def _demote_by_kill_switch(p, s, org, u, monkeypatch):
    monkeypatch.setenv(FLAG, "0")


def _demote_by_owner_verb(p, s, org, u, monkeypatch):
    from sigil.ui.provision import owner_demote_founders
    owner_demote_founders(s, reason="rollback", issued_at=9e9)


def _demote_by_set_member_role(p, s, org, u, monkeypatch):
    from sigil.ui.provision import owner_set_member_role
    owner_set_member_role(s, org, u, "org_admin", reason="support", issued_at=9e9)


@pytest.mark.parametrize("demote", [_demote_by_kill_switch, _demote_by_owner_verb, _demote_by_set_member_role])
def test_a_founders_unstarted_reservation_is_always_releasable_for_a_full_refund(flag_on, monkeypatch, demote):
    # Founder testing withdrawn (the kill switch, demote-founders, or an owner role change): the founder can no
    # longer reserve or start, but as an org admin it can still cancel the reservation it holds, and the whole
    # reservation returns to the org's balance.
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    a = _signup(p)
    u, org = a["username"], a["org_id"]
    _fund(p, org)
    _prove(p, u, org, "acme-founder.io")
    before = p.wallet.available(org)
    lease = p.launch_reserve(u, org, "acme-founder.io")
    assert p.wallet.available(org) == before - lease["units_reserved"] < before
    demote(p, s, org, u, monkeypatch)
    assert not p.orgs.admit_customer(username=u, org_id=org, permission="run_engagement")
    with pytest.raises(ProvisionDenied):
        p.launch_start(u, org, lease["lease"])
    with pytest.raises(ProvisionDenied):
        p.launch_reserve(u, org, "acme-founder.io")
    assert p.launch_cancel(u, org, lease["lease"]) == {"slug": lease["slug"], "refunded": lease["units_reserved"]}
    assert p.wallet.available(org) == before
    assert _audits(s, "launch_cancel")[-1]["outcome"] == "canceled"


def test_a_billing_admin_releases_a_reservation_but_a_reader_cannot(flag_on):
    # Cancelling a reserved, not started launch is a billing act (it only refunds the org's own balance): an
    # org_admin teammate may release the founder's reservation; a viewer or analyst teammate may not.
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    u, org, mate = _founder_and_mate(p)
    reader = _signup(p, email="reader@reader-founder.io", org="Reader")["username"]
    p.grant_member(u, org, reader, "viewer")
    _fund(p, org)
    _prove(p, u, org, "acme-founder.io")
    before = p.wallet.available(org)
    lease = p.launch_reserve(u, org, "acme-founder.io")
    for role in ("viewer", "analyst"):
        p.grant_member(u, org, reader, role)
        with pytest.raises(ProvisionDenied, match="may not manage launches"):
            p.launch_cancel(reader, org, lease["lease"])
    assert p.wallet.available(org) == before - lease["units_reserved"]
    p.grant_member(u, org, mate, "org_admin")
    assert p.launch_cancel(mate, org, lease["lease"])["refunded"] == lease["units_reserved"]
    assert p.wallet.available(org) == before


def test_a_billing_admin_never_refunds_a_started_launch(flag_on, monkeypatch):
    # The cancel stays a reserved-not-started release for every caller: once the founder started the launch, the
    # founder (as an org admin under the kill switch) and an org_admin teammate are both refused, and nothing moves.
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov()
    u, org, mate = _founder_and_mate(p)
    p.grant_member(u, org, mate, "org_admin")
    _fund(p, org)
    _prove(p, u, org, "acme-founder.io")
    lease = p.launch_reserve(u, org, "acme-founder.io")
    held = p.wallet.available(org)
    assert p.launch_start(u, org, lease["lease"])["slug"] == lease["slug"]
    monkeypatch.setenv(FLAG, "0")
    for requester in (u, mate):
        with pytest.raises(ProvisionDenied, match="has been started"):
            p.launch_cancel(requester, org, lease["lease"])
    assert p.wallet.available(org) == held


@pytest.mark.parametrize("preview, first, second, want, entry", [
    ("1", "1", "0", "org_admin", "trial-preview"), ("1", "0", "1", "founder", "trial-preview"),
    ("", "1", "0", "org_admin", "trial"), ("", "0", "1", "org_admin", "trial")])
def test_signup_retry_across_a_flag_flip_commits_one_trial_with_the_committing_role(monkeypatch, preview, first,
                                                                                    second, want, entry):
    from sigil.ui.provision import Provisioner
    monkeypatch.setenv(PREVIEW, preview)
    p, s = _prov(trial=True)
    tok = p.email_tokens.issue("retry@acme-founder.io", PURPOSE_VERIFY)
    real = Provisioner._audit
    armed = [True]

    def flaky(self, action, **kw):
        if action == "signup" and armed[0]:
            armed[0] = False
            raise OSError("audit store unavailable")
        return real(self, action, **kw)

    monkeypatch.setattr(Provisioner, "_audit", flaky)
    monkeypatch.setenv(FLAG, first)
    with pytest.raises(OSError):
        p.confirm_signup(tok, password=_PW, org_name="Retry")              # stops before its commit marker
    monkeypatch.setenv(FLAG, second)
    out = p.confirm_signup(tok, password=_PW, org_name="Retry")            # the same token: the retry commits
    assert p.orgs.membership_role(out["username"], out["org_id"]) == want
    assert p.wallet.available(out["org_id"]) == 100                      # exactly one trial
    assert p.wallet.has_grant_entry(out["org_id"], f"{entry}:{out['org_id']}")
    assert [r.get("role") for r in _audits(s, "signup")] == [want]       # one committed sign-up, its role


# --- the owner verbs ------------------------------------------------------------------------------------------

_CLI_STORE: list = []


def _run_cli(argv):
    from sigil import cli
    _CLI_STORE[-1].migrate()                 # the CLI runs on a segment-layout spine (idempotent)
    try:
        cli.main(argv)
    except SystemExit as e:
        return e.code or 0
    return 0


def _cli_store(monkeypatch, tmp_path):
    """The spine the `sigil` CLI process opens (its configured path) — shared with the test's provisioner."""
    from sigil import cli, config
    from sigil.spine.store import SpineStore
    path = tmp_path / "spine" / "spine.jsonl"
    monkeypatch.setattr(config, "SPINE_PATH", path)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: SpineStore(path))
    s = SpineStore(path)
    _CLI_STORE.append(s)
    return s


def test_owner_set_member_role_changes_a_founder_with_a_critical_audit(flag_on, monkeypatch, tmp_path, capsys):
    s = _cli_store(monkeypatch, tmp_path)
    p, _ = _prov(store=s)
    u, org, mate = _founder_and_mate(p)
    assert _run_cli(["org", "set-member-role", org, u, "org_admin", "--reason", "support request"]) == 0
    out = capsys.readouterr().out
    assert "founder -> org_admin" in out and "@" not in out
    assert p.orgs.membership_role(u, org) == "org_admin"
    audit = _audits(s, "owner_set_member_role")
    assert audit and audit[-1]["requester"] == "owner" and audit[-1]["role"] == "org_admin"
    assert audit[-1]["reason"] == "support request"
    # and back: the owner grants founder on an existing org
    assert _run_cli(["org", "set-member-role", org, u, "founder", "--reason", "restore"]) == 0
    assert p.orgs.membership_role(u, org) == "founder"
    # refusals: no reason, an unknown role, an inactive org, an unknown user, orphaning the org
    for argv in (["org", "set-member-role", org, u, "org_admin", "--reason", " "],
                 ["org", "set-member-role", org, u, "owner", "--reason", "x"],
                 ["org", "set-member-role", "org_nosuchorg", u, "viewer", "--reason", "x"],
                 ["org", "set-member-role", org, "cust_nobody", "viewer", "--reason", "x"],
                 ["org", "set-member-role", org, u, "viewer", "--reason", "x"]):
        assert _run_cli(argv) == 2, argv
    assert p.orgs.membership_role(u, org) == "founder"


def test_a_refused_owner_verb_writes_no_audit_row_and_no_grant(flag_on, monkeypatch, tmp_path):
    s = _cli_store(monkeypatch, tmp_path)
    p, _ = _prov(store=s)
    u, org, mate = _founder_and_mate(p)
    other = _signup(p, email="gone@gone-founder.io", org="Gone")
    p.orgs.revoke_org(other["org_id"])                              # an org that is no longer active

    def rows():
        return [r.payload for r in s.iter_records() if isinstance(r.payload, dict)
                and r.payload.get("signal") in ("provision.audit", MEMBERSHIP_SIGNAL)]

    before = rows()
    for argv in (["org", "set-member-role", org, u, "org_admin", "--reason", " "],
                 ["org", "set-member-role", org, u, "owner", "--reason", "x"],
                 ["org", "set-member-role", other["org_id"], other["username"], "viewer", "--reason", "x"],
                 ["org", "set-member-role", org, "cust_nobody", "viewer", "--reason", "x"],
                 ["org", "set-member-role", org, u, "viewer", "--reason", "x"],
                 ["org", "demote-founders", "--org", other["org_id"], "--reason", "x"],
                 ["org", "demote-founders", "--org", "org_nosuchorg", "--reason", "x"],
                 ["org", "demote-founders", "--reason", " "]):
        assert _run_cli(argv) == 2, argv
    assert rows() == before
    assert p.orgs.membership_role(u, org) == "founder"


def test_an_owner_change_applies_even_when_its_issued_at_is_older_than_the_current_grant(flag_on):
    # The owner verbs sign strictly above the member's current grant, so a slow or skewed clock can never leave an
    # owner change folded as stale (silently not applied) while its audit row says it happened.
    from sigil.ui.provision import owner_demote_founders, owner_set_member_role
    p, s = _prov()
    a, b = _signup(p), _signup(p, email="b@beta-founder.io", org="Beta")
    cur = next(m.issued_at for m in p.orgs.memberships(a["org_id"]) if m.username == a["username"])
    r = owner_set_member_role(s, a["org_id"], a["username"], "org_admin", reason="support", issued_at=cur - 500.0)
    assert r["previous_role"] == "founder" and p.orgs.membership_role(a["username"], a["org_id"]) == "org_admin"
    assert owner_demote_founders(s, reason="rollback", issued_at=1.0) == {"demoted": 1, "orgs": 1}
    assert p.orgs.membership_role(b["username"], b["org_id"]) == "org_admin"
    assert owner_demote_founders(s, reason="rollback", issued_at=1.0) == {"demoted": 0, "orgs": 0}


def test_demote_founders_skips_an_org_that_is_no_longer_active(flag_on, monkeypatch):
    # An org revoke whose member cascade did not finish leaves a founder membership under an inactive org: the
    # demote run leaves that org alone (no audit row, no grant) and still demotes every active org's founder.
    from sigil.governor.orgs import OrgRegistry
    from sigil.ui.provision import owner_demote_founders
    p, s = _prov()
    a, b = _signup(p), _signup(p, email="b@beta-founder.io", org="Beta")

    def interrupted(self, org_id, username):
        raise OSError("interrupted before the member cascade")

    with monkeypatch.context() as mp:
        mp.setattr(OrgRegistry, "_append_revoked_membership", interrupted)
        with pytest.raises(OSError):
            p.orgs.revoke_org(a["org_id"])
    assert p.orgs.org(a["org_id"]) is None
    assert [m.role for m in p.orgs.memberships(a["org_id"])] == ["founder"]
    assert owner_demote_founders(s, reason="rollback", issued_at=9e9) == {"demoted": 1, "orgs": 1}
    assert p.orgs.membership_role(b["username"], b["org_id"]) == "org_admin"
    assert [x["org_id"] for x in _audits(s, "owner_demote_founder")] == [b["org_id"]]


def test_every_member_verb_decides_inside_the_cross_process_membership_lock(flag_on, monkeypatch):
    # The cockpit's member verbs and the owner CLI verbs share one cross-process lock around their last-admin check,
    # audit and write. While another holder has it (an flock conflicts across open files, as across processes),
    # each verb gives up after its bounded wait with nothing written; once it is free, each proceeds.
    from vigil_integration.live.seam_lock import LockBusy

    from sigil.ui import provision as prov
    p, s = _prov()
    u, org, mate = _founder_and_mate(p)
    p.grant_member(u, org, mate, "analyst")
    monkeypatch.setattr(prov, "_MEMBERS_LOCK_WAIT_S", 0.05)

    def rows():
        return [r.payload for r in s.iter_records() if isinstance(r.payload, dict)
                and r.payload.get("signal") in ("provision.audit", MEMBERSHIP_SIGNAL)]

    verbs = (lambda: p.grant_member(u, org, mate, "viewer"),
             lambda: p.revoke_member(u, org, mate),
             lambda: prov.owner_set_member_role(s, org, mate, "org_admin", reason="support", issued_at=9e9),
             lambda: prov.owner_demote_founders(s, reason="rollback", issued_at=9e9))
    before = rows()
    with prov._members_lock(s):
        for verb in verbs:
            with pytest.raises(LockBusy):
                verb()
    assert rows() == before
    assert p.orgs.membership_role(mate, org) == "analyst" and p.orgs.membership_role(u, org) == "founder"
    for verb in verbs:
        verb()
    assert p.orgs.membership_role(mate, org) == "org_admin" and p.orgs.membership_role(u, org) == "org_admin"


def test_owner_set_member_role_audits_before_the_grant(flag_on, monkeypatch):
    from sigil.ui.provision import owner_set_member_role
    p, s = _prov()
    a = _signup(p)
    real = s.append

    def refuse_audit(**kw):
        if (kw.get("payload") or {}).get("signal") == "provision.audit":
            raise OSError("audit store unavailable")
        return real(**kw)

    monkeypatch.setattr(s, "append", refuse_audit)
    with pytest.raises(OSError):
        owner_set_member_role(s, a["org_id"], a["username"], "org_admin", reason="x", issued_at=9e9)
    monkeypatch.setattr(s, "append", real)
    assert p.orgs.membership_role(a["username"], a["org_id"]) == "founder"     # no grant without its audit


def test_demote_founders_is_idempotent_and_prints_counts_only(flag_on, monkeypatch, tmp_path, capsys):
    s = _cli_store(monkeypatch, tmp_path)
    p, _ = _prov(store=s)
    a = _signup(p)
    b = _signup(p, email="b@beta-founder.io", org="Beta")
    monkeypatch.setenv(FLAG, "0")
    c = _signup(p, email="c@gamma-founder.io", org="Gamma")             # an org_admin org, untouched
    assert _run_cli(["org", "demote-founders", "--org", b["org_id"], "--reason", "one org"]) == 0
    assert "demoted 1 founder membership(s) to org_admin in 1 org(s)" in capsys.readouterr().out
    assert _run_cli(["org", "demote-founders", "--reason", "rollback"]) == 0
    out = capsys.readouterr().out
    assert "demoted 1 founder membership(s) to org_admin in 1 org(s)" in out
    assert a["username"] not in out and "@" not in out
    assert _run_cli(["org", "demote-founders", "--reason", "rollback"]) == 0
    assert "demoted 0 founder membership(s)" in capsys.readouterr().out
    for x in (a, b, c):
        assert p.orgs.membership_role(x["username"], x["org_id"]) == "org_admin"
    assert len(_audits(s, "owner_demote_founder")) == 2
    assert _run_cli(["org", "demote-founders", "--reason", ""]) == 2


def test_rollback_procedure_demote_founders_leaves_an_administrator_an_earlier_build_recognises(
        flag_on, monkeypatch):
    from vigil_core import rbac

    from sigil.ui.provision import _member_admins, owner_demote_founders
    p, s = _prov()
    a = _signup(p)
    org = a["org_id"]
    earlier = {k: v for k, v in rbac.PERMISSIONS.items() if k != "founder"}   # a build without the role
    monkeypatch.setattr(rbac, "PERMISSIONS", earlier)
    assert _member_admins(p.orgs, org) == set()
    assert owner_demote_founders(s, reason="rollback", issued_at=9e9) == {"demoted": 1, "orgs": 1}
    assert _member_admins(p.orgs, org) == {a["username"]}


# --- payment and trial never change a role ---------------------------------------------------------------------

def test_a_verified_topup_and_a_trial_grant_write_no_membership_record(flag_on):
    from sigil.governor import catalog as cat
    from sigil.governor.billing import EVENT_TOPUP, BillingEvent, BillingSigner, MockBillingProvider
    from sigil.governor.invoices import InvoiceRegistry
    from sigil.governor.metering import PlanCreditLedger
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.governor.wallet import WalletRegistry
    p, s = _prov(trial=True)
    a = _signup(p)
    org = a["org_id"]
    assert p.wallet.has_grant_entry(org, f"trial-preview:{org}")
    before = sum(1 for _ in s.iter_records())
    signer = BillingSigner(MockBillingProvider("sek"), wallet=WalletRegistry(s), subscriptions=SubscriptionRegistry(s),
                           plan=PlanCreditLedger(s), catalog=cat.mintable_entitlements(),
                           expected=cat.mintable_expected(), invoices=InvoiceRegistry(s))
    top = next(e for e in cat._CATALOG if e.kind == EVENT_TOPUP)
    assert signer.apply(BillingEvent(event_id="evt_f1", kind=EVENT_TOPUP, org_id=org, created=100.0,
                                     price_id=top.price_id, amount_minor=top.amount_minor,
                                     currency=top.currency), now=100.0) is not None
    with p._lock:
        assert p._grant_signup_trial(org, "founder@acme-founder.io", source_ref="again") == "granted"
    new = [r.payload for i, r in enumerate(s.iter_records()) if i >= before]
    assert new and not any(isinstance(x, dict) and x.get("signal") == MEMBERSHIP_SIGNAL for x in new)
    assert p.orgs.membership_role(a["username"], org) == "founder"


# --- never a global role ---------------------------------------------------------------------------------------

def test_founder_is_never_an_account_role_and_carries_nothing_globally():
    from sigil.governor import accounts as acc
    from sigil.governor.orgs import OrgRegistry
    from sigil.ui.server import Handler
    for role in ("founder", "org_admin", "assessment_viewer"):
        with pytest.raises(ValueError):
            acc._check_role(role)
    p, s = _prov()
    a = _signup(p)
    pj = Handler._principal_json(None, acc.Principal(username="mallory", role="founder"))
    assert pj["role"] == "founder" and pj["permissions"] == []
    reg = OrgRegistry(s)
    for perm in ("read", "run_engagement", "view_assessments", "manage_billing"):
        assert reg.admit(global_role="founder", username="mallory", org_id=a["org_id"], permission=perm) is False
    assert reg.admit(global_role="operator", username="mallory", org_id=a["org_id"], permission="read") is True


def test_the_env_example_ships_the_production_value_and_leaves_step_up_unset():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, "deploy", "cockpit.env.example"), encoding="utf-8").read()
    lines = [ln.strip() for ln in text.splitlines()]
    assert "VIGIL_SIGNUP_FOUNDER_TESTER_ENABLED=1" in lines
    assert "VIGIL_TRIAL_PREVIEW_ENABLED=1" in lines                # the founder role needs the preview on
    assert not any(ln.startswith(("VIGIL_CUSTOMER_STEPUP_REQUIRED=", "VIGIL_CUSTOMER_PROD_EXECUTION=")) for ln in lines)
    assert "VIGIL_SETTLE_SPINE_RECORD=1" in lines                  # OD-4: the owner's production value


# --- the owner's founder_tester latch: OFF withholds the founder role from NEW sign-ups only -------------------

def test_the_founder_tester_latch_off_signs_up_org_admins_and_leaves_existing_founders(flag_on):
    from sigil.governor import customer_latch as cl
    from sigil.ui.provision import ProvisionDenied
    p, s = _prov(idp=_StubIdP(), trial=True)
    before = _signup(p, email="early@early-founder.io", org="Early")
    assert p.orgs.membership_role(before["username"], before["org_id"]) == "founder"
    cl.turn_off(s, "founder_tester", owner_key=None)          # the phone's OFF: unsigned, honoured at once
    a = _signup(p)
    g = p.oidc_finish(code="c", code_verifier="v", nonce="n", ip="1.2.3.4")
    for user, org in ((a["username"], a["org_id"]), (g["username"], g["orgs"][0])):
        assert p.orgs.membership_role(user, org) == "org_admin"      # the sign-up completes, with no testing
        with pytest.raises(ProvisionDenied):
            p.target_challenge(user, org, "acme-founder.io")
    assert p.orgs.membership_role(before["username"], before["org_id"]) == "founder"   # existing: unchanged
    assert [r.get("role") for r in _audits(s, "signup")] == ["founder", "org_admin", "org_admin"]


def test_the_founder_tester_latch_never_widens_the_environment(monkeypatch):
    # with the founder flag off the latch is not even read, and ON grants nothing beyond org_admin
    from sigil.ui import provision
    monkeypatch.setenv(PREVIEW, "1")
    calls: list = []
    assert provision._signup_role(lambda: calls.append(1) or True) == "org_admin" and calls == []
    monkeypatch.setenv(FLAG, "1")
    assert provision._signup_role(lambda: True) == "founder"
    assert provision._signup_role(lambda: False) == "org_admin"


def test_an_unreadable_founder_tester_latch_signs_up_an_org_admin(flag_on, monkeypatch):
    from sigil.governor import customer_latch as cl
    p, _s = _prov(trial=True)

    real = cl.CapabilityGate.reader

    class _Unreadable:                                     # only the founder_tester read fails
        def __init__(self, inner):
            self.inner = inner

        def is_enabled(self, name):
            if name == "founder_tester":
                raise OSError("spine unreadable")
            return self.inner.is_enabled(name)
    monkeypatch.setattr(cl.CapabilityGate, "reader", lambda *a, **k: _Unreadable(real(*a, **k)))
    a = _signup(p)
    assert p.orgs.membership_role(a["username"], a["org_id"]) == "org_admin"
