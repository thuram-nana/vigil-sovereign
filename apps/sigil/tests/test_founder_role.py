"""The founder role (owner-approved): the signing-up customer may self-serve scans on hosts the org proves.

Load-bearing invariants (each a mutation target):
  * flag OFF (code default): both sign-up paths grant `org_admin` exactly as before — no testing;
  * flag ON: both sign-up paths grant `founder` (server-set, read at the committing attempt); the founder can
    request a challenge, verify ONLY with the inline authorization affirmation, and reserve a launch on a host
    the org proved and the owner key authorized. No proof / no authority is still refused. A trial-preview org
    stays limited to the trial product and one registrable domain;
  * changing or revoking a founder is owner-only: customer member management refuses a founder target (the
    founder included, on themself), never grants `founder`/`operator`, and counts the founder as an
    administrator for the last-admin rule;
  * the kill switch: flag OFF admits an existing founder as `org_admin` (no testing, billing kept), with no spine
    write; flag ON restores it;
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
_clock = itertools.count(1)
_PW = "customer-pw-123"


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared authority seam
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    for var in (FLAG, "VIGIL_CUSTOMER_STEPUP_REQUIRED", "VIGIL_TRIAL_PREVIEW_ENABLED", "VIGIL_TIERED_PRODUCTS",
                "VIGIL_TRIAL_PRODUCT_ID", "VIGIL_ONE_LAUNCH_PER_HOST"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def flag_on(monkeypatch):
    monkeypatch.setenv(FLAG, "1")


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


@pytest.mark.parametrize("first, second, want", [("1", "0", "org_admin"), ("0", "1", "founder")])
def test_signup_retry_across_a_flag_flip_commits_one_trial_with_the_committing_role(monkeypatch, first, second,
                                                                                    want):
    from sigil.ui.provision import Provisioner
    p, s = _prov()
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
    assert p.wallet.has_grant_entry(out["org_id"], f"trial:{out['org_id']}")
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
    p, s = _prov()
    a = _signup(p)
    org = a["org_id"]
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
    assert not any(ln.startswith(("VIGIL_CUSTOMER_STEPUP_REQUIRED=", "VIGIL_CUSTOMER_PROD_EXECUTION=",
                                  "VIGIL_SETTLE_SPINE_RECORD=")) for ln in lines)
