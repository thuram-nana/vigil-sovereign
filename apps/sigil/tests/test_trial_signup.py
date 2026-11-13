"""S3a — the sign-up trial: size validation, the preview marker, one trial per canonical mailbox.

Load-bearing invariants (each a mutation target):
  * the trial size is validated at construction (an int in [0, TRIAL_MAX]); 0 means "no trial" and the sign-up
    still commits; a negative / non-int size fails at boot, before anything is appended;
  * VIGIL_TRIAL_PREVIEW_ENABLED OFF: the record is the legacy `trial:<org>` grant, exactly as before;
  * ON: the grant uses `trial-preview:<org>` and writes an owner-signed email claim on the canonical mailbox; a
    second sign-up from the same canonical mailbox (a "+tag" or gmail-dot variant, or a revoked account's
    mailbox) commits with NO trial and a generic `trial: "unavailable"`;
  * at most one trial per org whatever the flag does between retries; every append precedes the commit marker,
    so a crash at any point heals on the retry with exactly one grant.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.trial_claim import TrialClaimRegistry, key_digest
from sigil.governor.trial_policy import TRIAL_MAX, canonical_email
from sigil.governor.wallet import CREDIT_GRANT_SIGNAL, WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import Provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_FLAG = "VIGIL_TRIAL_PREVIEW_ENABLED"


def _prov(trial_credits=100, *, claims=True, store=None):
    s = store or SpineStore(tempfile.mktemp(suffix=".jsonl"))
    k = {"owner_key": OWNER, "trusted_pubkey": OP}
    wallet = WalletRegistry(s, **k)
    tc = TrialClaimRegistry(s, **k) if claims else None
    clock = itertools.count(1)
    p = Provisioner(s, customers=CustomerRegistry(s, **k), orgs=OrgRegistry(s, **k), wallet=wallet,
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=10_000.0),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=10_000.0,
                                                  base_lock_s=50.0),
                    email_sender=NullEmailSender(), trial_credits=trial_credits, trial_claims=tc,
                    expose_dev_tokens=True, now_fn=lambda: float(next(clock)))
    return p, s, wallet, tc


def _signup(p, email, ip="1.1.1.1"):
    tok = p.request_signup(email, ip=ip, now=100.0)["dev_token"]
    return p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", now=100.0)


def _grants(s):
    return [r.payload for r in s.iter_records() if r.payload.get("signal") == CREDIT_GRANT_SIGNAL]


# --- canonical mailbox -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("a, b, same", [
    ("jdoe@gmail.com", "J.Doe+x@GoogleMail.com", True),
    ("a@acme.io", "a+1@acme.io", True),
    ("  A@Acme.IO ", "a@acme.io", True),
    ("j.doe@acme.io", "jdoe@acme.io", False),      # dots fold only for gmail
    ("a@acme.io", "b@acme.io", False),
])
def test_canonical_email(a, b, same):
    assert (canonical_email(a) == canonical_email(b)) is same


@pytest.mark.parametrize("bad", ["", "a@", "@acme.io", "noatsign", "+tag@acme.io"])
def test_canonical_email_rejects_unusable_addresses(bad):
    assert canonical_email(bad) == ""


# --- (a) trial size validation (not behind a flag) --------------------------------------------------------------

@pytest.mark.parametrize("bad", [-5, "x", 1.5, True, TRIAL_MAX + 1])
def test_bad_trial_size_fails_at_construction_and_appends_nothing(bad):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    with pytest.raises(ValueError):
        _prov(bad, store=s)
    assert s.count() == 0


@pytest.mark.parametrize("flag", ["", "1"])
def test_zero_trial_commits_the_signup_with_no_grant(monkeypatch, flag):
    monkeypatch.setenv(_FLAG, flag)
    p, s, wallet, tc = _prov(0)
    tok = p.request_signup("z@acme.io", ip="1.1.1.1", now=100.0)["dev_token"]
    out = p.confirm_signup(tok, password="customer-pw-1", org_name="Z", now=100.0)
    assert out["org_id"] and wallet.available(out["org_id"]) == 0 and _grants(s) == []
    assert "trial" not in out
    with pytest.raises(Exception):                                 # the token was consumed: a retry is refused
        p.confirm_signup(tok, password="customer-pw-1", org_name="Z", now=100.0)
    assert _grants(s) == []


# --- (b) flag OFF: unchanged ------------------------------------------------------------------------------------

def test_flag_off_grants_the_legacy_trial_and_writes_no_claim(monkeypatch):
    monkeypatch.delenv(_FLAG, raising=False)
    p, s, wallet, tc = _prov()
    out = _signup(p, "a@acme.io")
    [g] = _grants(s)
    assert g["entry_id"] == f"trial:{out['org_id']}" and g["source_ref"] == "signup" and g["credits"] == 100
    assert tc.claims_of(out["org_id"]) == [] and "trial" not in out


# --- (b) flag ON ------------------------------------------------------------------------------------------------

def test_flag_on_grants_the_preview_trial_and_claims_the_mailbox(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    out = _signup(p, "a@acme.io")
    [g] = _grants(s)
    assert g["entry_id"] == f"trial-preview:{out['org_id']}" and g["source_ref"] == "signup"
    assert wallet.available(out["org_id"]) == 100
    assert tc.claimant("email", key_digest("email", "a@acme.io")) == out["org_id"]


@pytest.mark.parametrize("first, second", [
    ("jdoe@gmail.com", "J.Doe+x@GoogleMail.com"),
    ("a@acme.io", "a+1@acme.io"),
])
def test_a_second_signup_from_the_same_mailbox_gets_no_trial(monkeypatch, first, second):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _signup(p, first)
    out = _signup(p, second, ip="2.2.2.2")
    assert out["trial"] == "unavailable" and wallet.available(out["org_id"]) == 0
    assert len(_grants(s)) == 1


@pytest.mark.parametrize("first, second", [("a@acme.io", "b@acme.io"), ("j.doe@acme.io", "jdoe@acme.io")])
def test_distinct_mailboxes_each_get_a_trial(monkeypatch, first, second):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _signup(p, first)
    out = _signup(p, second, ip="2.2.2.2")
    assert "trial" not in out and wallet.available(out["org_id"]) == 100


def test_a_revoked_customers_mailbox_gets_no_second_trial(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    first = _signup(p, "a@acme.io")
    p.customers.revoke(first["username"])
    out = _signup(p, "a+again@acme.io", ip="2.2.2.2")
    assert out["trial"] == "unavailable" and wallet.available(out["org_id"]) == 0


def test_flag_on_without_a_claim_ledger_grants_nothing(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, _ = _prov(claims=False)
    out = _signup(p, "a@acme.io")
    assert out["trial"] == "unavailable" and _grants(s) == []


# --- retries and crashes ----------------------------------------------------------------------------------------

def _crash_after(monkeypatch, obj, name):
    real = getattr(obj, name)
    state = {"armed": True}

    def wrapper(*a, **kw):
        out = real(*a, **kw)
        if state["armed"]:
            state["armed"] = False
            raise RuntimeError("crash")
        return out

    monkeypatch.setattr(obj, name, wrapper)


@pytest.mark.parametrize("crash_on", ["claim", "grant", "audit"])
def test_a_crash_at_any_point_heals_with_exactly_one_grant(monkeypatch, crash_on):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    target = {"claim": (tc, "claim"), "grant": (wallet, "grant"), "audit": (p, "_audit")}[crash_on]
    _crash_after(monkeypatch, *target)
    tok = p.request_signup("a@acme.io", ip="1.1.1.1", now=100.0)["dev_token"]
    with pytest.raises(RuntimeError):
        p.confirm_signup(tok, password="customer-pw-1", org_name="A", now=100.0)
    out = p.confirm_signup(tok, password="customer-pw-1", org_name="A", now=100.0)   # the token was only peeked
    assert wallet.available(out["org_id"]) == 100 and "trial" not in out
    assert len({g["entry_id"] for g in _grants(s)}) == 1


@pytest.mark.parametrize("first_flag, second_flag", [("1", ""), ("", "1")])
def test_the_flag_flipping_between_attempts_still_grants_once(monkeypatch, first_flag, second_flag):
    p, s, wallet, tc = _prov()
    _crash_after(monkeypatch, p, "_audit")
    monkeypatch.setenv(_FLAG, first_flag)
    tok = p.request_signup("a@acme.io", ip="1.1.1.1", now=100.0)["dev_token"]
    with pytest.raises(RuntimeError):
        p.confirm_signup(tok, password="customer-pw-1", org_name="A", now=100.0)
    monkeypatch.setenv(_FLAG, second_flag)
    out = p.confirm_signup(tok, password="customer-pw-1", org_name="A", now=100.0)
    assert wallet.available(out["org_id"]) == 100, "exactly one trial whatever the flag did between attempts"
    assert len({g["entry_id"] for g in _grants(s)}) == 1


# --- has_grant_entry --------------------------------------------------------------------------------------------

def test_has_grant_entry_is_per_org_and_per_entry(monkeypatch):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    w.grant("org_a", 5, "trial", entry_id="trial:org_a", issued_at=1.0)
    for flag in ("1", ""):
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", flag)
        assert w.has_grant_entry("org_a", "trial:org_a")
        assert not w.has_grant_entry("org_b", "trial:org_a")
        assert not w.has_grant_entry("org_a", "trial-preview:org_a")
        assert not w.has_grant_entry("", "")


# --- the Google sign-up path ------------------------------------------------------------------------------------

def _google(p, s, email, sub):
    from sigil.governor.customer_credentials import CustomerCredentialRegistry
    from sigil.ui.customer_identity import CustomerIdentity
    p.customer_credentials = CustomerCredentialRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    ident = CustomerIdentity(method="google-oidc", email=email, email_verified=True,
                             federated_iss="https://accounts.google.com", federated_sub=sub)
    with p._lock:
        p._link_or_provision_federated(ident, now=100.0)


def test_google_signup_follows_the_same_rules(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _signup(p, "jdoe@gmail.com")
    _google(p, s, "j.doe+g@googlemail.com", "sub-1")          # the same canonical mailbox: no second trial
    _google(p, s, "other@gmail.com", "sub-2")
    entries = sorted(g["entry_id"].split(":")[0] + ":" + g["source_ref"] for g in _grants(s))
    assert entries == ["trial-preview:signup", "trial-preview:signup-google"]
    monkeypatch.delenv(_FLAG)
    _google(p, s, "legacy@gmail.com", "sub-3")
    assert sum(1 for g in _grants(s) if g["entry_id"].startswith("trial:")) == 1


def test_a_google_identity_without_a_mailbox_gets_no_preview_trial(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _google(p, s, "", "sub-nomail")
    assert _grants(s) == [], "no mailbox to key the one-per-mailbox limit on: no preview trial"


# --- (d) the per-canonical-mailbox sign-up limiter --------------------------------------------------------------

def _limited(max_fails=3):
    from sigil.ui.login_ratelimit import LoginRateLimiter
    p, s, wallet, tc = _prov()
    p.signup_email_limiter = LoginRateLimiter(tempfile.mkdtemp(), max_fails=max_fails, window_s=3600.0,
                                              base_lock_s=3600.0, max_lock_s=3600.0)
    return p


def test_the_mailbox_limiter_trips_across_many_ips_and_aliases():
    from sigil.ui.provision import ProvisionRateLimited
    p = _limited(3)
    for i, alias in enumerate(["a@acme.io", "a+1@acme.io", "A+2@acme.io"]):
        p.request_signup(alias, ip=f"10.0.0.{i}", now=100.0)
    with pytest.raises(ProvisionRateLimited):
        p.request_signup("a+3@acme.io", ip="10.0.0.9", now=101.0)
    p.request_signup("b@acme.io", ip="10.0.0.10", now=101.0)        # another mailbox is unaffected


def test_the_mailbox_limiter_is_not_counted_when_the_ip_guard_refused():
    from sigil.ui.provision import ProvisionRateLimited
    p = _limited(2)
    p.rate_limiter.check = lambda *k, now=None: 999.0              # the per-ip guard refuses every request
    for _ in range(5):
        with pytest.raises(ProvisionRateLimited):
            p.request_signup("victim@acme.io", ip="6.6.6.6", now=100.0)
    assert p.signup_email_limiter.locked("signup:mailbox:victim@acme.io", now=100.0) is None


# --- (e) owner backfill -----------------------------------------------------------------------------------------

def test_backfill_claims_every_existing_mailbox_once(monkeypatch):
    from sigil.governor.trial_claim import BACKFILL_HOLDER, backfill_email_claims
    monkeypatch.delenv(_FLAG, raising=False)
    p, s, wallet, tc = _prov()
    a = _signup(p, "a@acme.io")
    b = _signup(p, "Jdoe@gmail.com", ip="2.2.2.2")
    p.customers.create("loose@acme.io", password="customer-pw-9", username="loose", issued_at=9_000.0)
    r = backfill_email_claims(p.customers, p.orgs, tc, canonical=canonical_email, issued_at=10_000.0)
    assert r == {"claimed": 3, "skipped": 0, "unusable": 0}
    assert tc.claimant("email", key_digest("email", "a@acme.io")) == a["org_id"]
    assert tc.claimant("email", key_digest("email", "jdoe@gmail.com")) == b["org_id"]
    assert tc.claimant("email", key_digest("email", "loose@acme.io")) == BACKFILL_HOLDER
    again = backfill_email_claims(p.customers, p.orgs, tc, canonical=canonical_email, issued_at=10_001.0)
    assert again == {"claimed": 0, "skipped": 3, "unusable": 0}
    monkeypatch.setenv(_FLAG, "1")
    out = _signup(p, "j.doe+new@googlemail.com", ip="3.3.3.3")      # an existing account's mailbox variant
    assert out["trial"] == "unavailable"


def test_backfill_cli_runs_end_to_end(tmp_path, monkeypatch, capsys):
    from pathlib import Path

    from sigil import cli, config
    from sigil.governor.identity import ensure_owner_keypair
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setattr(config, "SPINE_PATH", Path(tmp_path) / "spine" / "spine.jsonl")
    ensure_owner_keypair()
    try:
        cli.main(["trial", "backfill-claims"])
    except SystemExit as e:
        assert not e.code
    assert "trial claims: 0 claimed" in capsys.readouterr().out


def test_the_factory_wires_the_mailbox_limiter_only_when_configured(monkeypatch):
    from sigil import config
    from sigil.ui.provision import build_provisioner
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    monkeypatch.setattr(config, "SIGNUP_EMAIL_PER_HOUR", 0)
    assert build_provisioner(s).signup_email_limiter is None          # default OFF
    monkeypatch.setattr(config, "SIGNUP_EMAIL_PER_HOUR", 5)
    monkeypatch.setattr(config, "SIGNUP_EMAIL_RATELIMIT_DIR", tempfile.mkdtemp())
    assert build_provisioner(s).signup_email_limiter is not None
    assert build_provisioner(s).trial_claims is not None


def test_backfill_covers_revoked_legacy_accounts(monkeypatch):
    from sigil.governor.trial_claim import backfill_email_claims
    monkeypatch.delenv(_FLAG, raising=False)
    p, s, wallet, tc = _prov()
    first = _signup(p, "a@acme.io")                                 # legacy trial, no claim
    p.customers.revoke(first["username"])
    r = backfill_email_claims(p.customers, p.orgs, tc, canonical=canonical_email, issued_at=10_000.0)
    assert r["claimed"] == 1
    monkeypatch.setenv(_FLAG, "1")
    for i, addr in enumerate(["a@acme.io", "a+1@acme.io"]):
        out = _signup(p, addr, ip=f"9.9.9.{i}")
        assert out["trial"] == "unavailable" and wallet.available(out["org_id"]) == 0


def test_the_cockpit_refuses_to_start_with_a_bad_trial_size(monkeypatch):
    from sigil import config
    from sigil.ui import server
    monkeypatch.setattr(config, "TRIAL_CREDITS", -5)
    with pytest.raises(ValueError):
        server.build_server(token="t" * 32, port=0)
