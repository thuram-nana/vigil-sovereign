"""S3c — trial-abuse hardening at sign-up (preview ON only; default OFF):

  * a mailbox on a DISPOSABLE domain (vendored, sha256-pinned CC0 list, subdomains included) gets NO trial; the
    account is still created and can buy; a missing or tampered list means no preview trial (fail-closed);
  * an OPT-IN per-client-IP soft limit (VIGIL_TRIAL_IP_LIMIT_ENABLED, VIGIL_TRIAL_GRANTS_PER_IP) on preview trial
    grants: over the limit, or an unknown IP, means no trial; only granted trials count; the limiter stores only
    sha256(key); the email and Google paths both carry the IP;
  * with the preview OFF none of this runs (the legacy grant is unchanged).
"""
from __future__ import annotations

import os
import tempfile

import pytest

from test_trial_signup import _FLAG, _google, _grants, _prov

from sigil.governor import disposable_email as de
from sigil.ui.login_ratelimit import LoginRateLimiter


def _signup(p, email, ip):
    tok = p.request_signup(email, ip=ip, now=100.0)["dev_token"]
    return p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", ip=ip, now=100.0)


def _with_ip_limit(p, n=2):
    d = tempfile.mkdtemp()
    p.trial_ip_limiter = LoginRateLimiter(d, max_fails=n, window_s=86400.0, base_lock_s=86400.0,
                                          max_lock_s=86400.0)
    return d


@pytest.mark.parametrize("email", ["a@mailinator.com", "b@sub.mailinator.com", "C@Mailinator.COM"])
def test_a_disposable_mailbox_gets_no_trial_but_the_account_exists(monkeypatch, email):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    out = _signup(p, email, "1.1.1.1")
    assert out["trial"] == "unavailable" and out["org_id"] and wallet.available(out["org_id"]) == 0
    assert p.customers.by_email(email.strip().lower()) is not None


def test_a_normal_mailbox_still_gets_its_trial(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    out = _signup(p, "founder@acme.io", "1.1.1.1")
    assert "trial" not in out and wallet.available(out["org_id"]) == 100


def test_a_tampered_list_means_no_preview_trial(monkeypatch, tmp_path):
    monkeypatch.setenv(_FLAG, "1")
    bad = tmp_path / "list.conf"
    bad.write_text("mailinator.com\n")
    monkeypatch.setattr(de, "LIST_PATH", bad)
    monkeypatch.setattr(de, "load_domains", lambda path=bad, pin=de.LIST_SHA256: None)
    p, s, wallet, tc = _prov()
    assert _signup(p, "founder@acme.io", "1.1.1.1")["trial"] == "unavailable"


def test_the_pinned_list_loads_and_a_tampered_copy_does_not(tmp_path):
    assert de.load_domains() and "mailinator.com" in de.load_domains()
    bad = tmp_path / "l.conf"
    bad.write_bytes(de.LIST_PATH.read_bytes() + b"\nevil.example\n")
    assert de.load_domains(bad) is None
    assert de.is_disposable("x@acme.io", domains=frozenset({"mailinator.com"})) is False
    assert de.is_disposable("x@a.b.mailinator.com", domains=frozenset({"mailinator.com"})) is True
    assert de.is_disposable("not-an-email", domains=frozenset()) is None


def test_the_preview_off_path_ignores_both_checks(monkeypatch):
    monkeypatch.delenv(_FLAG, raising=False)
    p, s, wallet, tc = _prov()
    _with_ip_limit(p, 1)
    for i, email in enumerate(["a@mailinator.com", "b@acme.io", "c@acme.io"]):
        assert wallet.available(_signup(p, email, "9.9.9.9")["org_id"]) == 100


def test_the_per_ip_soft_limit(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    d = _with_ip_limit(p, 2)
    assert wallet.available(_signup(p, "a@acme.io", "5.5.5.5")["org_id"]) == 100
    assert wallet.available(_signup(p, "b@acme.io", "5.5.5.5")["org_id"]) == 100
    third = _signup(p, "c@acme.io", "5.5.5.5")
    assert third["trial"] == "unavailable" and wallet.available(third["org_id"]) == 0
    assert wallet.available(_signup(p, "d@acme.io", "6.6.6.6")["org_id"]) == 100     # another IP
    assert all("5.5.5.5" not in n for n in os.listdir(d))                               # stored hashed only


def test_refused_signups_do_not_count_toward_the_ip_limit(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _with_ip_limit(p, 1)
    for addr in ("x@mailinator.com", "y@mailinator.com"):
        _signup(p, addr, "7.7.7.7")
    assert wallet.available(_signup(p, "real@acme.io", "7.7.7.7")["org_id"]) == 100


def test_an_unknown_ip_gets_no_trial_when_the_limit_is_on(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _with_ip_limit(p, 5)
    assert _signup(p, "a@acme.io", "")["trial"] == "unavailable"


def test_the_google_path_carries_the_ip(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _with_ip_limit(p, 1)
    from sigil.governor.customer_credentials import CustomerCredentialRegistry
    from sigil.ui.customer_identity import CustomerIdentity
    from test_trial_signup import OP, OWNER
    p.customer_credentials = CustomerCredentialRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    for i, email in enumerate(["g1@gmail.com", "g2@gmail.com"]):
        ident = CustomerIdentity(method="google-oidc", email=email, email_verified=True,
                                 federated_iss="https://accounts.google.com", federated_sub=f"sub-{i}")
        with p._lock:
            p._link_or_provision_federated(ident, now=100.0, ip="8.8.4.4")
    assert len(_grants(s)) == 1


def test_the_factory_wires_the_ip_limit_only_when_enabled(monkeypatch):
    from sigil import config
    from sigil.spine.store import SpineStore
    from sigil.ui.provision import build_provisioner
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    monkeypatch.delenv("VIGIL_TRIAL_IP_LIMIT_ENABLED", raising=False)
    assert build_provisioner(s).trial_ip_limiter is None
    monkeypatch.setenv("VIGIL_TRIAL_IP_LIMIT_ENABLED", "1")
    monkeypatch.setattr(config, "TRIAL_IP_LIMIT_DIR", tempfile.mkdtemp())
    assert build_provisioner(s).trial_ip_limiter is not None


def test_oidc_finish_hands_the_client_ip_to_the_provisioning(monkeypatch):
    from types import SimpleNamespace
    p, s, wallet, tc = _prov()
    p.customer_credentials = SimpleNamespace(by_federated=lambda iss, sub: None)
    p.oidc_provider = SimpleNamespace(verify=lambda **kw: SimpleNamespace(federated_iss="i", federated_sub="s"))
    seen = {}

    def fake(identity, *, now, ip=""):
        seen["ip"] = ip
        raise RuntimeError("stop")
    monkeypatch.setattr(p, "_link_or_provision_federated", fake)
    with pytest.raises(RuntimeError):
        p.oidc_finish(code="c", code_verifier="v", nonce="n", ip="4.3.2.1")
    assert seen["ip"] == "4.3.2.1"


# --- review fold: retry resume, IPv6 /64, fail-closed limit, withheld reasons, the real client IP ---------------------

def _withheld(s):
    return [r.payload.get("reason") for r in s.iter_records()
            if r.payload.get("signal") == "provision.audit" and r.payload.get("action") == "trial"
            and r.payload.get("outcome") == "withheld"]


def _claim_mailbox(p, org_id, email):
    from sigil.governor.trial_claim import key_digest
    from sigil.governor.trial_policy import canonical_email
    p.trial_claims.claim("email", key_digest("email", canonical_email(email)), org_id, issued_at=p._next_issued())


def test_a_retry_after_the_mailbox_claim_resumes_to_the_grant(monkeypatch):
    """A sign-up that stopped between its mailbox claim and its grant resumes to the grant on retry, even when the
    per-IP limit is now reached and the list is now unavailable; a NEW mailbox under the same conditions is refused."""
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _with_ip_limit(p, 1)
    p.trial_ip_limiter.record_failure("trial:grant:ip:5.5.5.5", now=p._now())       # the IP is at its limit
    _claim_mailbox(p, "org_retry", "founder@acme.io")
    monkeypatch.setattr(de, "load_domains", lambda path=None, pin=None: None)        # and the list is now unavailable
    with p._lock:
        assert p._grant_signup_trial("org_retry", "founder@acme.io", source_ref="signup", ip="5.5.5.5") == "granted"
        assert p._grant_signup_trial("org_new", "other@acme.io", source_ref="signup", ip="5.5.5.5") == "unavailable"
    assert wallet.available("org_retry") == 100 and wallet.available("org_new") == 0


@pytest.mark.parametrize("ip, bucket", [
    ("5.5.5.5", "5.5.5.5"), (" 5.5.5.5 ", "5.5.5.5"), ("::ffff:5.5.5.5", "5.5.5.5"),
    ("2001:db8::1", "2001:db8::/64"), ("2001:DB8:0:0:ffff::9", "2001:db8::/64"), ("2001:db8:0:1::1", "2001:db8:0:1::/64"),
    ("", None), ("not-an-ip", None), ("5.5.5.5, 6.6.6.6", None),
])
def test_the_per_ip_bucket(ip, bucket):
    from sigil.ui.provision import _trial_ip_bucket
    assert _trial_ip_bucket(ip) == bucket


def test_the_per_ip_limit_counts_an_ipv6_slash64_as_one_client(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _with_ip_limit(p, 1)
    assert wallet.available(_signup(p, "a@acme.io", "2001:db8::1")["org_id"]) == 100
    assert _signup(p, "b@acme.io", "2001:db8::2")["trial"] == "unavailable"           # same /64
    assert wallet.available(_signup(p, "c@acme.io", "2001:db8:0:1::1")["org_id"]) == 100   # another /64
    assert wallet.available(_signup(p, "d@acme.io", "9.9.9.9")["org_id"]) == 100
    assert _signup(p, "e@acme.io", "::ffff:9.9.9.9")["trial"] == "unavailable"        # the same IPv4 client


def test_a_zero_per_ip_limit_with_the_flag_on_withholds_every_trial(monkeypatch):
    from sigil import config
    from sigil.ui.provision import build_provisioner
    monkeypatch.setenv("VIGIL_TRIAL_IP_LIMIT_ENABLED", "1")
    monkeypatch.setattr(config, "TRIAL_IP_LIMIT_DIR", tempfile.mkdtemp())
    for n in (0, -1):
        monkeypatch.setattr(config, "TRIAL_GRANTS_PER_IP", n)
        limiter = build_provisioner(__import__("sigil.spine.store", fromlist=["SpineStore"]).SpineStore(
            tempfile.mktemp(suffix=".jsonl"))).trial_ip_limiter
        assert limiter is not None and limiter.locked("trial:grant:ip:1.1.1.1") is not None
        monkeypatch.setenv(_FLAG, "1")
        p, s, wallet, tc = _prov()
        p.trial_ip_limiter = limiter
        out = _signup(p, f"n{n + 5}@acme.io", "1.1.1.1")
        assert out["trial"] == "unavailable" and wallet.available(out["org_id"]) == 0


def test_a_withheld_trial_records_why(monkeypatch):
    monkeypatch.setenv(_FLAG, "1")
    p, s, wallet, tc = _prov()
    _signup(p, "a@mailinator.com", "1.1.1.1")
    _with_ip_limit(p, 1)
    _signup(p, "b@acme.io", "")
    _signup(p, "c@acme.io", "2.2.2.2")
    _signup(p, "d@acme.io", "2.2.2.2")
    monkeypatch.setattr(de, "load_domains", lambda path=None, pin=None: None)
    _signup(p, "e@acme.io", "3.3.3.3")
    assert _withheld(s) == ["disposable", "ip_unknown", "ip_limit", "list_unavailable"]
    assert all("@" not in r for r in _withheld(s))                                   # no mailbox in the audit


def test_the_customer_vhost_restores_the_visitor_ip_from_cloudflare():
    """Behind Cloudflare the per-IP limits must key on the visitor, not the Cloudflare edge: the customer vhost
    trusts CF-Connecting-IP from exactly the ranges the public vhost trusts (one list, refreshed together)."""
    from pathlib import Path
    rp = Path(__file__).resolve().parents[1] / "deploy" / "reverse-proxy"

    def cf(name):
        text = (rp / name).read_text(encoding="utf-8")
        ranges = [ln.split()[1].rstrip(";") for ln in text.splitlines() if ln.strip().startswith("set_real_ip_from")]
        return ranges, any(ln.strip().startswith("real_ip_header CF-Connecting-IP;") for ln in text.splitlines())
    public, customer = cf("vigil-public.nginx.conf"), cf("vigil-customer.nginx.conf")
    assert public[0] and customer == public and customer[1] is True
