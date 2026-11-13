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
