"""Slice E2b — customer Google-OIDC login: the identity provider (verify) + the provisioner tail
(oidc_finish: resolve-or-auto-provision, anti-takeover, signup cap) + the egress allowlist.

Load-bearing invariants (a false-green here is a customer-account-takeover or a cross-plane break):
  * the provider RE-EXECUTES the id_token crypto and applies the customer gate: email_verified STRICTLY the
    boolean True; the (iss,sub) pair is the binding; a bad nonce / missing sub / alg:none is refused;
  * oidc_finish auto-provisions a PASSWORDLESS customer+org+trial on a first verified sign-in and logs the
    SAME customer in on a second; it NEVER auto-attaches Google to an existing PASSWORD account by email
    (anti-takeover); the binding is (iss,sub), never the email;
  * the auto-provisioned customer is a governor.customer with an owner-signed (iss,sub) credential — NEVER a
    governor.account (AccountsRegistry resolves it to None) — so a Google login can never be an operator;
  * the global signup cap bounds Google auto-provision exactly as it bounds email signup;
  * the provisioner's OIDC egress is host-allowlisted (an off-allowlist token/JWKS host is refused).
"""
from __future__ import annotations

import base64
import itertools
import json
import tempfile

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sigil.governor.accounts import AccountsRegistry
from sigil.governor.customer_credentials import CustomerCredentialRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.customer_identity import (METHOD_GOOGLE_OIDC, CustomerIdentity, GoogleOidcIdentityProvider,
                                        IdentityRefused)
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.oidc import OidcConfig, OidcError, host_allowlisted_transport
from sigil.ui.provision import (ProvisionDenied, ProvisionError, ProvisionRateLimited, Provisioner,
                                _federated_username)

OWNER = generate_keypair()
OP = OWNER.public_key_b64

ISS = "https://accounts.google.com"
NONCE = "login-nonce-xyz"
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

CFG = OidcConfig(
    issuer=ISS, client_id="client-123", client_secret="the-secret",
    redirect_uri="https://app.vigil.example/api/customer/oidc/callback",
    authorize_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
    token_endpoint="https://oauth2.googleapis.com/token",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    scopes="openid email", username_claim="sub", signing_algs=("RS256",), clock_skew_seconds=60)


# ---- a loopback fake Google (no network): sign a real RS256 id_token the core actually verifies ----------
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _int_b64(n: int) -> str:
    return _b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def _jwk() -> dict:
    pub = RSA_KEY.public_key().public_numbers()
    return {"kty": "RSA", "kid": "test-kid", "alg": "RS256", "use": "sig",
            "n": _int_b64(pub.n), "e": _int_b64(pub.e)}


def _jwks_fetcher(_url):
    return {"keys": [_jwk()]}


def _sign_idtoken(claims: dict, *, alg="RS256") -> str:
    header = {"alg": alg, "kid": "test-kid", "typ": "JWT"}
    h, p = _b64u(json.dumps(header).encode()), _b64u(json.dumps(claims).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    if alg == "none":
        return f"{h}.{p}."
    sig = RSA_KEY.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64u(sig)}"


def _base_claims(**over) -> dict:
    c = {"iss": ISS, "sub": "google-sub-1", "aud": "client-123", "exp": 4600, "iat": 1000,
         "nonce": NONCE, "email": "alice@gmail.com", "email_verified": True}
    c.update(over)
    return c


def _poster_for(claims: dict, *, alg="RS256"):
    def _post(_url, _form):
        return {"id_token": _sign_idtoken(claims, alg=alg)}
    return _post


def _provider(claims: dict, *, alg="RS256") -> GoogleOidcIdentityProvider:
    return GoogleOidcIdentityProvider(CFG, http_post=_poster_for(claims, alg=alg),
                                      jwks_fetcher=_jwks_fetcher, now_fn=lambda: 1000.0)


# ---- the provider: crypto + the customer gate ------------------------------------------------------------
def test_provider_verifies_a_good_google_identity():
    idn = _provider(_base_claims()).verify(code="c", code_verifier="v", nonce=NONCE)
    assert idn.method == METHOD_GOOGLE_OIDC and idn.email == "alice@gmail.com" and idn.email_verified is True
    assert idn.federated_iss == ISS and idn.federated_sub == "google-sub-1"


@pytest.mark.parametrize("ev", [False, "true", "True", 1, 0, None])
def test_provider_refuses_non_boolean_email_verified(ev):
    # STRICT: only the JSON boolean True passes. A string "true", a 1, or an absent claim is REFUSED — the
    # auto-provision path must never trust a laxly-"verified" address.
    claims = _base_claims()
    if ev is None:
        claims.pop("email_verified")
    else:
        claims["email_verified"] = ev
    with pytest.raises(IdentityRefused):
        _provider(claims).verify(code="c", code_verifier="v", nonce=NONCE)


def test_provider_refuses_bad_nonce_missing_sub_and_alg_none():
    with pytest.raises(IdentityRefused):                       # nonce mismatch (id_token replay / mix-up)
        _provider(_base_claims()).verify(code="c", code_verifier="v", nonce="OTHER")
    with pytest.raises(IdentityRefused):                       # no (iss,sub) binding
        _provider(_base_claims(sub="")).verify(code="c", code_verifier="v", nonce=NONCE)
    with pytest.raises(IdentityRefused):                       # alg:none (algorithm-confusion, inherited)
        _provider(_base_claims(), alg="none").verify(code="c", code_verifier="v", nonce=NONCE)


# ---- the provisioner tail: resolve-or-auto-provision, anti-takeover, cap ---------------------------------
class _StubIdP:
    """A minimal provider stand-in so oidc_finish's resolve / auto-provision / anti-takeover / cap logic is
    tested apart from the crypto (the real provider is exercised above and in the end-to-end test)."""
    method = METHOD_GOOGLE_OIDC

    def __init__(self, identity=None, *, raises=False):
        self.identity, self.raises = identity, raises

    def verify(self, **_ctx):
        if self.raises:
            raise IdentityRefused("stub refuse")
        return self.identity


def _idn(sub="google-sub-1", email="alice@gmail.com"):
    return CustomerIdentity(method=METHOD_GOOGLE_OIDC, email=email, email_verified=True,
                            federated_iss=ISS, federated_sub=sub)


def _prov(idp=None, *, signup_cap=None):
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    wallet = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    creds = CustomerCredentialRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    tokens = EmailTokenLedger(tempfile.mkdtemp(), ttl_s=10_000.0)
    rl = LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=10_000.0, base_lock_s=50.0)
    clock = itertools.count(1)
    p = Provisioner(s, customers=custs, orgs=orgs, wallet=wallet, email_tokens=tokens, rate_limiter=rl,
                    customer_credentials=creds, oidc_provider=idp, signup_cap_limiter=signup_cap,
                    email_sender=NullEmailSender(), trial_credits=100, expose_dev_tokens=True,
                    now_fn=lambda: float(next(clock)))
    return p, s, creds


def test_oidc_finish_auto_provisions_then_logs_in_the_same_customer():
    idp = _StubIdP(_idn(sub="sub-A", email="a@gmail.com"))
    p, s, creds = _prov(idp)
    first = p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="1.2.3.4")
    assert first["username"].startswith("cust_") and len(first["orgs"]) == 1
    u, org = first["username"], first["orgs"][0]
    # the (iss,sub) binding was owner-signed + resolves; a trial was granted; it is NOT an operator account
    assert creds.by_federated(ISS, "sub-A") == u
    assert WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP).available(org) == 100
    assert AccountsRegistry(s).account(u) is None               # a Google customer is NEVER an operator account
    # a SECOND sign-in (same iss,sub) logs the SAME customer in — no new org, no doubled trial
    second = p.oidc_finish(code="c2", code_verifier="v2", nonce=NONCE, ip="1.2.3.4")
    assert second == {"username": u, "orgs": [org]}
    assert WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP).available(org) == 100  # trial not re-granted


def test_oidc_finish_refuses_email_already_owned_by_a_password_account_no_link():
    # ANTI-TAKEOVER: a verified Google email that collides with an EXISTING password customer is refused —
    # Google is never auto-attached by email; no federated binding is written.
    idp = _StubIdP(_idn(sub="sub-takeover", email="victim@acme.com"))
    p, s, creds = _prov(idp)
    # a password customer already owns victim@acme.com (email signup)
    tok = p.request_signup("victim@acme.com", ip="9.9.9.9", now=100.0)["dev_token"]
    pw_user = p.confirm_signup(tok, password="password-1", org_name="Victim", now=100.0)["username"]
    with pytest.raises(ProvisionDenied):
        p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="1.2.3.4")
    assert creds.by_federated(ISS, "sub-takeover") is None      # no binding minted
    assert CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP).by_email("victim@acme.com").username == pw_user
    # and the attacker's federated id maps to NO customer (never created)
    assert CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP).customer(
        _federated_username(ISS, "sub-takeover")) is None


def test_oidc_finish_two_distinct_google_accounts_are_separate_customers():
    idp = _StubIdP()
    p, _s, creds = _prov(idp)
    idp.identity = _idn(sub="sub-A", email="a@gmail.com")
    a = p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="1.1.1.1")
    idp.identity = _idn(sub="sub-B", email="b@gmail.com")
    b = p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="2.2.2.2")
    assert a["username"] != b["username"] and a["orgs"] != b["orgs"]
    assert creds.by_federated(ISS, "sub-A") == a["username"]
    assert creds.by_federated(ISS, "sub-B") == b["username"]


def test_oidc_finish_is_bound_by_iss_sub_not_email():
    # The resolver is (iss,sub); a different Google sub re-using the SAME email string still auto-provisions a
    # fresh customer (it is not the first one), proving the email is only a hint, never the binding. (The two
    # cannot collide in reality — Google emails are unique — but the resolver must not key on email.)
    idp = _StubIdP()
    p, _s, _creds = _prov(idp)
    idp.identity = _idn(sub="sub-A", email="same@gmail.com")
    a = p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="1.1.1.1")
    idp.identity = _idn(sub="sub-A", email="same@gmail.com")    # same sub -> same customer (login)
    again = p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="1.1.1.1")
    assert again["username"] == a["username"]


def test_oidc_finish_honours_the_global_signup_cap():
    cap = LoginRateLimiter(tempfile.mkdtemp(), max_fails=1, window_s=86400.0, base_lock_s=86400.0,
                           max_lock_s=86400.0)
    idp = _StubIdP()
    p, _s, _creds = _prov(idp, signup_cap=cap)
    idp.identity = _idn(sub="sub-A", email="a@gmail.com")
    p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="1.1.1.1")       # first auto-provision -> charges cap
    idp.identity = _idn(sub="sub-B", email="b@gmail.com")
    with pytest.raises(ProvisionRateLimited):
        p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="2.2.2.2")   # cap reached -> refused before mint


def test_oidc_finish_refused_identity_is_a_denial_and_counts_against_the_ip():
    p, _s, creds = _prov(_StubIdP(raises=True))
    with pytest.raises(ProvisionDenied):
        p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="1.2.3.4")
    assert creds.by_federated(ISS, "sub-A") is None             # nothing minted on a refused identity


def test_oidc_finish_fail_closed_when_not_configured():
    p, _s, _creds = _prov(idp=None)                             # oidc_provider None (customer OIDC off)
    with pytest.raises(ProvisionError):
        p.oidc_finish(code="c", code_verifier="v", nonce=NONCE, ip="1.2.3.4")


def test_oidc_finish_end_to_end_with_the_real_provider():
    # the REAL GoogleOidcIdentityProvider (fake IdP over the injected transport) through oidc_finish -> mint
    prov = _provider(_base_claims(sub="e2e-sub", email="e2e@gmail.com"))
    p, s, creds = _prov(prov)
    out = p.oidc_finish(code="auth-code", code_verifier="pkce-verifier", nonce=NONCE, ip="1.2.3.4")
    assert out["username"] == _federated_username(ISS, "e2e-sub")
    assert creds.by_federated(ISS, "e2e-sub") == out["username"]
    assert AccountsRegistry(s).account(out["username"]) is None


# ---- the config split: the keyless edge NEVER reads the client secret -----------------------------------
def test_customer_oidc_public_settings_never_carries_the_secret(monkeypatch):
    # the EDGE reads customer_oidc_public_settings() to build the authorize 302; it must NEVER carry the
    # client secret (that lives only in the provisioner's customer_oidc_settings()).
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_CLIENT_SECRET", "super-secret")
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_CLIENT_ID", "cid")
    from sigil import config
    assert config.customer_oidc_public_settings()["client_secret"] == ""        # edge: blank, always
    assert config.customer_oidc_settings()["client_secret"] == "super-secret"    # provisioner: the real secret


# ---- the egress allowlist (the provisioner's SSRF floor for the token/JWKS calls) ------------------------
def test_host_allowlisted_transport_refuses_off_allowlist_and_non_https():
    post, fetch = host_allowlisted_transport({"oauth2.googleapis.com", "www.googleapis.com"})
    with pytest.raises(OidcError):
        post("https://evil.example.com/token", {})             # off-allowlist host
    with pytest.raises(OidcError):
        fetch("https://metadata.internal/jwks")                # off-allowlist host (SSRF target)
    with pytest.raises(OidcError):
        post("http://oauth2.googleapis.com/token", {})         # non-https even for an allowed host
