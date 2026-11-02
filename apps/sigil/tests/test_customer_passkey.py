"""Slice E3b-2 — customer passkey (WebAuthn): provisioner enroll_passkey + passkey_login (a full standalone
login) on the E2a customer-credential substrate, reusing the hardened ui/webauthn.py.

Load-bearing invariants:
  * enroll gates on verify_registration (type/challenge/origin) + the active-customer gate; owner-signs via
    the E2a enroll_passkey (GLOBAL uniqueness refuses a credential_id already bound to another customer);
  * login resolves the customer by credential_id (fail-closed on 0 / ambiguous — A's credential never
    resolves to B), verifies the assertion (signature + challenge + origin + rpIdHash + user-presence), and
    enforces the sign-count CLONE-FLOOR (a count <= the stored high-water is refused); a pure signature check;
  * the resolved username is a cust_ identity, NEVER a governor.account (a passkey login is never operator);
  * fail-closed when passkey is not enabled/configured, for a non-customer, a wrong challenge/origin/rp_id, a
    tampered signature, or an unknown credential.
"""
from __future__ import annotations

import base64
import hashlib
import itertools
import json
import tempfile

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sigil.governor.accounts import AccountsRegistry
from sigil.governor.customer_credentials import CustomerCredentialRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui import webauthn as wa
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionError, Provisioner
from sigil.ui.signcount import SignCountLedger

OWNER = generate_keypair()
OP = OWNER.public_key_b64
RP = "app.vigil.example"
ORIGIN = "https://app.vigil.example"


class SoftAuthenticator:
    """A software WebAuthn authenticator (ES256): signs registrations + assertions the real ui/webauthn.py
    verifies. `rp` / `origin` are overridable per call to model a phishing / wrong-rp attempt."""

    def __init__(self):
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.count = 0

    def spki_b64(self) -> str:
        return base64.b64encode(self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode("ascii")

    def _client_data(self, challenge: str, typ: str, origin: str) -> bytes:
        return json.dumps({"type": typ, "challenge": wa.b64url_nopad(challenge.encode()),
                           "origin": origin}).encode("utf-8")

    def register(self, challenge: str, *, origin: str = ORIGIN) -> dict:
        return {"client_data_json": wa.b64url_nopad(self._client_data(challenge, "webauthn.create", origin)),
                "public_key_spki_b64": self.spki_b64(), "cose_alg": -7}

    def assert_(self, challenge: str, *, count: "int | None" = None, origin: str = ORIGIN, rp: str = RP,
                tamper: bool = False) -> dict:
        self.count = (self.count + 1) if count is None else count
        ad = hashlib.sha256(rp.encode()).digest() + bytes([0x01]) + self.count.to_bytes(4, "big")
        cdj = self._client_data(challenge, "webauthn.get", origin)
        sig = self._key.sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper:
            sig = sig[:-1] + bytes([sig[-1] ^ 0x01])
        return {"authenticator_data": wa.b64url_nopad(ad), "client_data_json": wa.b64url_nopad(cdj),
                "signature": wa.b64url_nopad(sig)}


def _prov(monkeypatch, *, configured=True, signcount=True):
    if configured:
        monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_RP_ID", RP)
        monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ORIGINS", ORIGIN)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    creds = CustomerCredentialRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    clock = itertools.count(1)
    p = Provisioner(
        s, customers=custs, orgs=orgs, wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        customer_credentials=creds,
        signcount=(SignCountLedger(tempfile.mkdtemp()) if signcount else None),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: float(next(clock)))
    return p, s, custs, creds, orgs


def _customer(custs, orgs, email="pk@acme.com", username="cust_pk00000000000000000001", org="org_pk01"):
    custs.create(email, issued_at=1.0, password="password-xyz", username=username)
    orgs.create_org(org, "Acme", owner=username, issued_at=2.0)
    orgs.grant_membership(org, username, "org_admin", issued_at=3.0)
    return username, org


def _enroll(p, u, auth, cid="cred-abc123", challenge="enroll-chal"):
    reg = auth.register(challenge)
    return p.enroll_passkey(u, credential_id=cid, public_key_spki_b64=reg["public_key_spki_b64"],
                            cose_alg=reg["cose_alg"], uv=False, client_data_json=reg["client_data_json"],
                            expected_challenge=challenge)


def _login(p, auth, cid="cred-abc123", challenge="login-chal", **kw):
    a = auth.assert_(challenge, **kw)
    return p.passkey_login(credential_id=cid, authenticator_data=a["authenticator_data"],
                           client_data_json=a["client_data_json"], signature=a["signature"],
                           expected_challenge=challenge)


# ---- enroll + login round trip + isolation -----------------------------------------------------------
def test_enroll_then_login_resolves_the_customer_and_is_not_an_operator(monkeypatch):
    p, s, custs, creds, orgs = _prov(monkeypatch)
    u, org = _customer(custs, orgs)
    auth = SoftAuthenticator()
    assert _enroll(p, u, auth)["ok"] and creds.by_credential_id("cred-abc123").username == u
    assert _login(p, auth, count=5) == {"username": u, "orgs": [org]}
    assert AccountsRegistry(s).account(u) is None                  # a passkey customer is NEVER an operator


def test_enroll_refuses_wrong_origin_and_non_customer(monkeypatch):
    p, _s, custs, _creds, orgs = _prov(monkeypatch)
    u, _ = _customer(custs, orgs)
    auth = SoftAuthenticator()
    # a registration whose clientData.origin is not in the allowlist is refused
    reg = auth.register("ch", origin="https://evil.example")
    with pytest.raises(ProvisionDenied):
        p.enroll_passkey(u, credential_id="cred-x", public_key_spki_b64=reg["public_key_spki_b64"],
                         cose_alg=reg["cose_alg"], uv=False, client_data_json=reg["client_data_json"],
                         expected_challenge="ch")
    with pytest.raises(ProvisionDenied):                           # a ghost cannot enroll
        _enroll(p, "cust_ghost0000000000000000001", auth, cid="cred-ghost")


# ---- the sign-count clone-floor ----------------------------------------------------------------------
def test_signcount_clone_floor_refuses_a_replay_then_accepts_a_higher_count(monkeypatch):
    p, _s, custs, _creds, orgs = _prov(monkeypatch)
    u, _ = _customer(custs, orgs)
    auth = SoftAuthenticator()
    _enroll(p, u, auth)
    assert _login(p, auth, count=5)["username"] == u              # floor -> 5
    with pytest.raises(ProvisionDenied):                          # count 5 again (clone) -> not strictly greater
        _login(p, auth, challenge="c2", count=5)
    with pytest.raises(ProvisionDenied):                          # a LOWER count -> refused
        _login(p, auth, challenge="c3", count=4)
    assert _login(p, auth, challenge="c4", count=6)["username"] == u   # a higher count advances the floor


# ---- assertion-verification refusals -----------------------------------------------------------------
def test_login_refuses_wrong_challenge_tampered_sig_wrong_rp_and_unknown_credential(monkeypatch):
    p, _s, custs, _creds, orgs = _prov(monkeypatch)
    u, _ = _customer(custs, orgs)
    auth = SoftAuthenticator()
    _enroll(p, u, auth)
    a = auth.assert_("realchal", count=5)                         # sign over 'realchal' but claim a different one
    with pytest.raises(ProvisionDenied):
        p.passkey_login(credential_id="cred-abc123", authenticator_data=a["authenticator_data"],
                        client_data_json=a["client_data_json"], signature=a["signature"],
                        expected_challenge="OTHERchal")
    with pytest.raises(ProvisionDenied):                          # a tampered signature
        _login(p, auth, challenge="c5", count=6, tamper=True)
    with pytest.raises(ProvisionDenied):                          # a wrong rp_id (phishing) -> rpIdHash mismatch
        _login(p, auth, challenge="c6", count=7, rp="evil.example")
    with pytest.raises(ProvisionDenied):                          # a wrong origin (phishing)
        _login(p, auth, challenge="c7", count=8, origin="https://evil.example")
    with pytest.raises(ProvisionDenied):                          # an unknown credential_id
        _login(p, auth, cid="cred-unknown", challenge="c8", count=9)


# ---- global uniqueness / cross-customer isolation ----------------------------------------------------
def test_a_credential_binds_one_customer_and_resolves_only_that_customer(monkeypatch):
    p, _s, custs, _creds, orgs = _prov(monkeypatch)
    ua, _ = _customer(custs, orgs, email="a@acme.com", username="cust_a000000000000000000001", org="org_a1")
    ub, _ = _customer(custs, orgs, email="b@beta.com", username="cust_b000000000000000000001", org="org_b1")
    authA = SoftAuthenticator()
    _enroll(p, ua, authA, cid="cred-shared")
    # B cannot enroll A's credential_id (E2a global uniqueness) — the anti-hijack crypto backing
    with pytest.raises(ProvisionDenied):
        _enroll(p, ub, SoftAuthenticator(), cid="cred-shared", challenge="bchal")
    # and a login with that credential resolves ONLY to A, never B
    assert _login(p, authA, cid="cred-shared", count=5)["username"] == ua


# ---- fail-closed posture -----------------------------------------------------------------------------
def test_passkey_fail_closed_when_not_enabled_or_not_configured(monkeypatch):
    # no signcount ledger wired ⇒ login refuses (cannot enforce the clone-floor)
    p, _s, custs, _creds, orgs = _prov(monkeypatch, signcount=False)
    u, _ = _customer(custs, orgs)
    auth = SoftAuthenticator()
    _enroll(p, u, auth)
    with pytest.raises(ProvisionError):
        _login(p, auth, count=5)
    # configured-off (no rp_id / origins) ⇒ both enroll and login refuse
    p2, _s2, custs2, _c2, orgs2 = _prov(monkeypatch, configured=False)
    monkeypatch.delenv("VIGIL_CUSTOMER_PASSKEY_RP_ID", raising=False)
    monkeypatch.delenv("VIGIL_CUSTOMER_PASSKEY_ORIGINS", raising=False)
    u2, _ = _customer(custs2, orgs2, email="c@acme.com", username="cust_c000000000000000000001", org="org_c1")
    with pytest.raises(ProvisionError):
        _enroll(p2, u2, SoftAuthenticator(), cid="cred-c")
