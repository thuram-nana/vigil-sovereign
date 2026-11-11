"""Slice E3b-1 — customer TOTP MFA: the provisioner enroll_totp + verify_mfa (the step-up / second-factor
PROOF primitive E3c consumes), on the E2a customer-credential substrate.

Load-bearing invariants:
  * enroll SEALS the secret via the owner vault under the CUSTOMER TOTP context (domain-separated from the
    operator context); only the sealed blob reaches the spine, the plaintext secret is returned ONCE;
  * verify_mfa is fail-closed at every step: active-customer gate, enrolled-TOTP gate, unseal-under-context,
    the ±1-step code check, AND the (username, step) replay guard (a spent code is refused);
  * MFA is ACCOUNT-level — a customer enrolls/verifies their OWN factor; a non-customer is refused;
  * the seal is context-bound: a blob sealed under the customer context never opens under another.
"""
from __future__ import annotations

import base64
import itertools
import tempfile

import pytest

from sigil.governor import totp as _totp
from sigil.governor.customer_credentials import CustomerCredentialRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, ProvisionError, Provisioner
from sigil.ui.totp_replay import TotpReplayLedger

from test_secrets_sealed import make_fake_tpm  # the fake-TPM vault provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64
NOW = 100000.0


def _prov(tmp_path, monkeypatch, *, provision_vault=True, mfa_replay=True):
    from sigil.platform import vault as vaultmod
    v = vaultmod.Vault(tmp_path / "vault", make_fake_tpm())
    if provision_vault:
        v.provision()
    monkeypatch.setattr(vaultmod, "_owner_vault", v)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    creds = CustomerCredentialRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    clock = itertools.count(1)
    p = Provisioner(
        s, customers=custs, orgs=OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        customer_credentials=creds,
        mfa_replay=(TotpReplayLedger(tempfile.mkdtemp()) if mfa_replay else None),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: float(next(clock)))
    return p, s, custs, creds


def _customer(custs, email="mfa@acme.com", username="cust_mfauser0000000000000001"):
    custs.create(email, issued_at=1.0, password="password-xyz", username=username)
    return username


def test_enroll_totp_seals_the_secret_and_returns_a_provisioning_uri(tmp_path, monkeypatch):
    p, _s, custs, creds = _prov(tmp_path, monkeypatch)
    u = _customer(custs)
    out = p.enroll_totp(u)
    assert out["ok"] and out["method"] == "totp"
    assert out["provisioning_uri"].startswith("otpauth://totp/") and "VIGIL" in out["provisioning_uri"]
    assert out["secret"]
    cred = creds.totp_for(u)
    assert cred is not None and cred.sealed_secret                      # the credential is enrolled on the spine
    # what is stored is the SEALED blob, not the plaintext secret
    assert out["secret"] not in (cred.sealed_secret or "")
    assert base64.b64decode(cred.sealed_secret)                         # a real base64 sealed blob


def test_verify_mfa_accepts_a_fresh_code_then_refuses_the_replay(tmp_path, monkeypatch):
    p, _s, custs, _creds = _prov(tmp_path, monkeypatch)
    u = _customer(custs)
    secret = p.enroll_totp(u)["secret"]
    code = _totp.code_now(secret, at=NOW)
    assert p.verify_mfa(u, code=code, now=NOW) == {"ok": True, "method": "totp"}
    with pytest.raises(ProvisionDenied):                                # same (username, step) → replay refused
        p.verify_mfa(u, code=code, now=NOW)


def test_verify_mfa_refuses_a_wrong_code(tmp_path, monkeypatch):
    p, _s, custs, _creds = _prov(tmp_path, monkeypatch)
    u = _customer(custs)
    secret = p.enroll_totp(u)["secret"]
    # a 6-digit code guaranteed NOT to match ANY step in the ±1 verify window (not just the current step) —
    # deterministic, so this can never flake on a rare adjacent-window collision.
    step = _totp.current_step(NOW)
    valid = {_totp.code_for_step(secret, step + d) for d in (-1, 0, 1)}
    wrong = next(f"{n:06d}" for n in range(1000000) if f"{n:06d}" not in valid)
    with pytest.raises(ProvisionDenied):
        p.verify_mfa(u, code=wrong, now=NOW)


def test_verify_mfa_refuses_when_no_totp_enrolled_and_for_a_non_customer(tmp_path, monkeypatch):
    p, _s, custs, _creds = _prov(tmp_path, monkeypatch)
    u = _customer(custs)
    with pytest.raises(ProvisionDenied):                                # a real customer with NO enrolled TOTP
        p.verify_mfa(u, code="123456", now=NOW)
    with pytest.raises(ProvisionDenied):                                # not a customer at all
        p.verify_mfa("cust_ghost000000000000000001", code="123456", now=NOW)


def test_enroll_and_verify_refuse_a_non_customer(tmp_path, monkeypatch):
    p, _s, _custs, creds = _prov(tmp_path, monkeypatch)
    with pytest.raises(ProvisionDenied):
        p.enroll_totp("cust_ghost000000000000000001")
    assert creds.totp_for("cust_ghost000000000000000001") is None       # nothing enrolled for a ghost


def test_reenroll_supersedes_via_the_high_water(tmp_path, monkeypatch):
    p, _s, custs, _creds = _prov(tmp_path, monkeypatch)
    u = _customer(custs)
    s1 = p.enroll_totp(u)["secret"]
    s2 = p.enroll_totp(u)["secret"]
    assert s1 != s2                                                     # a fresh secret each enroll
    # only the LATEST secret verifies (the per-(username,"totp") high-water superseded the first)
    assert p.verify_mfa(u, code=_totp.code_now(s2, at=NOW), now=NOW)["ok"]
    with pytest.raises(ProvisionDenied):
        p.verify_mfa(u, code=_totp.code_now(s1, at=NOW + 60), now=NOW + 60)   # old secret no longer valid


def test_enroll_fail_closed_when_vault_unprovisioned(tmp_path, monkeypatch):
    p, _s, custs, _creds = _prov(tmp_path, monkeypatch, provision_vault=False)
    u = _customer(custs)
    with pytest.raises(ProvisionError):                                 # cannot seal ⇒ clean refusal (not a 500)
        p.enroll_totp(u)


def test_verify_fail_closed_without_a_replay_ledger(tmp_path, monkeypatch):
    p, _s, custs, _creds = _prov(tmp_path, monkeypatch, mfa_replay=False)
    u = _customer(custs)
    # enroll works (no ledger needed), but a verify with no replay ledger fails closed — the guard can never
    # be silently disabled.
    secret = p.enroll_totp(u)["secret"]
    with pytest.raises(ProvisionError):
        p.verify_mfa(u, code=_totp.code_now(secret, at=NOW), now=NOW)


def test_customer_totp_seal_is_context_bound(tmp_path, monkeypatch):
    # a blob sealed under the CUSTOMER context must NOT open under the operator account-TOTP context
    from sigil import config
    from sigil.governor.accounts import TOTP_SEAL_CONTEXT
    from sigil.platform import vault as vaultmod
    v = vaultmod.Vault(tmp_path / "vault", make_fake_tpm()); v.provision()
    blob = v.seal_secret(b"super-secret-totp", context=config.CUSTOMER_TOTP_SEAL_CONTEXT)
    assert v.unseal_secret(blob, context=config.CUSTOMER_TOTP_SEAL_CONTEXT) == b"super-secret-totp"
    assert config.CUSTOMER_TOTP_SEAL_CONTEXT != TOTP_SEAL_CONTEXT       # domain-separated from the operator
    with pytest.raises(Exception):                                     # cross-context open fails (AEAD AAD bind)
        v.unseal_secret(blob, context=TOTP_SEAL_CONTEXT)
