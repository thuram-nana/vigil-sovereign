"""Authenticator-enrolment hardening (VIGIL_CUSTOMER_MFA_ENROLL_STEPUP, default OFF).

The finding (confirmed during the Account-security UI build): the customer MFA enrol paths need only a
logged-in session, with no step-up, and TOTP enrolment ACTIVATES the new secret BEFORE it is confirmed — so an
attacker on a hijacked session could silently replace a victim's second factor; and ``verify_mfa`` has no rate
limiter. This suite pins the three guards the flag turns on, over the REAL provisioner (real registries, a real
fake-TPM owner vault, a real pending store + limiter), and proves the flag-off path is byte-identical.

Load-bearing invariants (each test names the property it proves; each guard is mutation-verified):
  * CONFIRM-BEFORE-ACTIVATE — a hardened ``enroll_totp`` parks the sealed secret as PENDING and does NOT
    activate it; ``confirm_totp`` (a fresh code) activates it; a wrong/absent code never activates;
  * STEP-UP ON ENROLMENT — replacing/adding a factor when one already exists needs a FRESH ``mfa_at``; the
    FIRST factor (bootstrap, no existing factor) enrols without step-up; this holds for passkey too, and it is
    re-checked at ACTIVATION (a secret parked while the account had no factor needs step-up to be confirmed once
    the account has gained one);
  * RATE-LIMIT — ``verify_mfa``/``confirm_totp`` code-guessing and enrolment churn are bounded per account;
  * FLAG OFF is BYTE-IDENTICAL — enrol activates immediately, no pending is written, the response keeps its
    original keys, and ``confirm_totp`` refuses.
"""
from __future__ import annotations

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
from sigil.ui.pending_totp import PendingTotpEnrolments
from sigil.ui.provision import (ProvisionDenied, ProvisionError, ProvisionRateLimited,
                                ProvisionStepUpRequired, Provisioner)
from sigil.ui.totp_replay import TotpReplayLedger

from test_customer_passkey import ORIGIN as PK_ORIGIN  # the software WebAuthn authenticator + its rp/origin
from test_customer_passkey import RP as PK_RP
from test_customer_passkey import SoftAuthenticator
from test_secrets_sealed import make_fake_tpm  # the fake-TPM vault provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64
NOW = 100000.0
WINDOW = 300.0          # CUSTOMER_STEPUP_WINDOW_SECONDS default


def _prov(tmp_path, monkeypatch, *, hardened, max_fails=3, pending=True, limiter=True, ttl_s=900.0):
    from sigil.platform import vault as vaultmod
    v = vaultmod.Vault(tmp_path / "vault", make_fake_tpm())
    v.provision()
    monkeypatch.setattr(vaultmod, "_owner_vault", v)
    if hardened:
        monkeypatch.setenv("VIGIL_CUSTOMER_MFA_ENROLL_STEPUP", "1")
    else:
        monkeypatch.delenv("VIGIL_CUSTOMER_MFA_ENROLL_STEPUP", raising=False)
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    creds = CustomerCredentialRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    clock = itertools.count(1)
    pending_dir = tmp_path / "pending_totp"
    p = Provisioner(
        s, customers=custs, orgs=OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        wallet=WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        customer_credentials=creds,
        mfa_replay=TotpReplayLedger(tempfile.mkdtemp()),
        pending_totp=(PendingTotpEnrolments(pending_dir, ttl_s=ttl_s) if pending else None),
        mfa_limiter=(LoginRateLimiter(tempfile.mkdtemp(), max_fails=max_fails, window_s=1e4, base_lock_s=1e4)
                     if limiter else None),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: float(next(clock)))
    return p, s, custs, creds, pending_dir


def _customer(custs, email="mfa@acme.com", username="cust_mfauser0000000000000001"):
    custs.create(email, issued_at=1.0, password="password-xyz", username=username)
    return username


def _enroll_and_confirm(p, u, *, mfa_at=NOW, at=NOW):
    """Enrol a factor and immediately confirm it (the hardened round-trip) -> an active TOTP for `u`."""
    secret = p.enroll_totp(u, mfa_at=mfa_at, now=at)["secret"]
    p.confirm_totp(u, code=_totp.code_now(secret, at=at), mfa_at=mfa_at, now=at)
    return secret


# ---- confirm-before-activate -------------------------------------------------------------------------
def test_pending_secret_is_not_active_until_confirmed(tmp_path, monkeypatch):
    p, _s, custs, creds, _pd = _prov(tmp_path, monkeypatch, hardened=True)
    u = _customer(custs)
    out = p.enroll_totp(u, now=NOW)                                 # the FIRST factor: no step-up needed
    assert out["ok"] and out["pending"] is True and out["secret"]  # the response says it is pending
    assert creds.totp_for(u) is None                               # NOTHING is active yet (the whole fix)
    # confirming with a fresh code ACTIVATES it
    assert p.confirm_totp(u, code=_totp.code_now(out["secret"], at=NOW), now=NOW) == {"ok": True, "method": "totp"}
    cred = creds.totp_for(u)
    assert cred is not None and cred.sealed_secret                 # now the credential is active on the spine
    # the just-activated secret verifies (a later step, so the replay ledger does not refuse it)
    assert p.verify_mfa(u, code=_totp.code_now(out["secret"], at=NOW + 60), now=NOW + 60)["ok"]


def test_confirm_refuses_a_wrong_code_and_leaves_the_factor_inactive(tmp_path, monkeypatch):
    p, _s, custs, creds, _pd = _prov(tmp_path, monkeypatch, hardened=True)
    u = _customer(custs)
    secret = p.enroll_totp(u, now=NOW)["secret"]
    step = _totp.current_step(NOW)
    valid = {_totp.code_for_step(secret, step + d) for d in (-1, 0, 1)}
    wrong = next(f"{n:06d}" for n in range(1000000) if f"{n:06d}" not in valid)
    with pytest.raises(ProvisionDenied):
        p.confirm_totp(u, code=wrong, now=NOW)
    assert creds.totp_for(u) is None                               # a wrong code never activates


def test_confirm_refuses_when_there_is_no_pending_enrolment(tmp_path, monkeypatch):
    p, _s, custs, _creds, _pd = _prov(tmp_path, monkeypatch, hardened=True)
    u = _customer(custs)
    with pytest.raises(ProvisionDenied):                           # nothing was enrolled
        p.confirm_totp(u, code="123456", now=NOW)


def test_a_confirmed_pending_secret_is_cleared(tmp_path, monkeypatch):
    p, _s, custs, _creds, pending_dir = _prov(tmp_path, monkeypatch, hardened=True)
    u = _customer(custs)
    _enroll_and_confirm(p, u)
    # the pending marker is gone after a successful confirm (no second confirm can replay it). The second confirm
    # carries a fresh step-up, so it gets past the activation-time gate and is refused for having NOTHING pending.
    assert not any(pending_dir.glob("*.json"))
    with pytest.raises(ProvisionDenied, match="no pending"):
        p.confirm_totp(u, code="123456", mfa_at=NOW + 50, now=NOW + 60)


# ---- step-up on enrolment ----------------------------------------------------------------------------
def test_first_factor_enrolls_without_stepup(tmp_path, monkeypatch):
    p, _s, custs, _creds, _pd = _prov(tmp_path, monkeypatch, hardened=True)
    u = _customer(custs)
    # bootstrap: no existing factor, so NO mfa_at is required (you cannot step-up with a factor you lack)
    out = p.enroll_totp(u, mfa_at=0.0, now=NOW)
    assert out["ok"] and out["pending"] is True


def test_second_factor_enroll_refused_without_fresh_stepup(tmp_path, monkeypatch):
    p, _s, custs, _creds, _pd = _prov(tmp_path, monkeypatch, hardened=True)
    u = _customer(custs)
    _enroll_and_confirm(p, u)                                      # the account now HAS a factor
    with pytest.raises(ProvisionStepUpRequired):                  # replacing it with no fresh factor is refused
        p.enroll_totp(u, mfa_at=0.0, now=NOW + 120)
    with pytest.raises(ProvisionStepUpRequired):                  # a STALE mfa_at (older than the window) too
        p.enroll_totp(u, mfa_at=NOW - WINDOW - 10, now=NOW + 120)


def test_second_factor_enroll_allowed_with_a_fresh_stepup(tmp_path, monkeypatch):
    p, _s, custs, creds, _pd = _prov(tmp_path, monkeypatch, hardened=True)
    u = _customer(custs)
    _enroll_and_confirm(p, u)
    # a fresh mfa_at within the window lets the replacement proceed (to pending), then confirm supersedes (the
    # confirm re-checks the same step-up at activation, still fresh here)
    out = p.enroll_totp(u, mfa_at=NOW + 100, now=NOW + 120)
    assert out["ok"] and out["pending"] is True
    assert p.confirm_totp(u, code=_totp.code_now(out["secret"], at=NOW + 120), mfa_at=NOW + 100,
                          now=NOW + 120)["ok"]
    # only the NEW secret verifies now (the high-water superseded the first)
    assert p.verify_mfa(u, code=_totp.code_now(out["secret"], at=NOW + 180), now=NOW + 180)["ok"]


def test_passkey_second_factor_enroll_refused_without_fresh_stepup(tmp_path, monkeypatch):
    # adding a passkey when a TOTP already exists needs a fresh step-up too (the gate is factor-agnostic). We
    # only need to reach the gate, which fires before any WebAuthn material is parsed.
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_RP_ID", "app.vigil.example")
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ORIGINS", "https://app.vigil.example")
    p, _s, custs, _creds, _pd = _prov(tmp_path, monkeypatch, hardened=True)
    u = _customer(custs)
    _enroll_and_confirm(p, u)
    with pytest.raises(ProvisionStepUpRequired):
        p.enroll_passkey(u, credential_id="cred-x", public_key_spki_b64="AA==", cose_alg=-7, uv=False,
                         client_data_json="", expected_challenge="ch", mfa_at=0.0, now=NOW + 120)


def test_a_bootstrap_pending_needs_stepup_once_the_account_gained_a_factor(tmp_path, monkeypatch):
    # TOCTOU at ACTIVATION: a hijacked session parks a TOTP while the account has NO factor (the bootstrap
    # exemption lets it), then the owner adds a passkey. Confirming the parked secret would now ADD a second factor
    # to an account that has one, so the step-up gate is re-checked at confirm — not only at enrolment.
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_RP_ID", PK_RP)
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ORIGINS", PK_ORIGIN)
    p, _s, custs, creds, _pd = _prov(tmp_path, monkeypatch, hardened=True)
    u = _customer(custs)
    parked = p.enroll_totp(u, now=NOW)["secret"]                    # bootstrap: parked with no step-up
    reg = SoftAuthenticator().register("pk-chal")                  # the owner then adds a passkey (bootstrap too:
    assert p.enroll_passkey(u, credential_id="cred-owner",          # a parked TOTP is not an active factor)
                            public_key_spki_b64=reg["public_key_spki_b64"], cose_alg=reg["cose_alg"], uv=False,
                            client_data_json=reg["client_data_json"], expected_challenge="pk-chal",
                            now=NOW + 10)["ok"]
    code = _totp.code_now(parked, at=NOW + 20)
    with pytest.raises(ProvisionStepUpRequired):                    # no fresh step-up -> it stays inactive
        p.confirm_totp(u, code=code, mfa_at=0.0, now=NOW + 20)
    assert creds.totp_for(u) is None
    # with a fresh step-up (e.g. the owner just proved the passkey) the same confirm proceeds
    assert p.confirm_totp(u, code=code, mfa_at=NOW + 15, now=NOW + 20)["ok"]
    assert creds.totp_for(u) is not None


# ---- rate limiting -----------------------------------------------------------------------------------
def test_verify_mfa_is_rate_limited_then_even_a_good_code_is_refused(tmp_path, monkeypatch):
    p, _s, custs, _creds, _pd = _prov(tmp_path, monkeypatch, hardened=True, max_fails=3)
    u = _customer(custs)
    secret = _enroll_and_confirm(p, u)
    step = _totp.current_step(NOW + 240)
    valid = {_totp.code_for_step(secret, step + d) for d in (-1, 0, 1)}
    wrong = next(f"{n:06d}" for n in range(1000000) if f"{n:06d}" not in valid)
    for _ in range(3):                                             # three wrong codes exhaust the budget
        with pytest.raises(ProvisionDenied):
            p.verify_mfa(u, code=wrong, now=NOW + 240)
    # now the per-account code budget is locked: even a CORRECT code is refused (the guard precedes the check)
    good = _totp.code_now(secret, at=NOW + 240)
    with pytest.raises(ProvisionRateLimited):
        p.verify_mfa(u, code=good, now=NOW + 240)


def test_confirm_shares_the_code_budget_with_verify(tmp_path, monkeypatch):
    # confirm_totp guesses a code for the same account, so it draws on the SAME mfa:code budget as verify.
    p, _s, custs, _creds, _pd = _prov(tmp_path, monkeypatch, hardened=True, max_fails=3)
    u = _customer(custs)
    secret = p.enroll_totp(u, now=NOW)["secret"]
    step = _totp.current_step(NOW)
    valid = {_totp.code_for_step(secret, step + d) for d in (-1, 0, 1)}
    wrong = next(f"{n:06d}" for n in range(1000000) if f"{n:06d}" not in valid)
    for _ in range(3):
        with pytest.raises(ProvisionDenied):
            p.confirm_totp(u, code=wrong, now=NOW)
    with pytest.raises(ProvisionRateLimited):                      # the pending-code budget is bounded too
        p.confirm_totp(u, code=_totp.code_now(secret, at=NOW), now=NOW)


def test_enrolment_churn_is_rate_limited(tmp_path, monkeypatch):
    p, _s, custs, _creds, _pd = _prov(tmp_path, monkeypatch, hardened=True, max_fails=3)
    u = _customer(custs)
    for _ in range(3):                                             # three enrol attempts exhaust the enrol budget
        p.enroll_totp(u, now=NOW)
    with pytest.raises(ProvisionRateLimited):
        p.enroll_totp(u, now=NOW)


# ---- flag OFF is byte-identical ----------------------------------------------------------------------
def test_flag_off_enroll_activates_immediately_and_writes_no_pending(tmp_path, monkeypatch):
    # GOLDEN: with the flag off the enrol path is byte-identical to pre-hardening — the secret is ACTIVE at
    # once, nothing is parked as pending, and the response keeps exactly its four original keys.
    p, _s, custs, creds, pending_dir = _prov(tmp_path, monkeypatch, hardened=False)
    u = _customer(custs)
    out = p.enroll_totp(u, now=NOW)
    assert set(out) == {"ok", "method", "provisioning_uri", "secret"}   # NO "pending" key
    assert creds.totp_for(u) is not None                          # active immediately (today's behaviour)
    assert not pending_dir.exists() or not any(pending_dir.glob("*.json"))   # nothing parked
    # a fresh code verifies exactly as before (no rate limiting kicks in while the flag is off)
    assert p.verify_mfa(u, code=_totp.code_now(out["secret"], at=NOW), now=NOW)["ok"]


def test_flag_off_enrol_paths_read_the_clock_exactly_as_before(tmp_path, monkeypatch):
    # GOLDEN (state transitions): with the flag off, a TOTP enrol and a passkey enrol each read the provisioner
    # clock exactly ONCE — for the owner-signed credential's issued_at, as before the hardening. The hardened branch
    # (step-up, limiter, pending store) is never entered, so it can neither read the clock nor touch its stores.
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_RP_ID", PK_RP)
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ORIGINS", PK_ORIGIN)
    p, _s, custs, _creds, pending_dir = _prov(tmp_path, monkeypatch, hardened=False)
    u = _customer(custs)
    reads: "list[float]" = []
    real_now = p._now

    def _counting_now():
        reads.append(1.0)
        return real_now()

    p._now = _counting_now
    # the PRODUCTION call shape: the cockpit dispatch passes no `now`, so every clock read is a real `_now()`
    p.enroll_totp(u)
    assert len(reads) == 1
    reg = SoftAuthenticator().register("pk-chal")
    p.enroll_passkey(u, credential_id="cred-golden", public_key_spki_b64=reg["public_key_spki_b64"],
                     cose_alg=reg["cose_alg"], uv=False, client_data_json=reg["client_data_json"],
                     expected_challenge="pk-chal")
    assert len(reads) == 2
    assert not pending_dir.exists()                               # the pending store was never touched


def test_flag_off_confirm_refuses(tmp_path, monkeypatch):
    # confirm_totp is inert while the flag is off (the pending flow does not exist); it refuses.
    p, _s, custs, _creds, _pd = _prov(tmp_path, monkeypatch, hardened=False)
    u = _customer(custs)
    p.enroll_totp(u, now=NOW)
    with pytest.raises(ProvisionDenied):
        p.confirm_totp(u, code="123456", now=NOW)


def test_flag_off_second_enroll_needs_no_stepup_and_never_rate_limited(tmp_path, monkeypatch):
    # with the flag off, re-enrolling many times (today's behaviour) is never step-up-gated or rate-limited.
    p, _s, custs, creds, _pd = _prov(tmp_path, monkeypatch, hardened=False, max_fails=2)
    u = _customer(custs)
    secrets_seen = [p.enroll_totp(u, now=NOW)["secret"] for _ in range(5)]
    assert len(set(secrets_seen)) == 5                            # a fresh secret each time, all accepted
    assert creds.totp_for(u) is not None                         # the latest is active (high-water LWW)


def test_cockpit_confirm_action_is_absent_while_the_flag_is_off(monkeypatch):
    # The cockpit half of the double gate (the edge route is the other half, proven over the hop in test_custui):
    # with the flag OFF the provision dispatch answers None for `mfa_totp_confirm` — the unknown-action 404 —
    # WITHOUT calling the provisioner; ON, it calls confirm_totp with the hop-bound requester, the code and the
    # SESSION step-up stamp the edge relayed (never any other body field).
    from sigil.ui.server import Handler

    class _Stub:
        def __init__(self):
            self.calls = []

        def confirm_totp(self, requester, **kw):
            self.calls.append((requester, kw))
            return {"ok": True, "method": "totp"}

    stub = _Stub()
    body = {"code": "123456", "mfa_at": 42.0, "ip": "203.0.113.9"}
    monkeypatch.delenv("VIGIL_CUSTOMER_MFA_ENROLL_STEPUP", raising=False)
    assert Handler._provision_dispatch(None, stub, "mfa_totp_confirm", "cust_x", body) is None
    assert stub.calls == []
    monkeypatch.setenv("VIGIL_CUSTOMER_MFA_ENROLL_STEPUP", "1")
    assert Handler._provision_dispatch(None, stub, "mfa_totp_confirm", "cust_x", body) == {"ok": True,
                                                                                          "method": "totp"}
    assert stub.calls == [("cust_x", {"code": "123456", "mfa_at": 42.0})]
