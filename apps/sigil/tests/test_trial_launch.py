"""S7 — the trial launch gate: trial product only, one ICANN registrable domain per trial (first claim wins, with
signed-proof history), free-subdomain platforms / IP literals / localhost refused, and a global daily cap.

Applies ONLY to a locked trial-preview org; an unlocked or non-preview org launches exactly as before. The rule
only ever refuses — the four launch conditions (admit, proof, authority, credits) stay in LaunchGate. Here the
LaunchGate reserve is captured so each test pins what the trial gate allowed through.
"""
from __future__ import annotations

import itertools
import tempfile
import time

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.registrable_domain import (PSL_PATH, TrialDomainRefused, load_rules, parse, same_domain,
                                               trial_domain)
from sigil.governor.report_unlock import ReportUnlockRegistry
from sigil.governor.trial_claim import TrialClaimRegistry, key_digest
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import ProvisionDenied, Provisioner

_FLAG = "VIGIL_TRIAL_PREVIEW_ENABLED"
_PRODUCT = "vigil_launch_quick"
_it = itertools.count(1)


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    from sigil import config
    from sigil.governor.identity import ensure_owner_keypair
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine" / "spine.jsonl")
    monkeypatch.setenv(_FLAG, "1")
    monkeypatch.setenv("VIGIL_TIERED_PRODUCTS", "1")
    monkeypatch.setenv("VIGIL_TRIAL_PRODUCT_ID", _PRODUCT)
    monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", raising=False)
    ensure_owner_keypair()


def _prove(store, org, host):
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_it)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0 + next(_it),
                          ttl_seconds=1e12)


def _prov(monkeypatch, *, cap=5, store=None):
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.orgs import OrgRegistry
    s = store or SpineStore(tempfile.mktemp(suffix=".jsonl"))
    wallet = WalletRegistry(s)
    p = Provisioner(s, customers=CustomerRegistry(s), orgs=OrgRegistry(s), wallet=wallet,
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
                    email_sender=NullEmailSender(), trial_credits=100, trial_claims=TrialClaimRegistry(s),
                    trial_launch_limiter=(LoginRateLimiter(tempfile.mkdtemp(), max_fails=cap, window_s=86400.0,
                                                           base_lock_s=86400.0, max_lock_s=86400.0)
                                          if cap else None),
                    now_fn=lambda: float(next(_it)) + 1000.0)
    monkeypatch.setattr(p.orgs, "admit_customer", lambda **kw: True)
    return p, s


def _trial(store, org):
    WalletRegistry(store).grant(org, 100, "trial", entry_id=f"trial-preview:{org}", issued_at=float(next(_it)))


def _capture(monkeypatch):
    seen: list = []

    def _cap(self, *, requester, org_id, host, units, now):
        seen.append((org_id, host))
        return {"ok": True, "slug": "s", "host": host, "units_reserved": units, "nonce": f"n{len(seen)}",
                "not_before": 0.0, "not_after": 0.0, "lease": {}, "trust_root": {}}
    monkeypatch.setattr("sigil.ui.launch_gate.LaunchGate.reserve_launch", _cap)
    return seen


def _launch(p, org, host, product=_PRODUCT):
    return p.launch_reserve("u", org, host, product_id=product)


# --- registrable domains (ICANN only; private section refused) -------------------------------------------------

@pytest.mark.parametrize("a, b, same", [
    ("shop.acme.co.uk", "api.acme.co.uk", True),
    ("acme.co.uk", "beta.co.uk", False),
    ("www.acme.io", "acme.io", True),
    ("city.kawasaki.jp", "x.city.kawasaki.jp", True),      # an exception rule
])
def test_registrable_domain_grouping(a, b, same):
    assert (trial_domain(a) == trial_domain(b)) is same


@pytest.mark.parametrize("host, reason", [
    ("x.vercel.app", "private_suffix"), ("me.github.io", "private_suffix"), ("a.b.netlify.app", "private_suffix"),
    ("127.0.0.1", "ip_literal"), ("[::1]", "ip_literal"), ("10.1.2.3", "ip_literal"),
    ("localhost", "localhost"), ("dev.localhost", "localhost"),
    ("co.uk", "public_suffix"), ("intranet", "single_label"), ("a..b.com", "malformed_host"),
])
def test_ineligible_hosts_are_refused(host, reason):
    with pytest.raises(TrialDomainRefused) as e:
        trial_domain(host)
    assert e.value.reason == reason


def test_a_tampered_suffix_list_refuses_every_trial(tmp_path):
    bad = tmp_path / "psl.dat"
    bad.write_bytes(PSL_PATH.read_bytes() + b"\n// tampered\n")
    assert load_rules(bad) is None
    with pytest.raises(TrialDomainRefused) as e:
        trial_domain("acme.io", rules=load_rules(bad))
    assert e.value.reason == "suffix_list_unavailable"
    assert load_rules() is not None                                   # the pinned list loads


def test_the_parser_keeps_sections_apart():
    r = parse("// ===BEGIN ICANN DOMAINS===\ncom\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n"
              "// ===BEGIN PRIVATE DOMAINS===\nplatform.com\n// ===END PRIVATE DOMAINS===\n")
    assert trial_domain("a.b.com", rules=r) == "b.com"
    assert trial_domain("www.ck", rules=r) == "www.ck"
    assert trial_domain("x.y.ck", rules=r) == "x.y.ck"
    with pytest.raises(TrialDomainRefused):
        trial_domain("me.platform.com", rules=r)
    assert same_domain("a.b.com", "b.com", rules=r) and not same_domain("me.platform.com", "platform.com", rules=r)


# --- the gate ---------------------------------------------------------------------------------------------------

def test_first_claim_wins_and_the_first_org_keeps_launching(monkeypatch):
    seen = _capture(monkeypatch)
    p, s = _prov(monkeypatch)
    _trial(s, "org_a")
    _trial(s, "org_b")
    _prove(s, "org_a", "acme.io")
    _launch(p, "org_a", "acme.io")
    assert TrialClaimRegistry(s).claimant("domain", key_digest("domain", "acme.io")) == "org_a"
    _prove(s, "org_b", "www.acme.io")
    with pytest.raises(ProvisionDenied, match="one workspace per domain"):
        _launch(p, "org_b", "www.acme.io")
    _launch(p, "org_a", "acme.io")                                     # A still launches after B proved it
    assert seen == [("org_a", "acme.io"), ("org_a", "acme.io")]


@pytest.mark.parametrize("prior", ["paying", "legacy"])
def test_a_domain_another_org_already_proved_is_refused(monkeypatch, prior):
    seen = _capture(monkeypatch)
    p, s = _prov(monkeypatch)
    if prior == "legacy":
        WalletRegistry(s).grant("org_x", 100, "trial", entry_id="trial:org_x", issued_at=1.0)
    _prove(s, "org_x", "app.acme.io")
    _trial(s, "org_a")
    _prove(s, "org_a", "acme.io")
    with pytest.raises(ProvisionDenied, match="one workspace per domain"):
        _launch(p, "org_a", "acme.io")
    assert seen == []


def test_a_revoked_but_signed_proof_counts_and_an_unsigned_revoke_does_not(monkeypatch):
    _capture(monkeypatch)
    p, s = _prov(monkeypatch)
    _prove(s, "org_x", "old.acme.io")
    AssetOwnershipRegistry(s).revoke_proof("org_x", "old.acme.io")
    s.append(kind="event", source="governor", actor="X",
             payload={"signal": "governor.asset_ownership_proof", "org_id": "org_y", "host": "beta.io",
                      "state": "revoked"})
    _trial(s, "org_a")
    _prove(s, "org_a", "acme.io")
    with pytest.raises(ProvisionDenied):
        _launch(p, "org_a", "acme.io")
    _trial(s, "org_b")
    _prove(s, "org_b", "beta.io")
    _launch(p, "org_b", "beta.io")                                     # the unsigned revoke never "proved" it


def test_one_domain_per_trial_org(monkeypatch):
    _capture(monkeypatch)
    p, s = _prov(monkeypatch)
    _trial(s, "org_a")
    _prove(s, "org_a", "acme.io")
    _prove(s, "org_a", "other.io")
    _launch(p, "org_a", "acme.io")
    with pytest.raises(ProvisionDenied, match="one domain"):
        _launch(p, "org_a", "other.io")
    _launch(p, "org_a", "api.acme.io")                                 # same registrable domain: allowed


@pytest.mark.parametrize("host", ["me.github.io", "127.0.0.1", "localhost"])
def test_platforms_ips_and_localhost_are_refused_for_a_trial(monkeypatch, host):
    seen = _capture(monkeypatch)
    p, s = _prov(monkeypatch)
    _trial(s, "org_a")
    with pytest.raises(ProvisionDenied, match="your own registered domain"):
        _launch(p, "org_a", host)
    assert seen == []


def test_only_the_trial_product(monkeypatch):
    seen = _capture(monkeypatch)
    p, s = _prov(monkeypatch)
    _trial(s, "org_a")
    _prove(s, "org_a", "acme.io")
    for product in ("vigil_launch_deep", ""):
        with pytest.raises(ProvisionDenied, match="trial scan only"):
            _launch(p, "org_a", "acme.io", product=product)
    monkeypatch.delenv("VIGIL_TRIAL_PRODUCT_ID")
    with pytest.raises(ProvisionDenied, match="not available yet"):
        _launch(p, "org_a", "acme.io")
    assert seen == []


def test_the_daily_cap_is_checked_before_and_counted_after(monkeypatch):
    seen = _capture(monkeypatch)
    p, s = _prov(monkeypatch, cap=2)
    for org, host in (("org_a", "a.io"), ("org_b", "b.io"), ("org_c", "c.io")):
        _trial(s, org)
        _prove(s, org, host)
    _launch(p, "org_a", "a.io")
    _launch(p, "org_b", "b.io")
    with pytest.raises(ProvisionDenied, match="paused for today"):
        _launch(p, "org_c", "c.io")
    assert len(seen) == 2


def test_no_cap_configured_means_no_trial_launch(monkeypatch):
    seen = _capture(monkeypatch)
    p, s = _prov(monkeypatch, cap=0)
    _trial(s, "org_a")
    _prove(s, "org_a", "acme.io")
    with pytest.raises(ProvisionDenied, match="not available yet"):
        _launch(p, "org_a", "acme.io")
    assert seen == []


def test_a_refused_reserve_writes_no_claim_and_counts_nothing(monkeypatch):
    monkeypatch.setattr("sigil.ui.launch_gate.LaunchGate.reserve_launch",
                        lambda self, **kw: {"ok": False, "error": "insufficient credits"})
    p, s = _prov(monkeypatch, cap=1)
    _trial(s, "org_a")
    _prove(s, "org_a", "acme.io")
    with pytest.raises(ProvisionDenied, match="insufficient"):
        _launch(p, "org_a", "acme.io")
    assert TrialClaimRegistry(s).claims_of("org_a") == []
    assert p.trial_launch_limiter.locked("trial:launch:global", now=time.time()) is None


def test_unlocked_and_non_preview_orgs_skip_every_check(monkeypatch):
    seen = _capture(monkeypatch)
    p, s = _prov(monkeypatch, cap=0)
    _launch(p, "org_paying", "me.github.io", product="vigil_launch_deep")      # never a trial org
    _trial(s, "org_a")
    ReportUnlockRegistry(s).unlock("org_a", "topup", source_ref="e1", issued_at=1.0)
    _launch(p, "org_a", "127.0.0.1", product="vigil_launch_deep")
    monkeypatch.delenv(_FLAG)
    _trial(s, "org_b")
    _launch(p, "org_b", "localhost", product="vigil_launch_deep")
    assert len(seen) == 3


def test_checks_and_reserve_run_under_one_lock_hold(monkeypatch):
    """A proof appended by another org between the check and the reserve is impossible: the reserve sees the lock
    already held by this thread (the re-entrant spine lock is not released in between)."""
    p, s = _prov(monkeypatch)
    _trial(s, "org_a")
    _prove(s, "org_a", "acme.io")
    held = {}

    def _cap(self, **kw):
        held["owned"] = p._lock._is_owned()
        return {"ok": True, "slug": "s", "host": kw["host"], "units_reserved": kw["units"], "nonce": "n",
                "not_before": 0.0, "not_after": 0.0, "lease": {}, "trust_root": {}}
    monkeypatch.setattr("sigil.ui.launch_gate.LaunchGate.reserve_launch", _cap)
    _launch(p, "org_a", "acme.io")
    assert held["owned"] is True


def test_a_postpaid_org_that_started_on_the_trial_is_never_gated(monkeypatch):
    from sigil.governor.postpaid import PostpaidRegistry
    from sigil.ui.finding_preview import preview_locked
    seen = _capture(monkeypatch)
    p, s = _prov(monkeypatch, cap=0)
    _trial(s, "org_a")
    assert preview_locked(s, "org_a")
    PostpaidRegistry(s).set_account("org_a", 100000, 30, issued_at=float(next(_it)))
    assert not preview_locked(s, "org_a")
    _prove(s, "org_a", "acme.io")
    _prove(s, "org_a", "other.io")
    _launch(p, "org_a", "acme.io", product="vigil_launch_deep")
    _launch(p, "org_a", "other.io", product="vigil_launch_deep")
    assert len(seen) == 2


def test_a_restored_suffix_list_is_picked_up(tmp_path):
    f = tmp_path / "psl.dat"
    f.write_bytes(b"tampered")
    assert load_rules(f) is None
    f.write_bytes(PSL_PATH.read_bytes())
    assert load_rules(f) is not None
