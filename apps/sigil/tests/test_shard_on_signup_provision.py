"""Consumer PR-F — shard-placement-on-signup wired through the Provisioner (``_place_on_signup``) and its factory.

Pins the byte-identical-OFF contract and the flag-ON mint, counting the REAL spine records (never just a return):
  * every gate leg alone keeps the spine free of ``governor.shard_assignment`` records — no registry, the PR-F flag
    off (multi-shard on + topology set + registry injected: the one case where that flag alone decides), multi-shard
    off, no owner topology;
  * all gates ON ⇒ the sign-up owner-signs exactly ONE placement for the new org — on the email path, the Google
    path, and through the production factory ``build_provisioner``;
  * a crash right after the placement re-drives to exactly one placement (idempotent-forward sign-up);
  * the owner backfill and a sign-up share one cross-process placement lock.
A tenant never supplies a shard — placement is server-chosen from owner topology.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.customers import CustomerRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.shard_assignment import SIGNAL as SHARD_SIGNAL, ShardAssignmentRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import Provisioner

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_FLAGS = ("VIGIL_CUSTOMER_FAIR_QUEUE", "VIGIL_MULTI_SHARD", "VIGIL_SHARD_IDS")


def _prov(*, with_shards: bool, store=None):
    s = store or SpineStore(tempfile.mktemp(suffix=".jsonl"))
    custs = CustomerRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    orgs = OrgRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    wallet = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    tokens = EmailTokenLedger(tempfile.mkdtemp(), ttl_s=10_000.0)
    rl = LoginRateLimiter(tempfile.mkdtemp(), max_fails=3, window_s=10_000.0, base_lock_s=50.0)
    clock = itertools.count(1)
    shards = ShardAssignmentRegistry(s, owner_key=OWNER, trusted_pubkey=OP) if with_shards else None
    p = Provisioner(s, customers=custs, orgs=orgs, wallet=wallet, email_tokens=tokens, rate_limiter=rl,
                    email_sender=NullEmailSender(), trial_credits=100, expose_dev_tokens=True,
                    shard_assignments=shards, now_fn=lambda: float(next(clock)))
    return p, s, shards


def _signup(p, email="alice@acme.com") -> str:
    tok = p.request_signup(email, ip="1.1.1.1", now=100.0)["dev_token"]
    return p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", now=100.0)["org_id"]


def _shard_records(s) -> list:
    """Every shard-assignment record on the spine, whatever its signature — the ground truth a gate must keep empty."""
    return [r for r in s.iter_records() if isinstance(r.payload, dict) and r.payload.get("signal") == SHARD_SIGNAL]


def _set(monkeypatch, *, fair: bool, multi: bool, ids: str):
    for name, on in (("VIGIL_CUSTOMER_FAIR_QUEUE", fair), ("VIGIL_MULTI_SHARD", multi)):
        if on:
            monkeypatch.setenv(name, "1")
        else:
            monkeypatch.delenv(name, raising=False)
    if ids:
        monkeypatch.setenv("VIGIL_SHARD_IDS", ids)
    else:
        monkeypatch.delenv("VIGIL_SHARD_IDS", raising=False)


def _all_on(monkeypatch):
    _set(monkeypatch, fair=True, multi=True, ids="shard01,shard02")


# -- every gate leg alone keeps the spine free of placements ------------------------------------------------------

def test_signup_default_off_mints_no_placement(monkeypatch):
    _set(monkeypatch, fair=False, multi=False, ids="")
    p, s, shards = _prov(with_shards=True)
    org_id = _signup(p)
    assert org_id.startswith("org_")                       # the sign-up itself still works
    assert shards.placement(org_id) is None and _shard_records(s) == []


def test_signup_without_a_registry_is_a_noop(monkeypatch):
    # all gates ON, but no registry: nothing may be placed — not even through a registry built on the fly.
    _all_on(monkeypatch)
    p, s, _ = _prov(with_shards=False)
    org_id = _signup(p)
    assert org_id.startswith("org_")
    assert _shard_records(s) == [], "a placement was minted although no registry was injected"


def test_signup_prf_flag_off_multishard_on_topology_set_mints_no_placement(monkeypatch):
    # the ONE case where PR-F's own flag decides: multi-shard on, a topology named, the registry injected.
    _set(monkeypatch, fair=False, multi=True, ids="shard01,shard02")
    p, s, shards = _prov(with_shards=True)
    org_id = _signup(p)
    assert shards.placement(org_id) is None
    assert _shard_records(s) == [], "VIGIL_CUSTOMER_FAIR_QUEUE off must keep sign-up placement off"


def test_signup_flag_on_but_multi_shard_off_mints_no_placement(monkeypatch):
    _set(monkeypatch, fair=True, multi=False, ids="shard01")
    p, s, shards = _prov(with_shards=True)
    assert shards.placement(_signup(p)) is None and _shard_records(s) == []


def test_signup_all_on_but_no_topology_mints_no_placement(monkeypatch):
    _set(monkeypatch, fair=True, multi=True, ids="")
    p, s, shards = _prov(with_shards=True)
    assert shards.placement(_signup(p)) is None and _shard_records(s) == []   # fail-safe: no topology, no guess


# -- all gates ON ⇒ exactly one owner-signed placement ---------------------------------------------------------------

def test_signup_all_on_owner_signs_one_placement(monkeypatch):
    _all_on(monkeypatch)
    p, s, shards = _prov(with_shards=True)
    org_id = _signup(p)
    placement = shards.placement(org_id)
    assert placement is not None
    assert placement.shard_id in ("shard01", "shard02")   # an OWNER-named shard, never tenant-chosen
    assert placement.epoch == 1
    assert len(_shard_records(s)) == 1


def test_two_signups_balance_across_shards(monkeypatch):
    _all_on(monkeypatch)
    p, s, shards = _prov(with_shards=True)
    a = _signup(p, "a@x.com")
    b = _signup(p, "b@x.com")
    assert {shards.placement(a).shard_id, shards.placement(b).shard_id} == {"shard01", "shard02"}


def test_a_crash_right_after_the_placement_re_drives_to_exactly_one(monkeypatch):
    from test_trial_signup import _crash_after
    _all_on(monkeypatch)
    p, s, shards = _prov(with_shards=True)
    _crash_after(monkeypatch, p, "_place_on_signup")       # the placement is appended, then the process "dies"
    tok = p.request_signup("crash@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
    with pytest.raises(RuntimeError):
        p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", now=100.0)
    assert len(_shard_records(s)) == 1                     # placed before the crash ...
    org_id = p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", now=100.0)["org_id"]   # ... retried
    assert len(_shard_records(s)) == 1, "the retry placed the tenant a second time"
    assert shards.placement(org_id).epoch == 1


def test_the_google_signup_path_places_too(monkeypatch):
    from sigil.governor.customer_credentials import CustomerCredentialRegistry
    from sigil.ui.customer_identity import CustomerIdentity
    _all_on(monkeypatch)
    p, s, shards = _prov(with_shards=True)
    p.customer_credentials = CustomerCredentialRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    ident = CustomerIdentity(method="google-oidc", email="g@gmail.com", email_verified=True,
                             federated_iss="https://accounts.google.com", federated_sub="sub-g")
    with p._lock:
        p._link_or_provision_federated(ident, now=100.0)
    assert len(_shard_records(s)) == 1
    assert shards.placements()[0].shard_id in ("shard01", "shard02")


def test_signup_holds_the_cross_process_placement_lock(monkeypatch):
    # a placement taken while another process holds the placement lock fails CLOSED (nothing appended; the token
    # stays valid) instead of racing that process — then succeeds once the lock is free.
    from sigil.governor.shard_on_signup import placement_lock
    from vigil_integration.live.seam_lock import LockBusy
    import sigil.governor.shard_on_signup as sos
    _all_on(monkeypatch)
    p, s, shards = _prov(with_shards=True)
    monkeypatch.setattr(sos, "_PLACEMENT_LOCK_WAIT_S", 0.05)
    tok = p.request_signup("lock@acme.com", ip="1.1.1.1", now=100.0)["dev_token"]
    import subprocess
    import sys
    held = subprocess.Popen([sys.executable, "-c", (
        "import fcntl, os, sys, time\n"
        f"fd = os.open({str(s.path.parent / (s.path.stem + '.shards.lock'))!r}, os.O_RDWR | os.O_CREAT, 0o600)\n"
        "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('held', flush=True)\ntime.sleep(30)\n")],
        stdout=subprocess.PIPE, text=True)
    try:
        assert held.stdout.readline().strip() == "held"
        with pytest.raises(LockBusy):
            p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", now=100.0)
        assert _shard_records(s) == []
    finally:
        held.kill()
        held.wait()
    org_id = p.confirm_signup(tok, password="customer-pw-1", org_name="Acme", now=100.0)["org_id"]
    assert shards.placement(org_id) is not None and len(_shard_records(s)) == 1
    with placement_lock(s, wait_s=0.0):                    # released: the lock is free again after the sign-up
        pass


# -- the production factory ---------------------------------------------------------------------------------------------

def _factory(tmp_path, monkeypatch):
    from sigil import config
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui.provision import build_provisioner
    for attr in ("EMAIL_TOKENS_DIR", "LOGIN_RATELIMIT_DIR", "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    ensure_owner_keypair()
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    return build_provisioner(s, expose_dev_tokens=True), s


def test_the_production_factory_places_a_signup_when_all_gates_are_on(tmp_path, monkeypatch):
    _all_on(monkeypatch)
    p, s = _factory(tmp_path, monkeypatch)
    assert isinstance(p.shard_assignments, ShardAssignmentRegistry)
    org_id = _signup(p, "factory@acme.com")
    placement = ShardAssignmentRegistry(s, owner_key=None).placement(org_id)   # verified under the owner pubkey
    assert placement is not None and placement.shard_id in ("shard01", "shard02") and placement.epoch == 1
    assert len(_shard_records(s)) == 1


def test_the_production_factory_places_nothing_with_the_flag_off(tmp_path, monkeypatch):
    _set(monkeypatch, fair=False, multi=True, ids="shard01,shard02")
    p, s = _factory(tmp_path, monkeypatch)
    _signup(p, "factory-off@acme.com")
    assert _shard_records(s) == []
