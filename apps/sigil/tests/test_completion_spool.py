"""K4-5b — the SOVEREIGN settle-drain of the engagement-completion seam (+ the red-pen fold).

Drives the REAL path: reserve → publish lease → a keyless governance-signed completion signal on the settle
spool → ``CompletionSpoolWatcher.drain()`` verifies it against the owner-signed OFFENSE_GOVERNANCE_ROLE
delegation and calls the idempotent ``settle_launch``. Pins the money invariants:
  * a COMPLETED signal settles net-spend == reserved (flat-per-run, no refund) + tombstones the lease;
  * a CANCELED / FAILED signal settles consumed=0 (full refund);
  * a FORGED (wrong-key) / wrong-ROLE / out-of-scope / nonce-mismatched / tenant-mismatched signal is
    REJECTED — nothing settled;
  * a bad delegation refuses the whole drain at construction; an EXPIRED delegation settles NOTHING per drain
    and leaves the envelope for a later renewed drain (the per-drain re-verify, red-pen finding B);
  * the settle/tombstone WRITE shares the drain's base_dir with the lease READ — a completed run's tombstone
    lands in the SAME tree, so a second differently-outcomed completion can't re-settle (double refund, A);
  * a byte-identical replay is deduped; a mid-drain-crash file in working/ is reclaimed + reprocessed (K);
  * hostile files (FIFO / symlink / oversized / non-UTF-8) are quarantined, never hang or crash the drain (G).

Sovereign leg (the drain is owner-side; the envelope is built here with vigil_core + the integration
producer, both framework-free): PYTHONPATH=apps/sigil:integration.
"""
from __future__ import annotations

import itertools
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.jobs.completion_signal import emit_completion_signal
from vigil_integration.live.credit_lease_broker import (
    is_lease_settled, read_credit_lease, write_credit_lease,
)

_iss = itertools.count(1)
ORG, HOST, NOW = "org_a", "apme.cm", 2000.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _reserve(store, *, units=30, credits=100, publish_base=None):
    """Seat a member + wallet credits + ownership proof + a customer authority, then reserve + PUBLISH a lease.
    ``publish_base`` writes the lease bundle to a specific seam tree (default = $VIGIL_BASE_DIR). Returns
    (owner_keypair, reserve_result)."""
    owner = ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    g = LaunchGate(store)
    r = g.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW)
    assert r["ok"], r
    pg = LaunchGate(store, base_dir=publish_base) if publish_base is not None else g
    assert pg.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
    return owner, r


def _gov_and_delegation(owner, *, not_after=9_000_000_000):
    """A governance keypair + an owner-signed OFFENSE_GOVERNANCE_ROLE delegation scoped to the cust_ slug."""
    gov = generate_keypair()
    slug = _customer_slug()
    deleg = delegate_offense_governance(
        owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, scope=slug, not_after=not_after)
    return gov, deleg


def _customer_slug(org=ORG, host=HOST):
    from sigil.ui.target_authorization import _customer_slug as cs
    return cs(org, host)


def _avail(store):
    return WalletRegistry(store).available(ORG)


def _drain(store, spool, owner, deleg, *, scope=None, base=None, now=NOW):
    return CompletionSpoolWatcher(
        store, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
        scope=scope if scope is not None else _customer_slug(),
        base_dir=base if base is not None else os.environ["VIGIL_BASE_DIR"],
        now_fn=(now if callable(now) else (lambda: now))).drain()


def test_completed_settles_full_consumption_and_tombstones(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    assert _avail(s) == 70                                   # 30 of 100 reserved (held)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _drain(s, spool, owner, deleg)
    assert out == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}, out
    assert _avail(s) == 70                                   # flat-per-run: full reserved consumed, NO refund
    base = os.environ["VIGIL_BASE_DIR"]
    assert is_lease_settled(base, r["slug"], r["nonce"]) is True   # settle tombstoned + marked (K4-1)
    assert read_credit_lease(base, r["slug"]) is None


def test_canceled_settles_full_refund(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    assert _drain(s, spool, owner, deleg)["settled"] == 1
    assert _avail(s) == 100                                  # canceled → consumed 0 → full refund


def test_failed_settles_full_refund(monkeypatch):
    # red-pen fold (I): the 'failed' terminal outcome was never drained — a failed run refunds in full.
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="failed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _drain(s, spool, owner, deleg)
    assert out == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}, out
    assert _avail(s) == 100                                  # failed → consumed 0 → full refund


def test_forged_wrong_key_signal_is_rejected_nothing_settled(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)             # the delegation trusts gov...
    attacker = generate_keypair()
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", attacker.private_key_b64)], spool_dir=spool)   # ...but ATTACKER signed
    out = _drain(s, spool, owner, deleg)
    assert out["settled"] == 0 and out["rejected"] == 1
    assert _avail(s) == 70                                   # unchanged — no settle, credits still held


def test_nonce_mismatch_is_rejected(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce="a-different-nonce", outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _drain(s, spool, owner, deleg)
    assert out["settled"] == 0 and out["rejected"] == 1      # a completion for another launch can't settle this one
    assert _avail(s) == 70


def test_out_of_scope_completion_is_rejected(monkeypatch):
    # red-pen fold (F): the scope-bind rejecting branch was advertised but untested. A drain delegated/scoped
    # to slugA must refuse a validly-gov-signed completion carrying a DIFFERENT engagement_slug.
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)                  # delegation + drain scoped to cust_(ORG,HOST)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug="cust_" + "f" * 24, nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)   # a DIFFERENT slug
    out = _drain(s, spool, owner, deleg)
    assert out["settled"] == 0 and out["rejected"] == 1      # outside the delegated scope → refused
    assert _avail(s) == 70


def test_tenant_mismatched_lease_is_rejected(monkeypatch):
    # red-pen fold (C): the non-tautological tenant cross-check. A lease filed under the scope slug but whose
    # OWN owner-signed (org_id, scope_host) do NOT hash to that slug is refused (cross-tenant settle guard).
    s = _store()
    owner, _r = _reserve(s)
    slug = _customer_slug()
    t = datetime.fromtimestamp(NOW, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=slug, org_id="other_org", scope_host="other.example",
                            units_reserved=30, not_before=t - timedelta(hours=1), not_after=t + timedelta(hours=8),
                            nonce="n9", issued_at=NOW)
    signed = sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})
    base = os.environ["VIGIL_BASE_DIR"]
    write_credit_lease(base, slug, signed, _owner_root(owner))   # overwrite with the tenant-mismatched lease
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=slug, nonce="n9", outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _drain(s, spool, owner, deleg)
    assert out["settled"] == 0 and out["rejected"] == 1      # (org,host) don't hash to the slug → refused


def test_expired_delegation_settles_nothing_and_holds(monkeypatch):
    # red-pen fold (B): the delegation is re-verified against the CURRENT clock each drain. A watcher built
    # while the delegation is valid must STOP settling once it expires — and leave the envelope for a later
    # renewed drain (a transient hold, not a terminal drop).
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner, not_after=3000)  # expires at t=3000
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    # construct while valid (now=2500 < 3000), drain while EXPIRED (now=9000 > 3000)
    clock = iter([2500, 9000, 9000, 9000])
    watcher = CompletionSpoolWatcher(
        s, spool_dir=spool, owner_pubkey=owner.public_key_b64, delegation=deleg,
        scope=_customer_slug(), base_dir=os.environ["VIGIL_BASE_DIR"], now_fn=lambda: next(clock))
    out = watcher.drain()
    assert out == {"settled": 0, "noop": 0, "rejected": 0, "deduped": 0}, out   # held, not settled, not rejected
    assert len(list((Path(spool) / "incoming").glob("*.json"))) == 1            # envelope left for a renewed drain
    assert _avail(s) == 70                                                      # credits still held — no refund


def test_bad_delegation_refuses_the_whole_drain(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    attacker = generate_keypair()
    with pytest.raises(ValueError):                          # delegation not signed by THIS owner → refuse at construction
        CompletionSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), owner_pubkey=attacker.public_key_b64,
                               delegation=deleg, scope=_customer_slug())


def test_wrong_role_delegation_refuses_the_whole_drain(monkeypatch):
    # red-pen fold (H): only the construction-time OFFENSE_GOVERNANCE_ROLE check stops a correctly-owner-signed
    # but WRONG-ROLE delegation from arming the settle-drain. Pin that a spine-role delegation is refused.
    from vigil_core.delegation import OFFENSE_SPINE_ROLE, sign_delegation
    s = _store()
    owner, _r = _reserve(s)
    gov = generate_keypair()
    spine_deleg = sign_delegation(
        owner, role=OFFENSE_SPINE_ROLE, scope=_customer_slug(),
        authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
        threshold=1, not_after=9_000_000_000)
    with pytest.raises(ValueError):                          # right owner, WRONG role → refuse at construction
        CompletionSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), owner_pubkey=owner.public_key_b64,
                               delegation=spine_deleg, scope=_customer_slug())


def test_replay_is_deduped_no_double_settle(monkeypatch):
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    env_path = emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                                      signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    text = Path(env_path).read_text(encoding="utf-8")        # capture the exact bytes BEFORE the drain moves it
    assert _drain(s, spool, owner, deleg)["settled"] == 1
    assert _avail(s) == 100
    # replay the SAME envelope bytes under a fresh incoming name → deduped on sha256(text), not re-settled
    (Path(spool, "incoming") / "replay.json").write_text(text, encoding="utf-8")
    out2 = _drain(s, spool, owner, deleg)
    assert out2["deduped"] == 1 and out2["settled"] == 0
    assert _avail(s) == 100                                  # no double refund


def test_completed_then_canceled_for_same_lease_cannot_double_refund(monkeypatch):
    # red-pen fold (J + the real money guarantee): a completed THEN a canceled completion for the same
    # (slug, nonce) are DIFFERENT bytes (not sha256-deduped). The first (completed) tombstones the lease, so the
    # second (canceled) finds no live lease → a safe no-op, never a refund of an already-consumed run.
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    assert _drain(s, spool, owner, deleg) == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}
    assert _avail(s) == 70                                   # consumed in full, no refund
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)   # different bytes
    out2 = _drain(s, spool, owner, deleg)
    assert out2["settled"] == 0 and out2["noop"] == 1        # lease tombstoned → no live lease → safe no-op
    assert _avail(s) == 70                                   # NOT refunded — the run was consumed (no free run)


def test_no_published_lease_is_a_safe_noop(monkeypatch):
    # red-pen fold (J): a gov-signed completion whose slug has no published lease is a SAFE no-op (nothing to
    # settle — already settled/absent), archived as handled, never a rejected/crashed drain.
    s = _store()
    owner, _r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    slug = _customer_slug()
    # tombstone/remove the published lease first so none is present for this slug
    from vigil_integration.live.credit_lease_broker import tombstone_credit_lease
    tombstone_credit_lease(os.environ["VIGIL_BASE_DIR"], slug, _r["nonce"])
    emit_completion_signal(engagement_slug=slug, nonce=_r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _drain(s, spool, owner, deleg)
    assert out == {"settled": 0, "noop": 1, "rejected": 0, "deduped": 0}, out


def test_settle_tombstone_lands_in_the_drain_base_dir_not_env(monkeypatch):
    # red-pen fold (A): the money bug. The settle/tombstone WRITE must share the drain's base_dir with the lease
    # READ. Publish the lease into a SEPARATE tree X (!= $VIGIL_BASE_DIR); a completed settle must tombstone the
    # lease in X (the tree the drain reads), NOT in $VIGIL_BASE_DIR — else a second completion re-settles.
    s = _store()
    X = tempfile.mkdtemp()
    owner, r = _reserve(s, publish_base=X)                   # lease bundle lives in X
    env = os.environ["VIGIL_BASE_DIR"]
    assert X != env
    assert read_credit_lease(X, r["slug"]) is not None       # published in X
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="completed",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out = _drain(s, spool, owner, deleg, base=X)             # drain reads + writes base_dir=X
    assert out == {"settled": 1, "noop": 0, "rejected": 0, "deduped": 0}, out
    assert is_lease_settled(X, r["slug"], r["nonce"]) is True   # tombstone + marker landed in X (the read tree)
    assert read_credit_lease(X, r["slug"]) is None
    # a SECOND differently-outcomed completion for the same (slug,nonce) now finds no live lease in X → no re-settle
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    out2 = _drain(s, spool, owner, deleg, base=X)
    assert out2["settled"] == 0 and out2["noop"] == 1        # no double refund (the double-spend A enabled)


def test_crash_in_working_is_reclaimed_and_reprocessed(monkeypatch):
    # red-pen fold (K): a file stranded in working/ by a mid-drain crash is reclaimed to incoming/ and settled,
    # never silently lost (a lost refund/charge is money). Mirrors webhook_drain._reclaim_working.
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    env_path = emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                                      signers=[("gov", gov.private_key_b64)], spool_dir=spool)
    # simulate a crash AFTER claim but BEFORE archive: move the envelope into working/ by hand
    working = Path(spool) / "working"
    working.mkdir(parents=True, exist_ok=True)
    os.replace(env_path, working / Path(env_path).name)
    assert not list((Path(spool) / "incoming").glob("*.json"))   # nothing in incoming — only the stranded file
    out = _drain(s, spool, owner, deleg)                     # drain() reclaims working/ → reprocesses it
    assert out["settled"] == 1, out
    assert _avail(s) == 100                                  # the stranded refund was recovered, not lost


def test_hostile_files_are_quarantined_without_hanging(monkeypatch):
    # red-pen fold (G): a FIFO / symlink / oversized / non-UTF-8 file must be quarantined (O_NOFOLLOW/O_NONBLOCK
    # /S_ISREG/size-cap/UTF-8), never hang or crash the drain, and a valid completion alongside still settles.
    s = _store()
    owner, r = _reserve(s)
    gov, deleg = _gov_and_delegation(owner)
    spool = tempfile.mkdtemp()
    incoming = Path(spool) / "incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    os.mkfifo(incoming / "aaa_fifo.json")                                     # a FIFO (hang risk w/o O_NONBLOCK)
    (incoming / "bbb_big.json").write_bytes(b"x" * (65_536 + 10))             # oversized
    (incoming / "ccc_binary.json").write_bytes(b"\xff\xfe\x00\x01not utf8")   # non-UTF-8
    emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome="canceled",
                           signers=[("gov", gov.private_key_b64)], spool_dir=spool)  # a valid one too
    out = _drain(s, spool, owner, deleg)
    assert out["settled"] == 1 and out["rejected"] == 3, out                 # 3 hostile quarantined, 1 valid settled
    assert _avail(s) == 100
