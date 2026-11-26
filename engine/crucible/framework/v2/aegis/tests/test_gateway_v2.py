"""AEGIS AS-2c (gateway v2) — the V2 authority RESOLVER, deterministic and offline.

Covers the seven AS-2c behaviours at the resolver seam, with no sockets and an injected clock so every
assertion is reproducible:

  * dual-accept across an owner-root overlap set;
  * the monotone enforcement epoch FLOOR (below-floor ⇒ pass-through; the floor never regresses);
  * signed V2 revocation ⇒ pass-through;
  * the lease / outer-window lapse ⇒ pass-through (R16);
  * ``release_valid`` (no release root ⇒ never enforce ⇒ OBSERVE; a release-root release ⇒ ENFORCE);
  * the ≤1 s decision cache on an injected monotonic clock;
  * re-plant idempotency: one authority event per distinct (subject, epoch).

(The socket-level 421 / enforce / acceptance behaviours are in test_gateway_v2_e2e.py.)
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_core.authority_v2 import (
    AuthorityOutcome,
    AuthoritySubject,
    AuthorityWithdrawal,
    EnforceRelease,
    EnforcementOverride,
    EpochStatement,
    MonitoringAuthorityV2,
    MonitoringCapability,
    MonitoringLease,
    MonitoringRevocationV2,
    OverrideTarget,
    SubjectKind,
    sign_enforce_release,
    sign_epoch_statement,
    sign_monitoring_authority_v2,
    sign_monitoring_revocation_v2,
)

from framework.v2.aegis.authority_v2_check import (
    AuthorityEvent,
    AuthorityV2Cache,
    AuthorityV2Paths,
    MonotoneEpochFloor,
    _subject_dir_name,
    resolve_authority_v2,
)

ORG, HOST = "org_a", "apme.cm"
OWNER = generate_keypair()
OWNER_NEXT = generate_keypair()          # the incoming root during a rotation (dual-accept)
RELEASE = generate_keypair()             # the SEPARATE release root (AS-29)

OWNER_ROOT = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                               public_key_b64=OWNER.public_key_b64)])
OWNER_ROOT_NEXT = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner2", name="owner2",
                                                                    public_key_b64=OWNER_NEXT.public_key_b64)])
RELEASE_ROOT = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="rel", name="rel",
                                                                 public_key_b64=RELEASE.public_key_b64)])
B = MonitoringCapability.BLOCK
OBS = MonitoringCapability.OBSERVE


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _subject(org=ORG, host=HOST) -> AuthoritySubject:
    return AuthoritySubject(kind=SubjectKind.HOST, org_id=org, host=host)


def _grant(signer=OWNER, *, org=ORG, host=HOST, epoch=1, caps=(OBS,), nb=0.0, na=4.0e9,
           lease_nb=0.0, lease_na=4.0e9, instance="gw", replica=0):
    doc = MonitoringAuthorityV2(
        subject=_subject(org, host), capabilities=list(caps), epoch=epoch,
        not_before=_dt(nb), not_after=_dt(na),
        lease=MonitoringLease(not_before=_dt(lease_nb), not_after=_dt(lease_na)),
        instance_id=instance, replica_index=replica)
    kid = "owner" if signer is OWNER else "owner2"
    return sign_monitoring_authority_v2(doc, {kid: signer.private_key_b64})


def _paths(tmp: Path, *, instance="gw", replica=0) -> AuthorityV2Paths:
    subj = _subject()
    base = tmp / _subject_dir_name(subj)
    base.mkdir(parents=True, exist_ok=True)
    return AuthorityV2Paths(base=base, subject=subj, instance_id=instance, replica_index=replica)


def _plant(paths: AuthorityV2Paths, attr: str, signed) -> None:
    getattr(paths, attr).write_bytes(signed.model_dump_json().encode())


def _resolve(paths, *, owner_roots=(OWNER_ROOT,), release_roots=(), floor=None, now=1000.0, cap=B, on_event=None):
    return resolve_authority_v2(ORG, HOST, paths=paths, owner_roots=list(owner_roots),
                                release_roots=list(release_roots), floor=floor or MonotoneEpochFloor(),
                                now=_dt(now), requested_capability=cap, on_event=on_event)


# ---- no grant / invalid host ------------------------------------------------------------------------------
def test_no_grant_is_pass_through(tmp_path):
    d = _resolve(_paths(tmp_path))
    assert d.pass_through and d.reasons == ("no-grant",) and d.grant_present is False


def test_no_owner_root_is_pass_through(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant())
    assert _resolve(p, owner_roots=()).reasons == ("no-owner-root",)


# ---- dual-accept across the owner-root overlap set ---------------------------------------------------------
def test_dual_accept_grant_verifies_under_either_overlap_root(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(signer=OWNER_NEXT))                 # signed by the INCOMING root only
    # under the retiring root alone: unverified ⇒ pass-through.
    assert _resolve(p, owner_roots=(OWNER_ROOT,)).reasons == ("grant-unverified",)
    # under the overlap set (both roots): accepted ⇒ a live grant ⇒ OBSERVE.
    d = _resolve(p, owner_roots=(OWNER_ROOT, OWNER_ROOT_NEXT))
    assert d.observe and "grant-live" in d.reasons


def test_grant_for_another_subject_never_authorizes(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(host="other.cm"))                   # a grant that binds a different host
    # the grant verifies but binds the wrong subject (the file path is this subject's, the content is not).
    assert _resolve(p).reasons == ("grant-subject-mismatch",)


# ---- monotone enforcement floor --------------------------------------------------------------------------
def test_below_floor_grant_is_stale_pass_through(tmp_path):
    p = _paths(tmp_path)
    floor = MonotoneEpochFloor()
    _plant(p, "grant", _grant(epoch=2))
    # a signed EpochStatement raises the floor to 5; the epoch-2 grant is now STALE.
    _plant(p, "epoch", sign_epoch_statement(EpochStatement(subject=_subject(), epoch=5),
                                            {"owner": OWNER.private_key_b64}))
    d = _resolve(p, floor=floor)
    assert d.pass_through and "stale-epoch" in d.reasons and d.floor == 5


def test_floor_never_regresses(tmp_path):
    p = _paths(tmp_path)
    floor = MonotoneEpochFloor()
    _plant(p, "grant", _grant(epoch=9))
    _plant(p, "epoch", sign_epoch_statement(EpochStatement(subject=_subject(), epoch=7),
                                            {"owner": OWNER.private_key_b64}))
    assert _resolve(p, floor=floor).floor == 7
    # a LOWER epoch statement can never pull the floor back down.
    _plant(p, "epoch", sign_epoch_statement(EpochStatement(subject=_subject(), epoch=3),
                                            {"owner": OWNER.private_key_b64}))
    d = _resolve(p, floor=floor)
    assert d.floor == 7 and d.observe        # floor held at 7; the epoch-9 grant is at/above it ⇒ live


def test_an_unsigned_epoch_statement_does_not_raise_the_floor(tmp_path):
    p = _paths(tmp_path)
    floor = MonotoneEpochFloor()
    _plant(p, "grant", _grant(epoch=2))
    # signed under the WRONG key ⇒ not verified ⇒ ignored ⇒ floor stays 0 ⇒ the grant is live.
    _plant(p, "epoch", sign_epoch_statement(EpochStatement(subject=_subject(), epoch=5),
                                            {"rel": RELEASE.private_key_b64}))
    d = _resolve(p, floor=floor)
    assert d.floor == 0 and d.observe


# ---- signed revocation ------------------------------------------------------------------------------------
def test_signed_revocation_supersedes_the_grant(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(epoch=3))
    _plant(p, "revocation", sign_monitoring_revocation_v2(
        MonitoringRevocationV2(subject=_subject(), epoch=3), {"owner": OWNER.private_key_b64}))
    assert _resolve(p).reasons[0] == "revoked" or "revoked" in _resolve(p).reasons


def test_unsigned_revocation_is_ignored(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(epoch=3))
    _plant(p, "revocation", sign_monitoring_revocation_v2(
        MonitoringRevocationV2(subject=_subject(), epoch=3), {"rel": RELEASE.private_key_b64}))  # wrong key
    assert _resolve(p).observe             # forged revocation does not stop monitoring


# ---- lease / window lapse ⇒ pass-through (R16) ------------------------------------------------------------
def test_lapsed_lease_is_pass_through_even_inside_the_outer_window(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(nb=0.0, na=4.0e9, lease_nb=0.0, lease_na=500.0))   # outer open; lease closed by 500
    d = _resolve(p, now=1000.0)
    assert d.pass_through and "lease-lapsed" in d.reasons


def test_live_lease_observes(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(lease_nb=0.0, lease_na=4.0e9))
    assert _resolve(p, now=1000.0).observe


# ---- release_valid (AS-29) --------------------------------------------------------------------------------
def test_block_grant_without_a_release_root_stays_observe(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(caps=(OBS, B)))
    d = _resolve(p, release_roots=())      # AS-29 pending: no release root provisioned
    assert d.observe and d.release_valid is False and "no-release" in d.reasons


def test_block_grant_with_a_valid_release_enforces(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(caps=(OBS, B), epoch=2))
    _plant(p, "release", sign_enforce_release(
        EnforceRelease(subject=_subject(), released_capabilities=[B], epoch=2,
                       not_before=_dt(0.0), not_after=_dt(4.0e9)), {"rel": RELEASE.private_key_b64}))
    d = _resolve(p, release_roots=(RELEASE_ROOT,))
    assert d.enforce and d.release_valid and d.capability == B


def test_owner_root_cannot_satisfy_a_release(tmp_path):
    """The separate-root wall: a release signed under the OWNER key never verifies as a release."""
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(caps=(OBS, B), epoch=2))
    _plant(p, "release", sign_enforce_release(
        EnforceRelease(subject=_subject(), released_capabilities=[B], epoch=2,
                       not_before=_dt(0.0), not_after=_dt(4.0e9)), {"owner": OWNER.private_key_b64}))
    d = _resolve(p, release_roots=(RELEASE_ROOT,))
    assert d.observe and d.release_valid is False


def test_release_below_floor_does_not_enforce(tmp_path):
    p = _paths(tmp_path)
    floor = MonotoneEpochFloor()
    _plant(p, "grant", _grant(caps=(OBS, B), epoch=5))
    _plant(p, "epoch", sign_epoch_statement(EpochStatement(subject=_subject(), epoch=5),
                                            {"owner": OWNER.private_key_b64}))
    _plant(p, "release", sign_enforce_release(
        EnforceRelease(subject=_subject(), released_capabilities=[B], epoch=2,   # stale release epoch
                       not_before=_dt(0.0), not_after=_dt(4.0e9)), {"rel": RELEASE.private_key_b64}))
    d = _resolve(p, release_roots=(RELEASE_ROOT,), floor=floor)
    assert d.observe and "stale-release-epoch" in d.reasons


# ---- unsigned downgrade-only signals ----------------------------------------------------------------------
def test_unsigned_withdrawal_is_pass_through(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant())
    p.withdrawal.write_bytes(AuthorityWithdrawal(subject=_subject()).model_dump_json().encode())
    assert _resolve(p).pass_through


def test_unsigned_override_clamps_enforce_to_observe(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant(caps=(OBS, B), epoch=2))
    _plant(p, "release", sign_enforce_release(
        EnforceRelease(subject=_subject(), released_capabilities=[B], epoch=2,
                       not_before=_dt(0.0), not_after=_dt(4.0e9)), {"rel": RELEASE.private_key_b64}))
    p.override.write_bytes(EnforcementOverride(subject=_subject(),
                                               downgrade_to=OverrideTarget.OBSERVE).model_dump_json().encode())
    d = _resolve(p, release_roots=(RELEASE_ROOT,))
    assert d.observe and "override-observe" in d.reasons


# ---- the ≤1 s decision cache (injected monotonic clock) ---------------------------------------------------
def test_decision_cache_holds_for_the_ttl_then_refreshes(tmp_path):
    p = _paths(tmp_path)
    _plant(p, "grant", _grant())
    clock = [0.0]
    floor = MonotoneEpochFloor()
    cache = AuthorityV2Cache(
        lambda org, host: _resolve(p, floor=floor),
        monotonic=lambda: clock[0], ttl_s=1.0)
    first = cache.get(ORG, HOST)
    assert first.observe
    # delete the grant on disk; within the TTL the cache still returns the live decision.
    p.grant.unlink()
    clock[0] = 0.5
    assert cache.get(ORG, HOST).observe, "within TTL the cached decision is reused"
    # past the TTL the resolver re-reads and sees no grant ⇒ pass-through.
    clock[0] = 1.5
    assert cache.get(ORG, HOST).pass_through, "after TTL the decision refreshes"


# ---- re-plant idempotency: one event per (subject, epoch) -------------------------------------------------
def test_re_plant_produces_no_duplicate_event(tmp_path):
    p = _paths(tmp_path)
    floor = MonotoneEpochFloor()
    events: list[AuthorityEvent] = []
    _plant(p, "grant", _grant(epoch=4))
    # first resolve: the grant becomes live ⇒ exactly one planted event.
    _resolve(p, floor=floor, on_event=events.append)
    assert [e.epoch for e in events] == [4]
    # RE-PLANT the identical grant (same epoch) repeatedly ⇒ NO new event.
    for _ in range(3):
        _resolve(p, floor=floor, on_event=events.append)
    assert [e.epoch for e in events] == [4], "re-plant of an already-known grant produces no event"
    # a genuinely NEW generation (higher epoch) ⇒ one more event.
    _plant(p, "grant", _grant(epoch=5))
    _resolve(p, floor=floor, on_event=events.append)
    assert [e.epoch for e in events] == [4, 5]


def test_stale_re_plant_after_a_move_produces_no_event(tmp_path):
    """T-RP: after a 'move' advances the floor (a higher EpochStatement), re-planting the OLD grant is stale ⇒
    pass-through ⇒ no event (re-plant refused after move)."""
    p = _paths(tmp_path)
    floor = MonotoneEpochFloor()
    events: list[AuthorityEvent] = []
    _plant(p, "grant", _grant(epoch=2))
    _resolve(p, floor=floor, on_event=events.append)
    assert len(events) == 1
    # the move: a signed EpochStatement raises the floor above the old grant's epoch.
    _plant(p, "epoch", sign_epoch_statement(EpochStatement(subject=_subject(), epoch=6),
                                            {"owner": OWNER.private_key_b64}))
    d = _resolve(p, floor=floor, on_event=events.append)
    assert d.pass_through and "stale-epoch" in d.reasons
    assert len(events) == 1, "a stale re-plant after a move produces no event"


def test_resolver_is_total_on_a_malformed_grant(tmp_path):
    p = _paths(tmp_path)
    p.grant.write_bytes(b"{ not json")
    assert _resolve(p).pass_through       # never raises; degrades to pass-through
