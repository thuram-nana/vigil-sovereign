"""pause/resume PR-3 — the WORKER-side half: a COOPERATIVE in-flight pause halt is a RE-DRIVEABLE transient.

When a running customer launch is paused, the engine raises ``EngagementPaused`` (see
``engine/crucible/framework/v2/tests/test_engage_pause_halt.py``). This pins what the customer-launch worker
(``make_engage_worker``) does with it — the MONEY-CRITICAL contract:
  * NO settle on pause: neither a refunding terminal FAILED nor a COMPLETED is emitted (the lease is HELD for
    resume, never prematurely refunded/tombstoned nor charged);
  * the arm-attempt slot is ROLLED BACK so repeat pause/resume can NEVER exhaust ``_MAX_ARM_ATTEMPTS`` into a
    spurious terminal abandonment — a genuinely-failing launch still terminates after exactly
    ``_MAX_ARM_ATTEMPTS`` real CRASHES;
  * a resume-required marker is recorded so the RE-DRIVE resumes (``resume=True``) WITHOUT re-burning the
    single-use floor into a replay refusal, even though the rolled-back attempt count can read 1 again;
  * the worker RE-RAISES, so ``JobRunner`` still release_delivery + re-enqueues the launch for re-drive;
  * default-OFF: a run that never pauses is byte-identical (one fresh arm, one COMPLETED, no markers).

The mock engine (injected ``run``) lets us drive pause/crash/success deterministically without a live scan.
Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the EngagementPaused branch (pause falls into the FAILED path)   -> test_pause_halt_does_not_settle_and_rolls_back_attempt
  * drop _record_resume_required (re-drive re-burns ⇒ resume=False)        -> test_pause_then_resume_re_drives_resume_true_and_settles_once
  * drop _release_attempt (pauses consume crash budget)                    -> test_repeat_pause_preserves_full_crash_budget
"""
from __future__ import annotations

import datetime as _dt
import os
import tempfile
from datetime import timezone

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.jobs.engage_worker import (
    _ATTEMPTS_DIRNAME, _MAX_ARM_ATTEMPTS, _RESUME_MARK_SUFFIX, _attempt_key, make_engage_worker,
)
from vigil_integration.jobs.launch_trigger import launch_delivery_id
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.live.credit_lease_broker import write_credit_lease
from vigil_integration.live.credit_lease_pause import clear_lease_pause, is_lease_paused, record_lease_pause

# The worker imports framework LAZILY; framework is not on the sovereign-only leg, so skip cleanly there and
# run in the offense/integration CI leg (same posture as test_engage_runner.py).
pytest.importorskip("framework.v2.authority.store", reason="framework (offense) not importable in the sovereign leg")
from framework.v2.engage import EngagementPaused  # noqa: E402 — after importorskip, by design

SLUG, HOST, ORG = "cust_pr3redrive", "apme.cm", "org_a"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease(owner, *, nonce="n1", issued=1000.0, units=10):
    t = _dt.datetime.fromtimestamp(issued, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=SLUG, org_id=ORG, scope_host=HOST, units_reserved=units,
                            not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8),
                            nonce=nonce, issued_at=issued)
    return sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})


def _customer_authority(slug, scope, *, env="twin", issued_by="customer:org_a", now=1000.0):
    from framework.v2.authority.models import EngagementAuthority
    t = _dt.datetime.fromtimestamp(now, tz=timezone.utc)
    return EngagementAuthority(engagement_slug=slug, environment=env, scope=scope, issued_by=issued_by,
                               not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8))


def _rig(monkeypatch, owner, *, env="twin"):
    from framework.v2.authority import store as authz_store
    base = tempfile.mkdtemp()
    write_credit_lease(base, SLUG, _lease(owner), _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _customer_authority(slug, [HOST], env=env))
    return base


def _job(*, nonce="n1"):
    return SecurityJob.normalize(
        source="api", repo=HOST, engagement_slug=SLUG, tenant_id=ORG, commit=nonce,
        delivery_id=launch_delivery_id(SLUG, nonce),
        extra={"seed_url": f"https://{HOST}", "host": HOST, "nonce": nonce, "org_id": ORG})


def _mk(monkeypatch, base, run, emits):
    """Build the worker with a recorder in place of the real governance-signed settle emit, so a test observes
    EXACTLY which completion outcome (if any) the worker spools."""
    monkeypatch.setattr("vigil_integration.jobs.completion_signal.emit_completion_signal",
                        lambda **kw: emits.append(kw["outcome"]))
    return make_engage_worker(trust_root=object(), base_dir=base, run=run, signers=[("k", "v")])


def _attempts_dir(base):
    return os.path.join(base, _ATTEMPTS_DIRNAME)


def _slot(base, nonce, n):
    return os.path.join(_attempts_dir(base), f"{_attempt_key(SLUG, nonce)}.{n}.json")


def _resume_marker(base, nonce):
    return os.path.join(_attempts_dir(base), f"{_attempt_key(SLUG, nonce)}.{_RESUME_MARK_SUFFIX}.json")


# ---------------------------------------------------------------------------------------------------
def test_pause_halt_does_not_settle_and_rolls_back_attempt(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    emits: list = []

    def _run(**kw):
        raise EngagementPaused("paused mid-run")

    w = _mk(monkeypatch, base, _run, emits)
    with pytest.raises(EngagementPaused):
        w(_job(nonce="n1"))
    assert emits == []                              # NO completion signal — not FAILED (no premature refund), not COMPLETED
    assert not os.path.exists(_slot(base, "n1", 1))  # the attempt slot was ROLLED BACK (no crash-budget consumed)
    assert os.path.exists(_resume_marker(base, "n1"))  # resume-required recorded (so the re-drive resumes)


def test_pause_then_resume_re_drives_resume_true_and_settles_once(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    emits: list = []
    seen_resume: list = []
    state = {"paused": True}

    def _run(**kw):
        seen_resume.append(kw["resume"])
        if state["paused"]:
            raise EngagementPaused("paused")
        return {"facts": 0}

    w = _mk(monkeypatch, base, _run, emits)
    with pytest.raises(EngagementPaused):
        w(_job(nonce="n1"))                         # paused mid-run
    state["paused"] = False
    w(_job(nonce="n1"))                             # resume (clear) → re-drive
    # the first arm is fresh; the re-drive RESUMES (resume=True) despite the attempt slot being rolled back —
    # so it re-validates/re-binds WITHOUT re-burning the single-use floor into a replay refusal.
    assert seen_resume == [False, True]
    assert emits == ["completed"]                   # exactly ONE COMPLETED on the eventual success; NO FAILED raced it


def test_repeat_pause_preserves_full_crash_budget(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    emits: list = []
    mode = {"m": "pause"}

    def _run(**kw):
        if mode["m"] == "pause":
            raise EngagementPaused("paused")
        raise RuntimeError("genuine crash")

    w = _mk(monkeypatch, base, _run, emits)
    for _ in range(5):                              # five pause/resume cycles
        with pytest.raises(EngagementPaused):
            w(_job(nonce="n1"))
    assert emits == []                              # not one FAILED from any pause — the lease is HELD, never abandoned
    # the FULL crash budget still remains: it takes exactly _MAX_ARM_ATTEMPTS real crashes to terminate.
    mode["m"] = "crash"
    for i in range(_MAX_ARM_ATTEMPTS):
        with pytest.raises(RuntimeError):
            w(_job(nonce="n1"))
        expected = ["failed"] if i == _MAX_ARM_ATTEMPTS - 1 else []
        assert emits == expected, f"after crash {i + 1}: {emits}"  # FAILED ONLY on the terminal crash


def test_no_pause_is_byte_identical(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    emits: list = []
    seen_resume: list = []

    def _run(**kw):
        seen_resume.append(kw["resume"])
        return {"facts": 0}

    w = _mk(monkeypatch, base, _run, emits)
    w(_job(nonce="n1"))
    assert seen_resume == [False]                   # one fresh arm
    assert emits == ["completed"]                   # one COMPLETED
    assert not os.path.exists(_resume_marker(base, "n1"))  # a clean run records NO pause/resume marker


def test_pause_on_failsafe_mark_does_not_delete_a_prior_slot(monkeypatch):
    # Red-pen LOW (folded): _mark_attempt's FAIL-SAFE / SATURATED paths return an attempt number but mint NO
    # slot. A pause must then NOT roll back ``<key>.<attempt>`` — that slot belongs to a PRIOR attempt, and
    # unlinking it would silently erode crash budget (a genuinely-failing launch would need an extra real crash
    # to terminate). The _slot_created flag gates the rollback.
    import vigil_integration.jobs.engage_worker as EW
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    # a PRIOR crash's slot 1 exists on disk
    os.makedirs(_attempts_dir(base), exist_ok=True)
    open(_slot(base, "n1", 1), "w").close()
    # force THIS attempt onto the fail-safe path: attempt=1 but slot_created=False (no slot minted)
    monkeypatch.setattr(EW, "_mark_attempt", lambda base_dir, slug, nonce: (1, False))
    emits: list = []

    def _run(**kw):
        raise EngagementPaused("paused")

    w = _mk(monkeypatch, base, _run, emits)
    with pytest.raises(EngagementPaused):
        w(_job(nonce="n1"))
    assert emits == []                                     # no settle (pause path)
    assert os.path.exists(_slot(base, "n1", 1))            # the PRIOR slot survives — crash budget intact
    assert os.path.exists(_resume_marker(base, "n1"))      # resume-required still recorded (burn-driven, not slot-driven)


def test_hard2_arm_window_pause_failure_never_settles_and_rolls_back(monkeypatch):
    # HARD #2: a NON-EngagementPaused run failure while the lease is paused (the gate->arm window) is reversible:
    # NO FAILED settle even at the terminal attempt (no premature refund/tombstone), the slot is rolled back, and
    # NO resume-required is recorded (the precondition refused BEFORE the floor burn).
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    record_lease_pause(base, SLUG, "n1")                   # lease paused after pickup, before arm
    emits: list = []

    def _run(**kw):
        raise RuntimeError("precondition refused: lease is paused")   # EngagementRefused-shaped (NOT EngagementPaused)

    w = _mk(monkeypatch, base, _run, emits)
    for _ in range(_MAX_ARM_ATTEMPTS + 1):                 # past the terminal attempt
        with pytest.raises(RuntimeError):
            w(_job(nonce="n1"))
    assert emits == []                                     # never a FAILED settle while paused
    assert not os.path.exists(_resume_marker(base, "n1"))  # NO resume-required (floor was not burned)


def test_hard2_fail_safe_genuine_failure_with_no_pause_still_terminates(monkeypatch):
    # FAIL-SAFE: with NO pause marker, a genuine failure is NOT held — it takes the normal path and the terminal
    # attempt emits the refunding FAILED (so a broken launch still terminates; HARD #2 never swallows it).
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)                        # no pause recorded
    emits: list = []

    def _run(**kw):
        raise RuntimeError("genuine crash")

    w = _mk(monkeypatch, base, _run, emits)
    for i in range(_MAX_ARM_ATTEMPTS):
        with pytest.raises(RuntimeError):
            w(_job(nonce="n1"))
    assert emits == ["failed"]                             # terminal FAILED fires — not swallowed by HARD #2


def test_hard2_cleared_window_pause_re_arms_fresh_not_resume(monkeypatch):
    # The money-critical distinction from PR-3's in-flight pause: a gate->arm-window pause did NOT burn the floor,
    # so the re-drive after resume must arm FRESH (resume=False ⇒ consume), NOT resume — else the floor is never
    # burned and the lease is replayable (a free run). Proven by resume staying False across the re-drive.
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    record_lease_pause(base, SLUG, "n1")
    seen_resume: list = []
    emits: list = []

    def _run(**kw):
        seen_resume.append(kw["resume"])
        if is_lease_paused(base, SLUG, "n1"):
            raise RuntimeError("precondition refused (paused)")
        return {"facts": 0}

    w = _mk(monkeypatch, base, _run, emits)
    with pytest.raises(RuntimeError):
        w(_job(nonce="n1"))                                # window-pause failure → HARD #2 (no settle, no resume-required)
    clear_lease_pause(base, SLUG, "n1")                    # resume
    w(_job(nonce="n1"))                                    # re-drive
    assert seen_resume == [False, False]                   # BOTH fresh — the floor was never burned, so never resume
    assert emits == ["completed"]


def test_crash_does_not_set_resume_required(monkeypatch):
    # A genuine crash (NOT a pause) must NOT look like a pause: it consumes its attempt slot (crash budget) and
    # records NO resume-required marker — so crash re-drive resumes via the existing attempt>1 path, unchanged.
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    emits: list = []

    def _run(**kw):
        raise RuntimeError("crash")

    w = _mk(monkeypatch, base, _run, emits)
    with pytest.raises(RuntimeError):
        w(_job(nonce="n1"))
    assert not os.path.exists(_resume_marker(base, "n1"))  # NOT a pause → no resume-required
    assert os.path.exists(_slot(base, "n1", 1))            # the crash DID consume its attempt slot
