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

END TO END (the last section — the REAL engine under the REAL worker, on the REAL lease + pause seam):
  * the resume re-drive of a launch paused in flight RE-RUNS its scan and settles COMPLETED exactly once on
    the WHOLE report — it never settles the full reservation on the truncated scan the pause left behind;
  * a re-drive of a LATER launch on the same slug scans for itself — it never reloads an earlier launch's report;
  * a job never runs on a LATER launch's lease (the seam holds one lease per slug): it is refused before its
    arm, so each launch pays only for its own scan;
  * the re-scans pauses can cause one launch are bounded; past the bound the launch ends refunded, never charged.

The mock engine (injected ``run``) lets us drive pause/crash/success deterministically without a live scan.
Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the EngagementPaused branch (pause falls into the FAILED path)   -> test_pause_halt_does_not_settle_and_rolls_back_attempt
  * drop _record_resume_required (re-drive re-burns ⇒ resume=False)        -> test_pause_then_resume_re_drives_resume_true_and_settles_once
  * drop _release_attempt (pauses consume crash budget)                    -> test_repeat_pause_preserves_full_crash_budget
  * engine records a pause-cut scan as completed (resume reloads it)       -> test_e2e_resume_after_in_flight_pause_rescans_and_settles_once_on_the_whole_report
  * engine leaves the resume state unbound from the launch                 -> test_e2e_redrive_of_a_later_launch_never_settles_on_an_earlier_launchs_report
  * worker stops passing its job's nonce (launch_nonce) to the engine     -> test_e2e_a_job_never_runs_on_a_later_launchs_lease_so_each_launch_pays_only_for_its_own_scan
  * engine drops the pause re-scan bound                                  -> test_e2e_pause_rescans_are_bounded_then_the_launch_ends_refunded_never_charged
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import tempfile
import time
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


# ===================================================================================================
# END TO END — the REAL engine (``run_engagement``, its phase ledger, its lease precondition and its pause
# check) under the REAL worker, on a REAL owner-signed lease + the REAL pause marker. Only the scan campaign
# is a stand-in (no live target), and the governance-signed settle emit is replaced by a recorder.
# ===================================================================================================
def _e2e_rig(monkeypatch, tmp_path, owner):
    """Point the real engine at a hermetic seam + per-slug state dir, and return ``(base, publish)`` where
    ``publish(nonce)`` puts a CURRENT owner-signed lease for that launch on the seam."""
    from framework.v2 import engage as engage_mod
    from framework.v2.common import paths as _paths
    base = _rig(monkeypatch, owner)
    targets = tmp_path / "targets"
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)           # the phase ledger + scan snapshot
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")
    monkeypatch.setattr(engage_mod, "preflight", lambda slug, seed_url: None)   # no charter rig; the lease arm is real
    monkeypatch.setenv("VIGIL_BASE_DIR", base)                                 # the engine reads the seam from the env
    monkeypatch.setenv("CRUCIBLE_TENANT", ORG)
    issued = {"t": time.time()}

    def publish(nonce):
        issued["t"] += 1.0                          # a genuine re-lease is strictly newer (single-use floor)
        write_credit_lease(base, SLUG, _lease(owner, nonce=nonce, issued=issued["t"]), _owner_root(owner))
    return base, publish


def _e2e_worker(monkeypatch, base, emits):
    monkeypatch.setattr("vigil_integration.jobs.completion_signal.emit_completion_signal",
                        lambda **kw: emits.append(kw["outcome"]))
    return make_engage_worker(trust_root=object(), base_dir=base, signers=[("k", "v")],
                              profile_kwargs={"enable_chaining": False, "enable_oob": False})   # the DEFAULT (real) runner


def _e2e_campaign(monkeypatch, script, ctx=None):
    """Install a scan campaign whose Nth ``run`` executes ``script[N]`` — a callable returning the pages that
    scan fetched (or raising). Returns the list of scans that ran. ``ctx`` (a dict), when given, receives the
    engine's GATED ``send`` and the seed of the running scan, so a script step can drive a real gated action."""
    from framework.v2 import engage as engage_mod
    from framework.v2.scanner.campaign import ScanReport
    scans: list = []

    class _Fake:
        def __init__(self, *_a, **_k):
            self._send = _a[0] if _a else _k.get("send")

        def run(self, seed):
            scans.append(seed)
            if ctx is not None:
                ctx["send"], ctx["seed"] = self._send, seed
            return ScanReport(target=seed, pages_crawled=script[len(scans) - 1]())
    monkeypatch.setattr(engage_mod, "WebScanCampaign", _Fake)
    return scans


def _cut_by_pause(base, nonce, ctx, *, pages=1):
    """A scan step the customer's pause CUTS SHORT: the pause lands, the scan's next action goes through the
    engine's real gated send and is refused by the real halt check (no traffic), and the scan winds down with a
    truncated report of ``pages``."""
    def _step():
        from framework.v2.scanner.insertion import HttpRequest
        record_lease_pause(base, SLUG, nonce)
        resp = ctx["send"](HttpRequest(method="GET", url=f"{ctx['seed']}/next"))
        assert resp.get("refused") and "paused" in str(resp["refused"]).lower()
        return pages
    return _step


def test_e2e_resume_after_in_flight_pause_rescans_and_settles_once_on_the_whole_report(monkeypatch, tmp_path):
    from framework.v2 import launch_lease as LL
    owner = generate_keypair()
    base, publish = _e2e_rig(monkeypatch, tmp_path, owner)
    publish("n1")
    emits: list = []
    ctx: dict = {}
    # the customer pauses the RUNNING launch: its next action is refused and the scan comes back truncated
    scans = _e2e_campaign(monkeypatch, [_cut_by_pause(base, "n1", ctx), lambda: 99], ctx)
    w = _e2e_worker(monkeypatch, base, emits)

    with pytest.raises(EngagementPaused):
        w(_job(nonce="n1"))                         # the real arm burns the floor; the pause halts the run
    assert emits == []                              # no settle, no refund on pause
    assert not os.path.exists(_slot(base, "n1", 1))  # the arm attempt was not consumed by the pause
    assert os.path.exists(_resume_marker(base, "n1"))

    clear_lease_pause(base, SLUG, "n1")             # resume
    result = w(_job(nonce="n1"))                    # the re-drive
    assert len(scans) == 2                          # the resumed launch genuinely RE-RAN its scan...
    assert result.report.pages_crawled == 99        # ...and delivered the whole assessment, not the 1-page stub
    assert emits == ["completed"]                   # settled exactly once, on the whole report
    # the single-use floor was burned ONCE (by the fresh arm): the resume re-validated without re-consuming it
    ok, reason = LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, consume=True)
    assert ok is False and "replay" in reason


def test_e2e_redrive_of_a_later_launch_never_settles_on_an_earlier_launchs_report(monkeypatch, tmp_path):
    owner = generate_keypair()
    base, publish = _e2e_rig(monkeypatch, tmp_path, owner)
    emits: list = []

    def _crash():
        raise RuntimeError("scan crashed mid-way")

    scans = _e2e_campaign(monkeypatch, [lambda: 7, _crash, lambda: 42])
    w = _e2e_worker(monkeypatch, base, emits)

    publish("n1")
    assert w(_job(nonce="n1")).report.pages_crawled == 7       # launch 1 completes and settles
    assert emits == ["completed"]

    publish("n2")                                   # a genuine re-lease: launch 2 on the SAME (org, host) slug
    with pytest.raises(RuntimeError, match="scan crashed"):
        w(_job(nonce="n2"))                         # launch 2, attempt 1 (fresh arm) crashes mid-scan
    assert emits == ["completed"]                   # a transient crash settles nothing
    result = w(_job(nonce="n2"))                    # launch 2, attempt 2: the worker re-drives with resume=True
    assert len(scans) == 3                          # launch 2 scanned for ITSELF...
    assert result.report.pages_crawled == 42        # ...and settled on its own report, not launch 1's 7 pages
    assert emits == ["completed", "completed"]      # one settle per launch


def test_e2e_a_job_never_runs_on_a_later_launchs_lease_so_each_launch_pays_only_for_its_own_scan(
        monkeypatch, tmp_path):
    """Two unsettled launches of the same (org, host) are queued; the seam holds ONE lease per slug, so it now
    holds only launch n2's. Job n1 must not run on it: it is refused BEFORE the arm — no scan, no burn of n2's
    single-use floor, no settle. n2's own job then arms FRESH, scans for itself, and settles once on its own
    scan. (Before, job n1 ran under n2's lease and tagged its scan as n2's, and n2 reloaded that scan and was
    charged in full for a scan its own job never ran.)"""
    from framework.v2.common import paths as _paths
    from framework.v2.engage import EngagementRefused
    from framework.v2.phase_ledger import _launch_tag
    owner = generate_keypair()
    base, publish = _e2e_rig(monkeypatch, tmp_path, owner)
    emits: list = []
    scans = _e2e_campaign(monkeypatch, [lambda: 42])
    w = _e2e_worker(monkeypatch, base, emits)
    settles: list = []
    monkeypatch.setattr("vigil_integration.jobs.completion_signal.emit_completion_signal",
                        lambda **kw: settles.append((kw["nonce"], kw["outcome"])))

    publish("n1")
    publish("n2")                                   # the seam now holds ONLY launch n2's lease
    with pytest.raises(EngagementRefused, match="different launch"):
        w(_job(nonce="n1"))
    assert scans == [] and settles == []            # job n1 never scanned and settled nothing

    result = w(_job(nonce="n2"))                    # n2's FRESH arm still finds its floor unburned
    assert len(scans) == 1 and result.report.pages_crawled == 42
    assert settles == [("n2", "completed")]         # one scan, one charge — and it is n2's own scan
    recs = [json.loads(line) for line in _paths.phase_ledger_path(SLUG).read_text(encoding="utf-8").splitlines()
            if line.strip()]
    assert {r.get("launch") for r in recs if r.get("phase") == "scan"} == {_launch_tag("n2")}


def test_e2e_a_paused_launchs_job_does_not_run_on_a_later_launchs_lease(monkeypatch, tmp_path):
    """Same two-launch state, with launch n1 PAUSED while queued. The halt check used to be keyed to the seam
    lease (n2), so job n1 ran anyway. Now job n1 is refused before its arm and HELD (a paused launch is never
    refunded or charged), and nothing is scanned for it."""
    from framework.v2.engage import EngagementRefused
    owner = generate_keypair()
    base, publish = _e2e_rig(monkeypatch, tmp_path, owner)
    emits: list = []
    scans = _e2e_campaign(monkeypatch, [lambda: 42])
    w = _e2e_worker(monkeypatch, base, emits)
    publish("n1")
    publish("n2")
    record_lease_pause(base, SLUG, "n1")
    for _ in range(_MAX_ARM_ATTEMPTS + 1):          # past the terminal attempt: still held, never settled
        with pytest.raises(EngagementRefused):
            w(_job(nonce="n1"))
    assert scans == [] and emits == []


def test_e2e_pause_rescans_are_bounded_then_the_launch_ends_refunded_never_charged(monkeypatch, tmp_path):
    """Each pause that cuts a scan costs a whole re-scan for the one flat charge, and a pause consumes no crash
    attempt. With ``VIGIL_PAUSE_RESCAN_LIMIT=1`` the launch scans at most twice; every later re-drive is refused
    before any scan, and the worker's ORDINARY failure path ends the launch on its terminal attempt with exactly
    ONE refunding FAILED — never a COMPLETED charge, never a stranded reservation."""
    from framework.v2.engage import EngagementRefused
    monkeypatch.setenv("VIGIL_PAUSE_RESCAN_LIMIT", "1")
    owner = generate_keypair()
    base, publish = _e2e_rig(monkeypatch, tmp_path, owner)
    publish("n1")
    emits: list = []
    ctx: dict = {}
    scans = _e2e_campaign(monkeypatch, [_cut_by_pause(base, "n1", ctx), _cut_by_pause(base, "n1", ctx),
                                        lambda: 99], ctx)
    w = _e2e_worker(monkeypatch, base, emits)

    for _ in range(2):                              # the first scan + its one allowed re-scan, both cut
        with pytest.raises(EngagementPaused):
            w(_job(nonce="n1"))
        clear_lease_pause(base, SLUG, "n1")         # ...and resumed each time
    assert len(scans) == 2 and emits == []

    for i in range(_MAX_ARM_ATTEMPTS):
        with pytest.raises(EngagementRefused, match="pause re-scan limit"):
            w(_job(nonce="n1"))
        assert emits == (["failed"] if i == _MAX_ARM_ATTEMPTS - 1 else []), (i, emits)
    assert len(scans) == 2                          # no third scan ever ran
