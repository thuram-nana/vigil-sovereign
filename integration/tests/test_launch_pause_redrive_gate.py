"""pause/resume PR-4 (HARD #1) — a launch paused AFTER it was enqueued RE-DRIVES on resume, never strands.

PR-3 halts a RUNNING launch. This closes the other money-critical window the PR-3 red-pen flagged: a job
already sitting in the durable queue when its lease is paused. The customer-launch gate now classifies a
REVERSIBLE paused-lease refusal (`LEASE_PAUSED_DENIAL`) distinctly from a TERMINAL one (`no_lease`), and
`JobRunner.run_one` RELEASES the one-shot delivery on the paused one — so the seam poller re-produces it once
the pause clears, instead of `complete()`ing it with the delivery marker kept (which made the paid launch
un-re-admittable: the strand).

Pinned: gate classification (paused ⇒ `lease_paused`; settled ⇒ `no_lease`; clean ⇒ allowed; fail-SAFE toward
terminal); `run_one` releases the delivery ONLY on `lease_paused` (keeps it on a terminal refusal); the full
enqueue → pause → refuse → resume → RE-ADMIT-and-run loop; default-OFF byte-identical.

Audit fold (the DEFAULT ``base_dir``): every launch-runner factory defaults ``base_dir=None``. The lease verify
resolves that to ``VIGIL_BASE_DIR``; the pause reader did not (it raised), and the gate's classifier swallowed
the error as "not paused" — so on the default path a paused queued launch was refused ``no_lease``, its delivery
marker kept, and the resumed launch coalesced as ``duplicate_delivery`` forever (a paid launch stranded, credits
held until expiry). Pinned END TO END through the REAL gate + ``JobRunner`` + ``LaunchSeamDrain`` built by
``make_engage_scan_runner`` with its DEFAULT ``base_dir``; plus the classifier's fail direction (a lease that
still verifies is RELEASED for re-drive whenever only its pause conjunct refused it — paused, pause state
undeterminable, or resumed mid-check — and a lease that does not verify is never marked re-driveable).

Mutation-verify targets (each neuter reds a NAMED test here):
  * gate always returns "no_lease" (drop the _lease_refusal_is_pause branch) -> test_gate_classifies_a_paused_lease_as_reversible
  * run_one releases on EVERY refusal / never (drop the denial_code guard)   -> test_run_one_keeps_delivery_on_a_terminal_refusal / test_run_one_releases_delivery_only_on_a_paused_refusal
  * classifier re-reads the pause marker and swallows an error as "not paused" -> test_gate_releases_for_redrive_when_the_pause_state_is_undeterminable
  * classifier treats "not paused on re-read" as terminal                      -> test_gate_releases_for_redrive_when_a_resume_races_the_classification
  * classifier returns True for a lease that does not verify                   -> test_gate_terminal_lease_refusals_are_never_marked_redriveable
  * pause substrate default base drifts from the lease reader's                -> test_pause_substrate_default_base_is_the_lease_readers_default
"""
from __future__ import annotations

import datetime as _dt
import time
from datetime import timezone
from pathlib import Path

import pytest

from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)
from vigil_integration.jobs.authorize import LEASE_PAUSED_DENIAL, GateOutcome, build_customer_launch_gate
from vigil_integration.jobs.launch_trigger import launch_delivery_id
from vigil_integration.jobs.model import SecurityJob
from vigil_integration.jobs.queue import SecurityJobQueue
from vigil_integration.jobs.runner import JobRunner
from vigil_integration.live.credit_lease_broker import record_lease_settlement, write_credit_lease

# The gate + queue import framework LAZILY; framework is not on the sovereign leg, so skip cleanly there and
# run in the offense/integration CI leg (same posture as test_engage_runner / test_ci_runner).
pytest.importorskip("framework.v2.authority.store", reason="framework (offense) not importable in the sovereign leg")
pytest.importorskip("framework.v2.engagement_scheduler", reason="framework (offense) not importable in the sovereign leg")
_clp = pytest.importorskip("vigil_integration.live.credit_lease_pause")
record_lease_pause = _clp.record_lease_pause
clear_lease_pause = _clp.clear_lease_pause

SLUG, HOST, ORG = "cust_pr4gate", "apme.cm", "org_a"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease(owner, *, nonce="n1", issued=1000.0):
    t = _dt.datetime.fromtimestamp(issued, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=SLUG, org_id=ORG, scope_host=HOST, units_reserved=10,
                            not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8),
                            nonce=nonce, issued_at=issued)
    return sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})


def _customer_authority(slug, scope, *, now=1000.0):
    from framework.v2.authority.models import EngagementAuthority
    t = _dt.datetime.fromtimestamp(now, tz=timezone.utc)
    return EngagementAuthority(engagement_slug=slug, environment="twin", scope=scope, issued_by="customer:org_a",
                               not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8))


def _rig(monkeypatch, owner, *, settled=False):
    import tempfile

    from framework.v2.authority import store as authz_store
    base = tempfile.mkdtemp()
    write_credit_lease(base, SLUG, _lease(owner), _owner_root(owner))
    if settled:
        record_lease_settlement(base, SLUG, "n1")
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _customer_authority(slug, [HOST]))
    return base


def _job(*, nonce="n1"):
    return SecurityJob.normalize(
        source="api", repo=HOST, engagement_slug=SLUG, tenant_id=ORG, commit=nonce,
        delivery_id=launch_delivery_id(SLUG, nonce),
        extra={"seed_url": f"https://{HOST}", "host": HOST, "nonce": nonce, "org_id": ORG})


def _untagged_job(*, nonce="n1"):
    # UNtagged (tenant_id="") so _reconcile_tenant passes without sharding — isolates run_one's delivery handling
    # from the tenant boundary (the real gate's tenant bind is covered by the classification tests above).
    return SecurityJob.normalize(
        source="api", repo=HOST, engagement_slug=SLUG, tenant_id="", commit=nonce,
        delivery_id=launch_delivery_id(SLUG, nonce),
        extra={"seed_url": f"https://{HOST}", "host": HOST, "nonce": nonce})


# ------------------------------------------------------------------ gate classification (real lease) --
def test_gate_classifies_a_paused_lease_as_reversible(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    gate = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)
    assert gate(_job()).allowed is True                       # clean ⇒ allowed (default-OFF byte-identical)
    record_lease_pause(base, SLUG, "n1")
    out = gate(_job())
    assert out.allowed is False and out.denial_code == LEASE_PAUSED_DENIAL   # REVERSIBLE, not no_lease
    clear_lease_pause(base, SLUG, "n1")
    assert gate(_job()).allowed is True                       # resume ⇒ allowed again


def test_gate_terminal_refusal_stays_no_lease(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner, settled=True)             # a SETTLED lease is TERMINAL, not reversible
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())
    assert out.allowed is False and out.denial_code == "no_lease"


# ------------------------------------------------------------------ run_one delivery handling ---------
def _runner(q, gate):
    return JobRunner(queue=q, gate=gate, worker=lambda j: {"ok": 1}, assert_tenant=lambda: None)


def test_run_one_releases_delivery_only_on_a_paused_refusal(tmp_path):
    q = SecurityJobQueue(str(tmp_path / "q"))
    assert q.enqueue(_untagged_job()).enqueued is True
    out = _runner(q, lambda j: GateOutcome(False, "paused", LEASE_PAUSED_DENIAL)).run_one()
    assert out.state == "refused" and out.denial_code == LEASE_PAUSED_DENIAL
    # delivery was RELEASED ⇒ the SAME delivery re-admits (the poller can re-produce the launch on resume)
    assert q.enqueue(_untagged_job()).enqueued is True


def test_run_one_keeps_delivery_on_a_terminal_refusal(tmp_path):
    q = SecurityJobQueue(str(tmp_path / "q"))
    assert q.enqueue(_untagged_job()).enqueued is True
    assert _runner(q, lambda j: GateOutcome(False, "nope", "no_lease")).run_one().state == "refused"
    # delivery KEPT (terminal) ⇒ a re-delivery coalesces as duplicate, exactly as before PR-4
    assert q.enqueue(_untagged_job()).enqueued is False


def test_full_redrive_enqueue_pause_refuse_resume_readmit(tmp_path):
    q = SecurityJobQueue(str(tmp_path / "q"))
    state = {"paused": True}
    ran: list = []

    def gate(j):
        return GateOutcome(False, "paused", LEASE_PAUSED_DENIAL) if state["paused"] else GateOutcome(True, "ok")

    r = JobRunner(queue=q, gate=gate, worker=lambda j: ran.append(j) or {"ok": 1}, assert_tenant=lambda: None)
    assert q.enqueue(_untagged_job()).enqueued is True
    assert r.run_one().denial_code == LEASE_PAUSED_DENIAL      # paused ⇒ refused + delivery released
    assert ran == []                                           # never ran while paused
    state["paused"] = False                                    # resume
    assert q.enqueue(_untagged_job()).enqueued is True         # re-admitted (delivery was released)
    assert r.run_one().state == "done"
    assert len(ran) == 1                                       # ran EXACTLY once, on resume — never stranded, never doubled


# ------------------------------------------------------------------ classifier fail direction ---------
def test_gate_releases_for_redrive_when_the_pause_state_is_undeterminable(monkeypatch):
    # The pause store cannot be read at all (here the reader itself raises). The verify fails CLOSED on that —
    # the launch is REFUSED — but the lease still verifies, so nothing terminal has happened to it: it must be
    # RELEASED for re-drive. Classifying it ``no_lease`` keeps the delivery marker and strands a paid launch.
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)

    def _unreadable(*_a, **_k):
        raise RuntimeError("pause store unreadable (simulated)")

    monkeypatch.setattr(_clp, "is_lease_paused", _unreadable)
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)(_job())
    assert out.allowed is False                                 # fail-CLOSED: never run on an unknown pause state
    assert out.denial_code == LEASE_PAUSED_DENIAL               # ... but held for re-drive, NOT terminal


def test_gate_releases_for_redrive_when_a_resume_races_the_classification(monkeypatch):
    # The gate's verify sees the pause and refuses; the customer's resume lands before the refusal is classified.
    # The lease verifies and is no longer paused — the furthest thing from terminal — so it must be released.
    from framework.v2 import launch_lease as LL
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    record_lease_pause(base, SLUG, "n1")
    real = LL.read_verified_launch_nonce

    def _resume_lands_first(*a, **k):
        clear_lease_pause(base, SLUG, "n1")
        return real(*a, **k)

    monkeypatch.setattr(LL, "read_verified_launch_nonce", _resume_lands_first)
    gate = build_customer_launch_gate(trust_root=object(), base_dir=base, now=1000.0)
    out = gate(_job())
    assert out.allowed is False and out.denial_code == LEASE_PAUSED_DENIAL
    assert gate(_job()).allowed is True                         # and the re-driven pickup is admitted


@pytest.mark.parametrize("case", ["settled", "expired", "wrong_tenant", "wrong_host", "foreign_signer", "absent"])
@pytest.mark.parametrize("pause_marker", [False, True], ids=["no-pause-marker", "with-pause-marker"])
def test_gate_terminal_lease_refusals_are_never_marked_redriveable(monkeypatch, case, pause_marker):
    # The other direction: a lease that does NOT verify (with the pause conjunct skipped) is genuinely
    # un-runnable, and must stay TERMINAL — with or without a pause marker lying on the seam for its nonce — or
    # the runner would release its delivery and the launch would re-enqueue forever.
    import tempfile

    from framework.v2.authority import store as authz_store
    owner = generate_keypair()
    base = tempfile.mkdtemp()
    now, scope, signer, org = 1000.0, [HOST], owner, ORG
    if case == "expired":
        now = 1000.0 + 9 * 3600                                 # past not_after (issued + 8h)
    if case == "wrong_tenant":
        org = "org_b"                                           # the lease belongs to another tenant
    if case == "wrong_host":
        scope = ["other.cm"]                                    # the verified authority binds a different host
    if case == "foreign_signer":
        signer = generate_keypair()                             # not the pinned owner key
    if case != "absent":
        t = _dt.datetime.fromtimestamp(1000.0, tz=timezone.utc)
        doc = CreditLaunchLease(engagement_slug=SLUG, org_id=org, scope_host=HOST, units_reserved=10,
                                not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8),
                                nonce="n1", issued_at=1000.0)
        write_credit_lease(base, SLUG, sign_credit_launch_lease(doc, {"owner": signer.private_key_b64}),
                           _owner_root(owner))
    if case == "settled":
        record_lease_settlement(base, SLUG, "n1")
    if pause_marker:
        record_lease_pause(base, SLUG, "n1")
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _customer_authority(slug, scope, now=now))
    out = build_customer_launch_gate(trust_root=object(), base_dir=base, now=now)(_job())
    assert out.allowed is False and out.denial_code == "no_lease"


# ------------------------------------------------------------------ the DEFAULT base_dir --------------
@pytest.mark.parametrize("env", ["/some/seam", "", None], ids=["set", "empty", "unset"])
def test_pause_substrate_default_base_is_the_lease_readers_default(monkeypatch, env):
    # ONE resolution for both: the pause substrate's ``base_dir=None`` default is the lease reader's own
    # (``launch_lease._base_dir`` — what verify_customer_launch_lease / read_verified_launch_nonce resolve None
    # to). The both-plane pause module cannot import the engine, so the convention is restated there and pinned
    # equal here, in the leg where both are importable.
    from framework.v2 import launch_lease as LL
    if env is None:
        monkeypatch.delenv("VIGIL_BASE_DIR", raising=False)
    else:
        monkeypatch.setenv("VIGIL_BASE_DIR", env)
    assert _clp._seam_base(None) == LL._base_dir()
    assert _clp.pauses_root(None).parent == Path(LL._base_dir())
    assert _clp._seam_base("explicit") == "explicit"            # only None is defaulted


def _live_rig(monkeypatch, owner, tmp_path):
    """The production shape: ONE seam (``VIGIL_BASE_DIR``) both planes agree on, a lease + authority valid on the
    REAL clock (the default-argument runner and poller read ``time.time()``), and a process sharded for ORG."""
    from framework.v2.authority import store as authz_store
    base = str(tmp_path / "seam")
    now = time.time()
    monkeypatch.setenv("VIGIL_BASE_DIR", base)
    monkeypatch.setenv("CRUCIBLE_TENANT", ORG)
    write_credit_lease(base, SLUG, _lease(owner, issued=now), _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: _owner_root(owner))
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _customer_authority(slug, [HOST], now=now))
    return base


@pytest.mark.parametrize("explicit_base", [True, False], ids=["explicit-base_dir", "default-base_dir"])
def test_e2e_queued_pause_is_held_then_readmitted_and_runs_exactly_once(monkeypatch, tmp_path, explicit_base):
    # THE strand, end to end, through the REAL gate + JobRunner + LaunchSeamDrain as make_engage_scan_runner
    # wires them. "default-base_dir" is the factory called the way its signature invites (base_dir omitted): the
    # lease reader resolved the seam from VIGIL_BASE_DIR, the pause reader did not, and the launch was stranded.
    from vigil_integration.jobs.launch_runner import make_engage_scan_runner
    from vigil_integration.launch_drain import LaunchSeamDrain
    owner = generate_keypair()
    base = _live_rig(monkeypatch, owner, tmp_path)
    ran: list = []
    emits: list = []
    monkeypatch.setattr("vigil_integration.jobs.completion_signal.emit_completion_signal",
                        lambda **kw: emits.append(kw["outcome"]))
    kwargs = {"base_dir": base} if explicit_base else {}
    runner = make_engage_scan_runner(str(tmp_path / "queue"), trust_root=object(), assert_tenant=lambda: None,
                                     run=lambda **kw: ran.append(kw) or {"ok": 1}, **kwargs)
    drain = LaunchSeamDrain(base_dir=base, queue=runner.queue)

    assert drain.drain() == {"enqueued": 1, "duplicate": 0, "deferred": 0}
    record_lease_pause(base, SLUG, "n1")                        # the customer pauses while the launch is QUEUED
    out = runner.run_one()
    assert out.state == "refused" and out.denial_code == LEASE_PAUSED_DENIAL   # held, NOT "no_lease"
    assert ran == [] and emits == []                            # never ran, never settled / refunded while paused
    assert drain.drain() == {"enqueued": 0, "duplicate": 0, "deferred": 0}     # still paused ⇒ nothing produced
    assert runner.run_one().state == "empty"                    # ... and nothing to spin on
    clear_lease_pause(base, SLUG, "n1")                         # the customer resumes
    assert drain.drain() == {"enqueued": 1, "duplicate": 0, "deferred": 0}     # RE-ADMITTED, not a duplicate
    assert runner.run_one().state == "done"
    assert len(ran) == 1 and ran[0]["resume"] is False          # ran EXACTLY once, as a fresh arm
    assert emits == ["completed"]                               # one COMPLETED; no FAILED (refund) ever raced it
    # exactly-once after the run: the still-published lease re-polls as a duplicate, never a second run
    assert drain.drain() == {"enqueued": 0, "duplicate": 1, "deferred": 0}
    assert runner.run_one().state == "empty"
