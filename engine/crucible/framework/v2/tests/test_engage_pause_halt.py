"""pause/resume PR-3 — the engine-side COOPERATIVE IN-FLIGHT HALT of a RUNNING customer engagement.

PR-2 refuses a paused lease at the arm / enqueue CHOKEPOINT (before a run starts). PR-3 adds the other half:
a launch that is ALREADY RUNNING when its owner-signed lease is paused stops sending traffic at its next gated
action (the executor ``halt_check``, a sibling of the kill-switch) and the engine then RAISES a re-driveable
``EngagementPaused`` after the traffic phase — so the customer-launch worker RE-DRIVES (resume) rather than
settling a half-done run (that worker-side contract is covered by ``integration/tests/test_engage_worker_pause_redrive.py``).

Pinned here (code-verifiable, offline/hermetic):
  * EngagementPaused is a RE-DRIVEABLE halt, NOT a terminal EngagementRefused;
  * ``read_verified_launch_nonce`` surfaces THIS lease's nonce to DRIVE the pause lookup EVEN WHILE PAUSED
    (``check_pause=False``), while every arm/enqueue path (``verify_customer_launch_lease``) still REFUSES a
    paused lease — so a pause arriving in the enqueue→run window still leaves the run a halt binding;
  * ``_lease_is_paused`` is total + fail-closed-toward-HALT, and no-nonce ⇒ never pause-gated;
  * the executor ``halt_check`` degrades the next action exactly like a kill-switch trip (default None ⇒ byte-identical);
  * ``run_engagement`` RAISES EngagementPaused when a pause lands MID-RUN, and is byte-identical when none does.

Mutation-verify targets (each neuter reds a NAMED test here):
  * make EngagementPaused subclass EngagementRefused        -> test_engagement_paused_is_a_redriveable_not_a_refusal
  * drop ``check_pause=False`` in read_verified_launch_nonce -> test_read_nonce_surfaces_even_while_paused
  * make _lease_is_paused ignore the marker / return False   -> test_lease_is_paused_total_and_fail_closed
  * drop the halt_check branch in _authority_gate            -> test_executor_halt_check_degrades_like_killswitch
  * drop the post-scan ``raise EngagementPaused``            -> test_run_engagement_raises_on_in_flight_pause
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from framework.v2 import engage as engage_mod
from framework.v2 import launch_lease as LL
from framework.v2.agents.http_executor import HttpExecutor
from framework.v2.engage import EngagementPaused, EngagementRefused
from vigil_core import (
    AuthorizerKey, CreditLaunchLease, TrustRoot, generate_keypair, sign_credit_launch_lease,
)

# PR-3 seeds a lease + pause marker via the integration seam; crucible-core runs framework WITHOUT
# vigil_integration (the two-env boundary), so skip cleanly there — this belongs to the integration leg
# (exactly like the sibling test_launch_lease_pause.py).
_clb = pytest.importorskip("vigil_integration.live.credit_lease_broker")
_clp = pytest.importorskip("vigil_integration.live.credit_lease_pause")
write_credit_lease = _clb.write_credit_lease
record_lease_pause = _clp.record_lease_pause

SLUG, HOST, ORG, NONCE = "cust_pause3", "apme.cm", "org_a", "n1"


def _owner_root(owner):
    return TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])


def _lease(owner, *, slug=SLUG, org=ORG, host=HOST, nonce=NONCE, issued=1000.0):
    t = datetime.fromtimestamp(issued, tz=timezone.utc)
    doc = CreditLaunchLease(engagement_slug=slug, org_id=org, scope_host=host, units_reserved=10,
                            not_before=t - timedelta(hours=1), not_after=t + timedelta(hours=8),
                            nonce=nonce, issued_at=issued)
    return sign_credit_launch_lease(doc, {"owner": owner.private_key_b64})


def _rig(monkeypatch, owner, *, base=None):
    base = base or tempfile.mkdtemp()
    write_credit_lease(base, SLUG, _lease(owner), _owner_root(owner))
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: _owner_root(owner))
    return base


# ------------------------------------------------------------------ the exception semantics ----------
def test_engagement_paused_is_a_redriveable_not_a_refusal():
    # The worker keys the NO-settle / attempt-rollback re-drive on THIS exact type; if it were a subclass of
    # EngagementRefused a refusal handler could terminally convert a reversible pause.
    assert issubclass(EngagementPaused, RuntimeError)
    assert not issubclass(EngagementPaused, EngagementRefused)
    assert not issubclass(EngagementRefused, EngagementPaused)


# ------------------------------------------------------------------ read_verified_launch_nonce -------
def test_read_nonce_surfaces_even_while_paused(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    # not paused yet: the nonce reads, and the arm/enqueue verify ALLOWS.
    assert LL.read_verified_launch_nonce(SLUG, HOST, ORG, base_dir=base, now=1000.0) == NONCE
    assert LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=False)[0] is True
    # a pause lands: the arm/enqueue verify now REFUSES (PR-2) ...
    record_lease_pause(base, SLUG, NONCE)
    assert LL.verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=base, now=1000.0, consume=False)[0] is False
    # ... but the halt-binding nonce read STILL surfaces the nonce (check_pause=False) — else an in-flight run
    # would have NO pause binding.
    assert LL.read_verified_launch_nonce(SLUG, HOST, ORG, base_dir=base, now=1000.0) == NONCE


def test_read_nonce_fail_closed_for_wrong_host_or_absent(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    assert LL.read_verified_launch_nonce(SLUG, "evil.cm", ORG, base_dir=base, now=1000.0) is None
    assert LL.read_verified_launch_nonce(SLUG, HOST, "org_evil", base_dir=base, now=1000.0) is None
    assert LL.read_verified_launch_nonce("cust_absent", HOST, ORG, base_dir=base, now=1000.0) is None


# ------------------------------------------------------------------ _lease_is_paused -----------------
def test_lease_is_paused_total_and_fail_closed(monkeypatch):
    owner = generate_keypair()
    base = _rig(monkeypatch, owner)
    # no nonce ⇒ NEVER pause-gated (greenfield/operator runs)
    assert engage_mod._lease_is_paused(base, SLUG, None) is False
    assert engage_mod._lease_is_paused(base, SLUG, "") is False
    # no marker ⇒ False (default-OFF, byte-identical)
    assert engage_mod._lease_is_paused(base, SLUG, NONCE) is False
    # a recorded pause ⇒ True
    record_lease_pause(base, SLUG, NONCE)
    assert engage_mod._lease_is_paused(base, SLUG, NONCE) is True


# ------------------------------------------------------------------ executor halt_check --------------
def test_executor_halt_check_degrades_like_killswitch():
    # A sentinel slug ("<...>") skips authority binding, so the gate exercises ONLY the kill-switch + halt_check.
    paused = {"v": True}
    ex = HttpExecutor(engagement_slug="<halt-test>", base_url="http://127.0.0.1/",
                      halt_check=lambda: paused["v"])
    out = ex._authority_gate("GET", "http://127.0.0.1/x", "a1")
    assert out is not None and "paused" in out.note.lower()      # paused ⇒ the action is refused (no traffic)
    paused["v"] = False
    assert ex._authority_gate("GET", "http://127.0.0.1/x", "a2") is None   # not paused ⇒ proceeds
    # default None ⇒ byte-identical: no pause refusal ever
    ex2 = HttpExecutor(engagement_slug="<halt-test>", base_url="http://127.0.0.1/")
    assert ex2._authority_gate("GET", "http://127.0.0.1/x", "a3") is None


# ------------------------------------------------------------------ run_engagement raise -------------
def _campaign_that_pauses_mid_run(base):
    """A WebScanCampaign stand-in whose .run() records a pause MID-scan (after the precondition armed) then
    returns a minimal report — the exact 'the customer paused a running engagement' sequence."""
    from framework.v2.scanner.campaign import ScanReport

    class _Fake:
        def __init__(self, *_a, **_k):
            pass

        def run(self, seed):
            record_lease_pause(base, SLUG, NONCE)
            return ScanReport(target=seed, pages_crawled=1)
    return _Fake


def _campaign_clean():
    from framework.v2.scanner.campaign import ScanReport

    class _Fake:
        def __init__(self, *_a, **_k):
            pass

        def run(self, seed):
            return ScanReport(target=seed, pages_crawled=1)
    return _Fake


def _wire_customer_run(monkeypatch, base):
    """Make run_engagement treat SLUG as a customer launch whose lease verifies, WITHOUT dragging the full
    authority/preflight rig: the precondition's verify passes, and the nonce reads as NONCE (check_pause=False)."""
    monkeypatch.setenv("VIGIL_BASE_DIR", base)
    monkeypatch.setattr(LL, "customer_engagement_requires_lease", lambda slug: True)
    monkeypatch.setattr(LL, "verify_customer_launch_lease",
                        lambda slug, host, tenant, **kw: (True, "ok"))
    monkeypatch.setattr(LL, "read_verified_launch_nonce",
                        lambda slug, host, tenant, **kw: NONCE)
    # preflight scope: the seed host must be in-scope. Neutralize preflight + kill-switch for the hermetic run.
    monkeypatch.setattr(engage_mod, "preflight", lambda slug, seed_url: None)


def test_run_engagement_raises_on_in_flight_pause(monkeypatch):
    base = tempfile.mkdtemp()
    _wire_customer_run(monkeypatch, base)
    monkeypatch.setattr(engage_mod, "WebScanCampaign", _campaign_that_pauses_mid_run(base))
    with pytest.raises(EngagementPaused):
        engage_mod.run_engagement(SLUG, f"https://{HOST}/", enable_chaining=False)


def test_run_engagement_no_pause_is_byte_identical(monkeypatch):
    base = tempfile.mkdtemp()
    _wire_customer_run(monkeypatch, base)
    monkeypatch.setattr(engage_mod, "WebScanCampaign", _campaign_clean())
    result = engage_mod.run_engagement(SLUG, f"https://{HOST}/", enable_chaining=False)
    assert result.stopped_reason is None
    assert result.report.target == f"https://{HOST}/"
