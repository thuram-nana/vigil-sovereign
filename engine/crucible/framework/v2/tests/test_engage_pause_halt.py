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
  * ``run_engagement`` RAISES EngagementPaused when a pause lands MID-RUN, and is byte-identical when none does;
  * a scan the pause CUT is never recorded complete: after resume the launch RE-RUNS its scan (it does not
    reload the truncated report), without re-burning the single-use floor — proven against the REAL lease,
    the REAL pause marker and the REAL executor halt check on a loopback target;
  * a NEW lease on the same slug never resumes from the previous launch's scan.

Mutation-verify targets (each neuter reds a NAMED test here):
  * make EngagementPaused subclass EngagementRefused        -> test_engagement_paused_is_a_redriveable_not_a_refusal
  * drop ``check_pause=False`` in read_verified_launch_nonce -> test_read_nonce_surfaces_even_while_paused
  * make _lease_is_paused ignore the marker / return False   -> test_lease_is_paused_total_and_fail_closed
  * drop the halt_check branch in _authority_gate            -> test_executor_halt_check_degrades_like_killswitch
  * drop the post-scan ``raise EngagementPaused``            -> test_run_engagement_raises_on_in_flight_pause
  * record a pause-cut scan as completed                     -> test_resumed_launch_rescans_after_a_real_in_flight_pause
  * leave the phase ledger unbound from the lease nonce      -> test_a_new_lease_on_the_same_slug_never_resumes_from_the_previous_launch
"""
from __future__ import annotations

import json
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone

import pytest

from framework.v2 import engage as engage_mod
from framework.v2 import launch_lease as LL
from framework.v2.agents.http_executor import HttpExecutor
from framework.v2.common import paths as _paths
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
clear_lease_pause = _clp.clear_lease_pause

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


# ------------------------------------------------------------------ a pause-cut scan is re-run on resume
# The REAL substrate end to end: an owner-signed lease on the seam (verified + consumed by the real arm), the
# real pause marker, the real gated executor + its halt check, and loopback HTTP. Only the campaign is a
# stand-in — one that DRIVES the executor, so a pause really does cut it short.
SCAN_SLUG, SCAN_HOST = "cust_pause3scan", "127.0.0.1"
_PAGES = 6

_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
"""


class _ScanPlan:
    def __init__(self, pages=_PAGES):
        self.pages = pages
        self.scans = 0
        self.refusals = []
        self.before_action = lambda i: None
        self.crash = False


def _driving_campaign(plan):
    """A WebScanCampaign stand-in that sends one GET per page through the ``send`` the engine hands it (the
    real ``HttpExecutor.gated_fetch``) and, like the real campaign, winds down on refusals and returns a
    report of what it actually fetched."""
    from framework.v2.scanner.campaign import ScanReport
    from framework.v2.scanner.insertion import HttpRequest

    class _Fake:
        def __init__(self, send, **_k):
            self._send = send

        def run(self, seed):
            plan.scans += 1
            fetched = 0
            for i in range(plan.pages):
                plan.before_action(i)
                resp = self._send(HttpRequest(method="GET", url=f"{seed}p{i}"))
                if resp.get("refused"):
                    plan.refusals.append(str(resp["refused"]))
                elif resp.get("status") == 200:
                    fetched += 1
            if plan.crash:
                raise RuntimeError("simulated scan crash mid-op")
            return ScanReport(target=seed, pages_crawled=fetched)
    return _Fake


@pytest.fixture()
def loopback_launch(tmp_path, monkeypatch, httpserver):
    """A real customer launch against a loopback target. Returns ``(base, seed, publish)``: the seam base,
    the seed URL, and ``publish(nonce)`` which puts a current owner-signed lease for that launch on the seam."""
    targets = tmp_path / "targets"
    (targets / SCAN_SLUG).mkdir(parents=True)
    (targets / SCAN_SLUG / "charter.md").write_text(_CHARTER.format(slug=SCAN_SLUG), encoding="utf-8")
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")

    owner = generate_keypair()
    base = str(tmp_path / "seam")
    monkeypatch.setattr("framework.v2.authority.store.load_authority_root", lambda: _owner_root(owner))
    monkeypatch.setenv("VIGIL_BASE_DIR", base)
    monkeypatch.setenv("CRUCIBLE_TENANT", ORG)
    issued = {"t": time.time()}

    def publish(nonce):
        issued["t"] += 1.0                              # a genuine re-lease is strictly newer (single-use floor)
        write_credit_lease(base, SCAN_SLUG, _lease(owner, slug=SCAN_SLUG, host=SCAN_HOST, nonce=nonce,
                                                   issued=issued["t"]), _owner_root(owner))

    httpserver.expect_request(re.compile(r"^/p\d+$")).respond_with_data("ok", content_type="text/html")
    return base, f"http://{SCAN_HOST}:{httpserver.port}/", publish


def _scan_statuses(slug):
    path = _paths.phase_ledger_path(slug)
    recs = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r["status"] for r in recs if r.get("phase") == "scan"]


def _engage_scan(seed, plan, monkeypatch, **kw):
    monkeypatch.setattr(engage_mod, "WebScanCampaign", _driving_campaign(plan))
    return engage_mod.run_engagement(SCAN_SLUG, seed, enable_chaining=False, enable_oob=False, **kw)


def test_resumed_launch_rescans_after_a_real_in_flight_pause(loopback_launch, monkeypatch):
    base, seed, publish = loopback_launch
    publish("n1")
    plan = _ScanPlan()

    def _pause_before_third_action(i):
        if i == 2:
            record_lease_pause(base, SCAN_SLUG, "n1")          # the customer pauses the running launch
    plan.before_action = _pause_before_third_action

    with pytest.raises(EngagementPaused):
        _engage_scan(seed, plan, monkeypatch)                  # the real arm consumes the lease, then the pause lands
    assert len(plan.refusals) == _PAGES - 2                    # the real halt check stopped the traffic
    assert all("paused" in note.lower() for note in plan.refusals)
    assert _scan_statuses(SCAN_SLUG) == ["started", "halted"]  # NOT a completed scan
    assert not _paths.phase_report_path(SCAN_SLUG).exists()    # and nothing to reload

    clear_lease_pause(base, SCAN_SLUG, "n1")                   # resume
    plan.before_action = lambda i: None
    result = _engage_scan(seed, plan, monkeypatch, resume=True)
    assert plan.scans == 2                                     # the scan genuinely re-ran...
    assert result.report.pages_crawled == _PAGES               # ...and the whole assessment came back
    assert _scan_statuses(SCAN_SLUG)[-3:] == ["started", "completed", "snapshot"]
    # The single-use floor was burned exactly ONCE, by the fresh arm: the resume above passed the REAL
    # precondition without consuming (a second consume is refused as a replay — which is what would have
    # refused the resume itself had it re-armed fresh).
    ok, reason = LL.verify_customer_launch_lease(SCAN_SLUG, SCAN_HOST, ORG, base_dir=base, consume=True)
    assert ok is False and "replay" in reason


def test_a_new_lease_on_the_same_slug_never_resumes_from_the_previous_launch(loopback_launch, monkeypatch):
    base, seed, publish = loopback_launch
    publish("n1")
    first = _ScanPlan(pages=_PAGES)
    assert _engage_scan(seed, first, monkeypatch).report.pages_crawled == _PAGES   # launch 1 completes

    publish("n2")                                              # a genuine re-lease: launch 2 on the SAME slug
    second = _ScanPlan(pages=3)
    second.crash = True
    with pytest.raises(RuntimeError, match="simulated scan crash"):
        _engage_scan(seed, second, monkeypatch)                # launch 2's fresh arm crashes mid-scan
    second.crash = False

    result = _engage_scan(seed, second, monkeypatch, resume=True)   # the crash re-drive
    assert second.scans == 2                                   # launch 2 scanned for itself
    assert result.report.pages_crawled == 3                    # its own report, not launch 1's 6 pages
    # ...and launch 2's OWN completed scan is reusable by a later re-drive of launch 2
    again = _engage_scan(seed, second, monkeypatch, resume=True)
    assert second.scans == 2 and again.report.pages_crawled == 3
