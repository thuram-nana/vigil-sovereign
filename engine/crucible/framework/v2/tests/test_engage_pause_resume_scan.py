"""A resumed customer launch finishes ITS OWN scan — never a truncated one, never another launch's.

Two defects on the pause/resume + ``--resume`` path, both ending in a customer paying the full flat
reservation for an assessment they did not get:

  1. **A scan cut short by a pause was recorded as a completed scan.** The executor's cooperative halt turns
     every further action into a status-0 refusal, so the campaign winds down and RETURNS NORMALLY with a
     truncated report. ``run_engagement`` marked the scan phase completed and snapshotted that report before
     it raised the re-driveable ``EngagementPaused`` — so the resume re-drive (``resume=True``) skipped the
     scan, reloaded the truncated snapshot, and the launch settled COMPLETED at full charge.
  2. **The resume state was keyed per slug, not per launch.** The phase ledger and the scan snapshot live at
     per-slug paths, and a customer slug is reused by every launch of the same (org, host). A ``resume=True``
     run of a LATER launch could therefore skip its scan on the strength of an EARLIER launch's ledger and
     reload that launch's report.

The fix: a scan the pause cut is recorded ``halted`` (never completed, never snapshotted), and a customer
run's ledger + snapshot are bound to its launch (the owner-signed lease nonce). The two are coupled — once a
paused scan is no longer completed, an unbound resume would fall straight through to an earlier launch's
snapshot — so both are pinned here. Two consequences are pinned too: the re-scans a pause can cause one launch
are BOUNDED (``VIGIL_PAUSE_RESCAN_LIMIT``), and the launch a run binds to is the one the worker is RUNNING (its
job's nonce, checked against the verified seam lease before the arm), never whichever lease sits on the seam.

Hermetic and self-contained: this file needs NO ``vigil_integration`` (so it runs in the crucible-core leg,
not only the both-planes leg). The lease reads and the pause predicate are stubbed at the engine's own seam
functions; everything below them is REAL — the phase ledger, the gated ``HttpExecutor`` and its halt check,
and loopback HTTP to a pytest-httpserver. The real lease + pause substrate is exercised on the both-planes
leg by ``test_engage_pause_halt.py`` and ``integration/tests/test_engage_worker_pause_redrive.py``.

Mutation-verify targets (each neuter reds a NAMED test here):
  * record a pause-cut scan as completed (drop the ``_scan_cut_by_pause`` branch)
        -> test_scan_cut_by_a_pause_is_not_completed_and_resume_rescans_the_whole_target
  * drop the halt LATCH from ``_scan_cut_by_pause`` (ask only "is it paused now?")
        -> test_pause_cleared_before_the_scan_returns_still_forces_a_rescan
  * treat "paused as the scan returns" as a cut scan (re-add the at-return term to ``_scan_cut_by_pause``)
        -> test_pause_landing_after_the_last_action_keeps_the_whole_scan
  * apply the pause cut on the EC-3 budget-stop path too
        -> test_budget_stop_path_is_unchanged_by_a_cleared_pause
  * never bind the ledger to the launch (drop ``ledger.bind_launch`` in run_engagement)
        -> test_resume_of_a_later_launch_never_reloads_an_earlier_launchs_scan
  * count every prior record as this launch's (``PhaseLedger._owns`` -> True)
        -> test_bound_resume_ignores_another_launchs_completed_scan
  * reload the snapshot without checking it is this launch's (drop the digest check in ``load_report``)
        -> test_bound_load_report_returns_only_this_launchs_snapshot
  * treat an unidentifiable customer launch as an operator run (no binding without a nonce)
        -> test_customer_resume_with_no_readable_launch_identity_reuses_nothing
  * drop the pause re-scan bound (never refuse past ``VIGIL_PAUSE_RESCAN_LIMIT``)
        -> test_pause_rescans_of_one_launch_are_bounded_and_refused_before_any_traffic
  * apply the bound before the reload decision (refuse even when a completed scan would be reloaded)
        -> test_a_completed_scan_is_reloaded_even_when_the_limit_is_lowered_afterwards
  * count every launch's cut scans (``prior_halts`` ignoring ``_owns``)
        -> test_prior_halts_counts_only_this_launchs_halted_scans
  * fail open on a malformed limit (unbounded instead of the default)
        -> test_pause_rescan_limit_is_env_tunable_and_fails_closed_to_the_default
  * do not pass ``launch_nonce`` to the arm precondition as ``expect_nonce``
        -> test_a_job_whose_launch_is_not_the_lease_on_the_seam_is_refused_before_its_arm
  * bind the pause halt + resume state to the seam read instead of the job's ``launch_nonce``
        -> test_the_pause_halt_and_resume_state_bind_to_the_jobs_launch_not_to_a_later_lease
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer
from vigil_core import RunBudgetExceeded

from framework.v2 import engage as engage_mod
from framework.v2 import launch_lease as LL
from framework.v2.authority.killswitch import KillSwitch
from framework.v2.common import paths as _paths
from framework.v2.engage import EngagementPaused, EngagementRefused, run_engagement
from framework.v2.phase_ledger import P_PREFLIGHT, P_REASONING, P_SCAN, PhaseLedger, _launch_tag
from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.insertion import HttpRequest

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

SLUG = "cust_resumescan"       # a customer engagement slug: reused by every launch of the same (org, host)
PAGES = 6                      # what a WHOLE scan of the loopback target fetches


# --------------------------------------------------------------------------- fixtures / rig


@pytest.fixture()
def isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Re-root every per-slug path under tmp and lay down a signed, in-scope charter."""
    targets = tmp_path / "targets"
    targets.mkdir()
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")

    def build(slug: str) -> Path:
        td = targets / slug
        td.mkdir(parents=True, exist_ok=True)
        (td / "charter.md").write_text(_CHARTER.format(slug=slug), encoding="utf-8")
        return td

    return build


class _Launch:
    """The customer-launch seam state a test drives: which launch (lease nonce) is live, whether its lease is
    paused right now, and every ``consume`` the arm precondition was asked for (fresh arm = True, resume = False)."""

    def __init__(self, nonce: "str | None" = "n1") -> None:
        self.nonce = nonce
        self.paused = False
        self.consumes: list[bool] = []


def _wire_customer(monkeypatch: pytest.MonkeyPatch, launch: _Launch) -> None:
    """Make ``run_engagement`` treat SLUG as a customer launch whose lease verifies. Only the engine's own seam
    functions are stubbed (the lease verify / nonce read, and the pause predicate that would otherwise import
    ``vigil_integration``); the ledger, the executor and its halt check all run for real."""
    monkeypatch.setattr(LL, "customer_engagement_requires_lease", lambda slug: slug == SLUG)

    def _verify(slug, host, tenant, **kw):
        expect = kw.get("expect_nonce")
        if expect is not None and expect != launch.nonce:       # the real conjunct: another launch's lease
            return False, "the lease on the seam belongs to a different launch than the one being run"
        launch.consumes.append(bool(kw.get("consume", True)))
        return True, "ok"

    monkeypatch.setattr(LL, "verify_customer_launch_lease", _verify)
    monkeypatch.setattr(LL, "read_verified_launch_nonce", lambda slug, host, tenant, **kw: launch.nonce)
    monkeypatch.setattr(engage_mod, "_lease_is_paused",
                        lambda base, slug, nonce: bool(nonce) and launch.paused)


class _Plan:
    """What the driving campaign does on each ``run``: how many pages a whole scan fetches, plus an optional
    hook called before every action (to pause / resume / trip the kill-switch mid-scan) and after the last."""

    def __init__(self, pages: int = PAGES) -> None:
        self.pages = pages
        self.scans = 0
        self.refusals: list[str] = []
        self.before_action = lambda i: None
        self.after_scan = lambda: None
        self.crash = False
        self.budget_stop = False


def _driving_campaign(plan: _Plan):
    """A ``WebScanCampaign`` stand-in that DRIVES the real gated executor: one GET per page through the
    ``send`` the engine hands it (``HttpExecutor.gated_fetch``, so every action passes the kill-switch + the
    pause halt check). Like the real campaign it does not stop on a refusal — it winds down and returns a
    report of what it actually got, which is exactly how a pause-cut scan comes back truncated."""

    class _Fake:
        def __init__(self, send, **_k) -> None:
            self._send = send

        def run(self, seed: str) -> ScanReport:
            plan.scans += 1
            fetched = 0
            for i in range(plan.pages):
                plan.before_action(i)
                resp = self._send(HttpRequest(method="GET", url=f"{seed}p{i}"))
                if resp.get("refused"):
                    plan.refusals.append(str(resp["refused"]))
                elif resp.get("status") == 200:
                    fetched += 1
            plan.after_scan()
            if plan.crash:
                raise RuntimeError("simulated scan crash mid-op")
            if plan.budget_stop:
                raise RunBudgetExceeded(ceiling=50, spent=60)
            return ScanReport(target=seed, pages_crawled=fetched)

    return _Fake


def _serve(httpserver: HTTPServer) -> str:
    httpserver.expect_request(re.compile(r"^/p\d+$")).respond_with_data("ok", content_type="text/html")
    return f"http://127.0.0.1:{httpserver.port}/"


def _engage(seed: str, plan: _Plan, monkeypatch: pytest.MonkeyPatch, *, slug: str = SLUG, **kw):
    monkeypatch.setattr(engage_mod, "WebScanCampaign", _driving_campaign(plan))
    return run_engagement(slug, seed, enable_chaining=False, enable_oob=False, **kw)


def _read_ledger(slug: str) -> list[dict]:
    path = _paths.phase_ledger_path(slug)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _scan_statuses(slug: str = SLUG) -> list[str]:
    return [r["status"] for r in _read_ledger(slug) if r.get("phase") == P_SCAN]


def _scan_lifecycle(slug: str = SLUG) -> list[str]:
    """The scan phase's lifecycle transitions, without the launch-bound snapshot bookkeeping record — so a
    test that pins UNCHANGED behaviour reads the same on either side of the launch binding."""
    return [s for s in _scan_statuses(slug) if s != "snapshot"]


# =========================================================================== defect 1: the paused scan


def test_scan_cut_by_a_pause_is_not_completed_and_resume_rescans_the_whole_target(
        isolate, httpserver: HTTPServer, monkeypatch):
    """THE defect. A pause lands mid-scan: the real executor refuses every further action, the campaign
    returns a truncated report. That scan must not be recorded complete nor snapshotted; the resume re-drive
    must scan the whole target again and return the whole report — without re-burning the single-use arm."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    plan = _Plan()

    def _pause_before_third_action(i: int) -> None:
        if i == 2:
            launch.paused = True                      # the customer pauses the running launch
    plan.before_action = _pause_before_third_action

    with pytest.raises(EngagementPaused):
        _engage(seed, plan, monkeypatch)              # FRESH arm, paused in flight
    # the real halt check stopped the traffic: 2 pages fetched, the other 4 refused as PAUSED
    assert len(plan.refusals) == PAGES - 2
    assert all("paused" in note.lower() for note in plan.refusals)
    # ...and that truncated scan is NOT a completed scan, and left NO snapshot to be reloaded
    assert _scan_statuses() == ["started", "halted"]
    assert not _paths.phase_report_path(SLUG).exists()

    launch.paused = False                             # the customer resumes
    plan.before_action = lambda i: None
    result = _engage(seed, plan, monkeypatch, resume=True)

    assert plan.scans == 2                            # the resume genuinely re-ran the scan...
    assert result.report.pages_crawled == PAGES       # ...and delivered the WHOLE assessment, not 2 of 6 pages
    assert _scan_statuses() == ["started", "halted", "started", "completed", "snapshot"]
    # the single-use arm was consumed ONCE (the fresh arm); the resume re-validated without re-consuming
    assert launch.consumes == [True, False]

    # a later re-drive of the SAME launch (e.g. the worker failed after the run) reuses ITS OWN whole scan
    again = _engage(seed, plan, monkeypatch, resume=True)
    assert plan.scans == 2                            # no third scan — no repeat traffic at the target
    assert again.report.pages_crawled == PAGES
    assert launch.consumes == [True, False, False]


def test_pause_cleared_before_the_scan_returns_still_forces_a_rescan(
        isolate, httpserver: HTTPServer, monkeypatch):
    """The pause is cleared again while the scan is still running. Asked once after the scan, "is it paused?"
    says no — but two actions in the middle were refused, so the report has a hole. It must still be treated
    as cut: re-driveable, never completed, and the resume re-scans the whole target."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    plan = _Plan()

    def _pause_then_resume(i: int) -> None:
        if i == 2:
            launch.paused = True
        if i == 4:
            launch.paused = False                     # cleared before the scan returns
    plan.before_action = _pause_then_resume

    with pytest.raises(EngagementPaused):
        _engage(seed, plan, monkeypatch)
    assert launch.paused is False                     # NOT paused any more when the scan returned
    assert len(plan.refusals) == 2                    # ...yet actions 2 and 3 never reached the target
    assert _scan_statuses() == ["started", "halted"]
    assert not _paths.phase_report_path(SLUG).exists()

    plan.before_action = lambda i: None
    result = _engage(seed, plan, monkeypatch, resume=True)
    assert plan.scans == 2
    assert result.report.pages_crawled == PAGES


def test_pause_landing_after_the_last_action_keeps_the_whole_scan(
        isolate, httpserver: HTTPServer, monkeypatch):
    """The lease is paused only as the scan returns: the halt check refused NOTHING, so the report is whole. It
    is recorded completed and snapshotted like any whole scan; the run still halts (re-driveable, because the
    lease IS paused), and the resume reloads that whole scan instead of paying for a second, identical one."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    plan = _Plan()

    def _pause_at_the_end() -> None:
        launch.paused = True
    plan.after_scan = _pause_at_the_end

    with pytest.raises(EngagementPaused):
        _engage(seed, plan, monkeypatch)
    assert plan.refusals == []                        # the halt check never refused an action: the scan is whole
    assert _scan_statuses() == ["started", "completed", "snapshot"]
    assert _paths.phase_report_path(SLUG).is_file()

    launch.paused = False
    plan.after_scan = lambda: None
    result = _engage(seed, plan, monkeypatch, resume=True)
    assert plan.scans == 1                            # reloaded — no second scan for the same flat charge
    assert result.report.pages_crawled == PAGES
    assert _scan_statuses() == ["started", "completed", "snapshot", "skipped"]


def test_unpaused_customer_scan_completes_and_snapshots_once(isolate, httpserver: HTTPServer, monkeypatch):
    """No pause ever lands: the customer run completes its scan and snapshots it exactly as before, and a
    resume re-drive of the same launch reloads it instead of sending the traffic again."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    plan = _Plan()

    result = _engage(seed, plan, monkeypatch)
    assert result.stopped_reason is None and result.report.pages_crawled == PAGES
    assert _scan_lifecycle() == ["started", "completed"]
    assert launch.consumes == [True]

    resumed = _engage(seed, plan, monkeypatch, resume=True)
    assert plan.scans == 1                            # reloaded — the target saw no repeat traffic
    assert resumed.report.pages_crawled == PAGES
    assert _scan_lifecycle() == ["started", "completed", "skipped"]
    assert launch.consumes == [True, False]


def test_killswitch_halt_mid_scan_is_unchanged(isolate, httpserver: HTTPServer, monkeypatch):
    """The kill-switch is a TERMINAL stop, not a reversible pause, and its path is untouched: a trip mid-scan
    still degrades the remaining actions, the scan still completes + snapshots with what it has, and the run
    returns normally (no re-drive)."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    plan = _Plan()

    def _trip_before_third_action(i: int) -> None:
        if i == 2:
            KillSwitch(SLUG).trip("operator stop")
    plan.before_action = _trip_before_third_action

    result = _engage(seed, plan, monkeypatch)         # returns — never EngagementPaused
    assert result.report.pages_crawled == 2
    assert len(plan.refusals) == PAGES - 2
    assert all("kill-switch" in note.lower() for note in plan.refusals)
    assert _scan_lifecycle() == ["started", "completed"]
    assert _paths.phase_report_path(SLUG).is_file()


def test_budget_stop_path_is_unchanged_by_a_cleared_pause(isolate, httpserver: HTTPServer, monkeypatch):
    """EC-3: a run-budget stop mid-scan is a clean PARTIAL that returns normally (so the worker settles it).
    That path is untouched: a pause that came and went during the same scan does not turn the budget stop
    into a re-drive — exactly as before, only a lease that is STILL paused does."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    plan = _Plan()
    plan.budget_stop = True

    def _pause_then_resume(i: int) -> None:
        if i == 2:
            launch.paused = True
        if i == 4:
            launch.paused = False
    plan.before_action = _pause_then_resume

    result = _engage(seed, plan, monkeypatch)         # RETURNS a partial — not EngagementPaused
    assert len(plan.refusals) == 2                    # the pause halt did fire during the scan
    assert result.stopped_reason is not None and "budget" in result.stopped_reason.lower()
    assert _scan_statuses() == ["started", "failed"]

    # ...and a budget stop while the lease is STILL paused re-drives, as it always has
    launch.nonce = "n2"

    def _pause_and_stay_paused(i: int) -> None:
        if i == 2:
            launch.paused = True
    plan.before_action = _pause_and_stay_paused
    with pytest.raises(EngagementPaused):
        _engage(seed, plan, monkeypatch)
    assert _scan_statuses()[-2:] == ["started", "failed"]


# =========================================================================== defect 2: bound to the launch


def test_resume_of_a_later_launch_never_reloads_an_earlier_launchs_scan(
        isolate, httpserver: HTTPServer, monkeypatch):
    """Launch L1 completes on the slug. Launch L2 (a new lease on the SAME slug) crashes mid-scan and is
    re-driven with resume=True. L2 must run its own scan — not skip it because L1 completed one, and not
    reload L1's report."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)

    l1 = _Plan(pages=PAGES)
    r1 = _engage(seed, l1, monkeypatch)               # L1, fresh: completes + snapshots
    assert r1.report.pages_crawled == PAGES and l1.scans == 1

    launch.nonce = "n2"                               # a genuine re-lease: a NEW launch on the same slug
    l2 = _Plan(pages=3)                               # L2's own scan is distinguishable from L1's
    l2.crash = True
    with pytest.raises(RuntimeError, match="simulated scan crash"):
        _engage(seed, l2, monkeypatch)                # L2 attempt 1 (fresh) crashes mid-scan
    l2.crash = False

    r2 = _engage(seed, l2, monkeypatch, resume=True)  # L2 attempt 2: the worker's crash re-drive
    assert l2.scans == 2                              # L2 scanned for itself...
    assert r2.report.pages_crawled == 3               # ...and its report is L2's, not L1's 6-page one

    # L2's OWN completed scan is still reusable by a later re-drive of L2
    r2b = _engage(seed, l2, monkeypatch, resume=True)
    assert l2.scans == 2 and r2b.report.pages_crawled == 3


def test_resume_after_a_pause_never_falls_back_to_an_earlier_launchs_report(
        isolate, httpserver: HTTPServer, monkeypatch):
    """The two defects are coupled. Once a paused scan is no longer recorded complete, the resume must not
    then find an EARLIER launch's completed scan in the per-slug ledger and reload that launch's snapshot."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)

    l1 = _Plan(pages=PAGES)
    assert _engage(seed, l1, monkeypatch).report.pages_crawled == PAGES     # L1 completes; its snapshot is on disk

    launch.nonce = "n2"
    l2 = _Plan(pages=4)

    def _pause_before_second_action(i: int) -> None:
        if i == 1:
            launch.paused = True
    l2.before_action = _pause_before_second_action
    with pytest.raises(EngagementPaused):
        _engage(seed, l2, monkeypatch)                # L2 paused in flight

    launch.paused = False
    l2.before_action = lambda i: None
    r2 = _engage(seed, l2, monkeypatch, resume=True)
    assert l2.scans == 2                              # L2 re-scanned...
    assert r2.report.pages_crawled == 4               # ...and got ITS whole report (not L1's 6, not its own 1)


def test_customer_resume_with_no_readable_launch_identity_reuses_nothing(
        isolate, httpserver: HTTPServer, monkeypatch):
    """A customer run whose lease nonce cannot be read cannot be told apart from any other launch on the
    slug, so its resume reuses NO prior state: it re-scans (more work) rather than risk a foreign report."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch(None)                            # the nonce read yields nothing
    _wire_customer(monkeypatch, launch)
    plan = _Plan()

    assert _engage(seed, plan, monkeypatch).report.pages_crawled == PAGES
    assert plan.scans == 1
    resumed = _engage(seed, plan, monkeypatch, resume=True)
    assert plan.scans == 2                            # nothing reused
    assert resumed.report.pages_crawled == PAGES
    # ...and what such a run records is never attributable to a launch
    assert all("launch" not in r for r in _read_ledger(SLUG))


def test_operator_resume_is_per_slug_and_writes_the_records_it_always_has(
        isolate, httpserver: HTTPServer, monkeypatch):
    """An operator / greenfield engagement is never launch-bound: a plain --resume still reloads the slug's
    completed scan, and the ledger records carry exactly the fields they always carried."""
    isolate("alpha")
    seed = _serve(httpserver)
    plan = _Plan()

    fresh = _engage(seed, plan, monkeypatch, slug="alpha")
    assert fresh.report.pages_crawled == PAGES
    resumed = _engage(seed, plan, monkeypatch, slug="alpha", resume=True)
    assert plan.scans == 1                            # the operator resume reloaded the snapshot
    assert resumed.report.pages_crawled == PAGES

    recs = _read_ledger("alpha")
    assert all(set(r) == {"phase", "status", "ts"} for r in recs)           # no launch tag, no extra field
    assert [r["status"] for r in recs if r["phase"] == P_SCAN] == ["started", "completed", "skipped"]


# =========================================================================== the pause re-scan bound


def _cut_by_a_pause(plan: _Plan, launch: _Launch) -> None:
    """Every scan of ``plan`` is cut by a pause landing before its third action (the customer then resumes)."""
    def _pause_before_third_action(i: int) -> None:
        if i == 2:
            launch.paused = True
    plan.before_action = _pause_before_third_action


def test_pause_rescan_limit_is_env_tunable_and_fails_closed_to_the_default(monkeypatch):
    default = engage_mod.PAUSE_RESCAN_LIMIT_DEFAULT
    monkeypatch.delenv("VIGIL_PAUSE_RESCAN_LIMIT", raising=False)
    assert engage_mod._pause_rescan_limit() == default
    for raw, want in (("0", 0), ("5", 5), (" 3 ", 3), ("", default), ("-1", default), ("two", default),
                      ("2.5", default)):
        monkeypatch.setenv("VIGIL_PAUSE_RESCAN_LIMIT", raw)
        assert engage_mod._pause_rescan_limit() == want, raw


def test_pause_rescans_of_one_launch_are_bounded_and_refused_before_any_traffic(
        isolate, httpserver: HTTPServer, monkeypatch):
    """Every pause that cuts a scan costs a WHOLE re-scan for the same flat charge, and a pause consumes no
    crash attempt — so without a bound a launch could be made to re-scan for as long as its lease lasts.
    Past ``VIGIL_PAUSE_RESCAN_LIMIT`` cut scans the next run is refused BEFORE any traffic (a plain
    EngagementRefused, which the worker ends through its ordinary terminal-failure path)."""
    monkeypatch.delenv("VIGIL_PAUSE_RESCAN_LIMIT", raising=False)
    limit = engage_mod.PAUSE_RESCAN_LIMIT_DEFAULT
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    plan = _Plan()
    _cut_by_a_pause(plan, launch)

    for attempt in range(limit + 1):                  # the first scan + `limit` re-scans, each cut by a pause
        with pytest.raises(EngagementPaused):
            _engage(seed, plan, monkeypatch, resume=attempt > 0)
        launch.paused = False                         # ...and each time the customer resumes
    assert plan.scans == limit + 1
    assert _scan_lifecycle().count("halted") == limit + 1

    hits = len(httpserver.log)
    with pytest.raises(EngagementRefused, match="pause re-scan limit"):
        _engage(seed, plan, monkeypatch, resume=True)
    assert plan.scans == limit + 1                    # no further scan ran...
    assert len(httpserver.log) == hits                # ...and the target saw no further request
    assert _scan_lifecycle().count("started") == limit + 1


def test_a_launch_within_the_limit_still_finishes_its_scan_and_each_launch_has_its_own_budget(
        isolate, httpserver: HTTPServer, monkeypatch):
    """The bound never shortens a launch that stays within it: with a limit of 1, one cut scan is re-run and
    delivers the whole report. And the count is PER LAUNCH: an earlier launch's cut scans on the same slug never
    count against a later launch."""
    monkeypatch.setenv("VIGIL_PAUSE_RESCAN_LIMIT", "1")
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)

    cut = _Plan()
    _cut_by_a_pause(cut, launch)
    for attempt in range(2):                          # n1: two cut scans (the limit is 1)...
        with pytest.raises(EngagementPaused):
            _engage(seed, cut, monkeypatch, resume=attempt > 0)
        launch.paused = False
    with pytest.raises(EngagementRefused, match="pause re-scan limit"):
        _engage(seed, cut, monkeypatch, resume=True)  # ...so n1 gets no third scan

    launch.nonce = "n2"                               # a genuine re-lease: launch n2 on the SAME slug
    first = _Plan()
    _cut_by_a_pause(first, launch)
    with pytest.raises(EngagementPaused):
        _engage(seed, first, monkeypatch)             # n2's own scan runs (n1's cut scans are not n2's)...
    launch.paused = False
    whole = _Plan()
    result = _engage(seed, whole, monkeypatch, resume=True)   # ...and its one re-scan, within the limit, finishes
    assert whole.scans == 1 and result.report.pages_crawled == PAGES


def test_a_completed_scan_is_reloaded_even_when_the_limit_is_lowered_afterwards(
        isolate, httpserver: HTTPServer, monkeypatch):
    """The bound gates only a scan that would actually RUN. A launch that already completed its scan (after one
    cut) is re-driven — e.g. the worker failed after the run — once the limit has been lowered to 0: it must
    reload its own whole scan, not be refused."""
    monkeypatch.delenv("VIGIL_PAUSE_RESCAN_LIMIT", raising=False)
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    plan = _Plan()
    _cut_by_a_pause(plan, launch)
    with pytest.raises(EngagementPaused):
        _engage(seed, plan, monkeypatch)
    launch.paused = False
    plan.before_action = lambda i: None
    assert _engage(seed, plan, monkeypatch, resume=True).report.pages_crawled == PAGES
    assert plan.scans == 2

    monkeypatch.setenv("VIGIL_PAUSE_RESCAN_LIMIT", "0")
    again = _engage(seed, plan, monkeypatch, resume=True)
    assert plan.scans == 2 and again.report.pages_crawled == PAGES


# =========================================================================== bound to the JOB's launch


def test_a_job_whose_launch_is_not_the_lease_on_the_seam_is_refused_before_its_arm(
        isolate, httpserver: HTTPServer, monkeypatch):
    """The seam holds ONE lease per slug. When the worker runs job n1 while the seam already holds launch n2's
    lease, the engine refuses BEFORE its arm and before any traffic — so job n1 never burns n2's single-use
    floor and never runs a scan that n2 would later reload and settle on. n2's own job then arms fresh and
    scans for itself, and only n2's records are on the ledger."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n2")                            # the seam holds launch n2's lease
    _wire_customer(monkeypatch, launch)
    plan = _Plan()

    with pytest.raises(EngagementRefused, match="different launch"):
        _engage(seed, plan, monkeypatch, launch_nonce="n1")
    assert plan.scans == 0 and len(httpserver.log) == 0
    assert launch.consumes == []                      # n1 never reached the consume

    result = _engage(seed, plan, monkeypatch, launch_nonce="n2")
    assert plan.scans == 1 and result.report.pages_crawled == PAGES
    assert launch.consumes == [True]                  # n2's own fresh arm
    assert {r.get("launch") for r in _read_ledger(SLUG) if r["phase"] == P_SCAN} == {_launch_tag("n2")}


def test_the_pause_halt_and_resume_state_bind_to_the_jobs_launch_not_to_a_later_lease(
        isolate, httpserver: HTTPServer, monkeypatch):
    """Job n1 arms on its own lease; right after, a later launch's lease (n2) lands on the seam. The run must stay
    bound to n1: a pause of n1 halts it, and its records are n1's — never re-keyed to whatever the seam holds."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    paused: set = set()
    monkeypatch.setattr(engage_mod, "_lease_is_paused", lambda base, slug, nonce: nonce in paused)
    armed = LL.verify_customer_launch_lease

    def _arm_then_relaunch(slug, host, tenant, **kw):
        out = armed(slug, host, tenant, **kw)
        launch.nonce = "n2"                           # launch n2's lease replaces n1's on the seam
        return out
    monkeypatch.setattr(LL, "verify_customer_launch_lease", _arm_then_relaunch)
    plan = _Plan()

    def _pause_n1(i: int) -> None:
        if i == 2:
            paused.add("n1")                          # the customer pauses THIS job's launch
    plan.before_action = _pause_n1

    with pytest.raises(EngagementPaused):
        _engage(seed, plan, monkeypatch, launch_nonce="n1")
    assert len(plan.refusals) == PAGES - 2            # n1's pause halted n1's run
    assert {r.get("launch") for r in _read_ledger(SLUG) if r["phase"] == P_SCAN} == {_launch_tag("n1")}


# =========================================================================== PhaseLedger unit: binding


def _bound(slug: str, launch: "str | None", *, resume: bool = False) -> PhaseLedger:
    led = PhaseLedger(slug, resume=resume)
    led.bind_launch(launch)
    return led


def test_bound_ledger_tags_its_records_with_a_digest_never_the_raw_identity(isolate):
    isolate("alpha")
    nonce = "lease-nonce-0123456789abcdef"
    led = _bound("alpha", nonce)
    led.start(P_SCAN)
    led.complete(P_SCAN)
    recs = _read_ledger("alpha")
    tags = {r.get("launch") for r in recs}
    assert len(tags) == 1 and None not in tags                              # every record tagged, one launch
    tag = tags.pop()
    assert re.fullmatch(r"[0-9a-f]{64}", tag)
    assert nonce not in _paths.phase_ledger_path("alpha").read_text(encoding="utf-8")   # the raw value never lands
    # a different launch gets a different tag; the same launch the same one
    other = _bound("alpha", "another-launch")
    other.start(P_SCAN)
    assert _read_ledger("alpha")[-1]["launch"] != tag
    same = _bound("alpha", nonce)
    same.start(P_SCAN)
    assert _read_ledger("alpha")[-1]["launch"] == tag


def test_bound_resume_ignores_another_launchs_completed_scan(isolate):
    isolate("alpha")
    l1 = _bound("alpha", "n1")
    l1.complete(P_SCAN)
    l1.complete(P_REASONING)
    # a LATER launch on the same slug: nothing L1 completed is L2's
    l2 = _bound("alpha", "n2", resume=True)
    assert l2.should_run(P_SCAN) is True
    assert l2.should_run(P_REASONING) is True
    assert l2.completed_prior() == set()
    # the SAME launch still resumes from its own records
    again = _bound("alpha", "n1", resume=True)
    assert again.should_run(P_SCAN) is False
    assert again.completed_prior() == {P_SCAN, P_REASONING}


def test_bound_resume_ignores_untagged_records_and_an_unknown_launch_reuses_nothing(isolate):
    isolate("alpha")
    PhaseLedger("alpha").complete(P_SCAN)             # an untagged record (an unbound run / a pre-binding ledger)
    assert _bound("alpha", "n1", resume=True).should_run(P_SCAN) is True
    _bound("alpha", "n1").complete(P_SCAN)            # now n1 completed it too
    # an UNKNOWN launch identity matches nothing — not the untagged record, not n1's
    unknown = _bound("alpha", None, resume=True)
    assert unknown.should_run(P_SCAN) is True
    assert unknown.completed_prior() == set()
    # ...and what it writes is untagged, so no later bound ledger can ever claim it
    unknown.complete(P_REASONING)
    assert "launch" not in _read_ledger("alpha")[-1]
    assert _bound("alpha", "n1", resume=True).should_run(P_REASONING) is True


def test_bind_launch_is_total_and_an_undigestable_identity_reuses_nothing(isolate):
    isolate("alpha")
    PhaseLedger("alpha").complete(P_SCAN)
    led = PhaseLedger("alpha", resume=True)
    led.bind_launch("\ud800")                         # a lone surrogate cannot be encoded — must NOT raise
    assert led.should_run(P_SCAN) is True             # ...and is an unknown launch: nothing is reused
    led.complete(P_REASONING)
    assert "launch" not in _read_ledger("alpha")[-1]


def test_bound_load_report_returns_only_this_launchs_snapshot(isolate):
    isolate("alpha")
    seed = "http://127.0.0.1:9/"
    l1 = _bound("alpha", "n1")
    l1.complete(P_SCAN)
    l1.persist_report(ScanReport(target=seed, pages_crawled=7))
    assert _bound("alpha", "n1", resume=True).load_report().pages_crawled == 7   # its own snapshot reloads

    # L2 completed its scan but its snapshot write was lost: the file on disk is still L1's report
    l2 = _bound("alpha", "n2")
    l2.complete(P_SCAN)
    l2_resume = _bound("alpha", "n2", resume=True)
    assert l2_resume.should_run(P_SCAN) is False      # L2 did complete a scan...
    assert l2_resume.load_report() is None            # ...but the snapshot on disk is not L2's -> re-scan

    # once L2 snapshots, the file is L2's — and no longer L1's
    l2.persist_report(ScanReport(target=seed, pages_crawled=42))
    assert _bound("alpha", "n2", resume=True).load_report().pages_crawled == 42
    assert _bound("alpha", "n1", resume=True).load_report() is None
    # an unknown launch never reloads anything
    assert _bound("alpha", None, resume=True).load_report() is None


def test_bound_load_report_rejects_a_snapshot_changed_after_it_was_recorded(isolate):
    isolate("alpha")
    led = _bound("alpha", "n1")
    led.complete(P_SCAN)
    led.persist_report(ScanReport(target="http://127.0.0.1:9/", pages_crawled=7))
    path = _paths.phase_report_path("alpha")
    path.write_text(ScanReport(target="http://127.0.0.1:9/", pages_crawled=99).model_dump_json(),
                    encoding="utf-8")                 # the file no longer holds what n1 recorded
    assert _bound("alpha", "n1", resume=True).load_report() is None


def test_snapshot_record_never_makes_the_scan_skippable_and_is_not_mirrored_to_the_spine(isolate):
    isolate("alpha")

    class _Sink:
        def __init__(self) -> None:
            self.seen: list[str] = []

        def phase(self, name: str, **_fields: object) -> None:
            self.seen.append(name)

    sink = _Sink()
    led = PhaseLedger("alpha", sink=sink)
    led.bind_launch("n1")
    led.persist_report(ScanReport(target="http://127.0.0.1:9/", pages_crawled=1))   # snapshot WITHOUT a completed scan
    assert [r["status"] for r in _read_ledger("alpha")] == ["snapshot"]
    assert sink.seen == []                            # a bookkeeping record, not a phase transition
    assert _bound("alpha", "n1", resume=True).should_run(P_SCAN) is True


def test_unbound_ledger_is_per_slug_exactly_as_before(isolate):
    isolate("alpha")
    _bound("alpha", "n1").complete(P_SCAN)            # even a tagged record counts for an UNBOUND ledger
    led = PhaseLedger("alpha", resume=True)
    assert led.should_run(P_SCAN) is False
    # ...and it reloads whatever snapshot the slug holds, with no launch check and no snapshot record written
    PhaseLedger("alpha").persist_report(ScanReport(target="http://127.0.0.1:9/", pages_crawled=5))
    assert led.load_report().pages_crawled == 5
    assert [r["status"] for r in _read_ledger("alpha")] == ["completed"]


def test_prior_halts_counts_only_this_launchs_halted_scans(isolate):
    isolate("alpha")
    _bound("alpha", "n1").halt(P_SCAN)
    _bound("alpha", "n1").halt(P_SCAN)
    _bound("alpha", "n2").halt(P_SCAN)                # another launch's pause
    _bound("alpha", "n1").halt(P_REASONING)           # another phase
    PhaseLedger("alpha").halt(P_SCAN)                 # an untagged record
    assert _bound("alpha", "n1").prior_halts(P_SCAN) == 2
    assert _bound("alpha", "n2").prior_halts(P_SCAN) == 1
    assert _bound("alpha", "n3").prior_halts(P_SCAN) == 0
    assert _bound("alpha", None).prior_halts(P_SCAN) == 0


def test_halted_phase_is_recorded_and_retried_on_resume(isolate):
    isolate("alpha")
    led = PhaseLedger("alpha")
    led.start(P_SCAN)
    led.halt(P_SCAN)
    assert [r["status"] for r in _read_ledger("alpha")] == ["started", "halted"]
    assert PhaseLedger("alpha", resume=True).should_run(P_SCAN) is True     # halted is NOT completed


def test_preflight_records_before_the_binding_never_block_the_run(isolate, httpserver: HTTPServer, monkeypatch):
    """The ledger is bound once the launch is known (after preflight); the preflight records written before
    that are untagged and never skippable, so a bound customer run still records its whole lifecycle."""
    isolate(SLUG)
    seed = _serve(httpserver)
    launch = _Launch("n1")
    _wire_customer(monkeypatch, launch)
    _engage(seed, _Plan(), monkeypatch)
    recs = _read_ledger(SLUG)
    assert [r["status"] for r in recs if r["phase"] == P_PREFLIGHT] == ["started", "completed"]
    assert all("launch" in r for r in recs if r["phase"] == P_SCAN)
