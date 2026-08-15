"""
The engagement PHASE LEDGER + ``--resume`` (framework.v2.phase_ledger / engage.run_engagement).

The properties under test are the load-bearing contract of the slice:

  * **Persist.** Each phase's start/complete is appended (append-only) to a durable JSONL, and
    the scan snapshots its authoritative ScanReport.
  * **Resume skips ONLY what is sound to skip.** ``resume`` is not "skip every completed phase":
    only the two ``RESUMABLE_PHASES`` — the traffic-sending scan (reloaded from its snapshot
    instead of re-crawling) and the spine-emitting reasoning pass (whose re-emit would double-
    count) — are skipped. Every PURE, no-traffic reasoning phase — finding-confidence, chaining,
    and above all the GROUNDING veracity firewall — ALWAYS re-runs on resume, so a resumed
    result carries the SAME authoritative derived fields (grounding, finding_confidence, attack
    paths) as a fresh run, re-verified by the oracle re-firing, never a stale snapshot. A scan
    that only started/failed (crashed before completing) is RETRIED.
  * **Fail-open.** Every ledger write is total: an unwritable ledger, a corrupt line, or a
    missing snapshot degrades to a recorded no-op / a clean re-run — it NEVER raises into or
    changes the engagement, and it never mints a finding.

Everything is hermetic: the ScanReport is a canned pydantic object and ``WebScanCampaign`` is
replaced by a call-counting fake, so no traffic leaves the test host.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2 import engage as engage_mod
from framework.v2.agents.blackboard import Blackboard
from framework.v2.common import paths as _paths
from framework.v2.engage import EngagementRefused, run_engagement
from framework.v2.phase_ledger import (
    P_CHAINING,
    P_DEFENDER,
    P_FUSION,
    P_GROUNDING,
    P_PREFLIGHT,
    P_REASONING,
    P_SCAN,
    RESUMABLE_PHASES,
    PhaseLedger,
)
from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding

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


# --------------------------------------------------------------------------- fixtures


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


def _sample_report(target: str = "http://127.0.0.1:9/") -> ScanReport:
    f = AuditFinding(
        check_id="c1", bug_class="boolean_sqli", insertion_point="query:q", param="q",
        endpoint=f"{target}search?q=1", confidence=0.9, confirmed_by="predicate",
        rationale="1=1 diverged", oracle_context={"cert": "x"})
    return ScanReport(target=target, pages_crawled=2, requests_audited=4,
                      audit_requests_sent=4, active_findings=[f])


def _fake_campaign(report: ScanReport, *, raise_on_run: bool = False):
    """A WebScanCampaign stand-in that counts .run() invocations (so we can prove the scan is
    executed exactly once, or retried after a crash) and sends no traffic."""
    state = {"runs": 0}

    class _Fake:
        def __init__(self, *_a, **_k) -> None:
            pass

        def run(self, _seed_url):
            state["runs"] += 1
            if raise_on_run:
                raise RuntimeError("simulated scan crash mid-op")
            return report

    return _Fake, state


def _read_ledger(slug: str) -> list[dict]:
    path = _paths.phase_ledger_path(slug)
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _statuses(recs: list[dict], phase: str) -> list[str]:
    return [r["status"] for r in recs if r.get("phase") == phase]


# =========================================================================== PhaseLedger unit


def test_ledger_persists_started_and_completed(isolate):
    isolate("alpha")
    led = PhaseLedger("alpha")
    led.start(P_PREFLIGHT)
    led.complete(P_PREFLIGHT)
    recs = _read_ledger("alpha")
    assert _statuses(recs, P_PREFLIGHT) == ["started", "completed"]
    assert all(isinstance(r.get("ts"), int) for r in recs)   # run-status timestamp present


def test_ledger_is_append_only_across_instances(isolate):
    isolate("alpha")
    PhaseLedger("alpha").complete("scan")
    PhaseLedger("alpha").complete("chaining")   # a second instance must NOT truncate the first
    recs = _read_ledger("alpha")
    phases = [r["phase"] for r in recs]
    assert phases == ["scan", "chaining"]


def test_resume_should_run_skips_only_completed(isolate):
    isolate("alpha")
    seed = PhaseLedger("alpha")
    seed.complete(P_SCAN)                 # scan completed last run; chaining never recorded
    led = PhaseLedger("alpha", resume=True)
    assert led.should_run(P_SCAN) is False
    assert led.should_run(P_CHAINING) is True
    assert led.completed_prior() == {P_SCAN}


def test_resume_reruns_completed_pure_reasoning_phases(isolate):
    """The BLOCK fix: resume is a strict allowlist — only the scan and the spine-emitting
    reasoning pass may be skipped when completed. A COMPLETED pure-reasoning phase (chaining, and
    above all the GROUNDING veracity firewall) MUST still re-run on resume, because its output
    lives only in the prior process and the oracle must re-fire before findings are facts."""
    isolate("alpha")
    seed = PhaseLedger("alpha")
    # A prior run completed EVERY phase, including the veracity firewall.
    for ph in (P_SCAN, P_CHAINING, P_GROUNDING, P_REASONING):
        seed.complete(ph)
    led = PhaseLedger("alpha", resume=True)
    # The two RESUMABLE phases (completed) are skipped...
    assert RESUMABLE_PHASES == {P_SCAN, P_REASONING}
    assert led.should_run(P_SCAN) is False
    assert led.should_run(P_REASONING) is False
    # ...but the pure-reasoning phases re-run even though the prior run completed them.
    assert led.should_run(P_CHAINING) is True
    assert led.should_run(P_GROUNDING) is True     # the veracity firewall is NEVER skipped on resume


def test_resume_disabled_never_skips(isolate):
    isolate("alpha")
    PhaseLedger("alpha").complete(P_SCAN)
    led = PhaseLedger("alpha", resume=False)   # no --resume → always run
    assert led.should_run(P_SCAN) is True


def test_run_phase_runs_and_records(isolate):
    isolate("alpha")
    led = PhaseLedger("alpha")
    calls = []
    out = led.run_phase("chaining", lambda: (calls.append(1) or "value"))
    assert out == "value"
    assert calls == [1]
    assert _statuses(_read_ledger("alpha"), "chaining") == ["started", "completed"]


def test_run_phase_skips_completed_resumable_phase_without_calling_fn(isolate):
    # A RESUMABLE phase (the spine-emitting reasoning pass) completed in a prior run IS skipped
    # on resume — fn is not called and the default is returned.
    isolate("alpha")
    PhaseLedger("alpha").complete(P_REASONING)
    led = PhaseLedger("alpha", resume=True)
    calls = []
    out = led.run_phase(P_REASONING, lambda: calls.append(1), default="DFLT")
    assert out == "DFLT"
    assert calls == []                                 # the completed resumable phase did NOT re-execute
    assert _statuses(_read_ledger("alpha"), P_REASONING)[-1] == "skipped"


def test_run_phase_reruns_completed_pure_reasoning_phase_on_resume(isolate):
    # The BLOCK fix at the run_phase level: a COMPLETED pure-reasoning phase (chaining) RE-RUNS on
    # resume — fn IS called and a fresh started/completed pair is appended (append-only).
    isolate("alpha")
    PhaseLedger("alpha").complete(P_CHAINING)
    led = PhaseLedger("alpha", resume=True)
    calls = []
    out = led.run_phase(P_CHAINING, lambda: (calls.append(1) or "fresh"), default="DFLT")
    assert out == "fresh"                               # re-derived, not the skipped default
    assert calls == [1]                                # the reasoning phase DID re-execute on resume
    assert _statuses(_read_ledger("alpha"), P_CHAINING)[-1] == "completed"
    assert "skipped" not in _statuses(_read_ledger("alpha"), P_CHAINING)


def test_run_phase_disabled_records_nothing(isolate):
    isolate("alpha")
    led = PhaseLedger("alpha")
    calls = []
    out = led.run_phase("fusion", lambda: calls.append(1), enabled=False, default=7)
    assert out == 7 and calls == []
    assert _read_ledger("alpha") == []                 # a disabled phase leaves no trace


def test_run_phase_failure_is_fail_open_and_retried(isolate):
    isolate("alpha")

    def boom():
        raise ValueError("phase body blew up")

    led = PhaseLedger("alpha")
    out = led.run_phase("chaining", boom, default="safe")   # must NOT raise
    assert out == "safe"
    assert _statuses(_read_ledger("alpha"), "chaining") == ["started", "failed"]
    # a failed (not completed) phase is RETRIED on resume
    assert PhaseLedger("alpha", resume=True).should_run("chaining") is True


def test_report_snapshot_roundtrips(isolate):
    isolate("alpha")
    led = PhaseLedger("alpha")
    led.persist_report(_sample_report())
    back = led.load_report()
    assert back is not None
    assert back.pages_crawled == 2
    assert len(back.active_findings) == 1
    assert back.active_findings[0].oracle_context == {"cert": "x"}


def test_load_report_missing_returns_none(isolate):
    isolate("alpha")
    assert PhaseLedger("alpha").load_report() is None


def test_load_report_corrupt_returns_none(isolate):
    isolate("alpha")
    _paths.phase_report_path("alpha").parent.mkdir(parents=True, exist_ok=True)
    _paths.phase_report_path("alpha").write_text("{not json", encoding="utf-8")
    assert PhaseLedger("alpha").load_report() is None   # fail-open: falls back to re-scan


def test_corrupt_ledger_line_does_not_break_resume(isolate):
    isolate("alpha")
    path = _paths.phase_ledger_path("alpha")
    path.parent.mkdir(parents=True, exist_ok=True)
    # a valid completed record + a torn trailing line (a crash mid-write)
    path.write_text(
        json.dumps({"phase": "scan", "status": "completed", "ts": 1}) + "\n{part",
        encoding="utf-8")
    led = PhaseLedger("alpha", resume=True)
    assert led.should_run("scan") is False              # the intact record still counts
    assert led.completed_prior() == {"scan"}


def test_ledger_write_failure_is_fail_open(isolate, monkeypatch):
    isolate("alpha")
    # Point the ledger path's PARENT at an existing FILE so mkdir/os.open genuinely fail for any
    # uid (root included) — the write must be swallowed and fn must still run.
    blocker = _paths.target_dir("alpha")
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker_file = blocker.parent / "blocker"
    blocker_file.write_text("x", encoding="utf-8")
    monkeypatch.setattr(_paths, "phase_ledger_path", lambda s: blocker_file / f"{s}.phases.jsonl")

    led = PhaseLedger("alpha")
    calls = []
    led.start("scan")                                   # must not raise
    out = led.run_phase("chaining", lambda: calls.append(1) or "ok")
    assert out == "ok" and calls == [1]                 # engagement work proceeds despite dead ledger


# =========================================================================== run_engagement


def _run(slug, seed, campaign_cls, monkeypatch, **kw):
    monkeypatch.setattr(engage_mod, "WebScanCampaign", campaign_cls)
    return run_engagement(slug, seed, enable_chaining=True, **kw)


def test_engage_persists_ledger_and_report_snapshot(isolate, monkeypatch):
    isolate("alpha")
    seed = "http://127.0.0.1:9/"
    Fake, state = _fake_campaign(_sample_report(seed))
    result = _run("alpha", seed, Fake, monkeypatch)

    assert state["runs"] == 1
    assert len(result.report.active_findings) == 1
    recs = _read_ledger("alpha")
    assert _statuses(recs, P_PREFLIGHT) == ["started", "completed"]
    assert _statuses(recs, P_SCAN) == ["started", "completed"]
    assert "completed" in _statuses(recs, P_CHAINING)
    # the authoritative report was snapshotted for a future resume
    assert _paths.phase_report_path("alpha").is_file()
    snap = ScanReport.model_validate_json(
        _paths.phase_report_path("alpha").read_text(encoding="utf-8"))
    assert len(snap.active_findings) == 1


def _grounding_sig(result) -> list:
    """The veracity-firewall verdict per finding, reduced to its load-bearing signal (is_fact).
    An empty list means the firewall NEVER RAN — the exact silent drop the BLOCK described."""
    return [getattr(g, "is_fact", g) for g in (result.grounding or [])]


def _confidence_sig(result) -> list:
    """The per-finding confidence assessment reduced to its presence pattern (None == could not
    assess). Empty means the assess-findings reasoning phase never ran on this result."""
    return [g is not None for g in (result.finding_confidence or [])]


def test_resume_skips_the_scan_and_does_not_double_execute(isolate, monkeypatch):
    isolate("alpha")
    seed = "http://127.0.0.1:9/"
    report = _sample_report(seed)

    Fake, state = _fake_campaign(report)
    fresh = _run("alpha", seed, Fake, monkeypatch)      # a FULL fresh run — every phase executes
    assert state["runs"] == 1                           # first run scanned once

    # The fresh run's authoritative DERIVED deliverable — the firewall fired and produced a verdict
    # per finding, and confidence was assessed. These live ONLY in this process; nothing reloads them.
    fresh_grounding = _grounding_sig(fresh)
    fresh_confidence = _confidence_sig(fresh)
    assert len(fresh_grounding) == 1                    # the veracity firewall produced a live verdict
    assert len(fresh_confidence) == 1

    # RESUME: a NEW fake so we can prove .run() is never called again
    Fake2, state2 = _fake_campaign(report)
    result = _run("alpha", seed, Fake2, monkeypatch, resume=True)
    assert state2["runs"] == 0                          # the scan was NOT re-executed (idempotent)
    # the authoritative report was reloaded from the snapshot, not recrawled
    assert len(result.report.active_findings) == 1
    assert result.report.pages_crawled == 2

    # THE FIX (was green-washed): a resumed run must produce the SAME authoritative deliverable as a
    # fresh run — minus only the re-crawl — NOT a bare reloaded snapshot with its derived fields
    # dropped. Assert the resume RE-COMPUTED every pure-reasoning field to equal the fresh run's.
    assert _grounding_sig(result) == fresh_grounding    # veracity verdicts re-derived, identical
    assert _grounding_sig(result) != []                 # ...and the firewall actually RE-FIRED on resume
    assert _confidence_sig(result) == fresh_confidence
    assert list(result.attack_paths or []) == list(fresh.attack_paths or [])
    assert list(result.chained_conclusions or []) == list(fresh.chained_conclusions or [])

    recs = _read_ledger("alpha")
    assert recs[-1]["phase"] != "" and "skipped" in _statuses(recs, P_SCAN)
    # the SCAN was skipped (reloaded) — completed exactly once, on the fresh run
    assert _statuses(recs, P_SCAN).count("completed") == 1
    # the GROUNDING veracity firewall was NEVER skipped and re-fired on resume (completed twice)
    assert "skipped" not in _statuses(recs, P_GROUNDING)
    assert _statuses(recs, P_GROUNDING).count("completed") == 2
    # ...as did finding-confidence and chaining (pure reasoning always re-runs)
    assert _statuses(recs, P_CHAINING).count("completed") == 2
    # preflight STILL re-ran on resume (authorization is never skipped)
    assert _statuses(recs, P_PREFLIGHT).count("completed") == 2


def test_resume_recomputes_fusion_and_defender_without_double_counting_spine_events(
        isolate, monkeypatch):
    """The re-verify BLOCK: resume correctly RE-RUNS the pure-reasoning phases, but two of them —
    sensor fusion and the defender pass — ALSO write to the append-only spine. Re-running them
    verbatim double-counted their events on every resume (a fused-lead ``finding`` event per sensor
    LEAD + the defender gap-report observation), inflating the engagement's finding count. The fix
    RE-RUNS them (so ``fused_leads``/``defense`` recompute and a resumed result is as complete as a
    fresh one) but hands their EMITTING steps a NULL sink when the prior run already recorded the
    phase — so their events appear EXACTLY ONCE across fresh+resume. Uses a REAL Blackboard spine
    and a real operator fusion plan (a declared_service on the in-scope host)."""
    td = isolate("alpha")
    seed = "http://127.0.0.1:9/"
    # A real operator fusion plan: a declared_service on the IN-SCOPE host mints LEAD observations
    # that fusion mirrors onto the spine as `finding` events (finding_slug 'lead:...').
    (td / "fusion.json").write_text(json.dumps([
        {"sensor": "declared_service", "args": {"host": "127.0.0.1", "services": [
            {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": "1.18.0"},
            {"port": 8080, "protocol": "tcp", "service": "http", "product": "apache", "version": "2.4.41"},
        ]}}]), encoding="utf-8")

    bb = Blackboard(db_path=td.parent.parent / "spine.db")   # tmp_path/spine.db (real, on-disk)

    def _lead_finding_slugs() -> list[str]:
        """The fused-sensor LEAD finding events on the spine (finding_slug 'lead:...'), which the
        fusion phase emits — the exact events the BLOCK re-appended on every resume."""
        return sorted(
            s for s in (str((r.payload or {}).get("finding_slug", ""))
                        for r in bb.read(engagement="alpha", kinds=["finding"]))
            if s.startswith("lead:"))

    def _defender_gap_obs() -> list:
        return [r for r in bb.read(engagement="alpha", kinds=["observation"])
                if str((r.payload or {}).get("source", "")) == "defender:gap-report"]

    # FRESH run — spine + fusion + defender all active; every phase executes.
    Fake, state = _fake_campaign(_sample_report(seed))
    fresh = _run("alpha", seed, Fake, monkeypatch,
                 spine=bb, fuse_sensors=True, enable_defender=True)
    assert state["runs"] == 1
    # the DERIVED fields were computed, and their spine events were emitted ONCE.
    assert fresh.fused_leads > 0                        # fusion minted + folded LEADs (in-memory derived field)
    assert fresh.defense is not None                    # defender built its DefenseReport (in-memory derived field)
    fresh_leads = _lead_finding_slugs()
    assert len(fresh_leads) > 0                         # fused-lead finding events reached the spine on the fresh run
    assert len(_defender_gap_obs()) == 1               # the defender gap-report observation emitted exactly once
    total_findings_fresh = bb.count(engagement="alpha", kind="finding")

    # RESUME — fusion + defender RE-RUN (they are not RESUMABLE_PHASES), but must NOT re-emit.
    Fake2, state2 = _fake_campaign(_sample_report(seed))
    resumed = _run("alpha", seed, Fake2, monkeypatch,
                   spine=bb, fuse_sensors=True, enable_defender=True, resume=True)
    assert state2["runs"] == 0                          # the scan was reloaded from snapshot, not re-crawled

    # THE FIX — the derived fields are RECOMPUTED on resume (a resumed result is as complete)...
    assert resumed.fused_leads == fresh.fused_leads and resumed.fused_leads > 0
    assert resumed.defense is not None
    # ...but the spine events are NOT re-appended: the fused-lead findings and the defender
    # gap-report observation appear EXACTLY ONCE across fresh+resume (zero duplicates).
    assert _lead_finding_slugs() == fresh_leads         # no duplicate fused-lead finding events
    assert len(_defender_gap_obs()) == 1               # no duplicate defender gap-report observation
    assert bb.count(engagement="alpha", kind="finding") == total_findings_fresh  # finding count did not inflate

    # the ledger proves fusion + defender actually RE-RAN on resume (completed twice), while the
    # spine-emitting reasoning pass was SKIPPED (its re-emit is its only effect).
    recs = _read_ledger("alpha")
    assert _statuses(recs, P_FUSION).count("completed") == 2
    assert _statuses(recs, P_DEFENDER).count("completed") == 2
    assert "skipped" in _statuses(recs, P_REASONING)
    bb.close()


def test_resume_retries_a_scan_that_crashed_mid_op(isolate, monkeypatch):
    isolate("alpha")
    seed = "http://127.0.0.1:9/"

    # Run 1: the scan crashes mid-op → run_engagement propagates, scan is NOT marked completed.
    Boom, boom_state = _fake_campaign(_sample_report(seed), raise_on_run=True)
    monkeypatch.setattr(engage_mod, "WebScanCampaign", Boom)
    with pytest.raises(RuntimeError):
        run_engagement("alpha", seed)
    assert boom_state["runs"] == 1
    recs = _read_ledger("alpha")
    assert _statuses(recs, P_SCAN) == ["started"]       # started, never completed
    assert "completed" not in _statuses(recs, P_SCAN)
    assert not _paths.phase_report_path("alpha").is_file()   # no snapshot from a crashed scan

    # Run 2 (resume): the un-completed scan is RETRIED and now succeeds.
    Ok, ok_state = _fake_campaign(_sample_report(seed))
    result = _run("alpha", seed, Ok, monkeypatch, resume=True)
    assert ok_state["runs"] == 1                         # scan re-executed on resume
    assert len(result.report.active_findings) == 1
    assert _statuses(_read_ledger("alpha"), P_SCAN)[-1] == "completed"


def test_ledger_io_failure_never_sinks_the_engagement(isolate, monkeypatch):
    isolate("alpha")
    seed = "http://127.0.0.1:9/"
    # A totally broken ledger path helper (raises) must not stop the engagement returning a result.
    monkeypatch.setattr(_paths, "phase_ledger_path",
                        lambda s: (_ for _ in ()).throw(OSError("no ledger for you")))
    Fake, state = _fake_campaign(_sample_report(seed))
    result = _run("alpha", seed, Fake, monkeypatch)
    assert state["runs"] == 1
    assert len(result.report.active_findings) == 1      # the run completed despite the dead ledger


def test_preflight_refusal_is_recorded_and_raised(isolate, monkeypatch):
    isolate("alpha")
    # An out-of-scope seed must still be refused (authorization is never weakened by the ledger).
    Fake, state = _fake_campaign(_sample_report())
    monkeypatch.setattr(engage_mod, "WebScanCampaign", Fake)
    with pytest.raises(EngagementRefused):
        run_engagement("alpha", "http://10.9.9.9/")     # not in the charter scope
    assert state["runs"] == 0                            # refused BEFORE any scan
    assert _statuses(_read_ledger("alpha"), P_PREFLIGHT) == ["started", "failed"]
