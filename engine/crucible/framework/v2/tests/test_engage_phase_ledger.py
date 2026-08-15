"""
The engagement PHASE LEDGER + ``--resume`` (framework.v2.phase_ledger / engage.run_engagement).

The properties under test are the load-bearing contract of the slice:

  * **Persist.** Each phase's start/complete is appended (append-only) to a durable JSONL, and
    the scan snapshots its authoritative ScanReport.
  * **Resume, idempotent.** A phase a prior run COMPLETED is skipped on ``resume`` — never re-
    executed, never double-counted; the traffic-sending scan is reloaded from its snapshot
    instead of re-crawling. A phase that only started/failed (crashed before completing) is
    RETRIED.
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
from framework.v2.common import paths as _paths
from framework.v2.engage import EngagementRefused, run_engagement
from framework.v2.phase_ledger import (
    P_CHAINING,
    P_PREFLIGHT,
    P_SCAN,
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


def test_run_phase_skips_completed_without_calling_fn(isolate):
    isolate("alpha")
    PhaseLedger("alpha").complete("chaining")
    led = PhaseLedger("alpha", resume=True)
    calls = []
    out = led.run_phase("chaining", lambda: calls.append(1), default="DFLT")
    assert out == "DFLT"
    assert calls == []                                 # the completed phase did NOT re-execute
    assert _statuses(_read_ledger("alpha"), "chaining")[-1] == "skipped"


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


def test_resume_skips_the_scan_and_does_not_double_execute(isolate, monkeypatch):
    isolate("alpha")
    seed = "http://127.0.0.1:9/"
    report = _sample_report(seed)

    Fake, state = _fake_campaign(report)
    _run("alpha", seed, Fake, monkeypatch)
    assert state["runs"] == 1                           # first run scanned once

    # RESUME: a NEW fake so we can prove .run() is never called again
    Fake2, state2 = _fake_campaign(report)
    result = _run("alpha", seed, Fake2, monkeypatch, resume=True)
    assert state2["runs"] == 0                          # the scan was NOT re-executed (idempotent)
    # the authoritative report was reloaded from the snapshot, not recrawled
    assert len(result.report.active_findings) == 1
    assert result.report.pages_crawled == 2
    recs = _read_ledger("alpha")
    assert recs[-1]["phase"] != "" and "skipped" in _statuses(recs, P_SCAN)
    # preflight STILL re-ran on resume (authorization is never skipped)
    assert _statuses(recs, P_PREFLIGHT).count("completed") == 2


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
