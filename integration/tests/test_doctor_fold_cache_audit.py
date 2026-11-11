"""Front C S0d — `vigil doctor` reads the cockpit's fold-cache AUDIT (`$SIGIL_HOME/fold_cache_audit.json`, written by
`sigil.governor.fold_warm`) as inert JSON, without importing sigil (FATAL-2):

  * no report (the cache is off, or no audit yet) adds nothing — default output unchanged;
  * a recorded MISMATCH is a HARD issue (flips `ok`, `vigil doctor` exits 1);
  * a report older than twice its own interval (+1 h) is a NOTE (the audit thread is not running);
  * an unreadable / malformed report is a note, never a crash.

Integration leg (doctor only — framework-free).
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from vigil_integration import doctor as _doc

_REPO = Path(_doc.__file__).resolve().parents[2]
NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.timezone.utc).timestamp()


def _write(home, folds, *, ts="2026-11-11T11:00:00+00:00", interval=21600.0):
    (home / "fold_cache_audit.json").write_text(json.dumps(
        {"ok": True, "ts": ts, "pid": 4242, "interval_s": interval, "folds": folds}))


def test_no_report_adds_nothing(tmp_path):
    assert _doc._fold_cache_audit_report(tmp_path, now=NOW) == ({"present": False}, [], [])


def test_a_clean_audit_is_reported_and_rendered(tmp_path):
    _write(tmp_path, [{"fold": "governor.customer", "status": "match", "seq": 9},
                      {"fold": "governor.wallet", "status": "empty"},
                      {"fold": "governor.orgs", "status": "skipped", "reason": "x"}])
    section, issues, notes = _doc._fold_cache_audit_report(tmp_path, now=NOW)
    assert (issues, notes) == ([], [])
    assert section == {"present": True, "ts": "2026-11-11T11:00:00+00:00", "pid": 4242, "ok": True,
                       "matched": 1, "mismatched": 0, "skipped": 1}
    out = _doc.render({"ok": True, "issues": [], "notes": [], "fold_cache_audit": section})
    assert "OK fold cache audit (2026-11-11T11:00:00+00:00): 1 match, 0 MISMATCH, 1 skipped" in out


def test_a_mismatch_is_a_hard_issue(tmp_path):
    _write(tmp_path, [{"fold": "governor.wallet", "status": "MISMATCH", "seq": 77, "difference": "state.granted"}])
    section, issues, _notes = _doc._fold_cache_audit_report(tmp_path, now=NOW)
    assert section["ok"] is False and section["mismatched"] == 1
    assert len(issues) == 1 and "governor.wallet at seq 77" in issues[0] and "state.granted" in issues[0]
    out = _doc.render({"ok": False, "issues": issues, "notes": [], "fold_cache_audit": section})
    assert "!! fold cache audit" in out and "1 MISMATCH" in out


def test_a_stale_report_is_a_note(tmp_path):
    _write(tmp_path, [{"fold": "governor.customer", "status": "match", "seq": 1}],
           ts="2026-11-09T00:00:00+00:00", interval=3600.0)
    section, issues, notes = _doc._fold_cache_audit_report(tmp_path, now=NOW)
    assert section["stale"] is True and issues == [] and len(notes) == 1 and "not running" in notes[0]
    _write(tmp_path, [], ts="2026-11-09T00:00:00+00:00", interval=0.0)          # periodic audit disabled
    assert "stale" not in _doc._fold_cache_audit_report(tmp_path, now=NOW)[0]


def test_an_unreadable_report_is_a_note_never_a_crash(tmp_path):
    (tmp_path / "fold_cache_audit.json").write_text("{not json")
    section, issues, notes = _doc._fold_cache_audit_report(tmp_path, now=NOW)
    assert section["present"] and "error" in section and issues == [] and len(notes) == 1
    (tmp_path / "fold_cache_audit.json").write_text("[1, 2]")
    section, issues, notes = _doc._fold_cache_audit_report(tmp_path, now=NOW)
    assert "error" in section and issues == [] and len(notes) == 1
    out = _doc.render({"ok": True, "issues": [], "notes": notes, "fold_cache_audit": section})
    assert "fold cache audit (" not in out


def test_collect_wires_the_section_in(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    _write(tmp_path, [{"fold": "governor.wallet", "status": "MISMATCH", "seq": 3, "difference": "d"}])
    section, issues, _ = _doc._fold_cache_audit_report()
    assert section["mismatched"] == 1 and issues


def test_collect_lists_a_mismatch_as_intake_safe(tmp_path, monkeypatch):
    """A MISMATCH is EVIDENCE the auditing cockpit already acted on (dropped the entry), and only a RUNNING cockpit
    rewrites the report — so a scripted bring-up must not hold payment intake down on it: `collect` lists it under
    `intake_safe_issues` (read by tools/oneshot-bringup). It is still a hard issue; a clean audit adds no key."""
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    _write(tmp_path, [{"fold": "governor.wallet", "status": "match", "seq": 3}])
    assert "intake_safe_issues" not in _doc.collect(_REPO)
    _write(tmp_path, [{"fold": "governor.wallet", "status": "MISMATCH", "seq": 3, "difference": "d"}])
    report = _doc.collect(_REPO)
    mismatch = [i for i in report["issues"] if i.startswith("fold cache MISMATCH")]
    assert len(mismatch) == 1 and report["ok"] is False
    assert report["intake_safe_issues"] == mismatch
