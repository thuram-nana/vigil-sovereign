"""Front C S0d — `vigil doctor` reads the cockpit's fold-cache AUDIT (`$SIGIL_HOME/fold_cache_audit.json`, written by
`sigil.governor.fold_warm`) as inert JSON, without importing sigil (FATAL-2):

  * no report (the cache is off, or no audit yet) adds nothing — default output unchanged;
  * a recorded MISMATCH is a HARD issue (flips `ok`, `vigil doctor` exits 1);
  * a report older than twice its own interval (+1 h) is a NOTE (the audit thread is not running);
  * a fold whose rebuild from the spine RAISED during the audit is counted and noted (never hidden);
  * an unreadable / malformed report is a note, never a crash.
  * a MISMATCH a previous cockpit recorded (superseded at the running cockpit's start) is a NOTE naming it.

Integration leg (doctor only — framework-free).
"""
from __future__ import annotations

import datetime as dt
import json

from vigil_integration import doctor as _doc

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
    assert "could not be rebuilt" not in out


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


def test_a_fold_that_could_not_be_rebuilt_is_counted_and_noted(tmp_path):
    _write(tmp_path, [{"fold": "governor.customer", "status": "match", "seq": 9},
                      {"fold": "governor.wallet", "status": "error", "error": "SpineError: missing segment"},
                      {"fold": "governor.orgs", "status": "error", "error": "SpineError: missing segment"}])
    section, issues, notes = _doc._fold_cache_audit_report(tmp_path, now=NOW)
    assert section["errored"] == 2 and section["ok"] is True and issues == []
    assert len(notes) == 1 and "governor.wallet, governor.orgs" in notes[0] and "missing segment" in notes[0]
    assert "sigil verify" in notes[0]
    out = _doc.render({"ok": True, "issues": [], "notes": notes, "fold_cache_audit": section})
    assert "1 match, 0 MISMATCH, 0 skipped, 2 could not be rebuilt" in out


def test_a_superseded_mismatch_is_a_note_naming_the_previous_cockpit(tmp_path):
    """The running cockpit superseded, at its start, a report in which a previous cockpit recorded a MISMATCH: those
    caches are gone, but the evidence of a possible spine edit is not — a NOTE (never a hard issue) naming that
    cockpit's pid and audit time."""
    (tmp_path / "fold_cache_audit.json").write_text(json.dumps(
        {"ok": True, "ts": "2026-11-11T11:00:00+00:00", "pid": 1, "interval_s": 21600.0, "folds": [],
         "superseded": {"pid": 1, "ts": "2026-11-10T09:00:00+00:00", "ok": False,
                        "mismatched": ["governor.budget", "governor.wallet"]}}))
    section, issues, notes = _doc._fold_cache_audit_report(tmp_path, now=NOW)
    assert issues == [] and section["ok"] is True and section["superseded_mismatched"] == 2
    assert notes == ["a previous cockpit (pid 1, audit 2026-11-10T09:00:00+00:00) recorded a MISMATCH in "
                     "governor.budget, governor.wallet; its caches died with it, but investigate a possible spine "
                     "edit."]
    out = _doc.render({"ok": True, "issues": [], "notes": notes, "fold_cache_audit": section})
    assert "a previous cockpit (pid 1" in out


def test_a_superseded_verdict_without_a_mismatch_adds_nothing(tmp_path):
    for sup in ({"pid": 1, "ts": "t", "ok": True, "mismatched": []}, {"pid": 1, "mismatched": "governor.wallet"},
                "not a dict", {"pid": 1}):
        (tmp_path / "fold_cache_audit.json").write_text(json.dumps(
            {"ok": True, "ts": "2026-11-11T11:00:00+00:00", "pid": 2, "interval_s": 21600.0, "folds": [],
             "superseded": sup}))
        section, issues, notes = _doc._fold_cache_audit_report(tmp_path, now=NOW)
        assert (issues, notes) == ([], []) and "superseded_mismatched" not in section, sup
