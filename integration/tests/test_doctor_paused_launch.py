"""pause/resume PR-5 — doctor/observability reconciliation: a paused launch is an EXPECTED held state.

A positively-recorded pause ``(slug, nonce)`` is surfaced by ``vigil doctor`` as an ADVISORY NOTE + a
``report["paused_launches"]`` projection, NEVER a hard issue (it does not flip ``ok``): a paused launch is held
and re-admitted on resume by the PR-1..PR-4a plumbing, not stuck/lost/unsettled. DEFAULT-OFF: no markers ⇒ no
note, count 0, byte-identical. ``credit_lease_pause.paused_launches`` enumerates them (total, fail-safe); it is
NOT an alarm suppressor (a genuinely stuck lease carries no pause marker, and the #69 money-drain gate is
untouched).

Integration leg (doctor + credit_lease_pause, both framework-free; import only vigil_core + stdlib).

An UNREADABLE / corrupt marker is the opposite case: the launch gate fails CLOSED on it, so every launch of that
slug is held although nothing was positively paused, and the fail-open ``paused_launches`` projection cannot see
it. Doctor surfaces THAT as a hard ISSUE naming the slug only (never a nonce, never marker content).

Mutation-verify targets (each neuter reds a NAMED test here):
  * paused_launches ignores the marker / returns []     -> test_paused_launches_enumerates_slug_and_nonces
  * doctor emits the paused state as an _issue not _note -> test_doctor_surfaces_paused_launches_as_an_advisory_not_an_alarm
  * doctor drops the unreadable-marker probe             -> test_doctor_surfaces_an_unreadable_pause_marker_as_an_issue_naming_the_slug
  * doctor reports the unreadable marker as a _note      -> test_doctor_surfaces_an_unreadable_pause_marker_as_an_issue_naming_the_slug
  * doctor always adds the "unreadable" key              -> test_doctor_byte_identical_when_no_pauses
  * doctor names every slug (drops the cap)              -> test_doctor_unreadable_issue_is_bounded_but_the_report_lists_every_slug
"""
from __future__ import annotations

import json
from pathlib import Path

from vigil_integration import doctor as _doc
from vigil_integration.live.credit_lease_pause import (
    clear_lease_pause, is_lease_paused, paused_launches, pauses_root, record_lease_pause,
)

_REPO = Path(_doc.__file__).resolve().parents[2]


def test_paused_launches_enumerates_slug_and_nonces(tmp_path):
    base = str(tmp_path)
    assert paused_launches(base) == []                       # default-OFF: nothing recorded
    record_lease_pause(base, "cust_a", "n1")
    record_lease_pause(base, "cust_a", "n2")                 # same slug, two holds
    record_lease_pause(base, "cust_b", "n9")
    got = dict(paused_launches(base))
    assert sorted(got["cust_a"]) == ["n1", "n2"] and got["cust_b"] == ["n9"]
    clear_lease_pause(base, "cust_a", "n1")
    got = dict(paused_launches(base))
    assert got["cust_a"] == ["n2"] and got["cust_b"] == ["n9"]
    clear_lease_pause(base, "cust_a", "n2")                  # cust_a now has no holds
    got = dict(paused_launches(base))
    assert "cust_a" not in got and got["cust_b"] == ["n9"]   # a marker with an empty nonce set is not listed


def test_paused_launches_is_fail_safe_on_a_missing_or_bad_root(tmp_path):
    assert paused_launches(str(tmp_path / "nope")) == []     # absent dir ⇒ []
    root = tmp_path / "credit-lease-pauses"
    root.mkdir()
    (root / "cust_x.json").write_text("not json at all", encoding="utf-8")   # corrupt marker ⇒ contributes nothing
    assert paused_launches(str(tmp_path)) == []


def test_doctor_surfaces_paused_launches_as_an_advisory_not_an_alarm(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    (tmp_path / "base").mkdir()
    record_lease_pause(str(tmp_path / "base"), "cust_paused1", "n1")
    record_lease_pause(str(tmp_path / "base"), "cust_paused2", "n7")
    report = _doc.collect(_REPO)
    pl = report["paused_launches"]
    assert pl["count"] == 2 and pl["holds"] == 2 and sorted(pl["slugs"]) == ["cust_paused1", "cust_paused2"]
    assert any("currently PAUSED" in n for n in report["notes"])              # surfaced as an advisory NOTE
    assert not any("PAUSED" in i for i in report["issues"])                   # NEVER a hard issue (does not flip ok)
    assert "unreadable" not in pl                                             # readable pauses add no unreadable key
    assert not any("UNREADABLE" in i for i in report["issues"])               # ... and no unreadable-marker issue


def test_doctor_byte_identical_when_no_pauses(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    (tmp_path / "base").mkdir()
    report = _doc.collect(_REPO)
    assert report["paused_launches"] == {"count": 0, "holds": 0, "slugs": []}  # EXACT: no new key when off
    assert not any("PAUSED" in n for n in report["notes"])                    # no paused note when none are recorded
    assert not any("pause marker" in i for i in report["issues"])             # and no unreadable-marker issue


def test_doctor_surfaces_an_unreadable_pause_marker_as_an_issue_naming_the_slug(tmp_path, monkeypatch):
    # A corrupt marker HALTS every launch of its slug (the gate fails closed — unchanged, and asserted here) but
    # `paused_launches` cannot read it, so doctor used to report 0 paused launches: a real hold, invisible.
    base = tmp_path / "base"
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(base))
    base.mkdir()
    record_lease_pause(str(base), "cust_paused1", "nonce-RECORDED-aaa")      # a normal, readable pause
    # a TRUNCATED marker that still carries a nonce string — nothing from inside it may reach the report
    (pauses_root(str(base)) / "cust_broken.json").write_text(
        '{"kind": "vigil-credit-lease-pause-v1", "nonces": ["nonce-PAYLOAD-zzz"', encoding="utf-8")
    assert is_lease_paused(str(base), "cust_broken", "any-nonce-at-all") is True   # the gate holds it (fail-closed)

    report = _doc.collect(_REPO)
    pl = report["paused_launches"]
    assert pl["count"] == 1 and pl["holds"] == 1 and pl["slugs"] == ["cust_paused1"]   # readable pauses unchanged
    assert pl["unreadable"] == ["cust_broken"]
    hits = [i for i in report["issues"] if "cust_broken" in i]
    assert len(hits) == 1 and "UNREADABLE" in hits[0]                         # a hard ISSUE that names the slug
    assert report["ok"] is False                                              # ... so `vigil doctor` exits non-zero
    assert not any("cust_broken" in n for n in report["notes"])               # not downgraded to an advisory note
    assert "cust_paused1" not in hits[0]                                      # only the unreadable slug is named
    assert any("currently PAUSED" in n for n in report["notes"])              # the readable pause stays advisory
    blob = json.dumps(report)                                                 # no nonce / marker payload anywhere
    assert "nonce-PAYLOAD-zzz" not in blob and "nonce-RECORDED-aaa" not in blob
    assert "cust_broken" in _doc.render(report)                               # and the human rendering shows it


def test_doctor_unreadable_issue_is_bounded_but_the_report_lists_every_slug(tmp_path, monkeypatch):
    base = tmp_path / "base"
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(base))
    root = pauses_root(str(base))
    root.mkdir(parents=True)
    n = _doc._UNREADABLE_PAUSE_SLUGS_SHOWN + 2
    slugs = [f"cust_bad{i:02d}" for i in range(n)]
    for slug in slugs:
        (root / f"{slug}.json").write_text("{ corrupt", encoding="utf-8")
    report = _doc.collect(_REPO)
    assert report["paused_launches"]["unreadable"] == slugs                   # the structured report has them ALL
    (issue,) = [i for i in report["issues"] if "UNREADABLE" in i]             # exactly ONE issue, not one per slug
    assert issue.startswith(f"{n} customer launch pause marker(s)")
    assert slugs[_doc._UNREADABLE_PAUSE_SLUGS_SHOWN - 1] in issue             # the first N are named ...
    assert slugs[_doc._UNREADABLE_PAUSE_SLUGS_SHOWN] not in issue             # ... the rest are summarised
    assert "(+2 more)" in issue
