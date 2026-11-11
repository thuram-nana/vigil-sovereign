"""pause/resume PR-5 — doctor/observability reconciliation: a paused launch is an EXPECTED held state.

A positively-recorded pause ``(slug, nonce)`` is surfaced by ``vigil doctor`` as an ADVISORY NOTE + a
``report["paused_launches"]`` projection, NEVER a hard issue (it does not flip ``ok``): a paused launch is held
and re-admitted on resume by the PR-1..PR-4a plumbing, not stuck/lost/unsettled. DEFAULT-OFF: no markers ⇒ no
note, count 0, byte-identical. ``credit_lease_pause.paused_launches`` enumerates them (total, fail-safe); it is
NOT an alarm suppressor (a genuinely stuck lease carries no pause marker, and the #69 money-drain gate is
untouched).

Integration leg (doctor + credit_lease_pause, both framework-free; import only vigil_core + stdlib).

Mutation-verify targets (each neuter reds a NAMED test here):
  * paused_launches ignores the marker / returns []     -> test_paused_launches_enumerates_slug_and_nonces
  * doctor emits the paused state as an _issue not _note -> test_doctor_surfaces_paused_launches_as_an_advisory_not_an_alarm
"""
from __future__ import annotations

from pathlib import Path

from vigil_integration import doctor as _doc
from vigil_integration.live.credit_lease_pause import clear_lease_pause, paused_launches, record_lease_pause

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


def test_doctor_byte_identical_when_no_pauses(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    (tmp_path / "base").mkdir()
    report = _doc.collect(_REPO)
    assert report["paused_launches"]["count"] == 0
    assert not any("PAUSED" in n for n in report["notes"])                    # no paused note when none are recorded
