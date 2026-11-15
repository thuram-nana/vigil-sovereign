"""`vigil doctor` on the edges' stop timeout: every INSTALLED edge unit (sigil-customer / sigil-public, plain and
template) must let systemd wait for that edge's drain before it kills a stopping edge — the customer edge finishes an
action the cockpit is still completing for up to 75 s, so its units allow 90 s.

A host whose units were installed by an older release keeps TimeoutStopSec=20 until they are re-installed: then a
stop, a restart or an edge swap kills the customer edge part way through a sign-up email or a checkout — the action
done, the customer told it failed. That is a HARD issue naming the unit and the command to re-install it. A drop-in
counts (the last TimeoutStopSec=/TimeoutSec= wins); no value is systemd's default (90 s). Silent until an edge unit is
installed. Framework-free: tmp HOME trees only, no systemd needed.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
from test_doctor_deploy_units import _REPO, _isolated, _write

from vigil_integration import deploy_checks as dc
from vigil_integration import doctor as _doc

_UNITS = _REPO / "apps" / "sigil" / "deploy" / "systemd"


def _install(home: Path, unit: str, *, stop: "str | None" = None) -> Path:
    """Install the shipped unit, optionally with its TimeoutStopSec line replaced (None: as shipped; "": removed)."""
    udir = home / ".config" / "systemd" / "user"
    udir.mkdir(parents=True, exist_ok=True)
    dst = udir / unit
    shutil.copy(_UNITS / unit, dst)
    if stop is not None:
        text = dst.read_text(encoding="utf-8")
        line = f"TimeoutStopSec={stop}\n" if stop else ""
        text, n = re.subn(r"^TimeoutStopSec=.*\n", line, text, flags=re.M)
        assert n == 1
        dst.write_text(text, encoding="utf-8")
    return dst


def test_silent_without_an_edge_unit(tmp_path):
    assert dc.edge_stop_timeout_report(tmp_path, _REPO) == ({"configured": False}, [], [])


def test_the_shipped_units_are_clean(tmp_path):
    for unit in ("sigil-customer.service", "sigil-customer@.service", "sigil-public.service", "sigil-public@.service"):
        _install(tmp_path, unit)
    sec, issues, notes = dc.edge_stop_timeout_report(tmp_path, _REPO)
    assert issues == [] and notes == [] and sec["ok"] is True
    assert sec["units"] == {"sigil-customer.service": 90.0, "sigil-customer@.service": 90.0,
                            "sigil-public.service": 20.0, "sigil-public@.service": 20.0}


@pytest.mark.parametrize("unit,stale", [("sigil-customer.service", "20"), ("sigil-customer@.service", "20"),
                                        ("sigil-customer.service", "1min"), ("sigil-public@.service", "15s")])
def test_a_unit_from_an_older_release_is_a_hard_issue_naming_the_fix(tmp_path, unit, stale):
    _install(tmp_path, unit, stop=stale)
    sec, issues, _notes = dc.edge_stop_timeout_report(tmp_path, _REPO)
    edge = "customer" if "customer" in unit else "public"
    assert sec["ok"] is False and len(issues) == 1
    assert issues[0].startswith(f"{unit} lets systemd stop the {edge} edge after")
    assert f"may need {dc.EDGE_STOP_FLOOR_S[edge]} s" in issues[0]
    assert f"cp apps/sigil/deploy/systemd/{unit} ~/.config/systemd/user/" in issues[0]
    assert "daemon-reload" in issues[0] and "RELEASE-UPGRADE-ROLLBACK.md §2.6" in issues[0]


@pytest.mark.parametrize("value,secs", [("90", 90.0), ("90s", 90.0), ("1min 30s", 90.0), ("1min30s", 90.0),
                                        ("1.5min", 90.0), ("2h", 7200.0), ("infinity", float("inf")),
                                        ("81", 81.0), ("80", 80.0), ("1min 20s 900ms", 80.9)])
def test_the_unit_file_value_is_read_as_systemd_reads_it(tmp_path, value, secs):
    _install(tmp_path, "sigil-customer.service", stop=value)
    sec, issues, _notes = dc.edge_stop_timeout_report(tmp_path, _REPO)
    assert sec["units"]["sigil-customer.service"] == pytest.approx(secs)
    assert (issues == []) is (secs >= 81)


def test_a_drop_in_counts_and_timeoutsec_sets_the_stop_timeout_too(tmp_path):
    _install(tmp_path, "sigil-customer.service", stop="20")
    d = tmp_path / ".config" / "systemd" / "user" / "sigil-customer.service.d"
    _write(d / "longer.conf", "[Service]\nTimeoutStopSec=90\n")
    assert dc.edge_stop_timeout_report(tmp_path, _REPO)[1] == []                 # the drop-in raises it
    _install(tmp_path, "sigil-customer.service")                                  # the shipped unit (90 s) ...
    _write(d / "longer.conf", "[Service]\nTimeoutSec=30\n")                       # ... and TimeoutSec= after it
    sec, issues, _notes = dc.edge_stop_timeout_report(tmp_path, _REPO)            # sets both timeouts: 30 s
    assert len(issues) == 1 and sec["units"]["sigil-customer.service"] == 30.0


def test_no_value_is_systemds_default_and_an_unreadable_one_is_a_note(tmp_path):
    _install(tmp_path, "sigil-customer.service", stop="")
    sec, issues, notes = dc.edge_stop_timeout_report(tmp_path, _REPO)
    assert issues == [] and notes == [] and sec["units"]["sigil-customer.service"] == 90.0
    _install(tmp_path, "sigil-customer.service", stop="soon")
    sec, issues, notes = dc.edge_stop_timeout_report(tmp_path, _REPO)
    assert issues == [] and len(notes) == 1 and "could not be read" in notes[0]
    assert sec["units"]["sigil-customer.service"] == "unreadable"


def test_doctor_reports_and_renders_it(tmp_path, monkeypatch):
    home = _isolated(monkeypatch, tmp_path)
    assert _doc.collect(_REPO)["edge_stop_timeout"] == {"configured": False}
    _install(home, "sigil-customer@.service", stop="20")
    report = _doc.collect(_REPO)
    assert report["edge_stop_timeout"]["ok"] is False
    assert any(i.startswith("sigil-customer@.service lets systemd stop the customer edge after 20 s")
               for i in report["issues"])
    assert "edge stop timeouts: sigil-customer@.service 20 s" in _doc.render(report)
