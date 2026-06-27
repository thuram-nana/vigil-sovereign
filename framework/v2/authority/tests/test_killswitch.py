"""Tests for the persistent, fail-closed kill-switch."""

from __future__ import annotations

from pathlib import Path

from ..killswitch import KillSwitch


def test_trip_and_detect(tmp_path: Path) -> None:
    ks = KillSwitch("eng", path=tmp_path / "eng.halt")
    assert ks.is_tripped() is False
    ks.trip("operator pressed stop")
    assert ks.is_tripped() is True
    assert ks.reason() == "operator pressed stop"


def test_persists_across_instances(tmp_path: Path) -> None:
    p = tmp_path / "eng.halt"
    KillSwitch("eng", path=p).trip("halt now")
    # A fresh instance (simulating a process restart) still sees it tripped.
    assert KillSwitch("eng", path=p).is_tripped() is True


def test_first_reason_preserved_on_double_trip(tmp_path: Path) -> None:
    ks = KillSwitch("eng", path=tmp_path / "eng.halt")
    ks.trip("first reason")
    ks.trip("second reason")
    assert ks.reason() == "first reason"


def test_clear_lifts_halt(tmp_path: Path) -> None:
    ks = KillSwitch("eng", path=tmp_path / "eng.halt")
    ks.trip("stop")
    ks.clear(cleared_by="operator")
    assert ks.is_tripped() is False


def test_unreadable_file_still_counts_as_tripped(tmp_path: Path) -> None:
    p = tmp_path / "eng.halt"
    p.write_text("{ this is not valid json", encoding="utf-8")
    ks = KillSwitch("eng", path=p)
    assert ks.is_tripped() is True
    assert ks.reason() == "kill-switch file present but unreadable"
