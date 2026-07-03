"""Tests for the persistent, fail-closed kill-switch."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

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


def test_absent_file_reads_clear(tmp_path: Path) -> None:
    ks = KillSwitch("eng", path=tmp_path / "missing.halt")
    assert ks.is_tripped() is False


def test_stat_permission_error_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An EACCES while stat-ing (e.g. an unreadable parent dir) is ambiguous
    # and MUST be treated as TRIPPED, not swallowed to CLEAR the way
    # Path.is_file() would.
    p = tmp_path / "eng.halt"
    ks = KillSwitch("eng", path=p)

    real_stat = os.stat

    def boom(target: object, *a: object, **k: object) -> os.stat_result:
        if os.fspath(target) == os.fspath(p):
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_stat(target, *a, **k)

    monkeypatch.setattr(os, "stat", boom)
    assert ks.is_tripped() is True


def test_stat_symlink_loop_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "eng.halt"
    ks = KillSwitch("eng", path=p)

    real_stat = os.stat

    def loop(target: object, *a: object, **k: object) -> os.stat_result:
        if os.fspath(target) == os.fspath(p):
            raise OSError(errno.ELOOP, "Too many levels of symbolic links")
        return real_stat(target, *a, **k)

    monkeypatch.setattr(os, "stat", loop)
    assert ks.is_tripped() is True


def test_stat_enoent_reads_clear(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ENOENT positively proves absence -> CLEAR (normal untripped state).
    p = tmp_path / "eng.halt"
    ks = KillSwitch("eng", path=p)

    real_stat = os.stat

    def gone(target: object, *a: object, **k: object) -> os.stat_result:
        if os.fspath(target) == os.fspath(p):
            raise FileNotFoundError(errno.ENOENT, "No such file or directory")
        return real_stat(target, *a, **k)

    monkeypatch.setattr(os, "stat", gone)
    assert ks.is_tripped() is False
