"""phase_ledger -> customer-safe activity mirror (Live Control). The engine mirrors each phase transition to
the shared seam base so the SOVEREIGN Live Control edge can show the customer what VIGIL is doing. Flag-gated:
ON mirrors; OFF is a COMPLETE no-op, so engine behaviour is byte-identical by default."""
from __future__ import annotations

import tempfile

from vigil_core import live_activity as la

from framework.v2.phase_ledger import PhaseLedger


def test_transitions_mirror_to_the_activity_seam_when_the_flag_is_on(monkeypatch):
    base = tempfile.mkdtemp()
    monkeypatch.setenv("VIGIL_BASE_DIR", base)                 # the shared seam base both planes resolve
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_CONTROL", "1")
    pl = PhaseLedger("eng1")
    pl.start("scan")
    pl.complete("scan")
    pl.start("reasoning_pass")
    rows = la.read(base, "eng1")
    assert [(r["phase"], r["status"]) for r in rows] == [
        ("scan", "started"), ("scan", "completed"), ("reasoning_pass", "started")]
    assert rows[0]["label"] == "Running authorized checks"     # the customer sees a friendly stage label


def test_no_activity_emitted_when_the_flag_is_off(monkeypatch):
    base = tempfile.mkdtemp()
    monkeypatch.setenv("VIGIL_BASE_DIR", base)
    monkeypatch.delenv("VIGIL_CUSTOMER_LIVE_CONTROL", raising=False)
    pl = PhaseLedger("eng1")
    pl.start("scan")
    pl.complete("scan")
    assert la.read(base, "eng1") == []                         # nothing emitted — byte-identical engine behaviour
