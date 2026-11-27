"""phase_ledger -> customer-safe activity mirror (Live Control). The engine mirrors each phase transition to
the shared seam base so the SOVEREIGN Live Control edge can show the customer what VIGIL is doing. Flag-gated:
ON mirrors; OFF is a COMPLETE no-op, so engine behaviour is byte-identical by default."""
from __future__ import annotations

import tempfile

from vigil_core import live_activity as la

from framework.v2.phase_ledger import ORDERED_PHASES, P_PREFLIGHT, PhaseLedger


def test_the_customer_allowlist_is_exactly_the_engine_phase_constants():
    """The vigil_core customer-feed allowlist KEYS must be the engine phase constants byte-for-byte. emit() and
    read() both DROP any phase not on the allowlist, so a drift here silently hides stages from the customer feed
    (as it did: transfer_priors / assess_grounding / defender_pass were emitted but keyed transfer / grounding /
    defender, so the veracity step and two others never appeared). This is the one place both planes import
    together, so it is where the mirror is pinned — in BOTH directions, so a phantom key cannot creep in either."""
    assert set(la._PHASES) == set(ORDERED_PHASES), {
        "engine phases missing a customer label (silently dropped)": sorted(set(ORDERED_PHASES) - set(la._PHASES)),
        "allowlist keys that are not real engine phases (phantom)": sorted(set(la._PHASES) - set(ORDERED_PHASES)),
    }


def test_a_new_run_preflight_resets_the_customer_trail(monkeypatch):
    # the customer slug is per (org, host) and reused by every launch; a new run's preflight-started must reset the
    # trail so the feed shows the CURRENT run, not the concatenation of every past run on the same host.
    base = tempfile.mkdtemp()
    monkeypatch.setenv("VIGIL_BASE_DIR", base)
    monkeypatch.setenv("VIGIL_CUSTOMER_LIVE_CONTROL", "1")
    la.emit(base, "eng1", "scan", "completed", ts=1.0)             # a previous run on this slug
    la.emit(base, "eng1", "reasoning_pass", "completed", ts=2.0)
    assert len(la.read(base, "eng1")) == 2
    PhaseLedger("eng1").start(P_PREFLIGHT)                          # a new run attempt -> reset, then emit preflight
    assert [(r["phase"], r["status"]) for r in la.read(base, "eng1")] == [("preflight", "started")]


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
