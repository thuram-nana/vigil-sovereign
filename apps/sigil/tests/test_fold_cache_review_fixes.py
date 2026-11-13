"""Front C S0 — the second set of fixes from the retroactive review of the verified fold cache.

The contract: a cached read equals the flag-OFF full verified fold on the same bytes — the same answer, or the same
raise. Each test below reproduces a case where it did not, and requires equality now:

  * a hostile value that made a SIGNATURE CHECK raise (a lone surrogate the canonical JSON cannot encode, an int too
    large for a float): the cache folds every capability (and orgs + memberships) in one pass, so one such record
    took the others down with it, where the per-capability / per-signal full fold answered for them;
  * `BudgetLedger.spent` handed out the live cached counter list, read after the entry lock was released;
  * `PlanCreditLedger.debited_entry` raised on an unloadable snapshot where its live scan (which never loads it)
    answers;
  * a fold-cache MISMATCH report outlived the process whose caches disagreed, so `vigil doctor` / `sigil verify`
    kept failing after every restart;
  * the assessments index kept rows no reader can ask for (no slug, a non-str slug).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

import test_fold_cache_latches as L
from sigil import config
from sigil.governor import authn
from sigil.governor import budget as bd
from sigil.governor import capability as cp
from sigil.governor import fold_read, fold_warm
from sigil.governor import metering as mt
from sigil.governor import orgs as og
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine.store import SpineStore
from sigil.ui import assessments as am
from sigil.ui.target_authorization import _customer_slug

OWNER = generate_keypair()
PUB = OWNER.public_key_b64
KW = {"owner_key": OWNER, "trusted_pubkey": PUB}
FLAG = "VIGIL_FOLD_CACHE_ENABLED"


def _both(monkeypatch, fn) -> dict:
    """{"ON": ..., "OFF": ...}: `fn()` with the cache on (cold) and off; a raise is recorded by its type."""
    out = {}
    for label, flag in (("ON", "1"), ("OFF", "")):
        monkeypatch.setenv(FLAG, flag)
        fold_cache.clear_all()
        cp._CAP_CACHE.clear()
        try:
            out[label] = repr(fn())
        except Exception as e:  # noqa: BLE001 — compared
            out[label] = f"raises {type(e).__name__}"
    monkeypatch.delenv(FLAG, raising=False)
    return out


def _raw_line(store, payload, *, kind="event"):
    """A hand-written line (a tampering-class input) that continues the chain: seq + 1, prev_hash = the tip's
    entry_hash — so it is folded exactly like an appended record."""
    tip = list(SpineStore(store.path).iter_records())[-1]
    rec = {"seq": tip.seq + 1, "scope": "sigil", "kind": kind, "source": "governor", "actor": "WARDEN",
           "payload": payload, "parent_id": None, "supersedes_id": None, "ts": "2026-11-10T00:00:00+00:00",
           "cert_digest": f"d{tip.seq + 1}", "prev_hash": tip.entry_hash, "entry_hash": f"h{tip.seq + 1:064d}",
           "schema_version": 1}
    with open(store.path, "ab") as f:
        f.write((json.dumps(rec, ensure_ascii=True) + "\n").encode())


# ======================================================================================================
# 1. a hostile value in a signature check never raises out of a fold
# ======================================================================================================
@pytest.mark.parametrize("bad", ["\ud800", 10 ** 400, float("nan"), [1], {"x": 1}, None])
def test_as_issued_at_never_raises(bad):
    assert authn.as_issued_at(bad) == 0.0


def test_verify_signed_is_false_for_a_core_value_that_cannot_be_canonicalized():
    p = {"signal": "s", "x": "\ud800", "sig": "AAAA", "pubkey": PUB}
    assert authn.verify_signed(p, ("signal", "x"), PUB) is False


def test_one_unencodable_capability_record_does_not_disable_the_others(tmp_path, monkeypatch):
    store = SpineStore(tmp_path / "cap.jsonl")
    store.append(kind="event", source="x", actor="x", payload={"n": 1})
    _raw_line(store, {"signal": cp.SIGNAL, "capability": "voice", "state": "enabled", "issued_at": "\ud800",
                      "sig": "AAAA", "pubkey": PUB})
    gate = cp.CapabilityGate(store, **KW)
    for c in sorted(cp.CAPABILITIES):
        got = _both(monkeypatch, lambda c=c: gate.is_enabled(c))
        assert got["ON"] == got["OFF"], (c, got)


def test_an_owner_signed_enable_with_an_overflowing_issued_at_is_the_same_with_the_cache_on(tmp_path, monkeypatch):
    store = SpineStore(tmp_path / "cap.jsonl")
    gate = cp.CapabilityGate(store, **KW)
    gate.disable("voice", by="owner", reason="t")
    core = {"signal": cp.SIGNAL, "capability": "voice", "state": "enabled", "issued_at": 10 ** 400}
    store.append(kind="event", source="governor", actor="WARDEN", payload=authn.signed_payload(core, OWNER))
    gate.enable("gesture", issued_at=5.0)
    for c in sorted(cp.CAPABILITIES):
        got = _both(monkeypatch, lambda c=c: gate.is_enabled(c))
        assert got["ON"] == got["OFF"], (c, got)
        assert "raises" not in got["OFF"]


@pytest.mark.parametrize("signal,fields", [
    (og.ORG_SIGNAL, {"org_id": "zzz", "name": "\ud800", "owner": ""}),
    (og.MEMBERSHIP_SIGNAL, {"org_id": "zzz", "username": "u", "role": "\ud800"}),
])
def test_one_unencodable_org_record_does_not_take_the_other_signal_down(tmp_path, monkeypatch, signal, fields):
    store = SpineStore(tmp_path / "org.jsonl")
    reg = og.OrgRegistry(store, **KW)
    reg._append_active_org("acme", "n", "o", issued_at=1.0)
    reg._append_active_membership("acme", "alice", "operator", issued_at=1.0)
    _raw_line(store, {"signal": signal, **fields, "state": "active", "issued_at": 5.0, "sig": "AAAA", "pubkey": PUB})
    for read in (lambda: reg.orgs(), lambda: reg.org("acme"), lambda: reg.memberships("acme"),
                 lambda: reg.membership_role("acme", "alice")):
        got = _both(monkeypatch, read)
        assert got["ON"] == got["OFF"] and "raises" not in got["ON"], got


# ======================================================================================================
# 2. a cached reader returns a copy taken under the entry lock
# ======================================================================================================
def test_budget_spent_is_built_from_a_copy_taken_under_the_lock(tmp_path, monkeypatch):
    store = SpineStore(tmp_path / "spine.jsonl")
    day = "2026-11-11"
    for i in range(3):
        store.append(kind="event", source="agent", actor="ALPHA", payload={"decision": "auto", "i": i,
                     "usage": {"input_tokens": 1, "output_tokens": 1, "cost_usd": 0.01}},
                     ts=f"{day}T0{i}:00:00+00:00")
    monkeypatch.setenv(FLAG, "1")
    fold_cache.clear_all()
    seen = []
    real = fold_read.cached_unsigned_read

    def spy(cache, store_, *, seed, reader, live_window=False):
        def wrapped(view):
            out = reader(view)
            seen.append(out)
            return out
        return real(cache, store_, seed=seed, reader=wrapped, live_window=live_window)

    monkeypatch.setattr(bd, "cached_unsigned_read", spy)
    led = bd.BudgetLedger(store, bd.BudgetCaps(daily_actions=10, daily_tokens=100, daily_cost_usd=1.0))
    first = led.spent("ALPHA", day)
    assert seen and isinstance(seen[-1], tuple), "the reader hands out an immutable copy, not the live list"
    store.append(kind="event", source="agent", actor="ALPHA", payload={"decision": "auto",
                 "usage": {"input_tokens": 5, "output_tokens": 5, "cost_usd": 0.05}}, ts=f"{day}T05:00:00+00:00")
    assert seen[0] == (first.actions, first.interrupts, first.tokens, first.cost_usd), "the copy did not move"
    assert led.spent("ALPHA", day).actions == 4
    assert led.spent("ALPHA", "2026-01-01").actions == 0


# ======================================================================================================
# 3. debited_entry: the live scan never loads the snapshot, so neither may the cached read raise on it
# ======================================================================================================
def test_debited_entry_answers_like_its_scan_on_an_unreadable_head(tmp_path, monkeypatch):
    from sigil.spine import snapshot as snap_mod
    store = SpineStore(tmp_path / "spine.jsonl")
    plan = mt.PlanCreditLedger(store, **KW)
    plan.grant("acme", 100, period_end=1000.0, entry_id="g1", issued_at=1.0)
    plan.debit("acme", 40, period_end=1000.0, entry_id="r0", issued_at=2.0)
    head = tmp_path / "head.json"
    head.write_text("{ not a head", encoding="utf-8")
    monkeypatch.setattr(snap_mod, "HEAD_PATH", head)
    got = _both(monkeypatch, lambda: plan.debited_entry("acme", "r0"))
    assert got["ON"] == got["OFF"] == repr((40, 1000.0)), got
    other = _both(monkeypatch, lambda: plan.debited_entry("acme", "nope"))
    assert other["ON"] == other["OFF"] == "None"


# ======================================================================================================
# 4. an audit report describes the caches of the process that wrote it — they die with it
# ======================================================================================================
def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def _mismatch_report(pid: int) -> dict:
    return {"ok": False, "ts": "2026-11-11T00:00:00+00:00", "pid": pid, "spine": "x", "interval_s": 1.0,
            "folds": [{"fold": "governor.wallet", "status": "MISMATCH", "seq": 4, "difference": "state.debited"},
                      {"fold": "governor.customer", "status": "match", "seq": 4}]}


def test_a_report_from_a_dead_process_is_superseded_at_start_and_keeps_the_evidence(tmp_path, monkeypatch):
    path = tmp_path / "fold_cache_audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", path)
    dead = _dead_pid()
    path.write_text(json.dumps(_mismatch_report(dead)), encoding="utf-8")
    monkeypatch.delenv(FLAG, raising=False)                     # superseded even with the cache OFF
    assert fold_warm.start_background(lambda: SpineStore(tmp_path / "spine.jsonl")) is None
    rep = json.loads(path.read_text(encoding="utf-8"))
    assert rep["pid"] == os.getpid() and rep["ok"] is True and rep["folds"] == []
    assert rep["superseded"] == {"pid": dead, "ts": "2026-11-11T00:00:00+00:00", "ok": False,
                                 "mismatched": ["governor.wallet"]}
    assert rep["cache_enabled"] is False


def test_a_report_from_a_live_process_is_left_alone(tmp_path, monkeypatch):
    path = tmp_path / "fold_cache_audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", path)
    live = _mismatch_report(os.getppid())                        # our parent: alive
    path.write_text(json.dumps(live), encoding="utf-8")
    assert fold_warm.supersede_dead_report() is False
    assert json.loads(path.read_text(encoding="utf-8")) == live
    path.write_text("{ torn", encoding="utf-8")
    assert fold_warm.supersede_dead_report() is False             # unreadable: nothing to supersede
    path.unlink()
    assert fold_warm.supersede_dead_report() is False


@pytest.mark.parametrize("pid,alive", [(0, False), (-1, False), ("123", False), (True, False), (None, False)])
def test_only_a_positive_int_pid_can_be_alive(pid, alive):
    assert fold_warm._pid_alive(pid) is alive


def test_sigil_verify_does_not_count_a_dead_processs_mismatch(tmp_path, monkeypatch, capsys):
    from sigil.cli import _verify_fold_caches
    path = tmp_path / "fold_cache_audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", path)
    path.write_text(json.dumps(_mismatch_report(_dead_pid())), encoding="utf-8")
    assert _verify_fold_caches(False) is True
    out = capsys.readouterr().out
    assert "that process is gone" in out and "not counted" in out
    path.write_text(json.dumps(_mismatch_report(os.getpid())), encoding="utf-8")   # a LIVE process's mismatch
    assert _verify_fold_caches(False) is False
    assert "folds FAIL" in capsys.readouterr().out
    rep = _mismatch_report(os.getpid())
    rep["folds"] = [{"fold": "a", "status": "match"}, {"fold": "b", "status": "error", "error": "x"}]
    path.write_text(json.dumps(rep), encoding="utf-8")
    assert _verify_fold_caches(False) is True
    assert "1 cached fold(s) equal a rebuild; 1 could not be read" in capsys.readouterr().out


# ======================================================================================================
# 5. the assessments index holds only rows a reader can return (PR #1075's "equivalent mutant", resolved)
# ======================================================================================================
def test_the_assessments_index_holds_only_readable_rows(tmp_path, monkeypatch):
    """Agents append kind="finding" records with NO certificate; wildcard-scope findings carry no slug. None of them
    can ever be asked for — they must not accumulate in the cached index (and the count is unchanged)."""
    monkeypatch.setenv(FLAG, "1")
    fold_cache.clear_all()
    regs = L._Regs(SpineStore(str(tmp_path / "spine.jsonl")))
    L._prove(regs, "acme", L.HOSTS[0])
    slug = _customer_slug("acme", L.HOSTS[0])
    L._finding(regs.store, slug, 1)
    for payload in ({"signal": "web.actor.blocked", "summary": "s"}, {"certificate": "x"}, {"certificate": None},
                    {"certificate": {"finding_ref": "wild"}}, {"certificate": {"engagement_slug": 7}}):
        regs.store.append(kind="finding", source="agent", actor="actor", payload=payload)
    regs.store.append(kind="assessment_outcome", source="jobs", actor="runner", payload={"outcome": "done"})
    got = am.assessment_findings(regs.store, "acme", now=10.0)
    assert got["count"] == 1
    (entry,) = am._ASSESSMENTS_FOLD._entries.values()
    assert set(entry.state.findings) == {slug} and all(isinstance(k, str) for k in entry.state.outcomes)
    monkeypatch.setenv(FLAG, "")
    assert am.assessment_findings(regs.store, "acme", now=10.0) == got
