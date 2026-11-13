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
    kept failing after every restart; the writer is named by a per-process instance and the report lock, never by
    its PID alone (a container's cockpit has the same PID on every start), and a superseded MISMATCH stays visible;
  * the assessments index kept rows no reader can ask for (no slug, a non-str slug).
"""
from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import textwrap
import time

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


@pytest.mark.parametrize("err,alive", [(PermissionError(1, "Operation not permitted"), True),
                                       (ProcessLookupError(3, "No such process"), False)])
def test_a_process_running_under_another_user_is_alive(monkeypatch, err, alive):
    """`kill(pid, 0)` refused with EPERM: the process exists (another user's), so its report still describes caches
    that serve — a MISMATCH it recorded is not superseded."""
    def probe(pid, sig):
        raise err

    monkeypatch.setattr(fold_warm.os, "kill", probe)
    assert fold_warm._pid_alive(4242) is alive
    assert fold_warm.report_is_live(_mismatch_report(4242)) is alive


def test_sigil_verify_does_not_count_a_dead_processs_mismatch(tmp_path, monkeypatch, capsys):
    from sigil.cli import _verify_fold_caches
    path = tmp_path / "fold_cache_audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", path)
    path.write_text(json.dumps(_mismatch_report(_dead_pid())), encoding="utf-8")
    assert _verify_fold_caches(False) is True
    out = capsys.readouterr().out
    assert "that process is gone" in out and "not counted" in out
    live = dict(_mismatch_report(os.getpid()), instance=fold_warm.instance_id())     # THIS process's own report
    path.write_text(json.dumps(live), encoding="utf-8")
    assert _verify_fold_caches(False) is False
    assert "folds FAIL" in capsys.readouterr().out
    rep = _mismatch_report(os.getpid())
    rep["folds"] = [{"fold": "a", "status": "match"}, {"fold": "b", "status": "error", "error": "x"}]
    path.write_text(json.dumps(rep), encoding="utf-8")
    assert _verify_fold_caches(False) is True
    assert "1 cached fold(s) equal a rebuild; 1 could not be read" in capsys.readouterr().out


def _own(path):
    """Read the report at `path`."""
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("instance", ["an-earlier-cockpit", None])
def test_a_report_from_an_earlier_process_with_this_pid_is_superseded(tmp_path, monkeypatch, capsys, instance):
    """A container's cockpit is PID 1 on every start: a report left by the previous container names THIS process's
    PID. Its writer is gone (another instance, or a report from before instances), so `sigil verify` does not count
    it and the restarted cockpit supersedes it."""
    from sigil.cli import _verify_fold_caches
    path = tmp_path / "fold_cache_audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", path)
    rep = _mismatch_report(os.getpid())
    if instance is not None:
        rep["instance"] = instance
    path.write_text(json.dumps(rep), encoding="utf-8")
    assert fold_warm.report_is_live(rep, path) is False
    assert _verify_fold_caches(False) is True and "not counted" in capsys.readouterr().out
    monkeypatch.delenv(FLAG, raising=False)
    assert fold_warm.start_background(lambda: SpineStore(tmp_path / "spine.jsonl")) is None
    new = _own(path)
    assert new["pid"] == os.getpid() and new["instance"] == fold_warm.instance_id() and new["folds"] == []
    assert new["superseded"] == {"pid": os.getpid(), "ts": rep["ts"], "ok": False, "mismatched": ["governor.wallet"]}
    assert fold_warm.report_is_live(new, path) is True


_HOLDER = textwrap.dedent("""
    import json, os, sys
    from pathlib import Path
    from sigil.governor import fold_warm
    path = Path(sys.argv[1])
    assert fold_warm.hold_report_lock(path)
    fold_warm.write_report({"ok": False, "ts": "2026-11-11T00:00:00+00:00", "pid": 1, "instance": fold_warm.instance_id(),
                            "spine": "x", "interval_s": 1.0, "folds": [{"fold": "governor.wallet", "status": "MISMATCH",
                                                                       "seq": 4, "difference": "state.debited"}]}, path)
    print("ready", flush=True)
    sys.stdin.read()
""")


def test_a_report_whose_writer_holds_the_lock_is_live_in_every_other_process(tmp_path, monkeypatch):
    """Another running process holds the report lock and wrote the report (as PID 1, the PID every container's cockpit
    has): it is live here whatever its PID says — counted by `sigil verify`, never superseded. Once that process is
    gone the same report is dead and the next start supersedes it."""
    from sigil.cli import _verify_fold_caches
    path = tmp_path / "fold_cache_audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", path)
    holder = subprocess.Popen([sys.executable, "-c", _HOLDER, str(path)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "ready"
        rep = _own(path)
        assert rep["pid"] == 1 and rep["instance"] != fold_warm.instance_id()
        assert fold_warm.report_is_live(rep, path) is True
        assert fold_warm.supersede_dead_report(path) is False and _own(path) == rep
        assert fold_warm._holds_lock(path) is False                  # it could not take the lock the writer holds
        assert _verify_fold_caches(False) is False
    finally:
        holder.stdin.close()
        holder.wait(30)
    assert fold_warm.report_is_live(rep, path) is False
    assert fold_warm.supersede_dead_report(path) is True
    assert _own(path)["superseded"]["mismatched"] == ["governor.wallet"] and fold_warm._holds_lock(path)


def test_the_lock_holder_judges_another_instances_report_dead_whatever_its_pid(tmp_path):
    path = tmp_path / "fold_cache_audit.json"
    assert fold_warm.hold_report_lock(path) and fold_warm.hold_report_lock(path)          # once per process
    try:
        for pid in (os.getpid(), os.getppid(), 1):
            assert fold_warm.report_is_live(dict(_mismatch_report(pid), instance="another"), path) is False
        assert fold_warm.report_is_live(dict(_mismatch_report(4242), instance=fold_warm.instance_id()), path) is True
    finally:
        fold_warm._release_report_lock(path)


@pytest.mark.parametrize("instance", ["", 5, None])
def test_a_report_without_an_instance_falls_back_to_its_pid(instance):
    """Written before reports carried an instance (or a malformed one): its PID is all there is, never our own."""
    for pid, live in ((os.getppid(), True), (_dead_pid(), False), (os.getpid(), False)):
        rep = _mismatch_report(pid)
        if instance is not None:
            rep["instance"] = instance
        assert fold_warm.report_is_live(rep) is live, (pid, instance)


def test_an_audit_report_names_this_process(tmp_path):
    rep = fold_warm.audit(SpineStore(tmp_path / "spine.jsonl"))
    assert rep["instance"] == fold_warm.instance_id() and rep["pid"] == os.getpid()
    assert fold_warm.report_is_live(rep, tmp_path / "fold_cache_audit.json") is True


def test_a_concurrent_probe_is_not_a_holder(tmp_path):
    """Two processes probing at once (`sigil verify` while a cockpit starts) never see each other as the holder."""
    import fcntl
    path = tmp_path / "fold_cache_audit.json"
    path.with_suffix(".lock").write_text("")
    fd = os.open(path.with_suffix(".lock"), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)                 # another probe, mid-probe
        assert fold_warm._lock_held_elsewhere(path) is False
        assert fold_warm.report_is_live(dict(_mismatch_report(4242), instance="another"), path) is False
    finally:
        os.close(fd)


def test_without_the_lock_a_report_of_another_instance_is_dead(tmp_path):
    """Nobody holds the lock: the file was never created (the probe never creates it), or it exists unheld."""
    path = tmp_path / "fold_cache_audit.json"
    rep = dict(_mismatch_report(os.getppid()), instance="another")                    # its PID is even alive
    assert fold_warm.report_is_live(rep, path) is False
    assert not path.with_suffix(".lock").exists()
    path.with_suffix(".lock").write_text("")
    assert fold_warm.report_is_live(rep, path) is False


def test_a_lock_that_cannot_be_probed_keeps_the_report_live(tmp_path, monkeypatch):
    path = tmp_path / "fold_cache_audit.json"
    path.with_suffix(".lock").write_text("")
    rep = dict(_mismatch_report(4242), instance="another")

    def no_lock(fd, op):
        raise OSError(errno.ENOLCK, "No locks available")

    calls = []
    monkeypatch.setattr(fold_warm.fcntl, "flock", lambda fd, op: calls.append(op) or no_lock(fd, op))
    assert fold_warm.report_is_live(rep, path) is True
    calls.clear()
    assert fold_warm.hold_report_lock(path) is False and fold_warm._holds_lock(path) is False
    assert len(calls) == 1                                       # a hard error is not retried
    monkeypatch.undo()
    real_open = os.open

    def unopenable(p, flags, *a):
        if str(p).endswith(".lock"):
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_open(p, flags, *a)

    monkeypatch.setattr(fold_warm.os, "open", unopenable)
    assert fold_warm.report_is_live(rep, path) is True
    assert fold_warm.hold_report_lock(path) is False


def test_taking_the_report_lock_waits_out_a_momentary_probe(tmp_path, monkeypatch):
    """A probe holds a shared lock for microseconds: the cockpit retries, and takes the lock once it is free."""
    path = tmp_path / "fold_cache_audit.json"
    real, calls = fold_warm.fcntl.flock, []
    monkeypatch.setattr(fold_warm, "_LOCK_RETRY_S", 0.0)

    def busy_then_free(fd, op, busy=3):
        calls.append(op)
        if len(calls) <= busy:
            raise BlockingIOError(errno.EWOULDBLOCK, "busy")
        return real(fd, op)

    monkeypatch.setattr(fold_warm.fcntl, "flock", busy_then_free)
    try:
        assert fold_warm.hold_report_lock(path) is True and len(calls) == 4
    finally:
        fold_warm._release_report_lock(path)
    calls.clear()
    monkeypatch.setattr(fold_warm.fcntl, "flock", lambda fd, op: busy_then_free(fd, op, busy=10 ** 6))
    fds = len(os.listdir("/proc/self/fd"))
    assert fold_warm.hold_report_lock(path) is False and len(calls) == fold_warm._LOCK_TRIES
    assert fold_warm._holds_lock(path) is False and len(os.listdir("/proc/self/fd")) == fds    # no fd kept


def test_the_cockpit_holds_the_report_lock_while_it_runs(tmp_path, monkeypatch):
    """With the cache on, the cockpit start takes the lock (another process sees it held); with the cache off and no
    report, the start creates no lock file at all."""
    path = tmp_path / "fold_cache_audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", path)
    monkeypatch.delenv(FLAG, raising=False)
    assert fold_warm.start_background(lambda: SpineStore(tmp_path / "spine.jsonl")) is None
    assert not path.with_suffix(".lock").exists()
    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setenv("VIGIL_FOLD_CACHE_AUDIT_S", "0")
    monkeypatch.setattr(fold_warm, "_STARTED", set())
    stop = fold_warm.start_background(lambda: SpineStore(tmp_path / "spine.jsonl"), name="test")
    try:
        assert stop is not None
        probe = subprocess.run([sys.executable, "-c", "import sys; from pathlib import Path; "
                                "from sigil.governor import fold_warm; "
                                "print(fold_warm._lock_held_elsewhere(Path(sys.argv[1])))", str(path)],
                               capture_output=True, text=True, timeout=60)
        assert probe.stdout.strip() == "True", probe.stderr
    finally:
        stop.set()
        stop.thread.join(timeout=60)
        fold_warm._release_report_lock(path)


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded, use of fork:DeprecationWarning")
def test_a_forked_child_is_another_instance_and_keeps_no_copy_of_the_lock(tmp_path):
    path = tmp_path / "fold_cache_audit.json"
    assert fold_warm.hold_report_lock(path)
    mine = fold_warm.instance_id()
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:                                                    # the child outlives the cockpit's lock a while
        os.close(r)
        os.write(w, json.dumps([fold_warm.instance_id() != mine, fold_warm._holds_lock(path)]).encode())
        os.close(w)
        time.sleep(1.5)
        os._exit(0)
    try:
        os.close(w)
        with os.fdopen(r) as f:
            assert json.loads(f.read()) == [True, False]
        fold_warm._release_report_lock(path)                       # the cockpit is gone; its forked child is not
        assert fold_warm._lock_held_elsewhere(path) is False
    finally:
        os.waitpid(pid, 0)
    assert fold_warm.instance_id() == mine


def test_a_run_of_restarts_hands_a_superseded_mismatch_on(tmp_path, monkeypatch, capsys):
    """Restart, then restart again before any audit: the second supersede must not replace the earlier MISMATCH with
    the first restart's empty verdict. A newer MISMATCH of its own replaces it."""
    from sigil.cli import _verify_fold_caches
    path = tmp_path / "fold_cache_audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", path)
    path.write_text(json.dumps(dict(_mismatch_report(_dead_pid()), instance="first")), encoding="utf-8")
    assert fold_warm.supersede_dead_report(path) is True
    first = _own(path)["superseded"]
    assert first["mismatched"] == ["governor.wallet"]
    gone = dict(_own(path), instance="a-cockpit-that-restarted")
    path.write_text(json.dumps(gone), encoding="utf-8")
    assert fold_warm.supersede_dead_report(path) is True and _own(path)["superseded"] == first
    assert _verify_fold_caches(False) is True
    out = capsys.readouterr().out
    assert (f"a previous cockpit (pid {first['pid']}, audit {first['ts']}) recorded a MISMATCH in governor.wallet; "
            f"its caches died with it, but investigate a possible spine edit.") in out
    assert "folds OK" in out
    newer = dict(_mismatch_report(4242), instance="newer", ts="2026-11-12T00:00:00+00:00",
                 superseded=first, folds=[{"fold": "governor.orgs", "status": "MISMATCH", "seq": 9}])
    path.write_text(json.dumps(newer), encoding="utf-8")
    assert fold_warm.supersede_dead_report(path) is True
    assert _own(path)["superseded"] == {"pid": 4242, "ts": "2026-11-12T00:00:00+00:00", "ok": False,
                                        "mismatched": ["governor.orgs"]}


@pytest.mark.parametrize("superseded", [None, "x", {"pid": 7, "ts": "t", "mismatched": []},
                                        {"pid": 7, "ts": "t", "mismatched": "governor.wallet"}, {"pid": 7}])
def test_sigil_verify_prints_no_previous_cockpit_line_without_a_superseded_mismatch(tmp_path, monkeypatch, capsys,
                                                                                   superseded):
    from sigil.cli import _verify_fold_caches
    path = tmp_path / "fold_cache_audit.json"
    monkeypatch.setattr(config, "FOLD_AUDIT_PATH", path)
    rep = {"ok": True, "ts": "2026-11-11T00:00:00+00:00", "pid": 7, "folds": [{"fold": "a", "status": "match"}]}
    if superseded is not None:
        rep["superseded"] = superseded
    path.write_text(json.dumps(rep), encoding="utf-8")
    assert _verify_fold_caches(False) is True
    out = capsys.readouterr().out
    assert "previous cockpit" not in out and "folds OK" in out


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
