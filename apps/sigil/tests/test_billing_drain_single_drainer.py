"""ONE billing drainer per spool, across PROCESSES.

A drain pass begins by reclaiming ``working/`` (crash recovery). Before the lock a SECOND drainer — the timer
firing while a manual ``watch`` (or a slow earlier pass) was mid-verify — reclaimed the first one's in-flight
claim: the same charge was re-verified twice and, when the two outcomes differed (one processor blip), a payment
the first drainer credited was left standing in ``rejected/`` as a false "paid, not credited" alarm.

These run REAL processes against one real spool + spine: the holder is parked inside the processor re-verify (it
signals over the filesystem, no sleeps-as-synchronisation), and the contender is a separate interpreter.
"""
from __future__ import annotations

import base64
import fcntl
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

_SCHEMA = "vigil.webhook.billing.v1"

# One drain pass in a fresh interpreter. argv: spool spine mode gate. mode "hold" parks the re-verify until
# <gate>/release exists (announcing itself with <gate>/in-verify); "fail" makes the re-verify raise (a processor
# blip); "ok" re-verifies at once; "watch" runs the `watch` loop (re-verify parked like "hold") for ONE pass.
# Prints the drain result as one JSON line.
_DRAINER = r"""
import json, sys, time
from pathlib import Path
from sigil.governor.billing import EVENT_TOPUP, BillingSigner, Entitlement, FlutterwaveBillingProvider
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.billing_spool import BillingSpoolWatcher
from sigil.spine.store import SpineStore

spool, spine, mode, gate = sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4])
ensure_owner_keypair()

def verify(txid):
    if mode == "fail":
        raise RuntimeError("processor 503")
    if mode in ("hold", "watch"):
        (gate / "in-verify").write_text("x")
        while not (gate / "release").exists():
            time.sleep(0.02)
    return {"id": int(txid), "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
            "currency": "USD", "meta": {"price_id": "p"}}

s = SpineStore(spine)
signer = BillingSigner(FlutterwaveBillingProvider("dummy-hash", verify), wallet=WalletRegistry(s),
                       subscriptions=SubscriptionRegistry(s), plan=PlanCreditLedger(s),
                       catalog={"p": Entitlement(kind=EVENT_TOPUP, credits=200)})
watcher = BillingSpoolWatcher(signer, spool_dir=spool, verif_hash="dummy-hash")
if mode == "watch":
    class _OnePass:                       # the `watch` loop's stop: stop after its first pass
        def wait(self, interval):
            return True
    watcher.watch(interval=0.01, stop=_OnePass())
    out = {"watched": True}
else:
    out = watcher.drain()
print(json.dumps({"result": out, "available": WalletRegistry(SpineStore(spine)).available("acme")}), flush=True)
"""


@pytest.fixture()
def rig(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    gate = tmp_path / "gate"
    gate.mkdir()
    spool = home / "billing-spool"
    raw = json.dumps({"event": "charge.completed", "data": {"id": 4242}}).encode()
    (spool / "incoming").mkdir(parents=True)
    (spool / "incoming" / "4242.json").write_text(
        json.dumps({"schema": _SCHEMA, "body_b64": base64.b64encode(raw).decode("ascii")}), encoding="utf-8")
    env = dict(os.environ, SIGIL_HOME=str(home), PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    spine = str(home / "spine" / "spine.jsonl")
    procs: list[subprocess.Popen] = []

    def start(mode: str) -> subprocess.Popen:
        p = subprocess.Popen([sys.executable, "-c", _DRAINER, str(spool), spine, mode, str(gate)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        procs.append(p)
        return p

    yield SimpleNamespace(spool=spool, gate=gate, start=start)
    for p in procs:
        if p.poll() is None:
            p.kill()
        p.communicate()


def _finish(p: subprocess.Popen) -> dict:
    out, err = p.communicate(timeout=60)
    assert p.returncode == 0, err
    return json.loads(out.strip().splitlines()[-1])


def _wait_for(path: Path, proc: subprocess.Popen) -> None:
    deadline = time.monotonic() + 60
    while not path.exists():
        assert proc.poll() is None, proc.communicate()[1]
        assert time.monotonic() < deadline, f"timed out waiting for {path}"
        time.sleep(0.02)


def _tree(spool: Path) -> dict:
    return {d: sorted(p.name for p in (spool / d).iterdir() if p.name != ".drain.lock")
            for d in ("incoming", "working", "processed", "rejected")}


def test_a_second_drainer_process_touches_nothing_and_the_payment_is_credited_once(rig):
    holder = rig.start("hold")
    _wait_for(rig.gate / "in-verify", holder)               # the holder owns working/4242.json, mid re-verify
    before = _tree(rig.spool)
    assert before["working"] == ["4242.json"]

    # the contender's processor call would FAIL — before the lock it reclaimed the holder's claim and quarantined
    # a payment the holder then credited (a false "paid, not credited" alarm)
    second = _finish(rig.start("fail"))
    assert second["result"] == {"minted": 0, "noop": 0, "rejected": 0, "deduped": 0, "seqs": [], "busy": True}
    assert _tree(rig.spool) == before                        # nothing reclaimed, claimed, archived or quarantined

    (rig.gate / "release").write_text("x")
    first = _finish(holder)
    assert first["result"]["minted"] == 1 and "busy" not in first["result"]
    assert first["available"] == 200                         # credited exactly once
    after = _tree(rig.spool)
    assert after["rejected"] == [] and after["working"] == [] and after["incoming"] == []
    assert len(after["processed"]) == 1


def test_a_killed_holder_releases_the_lock_and_the_next_pass_recovers_its_claim(rig):
    holder = rig.start("hold")
    _wait_for(rig.gate / "in-verify", holder)
    holder.send_signal(signal.SIGKILL)                       # a crash mid-pass: no cleanup code runs
    holder.wait(timeout=30)
    assert _tree(rig.spool)["working"] == ["4242.json"]      # the claim is stranded …

    nxt = _finish(rig.start("ok"))                           # … and the kernel released the dead holder's lock
    assert "busy" not in nxt["result"] and nxt["result"]["minted"] == 1 and nxt["available"] == 200
    assert _tree(rig.spool)["working"] == []


def test_a_watch_pass_holds_the_same_lock(rig):
    """`sigil billing-drain watch` drains through the same locked pass: while ITS pass is mid-verify, a timer pass
    touches nothing."""
    watcher = rig.start("watch")
    _wait_for(rig.gate / "in-verify", watcher)
    before = _tree(rig.spool)
    assert before["working"] == ["4242.json"]
    second = _finish(rig.start("fail"))
    assert second["result"]["busy"] is True and _tree(rig.spool) == before
    (rig.gate / "release").write_text("x")
    assert _finish(watcher)["available"] == 200
    assert _tree(rig.spool)["working"] == [] and _tree(rig.spool)["rejected"] == []


def _hold_lock(spool: Path, timeout: float = 10.0) -> int:
    """Take the drain lock the way another drainer process would (a separate open file description). Never blocks:
    a lock the code under test failed to release FAILS the test (naming it) instead of hanging the suite."""
    (spool / "working").mkdir(parents=True, exist_ok=True)
    fd = os.open(spool / "working" / ".drain.lock", os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if time.monotonic() >= deadline:
                os.close(fd)
                pytest.fail(f"the drain lock on {spool} was never released")
            time.sleep(0.02)


def _watcher(tmp_path, spool: Path):
    from sigil.governor.billing import BillingSigner, FlutterwaveBillingProvider
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.metering import PlanCreditLedger
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.inbound.billing_spool import BillingSpoolWatcher
    from sigil.spine.store import SpineStore
    ensure_owner_keypair()
    s = SpineStore(tmp_path / "w-spine.jsonl")
    signer = BillingSigner(FlutterwaveBillingProvider("dummy-hash", lambda txid: None), wallet=WalletRegistry(s),
                           subscriptions=SubscriptionRegistry(s), plan=PlanCreditLedger(s), catalog={})
    return BillingSpoolWatcher(signer, spool_dir=spool, verif_hash="dummy-hash")


def test_the_lock_is_a_regular_file_not_the_working_directory(tmp_path):
    """A lock on the working/ DIRECTORY fd is refused by a network filesystem (flock is emulated with a byte-range
    lock there, which needs a writable regular file). The drain locks a regular file opened read-write; holding
    that file excludes a pass, and a lock on the directory itself does NOT stand in for it."""
    spool = tmp_path / "spool"
    w = _watcher(tmp_path, spool)
    (spool / "incoming" / "1.json").write_text("{}", encoding="utf-8")
    dfd = os.open(spool / "working", os.O_RDONLY)
    try:
        fcntl.flock(dfd, fcntl.LOCK_EX)                     # an old-style directory lock is not THE lock
        assert "busy" not in w.drain() and (spool / "working" / ".drain.lock").is_file()
    finally:
        os.close(dfd)
    (spool / "incoming" / "2.json").write_text("{}", encoding="utf-8")
    fd = _hold_lock(spool)
    try:
        assert w.drain()["busy"] is True and (spool / "incoming" / "2.json").exists()
    finally:
        os.close(fd)


def test_a_planted_non_regular_lock_refuses_the_pass_and_touches_nothing(tmp_path):
    spool = tmp_path / "spool"
    w = _watcher(tmp_path, spool)
    (spool / "incoming" / "1.json").write_text("{}", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("", encoding="utf-8")
    (spool / "working" / ".drain.lock").symlink_to(elsewhere)
    with pytest.raises(OSError):
        w.drain()
    (spool / "working" / ".drain.lock").unlink()
    os.mkfifo(spool / "working" / ".drain.lock")
    with pytest.raises(OSError, match="not a regular file"):
        w.drain()
    assert (spool / "incoming" / "1.json").exists() and not list((spool / "rejected").iterdir())


def test_watch_releases_the_lock_between_passes_and_drains_what_arrives_later(tmp_path):
    """`watch` takes the lock PER PASS: between two passes another drainer can take it (the timer coexists), and a
    webhook spooled after the first pass is drained by the second."""
    spool = tmp_path / "spool"
    w = _watcher(tmp_path, spool)
    (spool / "incoming" / "1.json").write_text("{}", encoding="utf-8")
    waits: list[int] = []

    class _Between:
        def wait(self, interval):
            waits.append(len(waits))
            if len(waits) == 1:
                os.close(_hold_lock(spool, timeout=2.0))            # the lock is FREE between passes
                (spool / "incoming" / "2.json").write_text("{}", encoding="utf-8")
                return False
            return True

    w.watch(interval=0.01, stop=_Between())
    assert len(waits) == 2
    assert sorted(p.name for p in (spool / "rejected").iterdir() if p.suffix == ".json") == ["1.json", "2.json"]
    assert not list((spool / "incoming").iterdir())


def test_a_starved_watch_says_so_instead_of_idling_silently(tmp_path, capsys, monkeypatch):
    """Another drainer holds the lock (a manual pass suspended mid-pass, a wedged one): every `watch` pass is busy
    and touches nothing. Once that has lasted `busy_warn_s` it WARNS — again every `busy_warn_s`, not once per pass —
    drains as soon as the lock is free, and a LATER short overlap starts a fresh count. (A fake monotonic clock that
    advances 0.05 s per pass, so the count of warnings is exact.)"""
    from sigil.inbound import billing_spool
    clock = [0.0]
    monkeypatch.setattr(billing_spool, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=time.sleep,
                                                               time=time.time))
    spool = tmp_path / "spool"
    w = _watcher(tmp_path, spool)
    (spool / "incoming" / "1.json").write_text("{}", encoding="utf-8")
    held = [_hold_lock(spool)]
    passes: list[int] = []

    class _Stop:
        def wait(self, interval):
            passes.append(len(passes) + 1)
            clock[0] += 0.05
            if len(passes) == 60:                                   # busy for t = 0 … 2.95 s
                os.close(held.pop())
            elif len(passes) == 61:                                 # one clean pass, then a short overlap
                held.append(_hold_lock(spool))
            return len(passes) >= 70

    w.watch(interval=0.01, stop=_Stop(), busy_warn_s=1.0)
    for fd in held:
        os.close(fd)
    err = capsys.readouterr().err
    warnings = [ln for ln in err.splitlines() if "has held the lock on" in ln]
    assert len(warnings) == 2, err                                   # at t = 1.0 and 2.0 — then reset
    assert str(spool) in warnings[0] and "for 1 s" in warnings[0] and "never both" in warnings[0]
    assert (spool / "rejected" / "1.json").exists()                  # the pass after the release drained it


def test_a_pass_waits_out_another_drainers_pass_then_drains(tmp_path):
    spool = tmp_path / "spool"
    w = _watcher(tmp_path, spool)
    (spool / "incoming" / "1.json").write_text("{}", encoding="utf-8")
    fd = _hold_lock(spool)
    threading.Timer(0.3, os.close, args=(fd,)).start()     # the other drainer's pass ends
    r = w.drain(wait_s=30)
    assert "busy" not in r and r["rejected"] == 1         # it ran (and quarantined the junk file)


@pytest.fixture()
def cli_rig(tmp_path, monkeypatch):
    from sigil import cli, config
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "user"))      # hermetic: the drain compares with ~/.sigil/cockpit.env
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine" / "spine.jsonl")
    monkeypatch.setattr(cli, "SpineStore", lambda: SpineStore(tmp_path / "own-spine.jsonl"))
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "dummy-hash")
    monkeypatch.delenv("VIGIL_BILLING_WEBHOOK_SPOOL", raising=False)
    monkeypatch.delenv("VIGIL_BILLING_SPOOL", raising=False)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: (lambda txid: None))
    monkeypatch.setattr(cli, "_BILLING_LOCK_WAIT_S", 0.3)
    ensure_owner_keypair()
    spool = tmp_path / "spool"
    (spool / "incoming").mkdir(parents=True)
    (spool / "incoming" / "1.json").write_text("{}", encoding="utf-8")
    return SimpleNamespace(cli=cli, spool=spool,
                           run=lambda: cli.cmd_billing_drain(SimpleNamespace(billing_cmd="drain", spool=str(spool),
                                                                             interval=0.1)))


def test_the_cli_pass_that_cannot_get_the_lock_fails_loudly_and_touches_nothing(cli_rig, capsys):
    """The vigil-billing-drain unit's ExecStart while another drainer holds the spool past the wait: a wedged
    holder must not hide behind a clean exit (the dead-man would read the unit HEALTHY while nothing drains)."""
    fd = _hold_lock(cli_rig.spool)
    try:
        with pytest.raises(SystemExit) as ei:
            cli_rig.run()
        cap = capsys.readouterr()
        assert ei.value.code == 1 and "has held the lock" in cap.err and "drained:" not in cap.out
        assert (cli_rig.spool / "incoming" / "1.json").exists() and not list((cli_rig.spool / "rejected").iterdir())
    finally:
        os.close(fd)
    with pytest.raises(SystemExit):                          # lock free again: the pass runs (and quarantines the
        cli_rig.run()                                        # junk file)
    assert "drained: 0 minted, 0 noop, 1 rejected" in capsys.readouterr().out


def test_the_cli_pass_waits_for_a_short_overlap_and_then_drains(cli_rig, capsys, monkeypatch):
    monkeypatch.setattr(cli_rig.cli, "_BILLING_LOCK_WAIT_S", 30.0)
    fd = _hold_lock(cli_rig.spool)
    threading.Timer(0.3, os.close, args=(fd,)).start()
    with pytest.raises(SystemExit):                          # it drained (the junk file is quarantined -> exit 1)
        cli_rig.run()
    cap = capsys.readouterr()
    assert "drained: 0 minted, 0 noop, 1 rejected" in cap.out and "has held the lock" not in cap.err


def test_the_cli_watch_warns_on_the_same_bound_as_the_cli_lock_wait(cli_rig, monkeypatch):
    from sigil.inbound.billing_spool import BillingSpoolWatcher
    seen: dict = {}
    monkeypatch.setattr(BillingSpoolWatcher, "watch", lambda self, **kw: seen.update(kw))
    cli_rig.cli.cmd_billing_drain(SimpleNamespace(billing_cmd="watch", spool=str(cli_rig.spool), interval=0.5))
    assert seen == {"interval": 0.5, "busy_warn_s": 0.3}           # cli_rig pins _BILLING_LOCK_WAIT_S = 0.3
