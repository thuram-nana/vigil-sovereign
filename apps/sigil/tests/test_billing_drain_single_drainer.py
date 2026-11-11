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
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

_SCHEMA = "vigil.webhook.billing.v1"

# One drain pass in a fresh interpreter. argv: spool spine mode gate. mode "hold" parks the re-verify until
# <gate>/release exists (announcing itself with <gate>/in-verify); "fail" makes the re-verify raise (a processor
# blip); "ok" re-verifies at once. Prints the drain result as one JSON line.
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
    if mode == "hold":
        (gate / "in-verify").write_text("x")
        while not (gate / "release").exists():
            time.sleep(0.02)
    return {"id": int(txid), "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
            "meta": {"price_id": "p"}}

s = SpineStore(spine)
signer = BillingSigner(FlutterwaveBillingProvider("dummy-hash", verify), wallet=WalletRegistry(s),
                       subscriptions=SubscriptionRegistry(s), plan=PlanCreditLedger(s),
                       catalog={"p": Entitlement(kind=EVENT_TOPUP, credits=200)})
out = BillingSpoolWatcher(signer, spool_dir=spool, verif_hash="dummy-hash").drain()
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
    return {d: sorted(p.name for p in (spool / d).iterdir()) for d in ("incoming", "working", "processed",
                                                                        "rejected")}


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


def test_the_cli_pass_that_finds_the_lock_held_says_so_and_exits_clean(tmp_path, monkeypatch, capsys):
    """The vigil-billing-drain unit's ExecStart while another drainer holds the spool: exit 0 (no false alarm),
    an honest line instead of a "drained: 0" that reads as an empty spool, and the webhook left exactly where it
    was."""
    from sigil import cli, config
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "spine" / "spine.jsonl")
    monkeypatch.setattr(cli, "SpineStore", lambda: SpineStore(tmp_path / "own-spine.jsonl"))
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "dummy-hash")
    monkeypatch.delenv("VIGIL_BILLING_WEBHOOK_SPOOL", raising=False)
    monkeypatch.delenv("VIGIL_BILLING_SPOOL", raising=False)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: (lambda txid: None))
    ensure_owner_keypair()
    spool = tmp_path / "spool"
    (spool / "incoming").mkdir(parents=True)
    (spool / "incoming" / "1.json").write_text("{}", encoding="utf-8")
    (spool / "working").mkdir()
    fd = os.open(spool / "working", os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)                       # "another drainer" (a separate open file description)
        cli.cmd_billing_drain(SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1))
        out = capsys.readouterr().out
        assert "skipped: another billing drainer holds the lock" in out and "drained:" not in out
        assert (spool / "incoming" / "1.json").exists() and not list((spool / "rejected").iterdir())
    finally:
        os.close(fd)
    with pytest.raises(SystemExit):                          # lock free again: the pass runs (and quarantines the
        cli.cmd_billing_drain(SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1))   # junk file)
    assert "drained: 0 minted, 0 noop, 1 rejected" in capsys.readouterr().out
