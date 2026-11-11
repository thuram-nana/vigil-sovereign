"""`sigil billing-drain` — the CLI verb that drains the inbound Flutterwave billing-webhook spool.

Pins: default-OFF behind VIGIL_BILLING_DRAIN_ENABLED; the verif-hash secret comes ONLY from the env (no argv
flag exists) and is NEVER printed; fail-closed without a secret or without a server-side transaction verifier;
when configured, a re-verified charge mints the OWNER-CATALOG entitlement exactly once (wire amount ignored).
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigil import cli
from sigil.governor import catalog
from sigil.governor.billing import EVENT_TOPUP
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore

_SECRET = "flw-cli-secret-DO-NOT-PRINT-7f3a"
_SCHEMA = "vigil.webhook.billing.v1"


@pytest.fixture()
def home(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setenv("SIGIL_HOME", d)
    # `cli.main()` runs a store-operability gate (assert_operable) BEFORE the command, against the store at
    # config.SPINE_PATH. Point it at THIS test's fresh home so the gate is not tripped by the shared,
    # order-polluted process home — another test earlier in the suite may have left a legacy single-file
    # spine at the import-time default, which would refuse `billing-drain` with exit 3 before it can reach
    # its own fail-closed refusals (exit 2). Mirrors the repo's config-retarget isolation convention.
    from sigil import config
    monkeypatch.setattr(config, "SPINE_PATH", Path(d) / "spine" / "spine.jsonl")
    monkeypatch.delenv("VIGIL_BILLING_DRAIN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_BILLING_WEBHOOK_SECRET", raising=False)
    ensure_owner_keypair()
    return d


def _topup():
    for pid, ent in catalog.entitlements().items():
        if ent.kind == EVENT_TOPUP:
            return pid, ent.credits
    pytest.skip("owner catalog has no top-up entry")


def _spool_charge(root: Path, txid: int, wire_amount=1):
    raw = json.dumps({"event": "charge.completed", "data": {"id": txid, "amount": wire_amount}}).encode()
    env = json.dumps({"schema": _SCHEMA, "body_b64": base64.b64encode(raw).decode("ascii")})
    (root / "incoming").mkdir(parents=True, exist_ok=True)
    (root / "incoming" / f"{txid}.json").write_text(env, encoding="utf-8")


def _verifier(price_id):
    amt, ccy = catalog.expected_amounts()[price_id]

    def v(txid):
        return {"id": int(txid), "status": "successful", "tx_ref": "vigil:acme:n1", "created_at": 100.0,
                "amount": amt / 100, "currency": ccy, "meta": {"price_id": price_id}}
    return v


def _run(argv, capsys):
    with pytest.raises(SystemExit) as ei:
        cli.main(argv)
    out = capsys.readouterr()
    return ei.value.code, out.out + out.err


def test_default_off(home, capsys, monkeypatch):
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _SECRET)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: _verifier(_topup()[0]))
    code, text = _run(["billing-drain", "drain", "--spool", tempfile.mkdtemp()], capsys)
    assert code == 2 and "disabled" in text and _SECRET not in text


def test_refuses_without_secret(home, capsys, monkeypatch):
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: _verifier(_topup()[0]))
    code, text = _run(["billing-drain", "--spool", tempfile.mkdtemp()], capsys)
    assert code == 2 and "VIGIL_BILLING_WEBHOOK_SECRET" in text


def test_refuses_without_verifier(home, capsys, monkeypatch):
    """No production verifier is provisioned -> the shipped seam refuses (fail-closed)."""
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _SECRET)
    spool = Path(tempfile.mkdtemp())
    _spool_charge(spool, 4242)
    code, text = _run(["billing-drain", "--spool", str(spool)], capsys)
    assert code == 2 and "verifier" in text and _SECRET not in text
    assert (spool / "incoming" / "4242.json").exists()          # nothing claimed / drained


def test_secret_is_not_an_argv_flag(home, capsys):
    with pytest.raises(SystemExit) as ei:
        cli.main(["billing-drain", "--spool", "x", "--secret", _SECRET])
    assert ei.value.code == 2                                   # argparse rejects: no such flag


def test_drains_catalog_mint_exactly_once_and_never_prints_secret(home, capsys, monkeypatch):
    pid, credits = _topup()
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _SECRET)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: _verifier(pid))
    spool = Path(tempfile.mkdtemp())
    _spool_charge(spool, 9911, wire_amount=1)
    ns = SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1)
    cli.cmd_billing_drain(ns)
    _spool_charge(spool, 9911, wire_amount=2)                   # a re-delivery (different bytes, same tx)
    cli.cmd_billing_drain(ns)
    out = capsys.readouterr()
    text = out.out + out.err
    assert "1 minted" in text and _SECRET not in text
    assert WalletRegistry(SpineStore()).available("acme") == credits  # catalog decides, credited once
    for p in spool.rglob("*"):
        if p.is_file():
            assert _SECRET.encode() not in p.read_bytes()
    for p in Path(os.environ["SIGIL_HOME"]).rglob("*"):         # never persisted on the spine either
        if p.is_file():
            assert _SECRET.encode() not in p.read_bytes()


def test_net2b_a_transient_processor_failure_is_deferred_not_alarmed_then_credited(home, capsys, monkeypatch):
    """NET-2b through the real CLI (the vigil-billing-drain unit's ExecStart): with VIGIL_NET_RECOVERY_ENABLED a
    processor 503 parks the webhook — the pass exits 0 (no false alarm), says so honestly, mints nothing — and the
    next due pass credits it exactly once. OFF, the same 503 quarantines and exits 1 (covered above + unchanged)."""
    from sigil.governor import flutterwave_egress as fe
    pid, credits = _topup()
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _SECRET)
    monkeypatch.setenv("VIGIL_NET_RECOVERY_ENABLED", "1")
    good = _verifier(pid)
    calls = {"n": 0}

    def flaky(txid):
        calls["n"] += 1
        if calls["n"] == 1:
            exc = fe.FlutterwaveEgressError("Flutterwave GET returned HTTP 503")
            exc.transient = True
            raise exc
        return good(txid)

    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: flaky)
    spool = Path(tempfile.mkdtemp())
    _spool_charge(spool, 9911)
    own = Path(home) / "net2b-spine.jsonl"                      # a PRIVATE store: SpineStore()'s default path is
    monkeypatch.setattr(cli, "SpineStore", lambda: SpineStore(own))   # bound at import and shared across tests
    before = WalletRegistry(SpineStore(own)).available("acme")
    assert before == 0
    ns = SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1)
    cli.cmd_billing_drain(ns)                                   # returns (exit 0): parked, NOT quarantined
    text = capsys.readouterr().out
    assert "0 minted" in text and "awaiting retry: 1 billing webhook(s)" in text and "(1 new this pass)" in text
    assert "ALARM" not in text
    assert WalletRegistry(SpineStore(own)).available("acme") == 0       # nothing minted while parked
    ledger = next((spool / "retry").glob("*.state"))
    state = json.loads(ledger.read_text())
    state["next_at"] = 0.0                                       # make it due now (the real wait is 5 s)
    ledger.write_text(json.dumps(state))
    cli.cmd_billing_drain(ns)
    out = capsys.readouterr().out
    assert "1 minted" in out and "awaiting retry" not in out          # nothing left parked
    assert WalletRegistry(SpineStore(own)).available("acme") == credits  # credited exactly once


def test_net2b_a_same_named_twin_still_alarms_and_never_resets_the_parked_budget(home, capsys, monkeypatch):
    """Through the real CLI oneshot (the unit's ExecStart). The processor redelivers the identical webhook while
    the original is parked: the twin is quarantined, so the pass exits NON-ZERO (the unit alarms) — and the
    parked payment's retry ledger is left exactly as it was (the bound is per payment, not per delivery)."""
    from sigil.governor import flutterwave_egress as fe
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _SECRET)
    monkeypatch.setenv("VIGIL_NET_RECOVERY_ENABLED", "1")

    def down(_txid):
        exc = fe.FlutterwaveEgressError("Flutterwave GET returned HTTP 503")
        exc.transient = True
        raise exc

    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: down)
    spool = Path(tempfile.mkdtemp())
    own = Path(home) / "net2b-twin-spine.jsonl"
    monkeypatch.setattr(cli, "SpineStore", lambda: SpineStore(own))
    ns = SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1)
    _spool_charge(spool, 9911)
    cli.cmd_billing_drain(ns)                                   # returns (exit 0): parked, due in 5 s
    ledger = spool / "retry" / "9911.json.state"
    before = ledger.read_bytes()
    assert json.loads(before)["attempts"] == 1
    capsys.readouterr()

    _spool_charge(spool, 9911)                                  # the identical redelivery: same NAME, still down
    with pytest.raises(SystemExit) as ei:
        cli.cmd_billing_drain(ns)
    out = capsys.readouterr()
    assert ei.value.code == 1 and "ALARM: 1 billing webhook(s) quarantined" in out.err   # the oneshot alarms
    assert "1 rejected" in out.out and "awaiting retry: 1 billing webhook(s)" in out.out
    assert "already awaiting a NET-2b retry" in (spool / "rejected" / "9911.json.reason").read_text()
    assert ledger.read_bytes() == before and (spool / "retry" / "9911.json").exists()    # budget untouched
    assert WalletRegistry(SpineStore(own)).available("acme") == 0                        # nothing minted
    assert _SECRET not in out.out + out.err


def test_net2b_off_the_cli_output_is_unchanged(home, capsys, monkeypatch):
    pid, _credits = _topup()
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _SECRET)
    monkeypatch.delenv("VIGIL_NET_RECOVERY_ENABLED", raising=False)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: _verifier(pid))
    spool = Path(tempfile.mkdtemp())
    _spool_charge(spool, 9911)
    cli.cmd_billing_drain(SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1))
    assert capsys.readouterr().out == "  drained: 1 minted, 0 noop, 0 rejected, 0 deduped\n"
