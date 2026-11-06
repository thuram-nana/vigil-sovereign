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
