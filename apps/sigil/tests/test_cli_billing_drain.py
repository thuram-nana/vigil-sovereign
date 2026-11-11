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


# ---- which spool is drained: ONE resolver, so the drain cannot run "healthy" on a directory nobody writes to ----

@pytest.fixture()
def armed(home, monkeypatch):
    """A fully configured drain (enabled, secret, a verifier that re-verifies a top-up), a PRIVATE spine, a HOME
    whose ~/.sigil is NOT this test's SIGIL_HOME (the GO-LIVE "moved SIGIL_HOME" deployment), and no spool var."""
    pid, credits = _topup()
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _SECRET)
    monkeypatch.delenv("VIGIL_BILLING_WEBHOOK_SPOOL", raising=False)
    monkeypatch.delenv("VIGIL_BILLING_SPOOL", raising=False)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: _verifier(pid))
    own = Path(home) / "resolver-spine.jsonl"
    monkeypatch.setattr(cli, "SpineStore", lambda: SpineStore(own))
    user_home = Path(tempfile.mkdtemp())
    monkeypatch.setenv("HOME", str(user_home))
    return SimpleNamespace(sigil_home=Path(home), user_home=user_home, credits=credits,
                           available=lambda: WalletRegistry(SpineStore(own)).available("acme"))


def test_with_no_spool_named_the_drain_follows_a_moved_sigil_home(armed, capsys):
    """The shipped unit names no spool. The proxy spooled a paid webhook under the MOVED home; the drain must find
    it there — not report a clean pass over an empty ~/.sigil/billing-spool."""
    _spool_charge(armed.sigil_home / "billing-spool", 9911)
    cli.main(["billing-drain", "drain"])
    assert "1 minted" in capsys.readouterr().out and armed.available() == armed.credits
    assert not (armed.user_home / ".sigil").exists()                # the fixed default was never even created


def test_with_no_spool_named_the_drain_uses_the_proxys_own_spool_variable(armed, capsys, monkeypatch):
    elsewhere = Path(tempfile.mkdtemp()) / "intake"
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SPOOL", str(elsewhere))
    _spool_charge(elsewhere, 9911)
    cli.main(["billing-drain"])
    assert "1 minted" in capsys.readouterr().out and armed.available() == armed.credits
    assert not (armed.sigil_home / "billing-spool").exists()


def test_the_env_override_still_names_the_spool(armed, capsys, monkeypatch):
    """An existing ~/.config/vigil/billing-drain.env that sets VIGIL_BILLING_SPOOL keeps working with the new
    unit (which no longer passes --spool)."""
    custom = Path(tempfile.mkdtemp()) / "custom-spool"
    monkeypatch.setenv("VIGIL_BILLING_SPOOL", str(custom))
    _spool_charge(custom, 9911)
    _spool_charge(armed.sigil_home / "billing-spool", 7777)
    cli.main(["billing-drain", "drain"])
    assert "1 minted" in capsys.readouterr().out
    assert (armed.sigil_home / "billing-spool" / "incoming" / "7777.json").exists()   # not the derived one


def test_a_spool_that_contradicts_the_proxys_spool_is_refused_not_drained(armed, capsys, monkeypatch):
    intake, other = Path(tempfile.mkdtemp()) / "intake", Path(tempfile.mkdtemp()) / "other"
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SPOOL", str(intake))
    _spool_charge(other, 9911)
    code, text = _run(["billing-drain", "--spool", str(other)], capsys)
    assert code == 2 and "NOT the spool the proxy writes paid webhooks to" in text and _SECRET not in text
    assert (other / "incoming" / "9911.json").exists() and not (other / "working").exists()   # nothing touched
    # the same directory spelled differently is NOT a contradiction
    (intake / "incoming").mkdir(parents=True)
    alias = intake.parent / "alias"
    alias.symlink_to(intake)
    cli.main(["billing-drain", "--spool", str(alias)])
    assert "drained: 0 minted" in capsys.readouterr().out


def test_the_fixed_home_default_is_refused_when_sigil_home_is_elsewhere(armed, capsys, monkeypatch):
    """An installed OLDER unit still passes its fixed default (--spool ~/.sigil/billing-spool). With SIGIL_HOME
    moved that directory is one the proxy never writes to: the pass must FAIL (the dead-man alarms), not exit 0."""
    legacy = armed.user_home / ".sigil" / "billing-spool"
    code, text = _run(["billing-drain", "drain", "--spool", str(legacy)], capsys)
    assert code == 2 and "fixed ~/.sigil default, but SIGIL_HOME is" in text
    assert str(armed.sigil_home / "billing-spool") in text and not legacy.exists()
    # … unless the operator confirms the proxy really spools there
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SPOOL", str(legacy))
    cli.main(["billing-drain", "drain", "--spool", str(legacy)])
    assert "drained: 0 minted" in capsys.readouterr().out


def test_the_fixed_home_default_is_fine_when_sigil_home_was_never_moved(armed, capsys, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(armed.user_home / ".sigil"))
    legacy = armed.user_home / ".sigil" / "billing-spool"
    _spool_charge(legacy, 9911)
    cli.main(["billing-drain", "drain", "--spool", str(legacy)])
    assert "1 minted" in capsys.readouterr().out


def test_a_derived_spool_is_still_refused_when_it_is_not_an_absolute_expanded_path(armed, capsys, monkeypatch):
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SPOOL", "%h/.sigil/billing-spool")
    code, text = _run(["billing-drain"], capsys)
    assert code == 2 and "--spool must be an ABSOLUTE" in text


def test_a_drain_that_cannot_see_the_moved_sigil_home_refuses_instead_of_draining_an_empty_spool(tmp_path):
    """The operator moved SIGIL_HOME for the cockpit and the proxy (GO-LIVE §2) but not into the drain's env file.
    With no spool named the drain then derives ~/.sigil/billing-spool — a directory the proxy never writes to — and
    used to exit 0 on it forever while the paid webhook waited under the moved home. A REAL interpreter (the
    owner-key paths are bound at import, from the environment the unit gives the process)."""
    import subprocess
    import sys
    user_home, moved = tmp_path / "user", tmp_path / "mnt" / ".sigil"
    user_home.mkdir()
    _spool_charge(moved / "billing-spool", 9911)
    env = {k: v for k, v in os.environ.items() if k not in ("SIGIL_HOME", "VIGIL_BILLING_SPOOL",
                                                             "VIGIL_BILLING_WEBHOOK_SPOOL")}
    env.update(HOME=str(user_home), VIGIL_BILLING_DRAIN_ENABLED="1", VIGIL_BILLING_WEBHOOK_SECRET=_SECRET,
               VIGIL_FLW_SECRET_KEY="dummy-flw-key", PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    r = subprocess.run([sys.executable, "-c", "from sigil.cli import main; main(['billing-drain', 'drain'])"],
                       env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "holds no owner identity" in r.stderr and "billing-drain.env" in r.stderr and "drained:" not in r.stdout
    assert _SECRET not in r.stdout + r.stderr and "dummy-flw-key" not in r.stdout + r.stderr
    assert not (user_home / ".sigil" / "billing-spool").exists()                 # the wrong spool was never made
    assert (moved / "billing-spool" / "incoming" / "9911.json").exists()
