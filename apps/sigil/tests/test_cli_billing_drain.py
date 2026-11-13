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
    monkeypatch.setenv("HOME", tempfile.mkdtemp())   # hermetic: the drain compares with ~/.sigil/cockpit.env
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


# ---- WHOSE home: the money mint never falls back to an implicit ~/.sigil --------------------------------------

_DUMMY_FLW = "dummy-flw-key"


def _real_drain(tmp_path, *, stray_owner: bool, proxy_spool: bool, sigil_home: "Path | None" = None):
    """`sigil billing-drain drain` in a REAL interpreter, as the unit runs it, after the GO-LIVE §2 move: the
    cockpit's home is <tmp>/mnt/.sigil (holding the paid webhook the proxy spooled), the drain's env has no
    SIGIL_HOME. ``stray_owner``: an owner-signing command was run once without SIGIL_HOME exported (or a pre-move
    install / a copy-migration left one), so ~/.sigil holds a REAL owner identity. ``proxy_spool``: the drain env
    carries the proxy's VIGIL_BILLING_WEBHOOK_SPOOL (the right spool — but a ~/.sigil spine)."""
    import subprocess
    import sys
    user_home, moved = tmp_path / "user", tmp_path / "mnt" / ".sigil"
    user_home.mkdir()
    _spool_charge(moved / "billing-spool", 9911)
    env = {k: v for k, v in os.environ.items() if k not in ("SIGIL_HOME", "SIGIL_SPINE_DIR", "VIGIL_BILLING_SPOOL",
                                                             "VIGIL_BILLING_WEBHOOK_SPOOL")}
    env.update(HOME=str(user_home), PYTHONPATH=os.pathsep.join(p for p in sys.path if p))
    if stray_owner:
        subprocess.run([sys.executable, "-c", "from sigil.governor.identity import ensure_owner_keypair; "
                        "ensure_owner_keypair()"], env=env, check=True, timeout=120)
        assert (user_home / ".sigil" / "spine" / "keys" / "owner.pub").is_file()
    env.update(VIGIL_BILLING_DRAIN_ENABLED="1", VIGIL_BILLING_WEBHOOK_SECRET=_SECRET, VIGIL_FLW_SECRET_KEY=_DUMMY_FLW,
               VIGIL_FLW_API_BASE="http://127.0.0.1:1")   # a re-verify would be refused before any socket opens
    if proxy_spool:
        env["VIGIL_BILLING_WEBHOOK_SPOOL"] = str(moved / "billing-spool")
    if sigil_home is not None:
        env["SIGIL_HOME"] = str(sigil_home)
    r = subprocess.run([sys.executable, "-c", "from sigil.cli import main; main(['billing-drain', 'drain'])"],
                       env=env, capture_output=True, text=True, timeout=120)
    return r, user_home, moved


@pytest.mark.parametrize("stray_owner", [False, True], ids=["no-owner-key-in-~/.sigil", "stray-owner-key-in-~/.sigil"])
@pytest.mark.parametrize("proxy_spool", [False, True], ids=["no-spool-named", "proxy-spool-named"])
def test_a_drain_without_sigil_home_refuses_whatever_identity_sits_in_the_default_home(tmp_path, stray_owner,
                                                                                         proxy_spool):
    """The operator moved SIGIL_HOME for the cockpit and the proxy but not into the drain's env file. The drain used
    to fall back to ~/.sigil: with no spool named it drained an empty ~/.sigil/billing-spool and exited 0 forever
    (the dead-man reading it HEALTHY) — refused only while ~/.sigil held no owner key, which any owner-signing
    command run without SIGIL_HOME exported creates; given the proxy's spool it CONSUMED the paid webhook onto a
    ~/.sigil spine the cockpit never reads. Now it refuses before touching any spool or spine."""
    r, user_home, moved = _real_drain(tmp_path, stray_owner=stray_owner, proxy_spool=proxy_spool)
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "SIGIL_HOME is not set" in r.stderr and "billing-drain.env" in r.stderr and "drained:" not in r.stdout
    assert _SECRET not in r.stdout + r.stderr and _DUMMY_FLW not in r.stdout + r.stderr
    assert not (user_home / ".sigil" / "billing-spool").exists()                 # the wrong spool was never made
    assert not (user_home / ".sigil" / "spine" / "spine.jsonl").exists()        # nothing minted onto ~/.sigil
    spool = moved / "billing-spool"
    assert (spool / "incoming" / "9911.json").exists()                           # the paid webhook still waits …
    assert sorted(p.name for p in spool.iterdir()) == ["incoming"]               # … untouched (no claim, no lock)


def test_a_sigil_home_that_holds_no_owner_identity_is_refused(tmp_path):
    """SIGIL_HOME is set, but to a directory that is not the cockpit's (a mistyped path, a fresh volume): nothing
    could be minted there, and its spool is not the proxy's. Refused rather than drained "healthy"."""
    typo = tmp_path / "mnt" / ".sigil-typo"
    r, user_home, moved = _real_drain(tmp_path, stray_owner=True, proxy_spool=True, sigil_home=typo)
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "holds no owner identity" in r.stderr and str(typo) in r.stderr and "drained:" not in r.stdout
    assert (moved / "billing-spool" / "incoming" / "9911.json").exists()
    assert sorted(p.name for p in (moved / "billing-spool").iterdir()) == ["incoming"]


def test_sigil_home_must_be_absolute_and_expanded(armed, capsys, monkeypatch):
    spool = Path(tempfile.mkdtemp()) / "spool"
    for bad in ("%h/.sigil", "relative/.sigil"):
        monkeypatch.setenv("SIGIL_HOME", bad)
        code, text = _run(["billing-drain", "drain", "--spool", str(spool)], capsys)
        assert code == 2 and "SIGIL_HOME must be an ABSOLUTE" in text and repr(bad) in text
    assert not spool.exists()


def test_a_drain_whose_sigil_home_is_not_the_cockpits_refuses(armed, capsys):
    """billing-drain.env still names the OLD volume after a copy-migration (a real owner key and spine there) while
    the cockpit's env file names the new one: draining the old spool would exit 0 over a directory the proxy no
    longer writes to. Refused, naming both."""
    cockpit_env = armed.user_home / ".sigil" / "cockpit.env"
    cockpit_env.parent.mkdir(parents=True)
    new_home = Path(tempfile.mkdtemp()) / "new-volume" / ".sigil"
    cockpit_env.write_text(f"SIGIL_UI_PORT=8765\nSIGIL_HOME={new_home}\n", encoding="utf-8")
    _spool_charge(armed.sigil_home / "billing-spool", 9911)
    code, text = _run(["billing-drain", "drain"], capsys)
    assert code == 2 and "is not the cockpit's" in text and str(cockpit_env) in text and str(new_home) in text
    assert str(armed.sigil_home) in text and _SECRET not in text
    assert sorted(p.name for p in (armed.sigil_home / "billing-spool").iterdir()) == ["incoming"]   # untouched
    # systemd ignores a line with no "=": the cockpit still runs on the new volume
    cockpit_env.write_text(f"SIGIL_HOME={new_home}\nSIGIL_HOME\n", encoding="utf-8")
    code, text = _run(["billing-drain", "drain"], capsys)
    assert code == 2 and "is not the cockpit's" in text


def test_the_cockpit_env_check_reads_systemd_syntax_and_accepts_the_same_directory(armed, capsys):
    """Comments, quotes, a later assignment overriding an earlier one (systemd's rule), and the same directory
    spelled through a symlink all agree; a cockpit env file naming no SIGIL_HOME (the cockpit on its default) is
    nothing to compare against."""
    cockpit_env = armed.user_home / ".sigil" / "cockpit.env"
    cockpit_env.parent.mkdir(parents=True)
    alias = Path(tempfile.mkdtemp()) / "alias"
    alias.symlink_to(armed.sigil_home)
    cockpit_env.write_text(f"# SIGIL_HOME=/somewhere/else\n; SIGIL_HOME=/nor/here\nSIGIL_HOME=/stale/first\n"
                           f"  SIGIL_HOME = \"{alias}\"  \n", encoding="utf-8")
    _spool_charge(armed.sigil_home / "billing-spool", 9911)
    cli.main(["billing-drain", "drain"])
    assert "1 minted" in capsys.readouterr().out and armed.available() == armed.credits
    for nothing_to_compare in ("SIGIL_UI_PORT=8765\n", "SIGIL_HOME=/stale/first\nSIGIL_HOME=\n"):
        cockpit_env.write_text(nothing_to_compare, encoding="utf-8")
        cli.main(["billing-drain", "drain"])
        assert "drained: 0 minted" in capsys.readouterr().out


def test_the_cockpit_env_check_never_blocks_or_crashes_on_a_file_that_is_not_regular(armed, monkeypatch):
    """A FIFO planted at the cockpit env file's name would block a plain read forever (the pass wedged until the
    unit's timeout); one replaced between the check and the open must not crash the drain. Neither is a value."""
    import threading
    cockpit_env = armed.user_home / ".sigil" / "cockpit.env"
    cockpit_env.parent.mkdir(parents=True)
    os.mkfifo(cockpit_env)
    got: list = []
    t = threading.Thread(target=lambda: got.append(cli._cockpit_env_sigil_home()), daemon=True)
    t.start()
    t.join(5)
    blocked = t.is_alive()
    if blocked:                                              # release the blocked reader before failing
        os.close(os.open(cockpit_env, os.O_WRONLY | os.O_NONBLOCK))
        t.join(10)
    assert not blocked and got == [None]
    cockpit_env.unlink()
    cockpit_env.mkdir()                                      # "replaced by something unreadable after the check"
    monkeypatch.setattr(Path, "is_file", lambda self: True)
    assert cli._cockpit_env_sigil_home() is None
