"""Stripe parity ST-8: `sigil billing-drain --provider stripe`, the Stripe lane of the billing drain.

Pins: every fail-closed refusal (exit 2, env names only, never a secret); a proxy-format Stripe envelope drains
through the re-fetch to exactly one owner-catalog mint; the HMAC is re-verified at the envelope's receive time (a
20-minute-old delivery still mints, a future one is quarantined); a transient fetch failure parks under NET-2b; a
404 quarantines; each lane quarantines the other lane's envelopes; and the default lane is the Flutterwave one,
untouched by any VIGIL_STRIPE_* setting.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigil import cli
from sigil.governor import catalog
from sigil.governor.billing import EVENT_TOPUP
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.stripe_egress import StripeEgressError
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore

_WHSEC = "whsec_" + "cli-st8-DO-NOT-PRINT"
_FLW = "flw-" + "cli-st8-secret"


def _key(mode="test"):
    return "_".join(["sk", mode, "dummy" + "0" * 6 + "notreal"])


@pytest.fixture()
def home(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setenv("SIGIL_HOME", d)
    monkeypatch.setenv("HOME", tempfile.mkdtemp())   # hermetic: the drain compares with ~/.sigil/cockpit.env
    from sigil import config
    monkeypatch.setattr(config, "SPINE_PATH", Path(d) / "spine" / "spine.jsonl")
    for k in ("VIGIL_BILLING_DRAIN_ENABLED", "VIGIL_BILLING_WEBHOOK_SECRET", "VIGIL_BILLING_SPOOL",
              "VIGIL_BILLING_WEBHOOK_SPOOL", "VIGIL_NET_RECOVERY_ENABLED", "VIGIL_STRIPE_WEBHOOK_SPOOL",
              "VIGIL_STRIPE_BILLING_SPOOL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_STRIPE_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_ENABLE_STRIPE", "1")
    monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SECRET", _WHSEC)
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _key())
    monkeypatch.setenv("VIGIL_STRIPE_API_VERSION", "2000-01-01")
    ensure_owner_keypair()
    own = Path(d) / "stripe-lane-spine.jsonl"
    monkeypatch.setattr(cli, "SpineStore", lambda: SpineStore(own))
    return own


def _topup():
    for pid, ent in catalog.mintable_entitlements().items():
        if ent.kind == EVENT_TOPUP and pid in catalog.mintable_expected():
            return pid, ent.credits
    pytest.skip("owner catalog has no top-up entry")


def _session_fetcher(pid, calls=None, fail=None):
    amt, ccy = catalog.mintable_expected()[pid]

    def fetch(kind, oid):
        if calls is not None:
            calls.append((kind, oid))
        if fail is not None:
            raise fail
        return {"object": "checkout.session", "id": oid, "livemode": False, "mode": "payment",
                "status": "complete", "payment_status": "paid", "client_reference_id": "vigil:acme:n1",
                "metadata": {"org_id": "acme", "price_id": pid}, "amount_total": amt, "currency": ccy.lower(),
                "created": 1000}
    return fetch


def _spool_stripe(root: Path, *, oid="cs_test_a1", received_at=None, name="evt1.json", secret=_WHSEC):
    received_at = time.time() if received_at is None else received_at
    t = int(received_at)
    raw = json.dumps({"id": "evt_1", "type": "checkout.session.completed", "livemode": False,
                      "data": {"object": {"id": oid}}}).encode()
    mac = hmac.new(secret.encode(), f"{t}.".encode() + raw, hashlib.sha256).hexdigest()
    env = {"schema": "vigil.webhook.stripe.v1", "body_b64": base64.b64encode(raw).decode("ascii"),
           "stripe_signature": f"t={t},v1={mac}", "received_at": received_at}
    (root / "incoming").mkdir(parents=True, exist_ok=True)
    (root / "incoming" / name).write_text(json.dumps(env), encoding="utf-8")


def _ns(spool, provider="stripe"):
    return SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1, provider=provider)


def _run(argv, capsys):
    with pytest.raises(SystemExit) as ei:
        cli.main(argv)
    out = capsys.readouterr()
    return ei.value.code, out.out + out.err


# ---- refusals ----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("env,expect", [
    ({"VIGIL_STRIPE_BILLING_DRAIN_ENABLED": "true"}, "disabled"),
    ({"VIGIL_BILLING_ENABLE_STRIPE": ""}, "VIGIL_BILLING_ENABLE_STRIPE"),
    ({"VIGIL_STRIPE_WEBHOOK_SECRET": ""}, "VIGIL_STRIPE_WEBHOOK_SECRET"),
    ({"VIGIL_BILLING_WEBHOOK_SECRET": _WHSEC}, "must differ"),
    ({"VIGIL_STRIPE_SECRET_KEY": ""}, "no server-side Stripe object fetcher"),
    ({"VIGIL_STRIPE_SECRET_KEY": "dummy-unrecognisable"}, "live or test"),
    ({"VIGIL_STRIPE_API_VERSION": ""}, "VIGIL_STRIPE_API_VERSION"),
])
def test_each_refusal_exits_2_and_never_prints_a_secret(home, capsys, monkeypatch, env, expect):
    pid, _credits = _topup()
    if env.get("VIGIL_STRIPE_SECRET_KEY", None) != "":
        monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool)
    code, text = _run(["billing-drain", "drain", "--provider", "stripe", "--spool", str(spool)], capsys)
    assert code == 2 and expect in text, text
    assert _WHSEC not in text and _key() not in text
    assert (spool / "incoming" / "evt1.json").exists()                     # nothing claimed


@pytest.mark.parametrize("var", ["VIGIL_BILLING_SPOOL", "VIGIL_BILLING_WEBHOOK_SPOOL"])
def test_the_stripe_lane_refuses_the_flutterwave_spool(home, capsys, monkeypatch, var):
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    spool = Path(tempfile.mkdtemp())
    monkeypatch.setenv(var, str(spool) + "/")                              # the same dir, spelled differently
    code, text = _run(["billing-drain", "--provider", "stripe", "--spool", str(spool)], capsys)
    assert code == 2 and "Flutterwave billing spool" in text


# ---- draining ----------------------------------------------------------------------------------------------------
def test_a_signed_stripe_delivery_mints_once_through_the_re_fetch(home, capsys, monkeypatch):
    pid, credits = _topup()
    calls: list = []
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid, calls))
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool, received_at=time.time() - 20 * 60)               # drained 20 min after receipt
    cli.cmd_billing_drain(_ns(spool))
    _spool_stripe(spool, name="evt1-redelivery.json")                     # Stripe redelivers the same event
    cli.cmd_billing_drain(_ns(spool))
    text = capsys.readouterr().out
    assert "1 minted" in text and _WHSEC not in text
    assert WalletRegistry(SpineStore(home)).available("acme") == credits    # exactly once
    assert calls == [("checkout_session", "cs_test_a1")] * 2


def test_a_future_receive_time_is_quarantined(home, capsys, monkeypatch):
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool, received_at=time.time() + 3600)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_billing_drain(_ns(spool))
    assert ei.value.code == 1 and WalletRegistry(SpineStore(home)).available("acme") == 0
    assert "implausible received_at" in "".join(p.read_text() for p in (spool / "rejected").glob("*.reason"))


def test_a_transient_fetch_failure_parks_under_net_recovery(home, capsys, monkeypatch):
    pid, _credits = _topup()
    monkeypatch.setenv("VIGIL_NET_RECOVERY_ENABLED", "1")
    exc = StripeEgressError("Stripe GET returned HTTP 503")
    exc.transient = True
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid, fail=exc))
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool)
    cli.cmd_billing_drain(_ns(spool))                                      # exit 0: parked, not an alarm
    text = capsys.readouterr().out
    assert "awaiting retry: 1" in text and list((spool / "retry").glob("*.state"))
    assert WalletRegistry(SpineStore(home)).available("acme") == 0


def test_a_404_is_quarantined_not_processed(home, capsys, monkeypatch):
    pid, _credits = _topup()
    monkeypatch.setenv("VIGIL_NET_RECOVERY_ENABLED", "1")
    monkeypatch.setattr(cli, "_stripe_object_fetcher",
                        lambda: _session_fetcher(pid, fail=StripeEgressError("Stripe GET returned HTTP 404")))
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_billing_drain(_ns(spool))
    assert ei.value.code == 1
    assert list((spool / "rejected").glob("*.json")) and not list((spool / "processed").glob("*.json"))


# ---- lane separation -----------------------------------------------------------------------------------------------
def test_each_lane_quarantines_the_other_lanes_envelopes(home, capsys, monkeypatch):
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    sspool = Path(tempfile.mkdtemp())
    raw = json.dumps({"event": "charge.completed", "data": {"id": 9911}}).encode()
    (sspool / "incoming").mkdir(parents=True)
    (sspool / "incoming" / "flw.json").write_text(json.dumps(
        {"schema": "vigil.webhook.billing.v1", "body_b64": base64.b64encode(raw).decode()}))
    with pytest.raises(SystemExit):
        cli.cmd_billing_drain(_ns(sspool))
    assert "unexpected envelope schema" in "".join(p.read_text() for p in (sspool / "rejected").glob("*.reason"))

    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _FLW)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: (lambda txid: None))
    fspool = Path(tempfile.mkdtemp())
    _spool_stripe(fspool)
    with pytest.raises(SystemExit):
        cli.cmd_billing_drain(_ns(fspool, provider="flutterwave"))
    assert "unexpected envelope schema" in "".join(p.read_text() for p in (fspool / "rejected").glob("*.reason"))
    assert WalletRegistry(SpineStore(home)).available("acme") == 0


def test_the_default_lane_is_flutterwave_and_reads_no_stripe_setting(home, capsys, monkeypatch):
    from sigil.governor import billing
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", "garbage")
    monkeypatch.setenv("VIGIL_STRIPE_API_VERSION", "garbage")
    monkeypatch.setenv("VIGIL_STRIPE_BILLING_DRAIN_ENABLED", "0")
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _FLW)
    monkeypatch.setattr(cli, "_billing_transaction_verifier", lambda: (lambda txid: None))
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: pytest.fail("the Flutterwave lane read Stripe"))
    built = []
    real = billing.FlutterwaveBillingProvider
    monkeypatch.setattr(billing, "FlutterwaveBillingProvider", lambda *a, **k: built.append(1) or real(*a, **k))
    spool = Path(tempfile.mkdtemp())
    cli.main(["billing-drain", "drain", "--spool", str(spool)])
    assert built == [1] and "0 minted" in capsys.readouterr().out


def test_the_stripe_lane_signer_requires_a_verified_currency(home, monkeypatch):
    """Defense in depth behind the adapter: the Stripe lane's signer refuses a priced event with no currency."""
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    watcher = cli._stripe_billing_watcher(_ns(tempfile.mkdtemp()))
    assert watcher.signer._require_verified_amount is True
    assert watcher._reader.schema == "vigil.webhook.stripe.v1"


def test_a_missing_fetcher_is_refused_even_with_a_valid_key(home, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: None)
    code, text = _run(["billing-drain", "--provider", "stripe", "--spool", tempfile.mkdtemp()], capsys)
    assert code == 2 and "object fetcher" in text


# ---- review fold: the Stripe lane never buries a paid charge -----------------------------------------------------------
def test_a_secret_mismatch_between_proxy_and_drain_is_quarantined_and_alarms(home, capsys, monkeypatch):
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool, secret="whsec_" + "the-proxy-had-another")       # what the proxy accepted
    with pytest.raises(SystemExit) as ei:
        cli.cmd_billing_drain(_ns(spool))
    assert ei.value.code == 1 and "ALARM" in capsys.readouterr().err
    assert list((spool / "rejected").glob("*.json")) and not list((spool / "processed").glob("*.json"))
    assert "does not verify" in "".join(p.read_text() for p in (spool / "rejected").glob("*.reason"))


def test_a_paid_session_with_no_tenant_alarms_without_any_plan_flag(home, capsys, monkeypatch):
    pid, _credits = _topup()
    monkeypatch.delenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_BILLING_PLAN_ALARM", raising=False)
    base = _session_fetcher(pid)

    def no_tenant(kind, oid):
        obj = dict(base(kind, oid))
        obj["client_reference_id"] = None
        obj["metadata"] = {"price_id": pid}
        return obj
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: no_tenant)
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_billing_drain(_ns(spool))
    assert ei.value.code == 1
    assert "UN-MINTED" in "".join(p.read_text() for p in (spool / "rejected").glob("*.reason"))


def test_the_stripe_lane_refuses_the_default_flutterwave_spool(home, capsys, monkeypatch):
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    import os
    flw_default = os.path.join(os.environ["SIGIL_HOME"], "billing-spool")
    os.makedirs(flw_default, exist_ok=True)
    code, text = _run(["billing-drain", "--provider", "stripe", "--spool", flw_default], capsys)
    assert code == 2 and "Flutterwave billing spool" in text


# ---- audit E2 on the Stripe lane: the same operating guards as the Flutterwave drain ---------------------------------
def _stripe_argv(spool):
    return ["billing-drain", "drain", "--provider", "stripe", "--spool", str(spool)]


def test_the_stripe_lane_requires_sigil_home_absolute_and_expanded(home, capsys, monkeypatch):
    """The Stripe drain mints onto the spine under SIGIL_HOME too: it never falls back to an implicit ~/.sigil."""
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool)
    monkeypatch.delenv("SIGIL_HOME")
    code, text = _run(_stripe_argv(spool), capsys)
    assert code == 2 and "SIGIL_HOME is not set" in text and "billing-drain-stripe.env" in text, text
    for bad in ("%h/.sigil", "relative/.sigil"):
        monkeypatch.setenv("SIGIL_HOME", bad)
        code, text = _run(_stripe_argv(spool), capsys)
        assert code == 2 and "SIGIL_HOME must be an ABSOLUTE" in text and repr(bad) in text
    assert _WHSEC not in text and sorted(p.name for p in spool.iterdir()) == ["incoming"]   # nothing claimed


def test_the_stripe_lane_refuses_a_sigil_home_that_is_not_the_cockpits(home, capsys, monkeypatch):
    import os
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool)
    cockpit_env = Path(os.environ["HOME"]) / ".sigil" / "cockpit.env"
    cockpit_env.parent.mkdir(parents=True)
    cockpit_env.write_text("SIGIL_HOME=/srv/new-volume/.sigil\n", encoding="utf-8")
    code, text = _run(_stripe_argv(spool), capsys)
    assert code == 2 and "is not the cockpit's" in text and "billing-drain-stripe.env" in text, text
    assert sorted(p.name for p in spool.iterdir()) == ["incoming"]


def test_the_stripe_lane_refuses_a_home_with_no_owner_identity(tmp_path):
    """A real interpreter (the owner key paths are fixed at import): SIGIL_HOME names a directory with no owner
    identity — not the cockpit's — so the Stripe drain refuses rather than run "healthy" over it."""
    import os
    import subprocess
    import sys
    typo, user = tmp_path / "mnt" / ".sigil-typo", tmp_path / "user"
    user.mkdir()
    spool = tmp_path / "stripe-spool"
    _spool_stripe(spool)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VIGIL_", "SIGIL_"))}
    env.update(HOME=str(user), SIGIL_HOME=str(typo), PYTHONPATH=os.pathsep.join(p for p in sys.path if p),
               VIGIL_STRIPE_BILLING_DRAIN_ENABLED="1", VIGIL_BILLING_ENABLE_STRIPE="1",
               VIGIL_STRIPE_WEBHOOK_SECRET=_WHSEC, VIGIL_STRIPE_SECRET_KEY=_key(),
               VIGIL_STRIPE_API_VERSION="2000-01-01")
    r = subprocess.run([sys.executable, "-c", f"from sigil.cli import main; main({_stripe_argv(spool)!r})"],
                       env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "holds no owner identity" in r.stderr and str(typo) in r.stderr and "drained:" not in r.stdout
    assert _WHSEC not in r.stdout + r.stderr and sorted(p.name for p in spool.iterdir()) == ["incoming"]


def test_a_stripe_spool_that_contradicts_the_proxys_stripe_spool_is_refused(home, capsys, monkeypatch):
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    intake, other = Path(tempfile.mkdtemp()) / "intake", Path(tempfile.mkdtemp()) / "other"
    monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SPOOL", str(intake))
    _spool_stripe(other)
    code, text = _run(_stripe_argv(other), capsys)
    assert code == 2 and "NOT the spool the proxy writes paid webhooks to" in text and "VIGIL_STRIPE_WEBHOOK_SPOOL" in text
    assert sorted(p.name for p in other.iterdir()) == ["incoming"]                        # nothing touched
    (intake / "incoming").mkdir(parents=True)
    alias = intake.parent / "alias"
    alias.symlink_to(intake)                                       # the same directory spelled differently
    cli.main(_stripe_argv(alias))
    assert "drained: 0 minted" in capsys.readouterr().out


def test_the_stripe_units_fixed_home_default_is_refused_when_sigil_home_is_elsewhere(home, capsys, monkeypatch):
    """The Stripe unit passes its %h/.sigil/stripe-billing-spool default; once SIGIL_HOME is moved that is a
    directory the proxy does not write to — the pass must FAIL, not exit 0 — unless the proxy's variable confirms it."""
    import os
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    legacy = Path(os.environ["HOME"]) / ".sigil" / "stripe-billing-spool"
    code, text = _run(_stripe_argv(legacy), capsys)
    assert code == 2 and "fixed ~/.sigil default, but SIGIL_HOME is" in text, text
    assert os.path.join(os.environ["SIGIL_HOME"], "stripe-billing-spool") in text and not legacy.exists()
    monkeypatch.setenv("VIGIL_STRIPE_WEBHOOK_SPOOL", str(legacy))
    cli.main(_stripe_argv(legacy))
    assert "drained: 0 minted" in capsys.readouterr().out
    monkeypatch.delenv("VIGIL_STRIPE_WEBHOOK_SPOOL")
    monkeypatch.setenv("SIGIL_HOME", str(Path(os.environ["HOME"]) / ".sigil"))  # never moved: the default is fine
    cli.main(_stripe_argv(legacy))
    assert "drained: 0 minted" in capsys.readouterr().out


def test_a_stripe_pass_that_cannot_get_the_lock_fails_loudly_and_touches_nothing(home, capsys, monkeypatch):
    """The shared single-drainer lock and its CLI handling hold on the Stripe lane: a pass whose spool another
    drainer holds past the wait exits 1 (the dead-man alarms) and claims nothing."""
    import fcntl
    import os
    pid, _credits = _topup()
    monkeypatch.setattr(cli, "_stripe_object_fetcher", lambda: _session_fetcher(pid))
    monkeypatch.setattr(cli, "_BILLING_LOCK_WAIT_S", 0.3)
    spool = Path(tempfile.mkdtemp())
    _spool_stripe(spool)
    (spool / "working").mkdir()
    fd = os.open(spool / "working" / ".drain.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, text = _run(_stripe_argv(spool), capsys)
        assert code == 1 and "has held the lock" in text and "drained:" not in text, text
        assert (spool / "incoming" / "evt1.json").exists() and not list((spool / "rejected").iterdir())
    finally:
        os.close(fd)
    cli.main(_stripe_argv(spool))                         # lock free: the pass runs and mints
    assert "drained: 1 minted" in capsys.readouterr().out
