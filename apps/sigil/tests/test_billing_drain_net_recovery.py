"""NET-2b (#73) — the money-IN billing drain auto-retries a TRANSIENT processor failure, bounded + default-OFF.

The gap this closes: the proxy 202s a paid webhook as soon as it spools, so the processor never redelivers; a
transient failure of the MANDATORY server-side re-verify (timeout / reset / 5xx / rate limit) used to quarantine
the envelope on sight, so every payment that landed during a processor blip waited for an operator to move it back
by hand (the customer paid, no credit). With ``VIGIL_NET_RECOVERY_ENABLED`` ON the drain parks it and re-tries on
the shared NET-2 schedule; once the bound is spent it quarantines + alarms exactly as before.

What these pin (each mutation-verified):
  * the egress marks ONLY retry-curable failures ``transient`` (transport, 408/425/429/5xx) — never a guard refusal,
    a 4xx, a malformed txid, a missing secret, an oversize or non-JSON body — and the mark changes neither the
    exception TYPE nor its MESSAGE (a reader that ignores it sees the pre-NET-2b exception);
  * OFF: byte-identical — quarantined on sight with the SAME reason text, no ``retry/`` dir, the same result shape;
  * ON: parked (nothing minted, nothing quarantined, the unit does not alarm), re-admitted only when DUE on the
    5 s → 5 min doubling schedule, minted EXACTLY ONCE on recovery, the ledger cleared;
  * BOUNDED: a processor that stays down costs exactly 8 retries, then quarantine with an honest reason;
  * a non-transient failure (raw ``ConnectionError`` from a hand-rolled verifier, a 401) still quarantines on sight;
  * FAIL-SAFE: an untrusted ledger, an unreadable clock, a name collision or flipping the flag OFF never yields an
    unbounded retry, a clobbered webhook, or a stranded one; a crash mid-deferral keeps the budget;
  * a retry can never double-credit (a twin delivery while parked credits once);
  * the dangling-checkout sweep reports a parked tx_ref as ``retrying`` (not ``no_webhook``).
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
from pathlib import Path

import pytest

from sigil.governor import flutterwave_egress as fe
from sigil.governor.billing import EVENT_TOPUP, BillingSigner, Entitlement, FlutterwaveBillingProvider
from sigil.governor.metering import PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound import quarantined_count
from sigil.inbound.billing_spool import BillingSpoolWatcher
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_SECRET = "flw-verif-hash-net2b"
_DUMMY = "dummy-not-a-real-key-DO-NOT-PRINT"
_SCHEMA = "vigil.webhook.billing.v1"
_OK = {"status": "success", "data": {"id": 9911, "status": "successful", "tx_ref": "vigil:acme:n1",
                                     "created_at": 100.0, "meta": {"price_id": "price_topup_200"}}}
_SCHEDULE = [5.0, 10.0, 20.0, 40.0, 80.0, 160.0, 300.0, 300.0]     # the shared NET-2 defaults (8 retries)


@pytest.fixture(autouse=True)
def _egress_env(monkeypatch):
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)
    monkeypatch.delenv("VIGIL_NET_RECOVERY_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_FLW_API_BASE", raising=False)


def _on(monkeypatch):
    monkeypatch.setenv("VIGIL_NET_RECOVERY_ENABLED", "1")


class _Processor:
    """A scripted processor behind the REAL egress (``_request_json`` + its exception classification): each call
    pops the next step — an Exception to raise from the socket layer, or a dict to return as the JSON body."""

    def __init__(self, monkeypatch, steps):
        self.steps = list(steps)
        self.calls = 0
        monkeypatch.setattr(fe, "_do_open", self._open)

    def _open(self, req, timeout):
        self.calls += 1
        step = self.steps.pop(0) if self.steps else self.steps_default
        if isinstance(step, BaseException):
            raise step
        return _Resp(json.dumps(step).encode())

    steps_default = urllib.error.URLError("still down")


class _Resp:
    def __init__(self, body):
        self._b = body

    def read(self, _n):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http(code):
    return urllib.error.HTTPError("https://api.flutterwave.com/v3/x", code, "x", {}, None)


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _rig(tmp_path, clock=None, verifier=None):
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    w = WalletRegistry(s, owner_key=OWNER, trusted_pubkey=OP)
    signer = BillingSigner(FlutterwaveBillingProvider(_SECRET, verifier or fe.make_transaction_verifier()),
                           wallet=w, subscriptions=SubscriptionRegistry(s, owner_key=OWNER, trusted_pubkey=OP),
                           plan=PlanCreditLedger(s, owner_key=OWNER, trusted_pubkey=OP),
                           catalog={"price_topup_200": Entitlement(kind=EVENT_TOPUP, credits=200)})
    spool = tmp_path / "billing-spool"
    watcher = BillingSpoolWatcher(signer, spool_dir=spool, verif_hash=_SECRET, now_fn=clock or _Clock())
    return w, watcher, spool


def _envelope(txid=9911, *, pad=""):
    body = json.dumps({"event": "charge.completed", "data": {"id": txid, "tx_ref": "vigil:acme:n1"}}).encode()
    return (json.dumps({"schema": _SCHEMA, "body_b64": base64.b64encode(body).decode("ascii")}) + pad).encode()


def _spool(spool: Path, env: bytes, name=None) -> str:
    name = name or (hashlib.sha256(env).hexdigest()[:32] + ".json")
    (spool / "incoming").mkdir(parents=True, exist_ok=True)
    (spool / "incoming" / name).write_bytes(env)
    return name


def _ledger(spool: Path, name: str) -> dict:
    return json.loads((spool / "retry" / (name + ".state")).read_text())


# --- the egress classification ----------------------------------------------------------------------------------

@pytest.mark.parametrize("fault,transient", [
    (urllib.error.URLError("dns"), True), (TimeoutError("t"), True), (ConnectionResetError("r"), True),
    (_http(500), True), (_http(502), True), (_http(503), True), (_http(504), True), (_http(599), True),
    (_http(408), True), (_http(425), True), (_http(429), True),
    (_http(400), False), (_http(401), False), (_http(403), False), (_http(404), False), (_http(302), False),
    (_http(600), False),
])
def test_egress_marks_only_retry_curable_failures_transient(monkeypatch, fault, transient):
    _Processor(monkeypatch, [fault])
    with pytest.raises(fe.FlutterwaveEgressError) as ei:
        fe.make_transaction_verifier()("9911")
    assert ei.value.transient is transient
    assert type(ei.value).__name__ == "FlutterwaveEgressError"           # the TYPE a reason sidecar names is unchanged
    if isinstance(fault, urllib.error.HTTPError):
        assert str(ei.value) == f"Flutterwave GET returned HTTP {fault.code}"           # message unchanged
    else:
        assert str(ei.value) == f"Flutterwave GET transport failure ({type(fault).__name__})"


def test_egress_refusals_a_retry_cannot_cure_are_never_transient(monkeypatch):
    verify = fe.make_transaction_verifier()
    with pytest.raises(fe.FlutterwaveEgressError) as bad_id:
        verify("../etc")                                                  # malformed txid
    monkeypatch.setenv("VIGIL_FLW_API_BASE", "https://evil.example")
    with pytest.raises(fe.FlutterwaveEgressError) as guard:
        verify("9911")                                                    # off-allowlist host (guard)
    monkeypatch.delenv("VIGIL_FLW_API_BASE")
    monkeypatch.delenv("VIGIL_FLW_SECRET_KEY")
    with pytest.raises(fe.FlutterwaveEgressError) as nokey:
        verify("9911")                                                    # missing secret
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)
    monkeypatch.setattr(fe, "_do_open", lambda req, timeout: _Resp(b"<html>not json"))
    with pytest.raises(fe.FlutterwaveEgressError) as notjson:
        verify("9911")
    monkeypatch.setattr(fe, "_do_open", lambda req, timeout: _Resp(b"x" * (fe._MAX_RESPONSE_BYTES + 1)))
    with pytest.raises(fe.FlutterwaveEgressError) as big:
        verify("9911")
    assert [e.value.transient for e in (bad_id, guard, nokey, notjson, big)] == [False] * 5
    assert fe.FlutterwaveEgressError("x").transient is False             # the class default


def test_an_http_error_with_a_non_integer_code_is_not_transient_and_still_fails_closed(monkeypatch):
    err = _http(503)
    err.code = None
    _Processor(monkeypatch, [err])
    with pytest.raises(fe.FlutterwaveEgressError) as ei:
        fe.make_transaction_verifier()("9911")
    assert ei.value.transient is False


# --- OFF: byte-identical ----------------------------------------------------------------------------------------

def test_off_a_transient_failure_quarantines_on_sight_exactly_as_before(tmp_path, monkeypatch):
    proc = _Processor(monkeypatch, [_http(503)])
    w, watcher, spool = _rig(tmp_path)
    name = _spool(spool, _envelope())
    res = watcher.drain()
    assert res == {"minted": 0, "noop": 0, "rejected": 1, "deduped": 0, "seqs": []}   # the pre-NET-2b shape
    assert (spool / "rejected" / (name + ".reason")).read_text() == \
        "rejected (unexpected FlutterwaveEgressError): Flutterwave GET returned HTTP 503"
    assert not (spool / "retry").exists()                                  # the spool tree is unchanged
    assert sorted(p.name for p in spool.iterdir()) == ["incoming", "processed", "rejected", "working"]
    assert proc.calls == 1 and w.available("acme") == 0


@pytest.mark.parametrize("value", ["", "0", "false", "off", "no", "2", "enabled"])
def test_only_an_explicit_truthy_token_turns_it_on(tmp_path, monkeypatch, value):
    monkeypatch.setenv("VIGIL_NET_RECOVERY_ENABLED", value)
    _Processor(monkeypatch, [_http(503)])
    _w, watcher, spool = _rig(tmp_path)
    _spool(spool, _envelope())
    assert watcher.drain()["rejected"] == 1 and not (spool / "retry").exists()


# --- ON: park, re-admit when due, mint once ---------------------------------------------------------------------

def test_on_a_transient_failure_is_parked_then_minted_once_when_the_processor_recovers(tmp_path, monkeypatch):
    _on(monkeypatch)
    clock = _Clock(1000.0)
    proc = _Processor(monkeypatch, [_http(503), _OK])
    w, watcher, spool = _rig(tmp_path, clock)
    name = _spool(spool, _envelope())

    res = watcher.drain()
    assert res == {"minted": 0, "noop": 0, "rejected": 0, "deduped": 0, "seqs": [], "deferred": 1}
    assert (spool / "retry" / name).exists() and quarantined_count(spool / "rejected") == 0   # no alarm
    led = _ledger(spool, name)
    assert led["attempts"] == 1 and led["next_at"] == 1005.0
    assert led["last_error"] == "FlutterwaveEgressError: Flutterwave GET returned HTTP 503"
    assert _DUMMY not in json.dumps(led)                                    # never the secret
    assert w.available("acme") == 0                                         # NOTHING minted while parked

    clock.t = 1004.9                                                        # not yet due -> stays parked
    assert watcher.drain()["deferred"] == 0 and proc.calls == 1 and (spool / "retry" / name).exists()

    clock.t = 1005.0                                                        # due -> re-admitted, verified, minted
    res = watcher.drain()
    assert res["minted"] == 1 and res["deferred"] == 0 and proc.calls == 2
    assert w.available("acme") == 200
    assert list((spool / "retry").iterdir()) == []                         # envelope AND ledger gone
    assert list((spool / "rejected").iterdir()) == []

    clock.t = 99_999.0                                                      # nothing left to retry, ever
    assert watcher.drain()["minted"] == 0 and proc.calls == 2 and w.available("acme") == 200


def test_bounded_a_processor_that_stays_down_costs_exactly_eight_retries_then_alarms(tmp_path, monkeypatch):
    _on(monkeypatch)
    clock = _Clock(1000.0)
    proc = _Processor(monkeypatch, [])                                      # every call: URLError (down)
    w, watcher, spool = _rig(tmp_path, clock)
    name = _spool(spool, _envelope())
    delays = []
    watcher.drain()
    for _ in range(8):
        led = _ledger(spool, name)
        delays.append(led["next_at"] - clock.t)
        clock.t = led["next_at"]
        watcher.drain()
    assert delays == _SCHEDULE                                              # 5 s doubling, capped at 5 min
    assert proc.calls == 9                                                  # the first try + 8 bounded retries
    assert quarantined_count(spool / "rejected") == 1                       # the unit alarms, as without the flag
    reason = (spool / "rejected" / (name + ".reason")).read_text()
    assert reason == ("rejected (transient FlutterwaveEgressError persisted through 8 bounded NET-2b retries): "
                      "Flutterwave GET transport failure (URLError)")
    assert not (spool / "retry" / name).exists() and not (spool / "retry" / (name + ".state")).exists()
    clock.t += 10_000
    watcher.drain()
    assert proc.calls == 9 and w.available("acme") == 0                     # quarantined is final until an operator


def test_an_operator_requeue_after_exhaustion_gets_a_fresh_budget(tmp_path, monkeypatch):
    _on(monkeypatch)
    clock = _Clock(1000.0)
    _Processor(monkeypatch, [urllib.error.URLError("d")] * 9 + [_OK])
    w, watcher, spool = _rig(tmp_path, clock)
    name = _spool(spool, _envelope())
    for _ in range(9):
        watcher.drain()
        clock.t += 1000
    assert (spool / "rejected" / name).exists()
    (spool / "rejected" / name).rename(spool / "incoming" / name)          # the runbook's manual re-queue
    assert watcher.drain()["minted"] == 1 and w.available("acme") == 200


@pytest.mark.parametrize("fault", [_http(401), _http(404)])
def test_on_a_non_transient_egress_failure_still_quarantines_on_sight(tmp_path, monkeypatch, fault):
    _on(monkeypatch)
    _Processor(monkeypatch, [fault])
    _w, watcher, spool = _rig(tmp_path)
    name = _spool(spool, _envelope())
    assert watcher.drain()["rejected"] == 1
    assert (spool / "rejected" / (name + ".reason")).read_text() == \
        f"rejected (unexpected FlutterwaveEgressError): Flutterwave GET returned HTTP {fault.code}"
    assert not (spool / "retry").exists()


def test_on_an_unmarked_exception_is_never_retried(tmp_path, monkeypatch):
    """Only the egress's explicit mark defers: a hand-rolled verifier's raw ConnectionError (or a spine OSError,
    or the plan alarm) still quarantines on sight — the pre-NET-2b contract."""
    _on(monkeypatch)

    def raw(_txid):
        raise ConnectionError("unmarked")

    _w, watcher, spool = _rig(tmp_path, verifier=raw)
    _spool(spool, _envelope())
    assert watcher.drain()["rejected"] == 1 and not (spool / "retry").exists()


# --- fail-safe edges -------------------------------------------------------------------------------------------

def test_flipping_the_flag_off_strands_nothing(tmp_path, monkeypatch):
    _on(monkeypatch)
    clock = _Clock(1000.0)
    _Processor(monkeypatch, [_http(503), _OK])
    w, watcher, spool = _rig(tmp_path, clock)
    name = _spool(spool, _envelope())
    assert watcher.drain()["deferred"] == 1
    monkeypatch.delenv("VIGIL_NET_RECOVERY_ENABLED")                        # operator turns it off mid-wait
    res = watcher.drain()                                                   # NOT due yet — re-admitted anyway
    assert res["minted"] == 1 and "deferred" not in res and w.available("acme") == 200
    assert list((spool / "retry").iterdir()) == []


def test_off_with_a_parked_envelope_still_failing_quarantines_it(tmp_path, monkeypatch):
    _on(monkeypatch)
    _Processor(monkeypatch, [_http(503), _http(503)])
    _w, watcher, spool = _rig(tmp_path)
    name = _spool(spool, _envelope())
    watcher.drain()
    monkeypatch.delenv("VIGIL_NET_RECOVERY_ENABLED")
    assert watcher.drain()["rejected"] == 1 and (spool / "rejected" / name).exists()
    assert list((spool / "retry").iterdir()) == []                          # ledger cleared with the quarantine


@pytest.mark.parametrize("ledger", [b"{not json", b'{"attempts": -1, "next_at": 0}', b'{"attempts": true}',
                                    b'{"attempts": "3"}', b"[]"])
def test_an_untrusted_ledger_is_never_an_unbounded_retry(tmp_path, monkeypatch, ledger):
    _on(monkeypatch)
    clock = _Clock(1000.0)
    proc = _Processor(monkeypatch, [_http(503), _http(503)])
    _w, watcher, spool = _rig(tmp_path, clock)
    name = _spool(spool, _envelope())
    watcher.drain()
    (spool / "retry" / (name + ".state")).write_bytes(ledger)               # tamper / corruption
    assert watcher.drain()["rejected"] == 1 and proc.calls == 2             # re-admitted at once, then NOT retried
    assert "untrusted NET-2b retry ledger" in (spool / "rejected" / (name + ".reason")).read_text()


def test_a_symlinked_ledger_is_untrusted(tmp_path, monkeypatch):
    _on(monkeypatch)
    _Processor(monkeypatch, [_http(503), _http(503)])
    _w, watcher, spool = _rig(tmp_path)
    name = _spool(spool, _envelope())
    watcher.drain()
    sp = spool / "retry" / (name + ".state")
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"attempts": 0, "next_at": 0}))
    sp.unlink()
    sp.symlink_to(target)
    assert watcher.drain()["rejected"] == 1


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), True])
def test_an_unreadable_clock_quarantines_instead_of_retrying(tmp_path, monkeypatch, bad):
    _on(monkeypatch)
    _Processor(monkeypatch, [_http(503)])
    w, watcher, spool = _rig(tmp_path)
    watcher._now = lambda: bad
    name = _spool(spool, _envelope())
    res = watcher.drain()
    assert res["rejected"] == 1 and res["deferred"] == 0
    assert "clock unreadable" in (spool / "rejected" / (name + ".reason")).read_text()


def test_a_crash_between_ledger_and_park_keeps_the_budget(tmp_path, monkeypatch):
    """The ledger is written FIRST: a crash before the park leaves the envelope in working/, the next pass reclaims
    it, and its next transient failure is counted against the SAME budget (attempts 2, not 1)."""
    _on(monkeypatch)
    _Processor(monkeypatch, [_http(503), _http(503)])
    _w, watcher, spool = _rig(tmp_path)
    name = _spool(spool, _envelope())
    real_replace = __import__("os").replace

    def crash_on_park(src, dst):
        if Path(dst).parent.name == "retry" and not str(dst).endswith(".state"):
            raise KeyboardInterrupt("daemon killed mid-deferral")
        return real_replace(src, dst)

    monkeypatch.setattr("sigil.inbound.billing_spool.os.replace", crash_on_park)
    with pytest.raises(KeyboardInterrupt):
        watcher.drain()
    monkeypatch.setattr("sigil.inbound.billing_spool.os.replace", real_replace)
    assert (spool / "working" / name).exists() and _ledger(spool, name)["attempts"] == 1
    assert watcher.drain()["deferred"] == 1 and _ledger(spool, name)["attempts"] == 2


def test_a_same_named_different_webhook_is_never_clobbered(tmp_path, monkeypatch):
    _on(monkeypatch)
    _Processor(monkeypatch, [_http(503), _http(503)])
    _w, watcher, spool = _rig(tmp_path)
    first = _envelope(9911)
    _spool(spool, first, name="x.json")
    watcher.drain()                                                         # parked as retry/x.json
    _spool(spool, _envelope(9912), name="x.json")                          # a DIFFERENT webhook, same name
    watcher._readmit_retries = lambda **k: None                            # hold the parked one in place
    res = watcher.drain()
    assert res["rejected"] == 1 and (spool / "retry" / "x.json").read_bytes() == first
    assert "already awaiting a NET-2b retry" in (spool / "rejected" / "x.json.reason").read_text()


def test_a_readmit_never_overwrites_a_pending_incoming_webhook(tmp_path, monkeypatch):
    _on(monkeypatch)
    clock = _Clock(1000.0)
    _Processor(monkeypatch, [_http(503)])
    _w, watcher, spool = _rig(tmp_path, clock)
    _spool(spool, _envelope(9911), name="x.json")
    watcher.drain()
    other = _envelope(9912)
    (spool / "incoming" / "x.json").write_bytes(other)
    clock.t = 5000.0
    watcher._readmit_retries(recovery_on=True)
    assert (spool / "incoming" / "x.json").read_bytes() == other and (spool / "retry" / "x.json").exists()


def test_a_twin_delivery_while_parked_credits_exactly_once(tmp_path, monkeypatch):
    _on(monkeypatch)
    clock = _Clock(1000.0)
    _Processor(monkeypatch, [_http(503), _OK, _OK])
    w, watcher, spool = _rig(tmp_path, clock)
    _spool(spool, _envelope())                                              # parked
    watcher.drain()
    _spool(spool, _envelope(pad=" "))                                       # the processor's twin (new bytes)
    assert watcher.drain()["minted"] == 1                                   # not due: only the twin is tried
    assert w.available("acme") == 200
    clock.t = 2000.0
    res = watcher.drain()                                                   # the parked one re-verifies; its grant
    assert res["rejected"] == 0 and list((spool / "retry").iterdir()) == []   # re-appends the SAME entry_id,
    assert w.available("acme") == 200                                       # a no-op in the wallet fold (by design)
    grants = [r for r in w.store.iter_records() if r.payload.get("signal") == "governor.credit_grant"]
    assert {g.payload["entry_id"] for g in grants} == {"9911"}              # one transaction, credited once


def test_the_watch_loop_retries_without_an_operator(tmp_path, monkeypatch):
    import threading
    _on(monkeypatch)
    clock = _Clock(1000.0)
    _Processor(monkeypatch, [_http(503), _OK])
    w, watcher, spool = _rig(tmp_path, clock)
    _spool(spool, _envelope())
    stop = threading.Event()
    passes = {"n": 0}
    real = watcher.drain

    def counted():
        passes["n"] += 1
        clock.t += 3.0
        out = real()
        if w.available("acme") == 200:
            stop.set()
        return out

    watcher.drain = counted
    watcher.watch(interval=0.0, stop=stop)
    assert w.available("acme") == 200 and passes["n"] == 3                  # t=1003 park, 1006 due -> minted


# --- the dangling-checkout sweep ---------------------------------------------------------------------------------

def test_the_checkout_sweep_reports_a_parked_tx_ref_as_retrying(tmp_path, monkeypatch):
    from sigil import ops_sweeps
    _on(monkeypatch)
    _Processor(monkeypatch, [_http(503)])
    _w, watcher, spool = _rig(tmp_path)
    _spool(spool, _envelope())
    watcher.drain()
    out = ops_sweeps.sweep_dangling_tx_refs([{"tx_ref": "vigil:acme:n1", "created": 0.0}], spool_dir=spool,
                                            now=10_000.0, ttl_s=100.0)
    assert out == {"applied": False, "items": [{"tx_ref": "vigil:acme:n1", "created": 0.0, "status": "retrying"}]}

@pytest.mark.parametrize("skew", [-86_400.0, -301.0])
def test_a_backwards_clock_or_tampered_due_time_cannot_park_a_webhook_beyond_one_capped_delay(tmp_path, monkeypatch,
                                                                                               skew):
    """The wait recorded is at most the schedule's cap (300 s). A remaining wait LONGER than that is impossible by
    construction — a wall clock stepped backwards, or a tampered ``next_at`` — and re-admits at once instead of
    leaving a paid webhook parked (healthy, un-alarmed) indefinitely."""
    _on(monkeypatch)
    clock = _Clock(100_000.0)
    _Processor(monkeypatch, [_http(503), _OK])
    w, watcher, spool = _rig(tmp_path, clock)
    name = _spool(spool, _envelope())
    watcher.drain()
    assert watcher.parked_count() == 1
    clock.t = 100_000.0 + skew                                              # the clock steps BACK
    assert watcher.drain()["minted"] == 1 and w.available("acme") == 200
    assert watcher.parked_count() == 0


def test_a_far_future_next_at_is_not_trusted(tmp_path, monkeypatch):
    _on(monkeypatch)
    clock = _Clock(1000.0)
    _Processor(monkeypatch, [_http(503), _OK])
    w, watcher, spool = _rig(tmp_path, clock)
    name = _spool(spool, _envelope())
    watcher.drain()
    sp = spool / "retry" / (name + ".state")
    sp.write_text(json.dumps({**json.loads(sp.read_text()), "next_at": 1e18}))
    assert watcher.drain()["minted"] == 1 and w.available("acme") == 200


def test_parked_count_reflects_the_retry_queue(tmp_path, monkeypatch):
    _on(monkeypatch)
    _Processor(monkeypatch, [_http(503), _http(503)])
    _w, watcher, spool = _rig(tmp_path)
    assert watcher.parked_count() == 0                                      # no retry/ at all
    _spool(spool, _envelope(9911))
    _spool(spool, _envelope(9912))
    watcher.drain()
    assert watcher.parked_count() == 2


@pytest.mark.parametrize("bad", [True, float("nan"), "soon", None])
def test_a_broken_clock_at_readmit_time_never_holds_a_webhook_parked(tmp_path, monkeypatch, bad):
    _on(monkeypatch)
    _Processor(monkeypatch, [_http(503)])
    _w, watcher, spool = _rig(tmp_path, _Clock(1000.0))
    name = _spool(spool, _envelope())
    watcher.drain()
    sp = spool / "retry" / (name + ".state")
    sp.write_text(json.dumps({**json.loads(sp.read_text()), "next_at": 1001.0}))   # due in 1 s: a plausible wait
    watcher._now = lambda: bad
    watcher._readmit_retries(recovery_on=True)
    assert (spool / "incoming" / name).exists() and watcher.parked_count() == 0
