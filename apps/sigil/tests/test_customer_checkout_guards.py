"""Audit E1 — the customer-checkout guards hold over the REAL edge -> cockpit hop, not just on one instance.

(a) The checkout-creation rate limit was instance-local, and the cockpit builds a fresh Provisioner per request, so
    over HTTP it limited nothing (12 real-hop POSTs were all created). It is now the filesystem-backed
    LoginRateLimiter (its guard-and-count ``admit``), durable across requests AND processes, and fail-closed when
    its state cannot be read or written.
(b) The second-plan guard read only DRAINED subscriptions, so several plan checkouts could be created (and paid)
    before the first plan's webhook drained. An owner-signed, expiring, cross-process-exclusive PENDING
    plan-checkout record now refuses a second plan checkout for the org until the plan drains (then the drained
    subscription refuses it) or the record expires. Top-ups are unaffected.
"""
from __future__ import annotations

import concurrent.futures
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _opener, _post, _stack
from test_customer_checkout import _iso, _on, _provisioner, _real_provider  # noqa: F401  (_iso is autouse)

_TOPUP = "vigil_topup_1k"
_CHECKOUT = "/api/customer/billing/checkout"


def _signup(ep, email="guard@acme.com"):
    op = _opener()
    t = _post(op, ep, "/api/customer/signup/request", {"email": email})[1]["dev_token"]
    c, _r = _post(op, ep, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "G"})
    assert c == 200
    return op


def _hop_stack(tmp_path, monkeypatch, posted):
    from sigil.ui import provision
    _on(monkeypatch)
    monkeypatch.setattr(provision.Provisioner, "_checkout_provider", lambda self: _real_provider(posted))
    return _stack(tmp_path, monkeypatch)


# --- (a) the durable checkout rate limit -------------------------------------------------------------------------

def test_the_checkout_rate_limit_holds_over_the_real_hop(tmp_path, monkeypatch):
    """12 sequential real-hop POSTs (each one a FRESH cockpit Provisioner): exactly _CHECKOUT_MAX are created."""
    from sigil.ui.provision import Provisioner
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep)
        res = [_post(op, ep, _CHECKOUT, {"price_id": _TOPUP}) for _ in range(Provisioner._CHECKOUT_MAX + 2)]
        codes = [c for c, _r in res]
        assert codes[:Provisioner._CHECKOUT_MAX] == [200] * Provisioner._CHECKOUT_MAX, res
        assert codes[Provisioner._CHECKOUT_MAX:] == [403, 403], res
        assert "too many checkout attempts" in json.dumps(res[-1][1])
        assert len(posted) == Provisioner._CHECKOUT_MAX            # the refused attempts never reached the processor
    finally:
        sov.shutdown(); edge.shutdown()


def test_concurrent_real_hop_checkouts_cannot_overrun_the_limit(tmp_path, monkeypatch):
    from sigil.ui.provision import Provisioner
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep, "race@acme.com")
        n = Provisioner._CHECKOUT_MAX + 6
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            codes = list(ex.map(lambda _i: _post(op, ep, _CHECKOUT, {"price_id": _TOPUP})[0], range(n)))
        assert codes.count(200) == Provisioner._CHECKOUT_MAX and codes.count(403) == 6, codes
        assert len(posted) == Provisioner._CHECKOUT_MAX
    finally:
        sov.shutdown(); edge.shutdown()


@pytest.mark.parametrize("fault", ["unwritable", "corrupt"])
def test_limiter_state_that_cannot_be_read_or_written_refuses_over_the_hop(tmp_path, monkeypatch, fault):
    import hashlib

    from sigil import config
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep, f"{fault}@acme.com")
        d = Path(config.CHECKOUT_RATELIMIT_DIR)
        if fault == "unwritable":
            d.write_text("not a directory", encoding="utf-8")       # the marker dir cannot be created / written
        else:
            assert _post(op, ep, _CHECKOUT, {"price_id": _TOPUP})[0] == 200
            for m in d.iterdir():
                if len(m.name) == len(hashlib.sha256(b"").hexdigest()):
                    m.write_text("{not json", encoding="utf-8")        # a corrupt / hostile marker
        before = len(posted)
        c, r = _post(op, ep, _CHECKOUT, {"price_id": _TOPUP})
        assert c == 403 and "too many checkout attempts" in json.dumps(r), (c, r)
        assert len(posted) == before                                   # nothing reached the processor
    finally:
        sov.shutdown(); edge.shutdown()


def test_an_unwired_checkout_limiter_refuses(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    p.checkout_limiter = None
    p._checkout_provider = lambda: pytest.fail("never reached without a limiter")
    with pytest.raises(ProvisionDenied, match="too many checkout attempts"):
        p.billing_checkout(admin, org, _TOPUP)


def test_the_limit_is_per_requester_as_well_as_per_org(monkeypatch):
    """One billing admin of TWO orgs cannot double their budget by alternating orgs: the requester key trips too."""
    from sigil.ui.provision import Provisioner, ProvisionDenied
    _on(monkeypatch)
    p, admin, _t, org, other, _w = _provisioner()
    p.orgs.grant_membership(other, admin, "org_admin", issued_at=5.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    for _ in range(Provisioner._CHECKOUT_MAX):
        p.billing_checkout(admin, org, _TOPUP, now=5000.0)
    with pytest.raises(ProvisionDenied, match="too many checkout attempts"):
        p.billing_checkout(admin, other, _TOPUP, now=5001.0)          # a fresh org, the same exhausted requester
    assert len(posted) == Provisioner._CHECKOUT_MAX


def test_the_factory_wires_the_durable_checkout_limiter(tmp_path, monkeypatch):
    from sigil import config
    from sigil.spine.store import SpineStore
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner, build_provisioner
    monkeypatch.setattr(config, "CHECKOUT_RATELIMIT_DIR", tmp_path / "chk")
    p = build_provisioner(SpineStore(str(tmp_path / "s.jsonl")))
    lim = p.checkout_limiter
    assert isinstance(lim, LoginRateLimiter) and lim.dir == tmp_path / "chk"
    assert (lim.max_fails, lim.window_s) == (Provisioner._CHECKOUT_MAX, Provisioner._CHECKOUT_WINDOW_S)
    assert lim.base_lock_s >= Provisioner._CHECKOUT_WINDOW_S


# --- the limiter's guard-and-count primitive ------------------------------------------------------------------

def _limiter(d, **kw):
    from sigil.ui.login_ratelimit import LoginRateLimiter
    return LoginRateLimiter(d, **{"max_fails": 3, "window_s": 100.0, "base_lock_s": 100.0, **kw})


def test_admit_counts_every_attempt_and_refuses_past_the_ceiling(tmp_path):
    lim = _limiter(tmp_path / "l")
    assert [lim.admit("a", "b", now=10.0) for _ in range(3)] == [None, None, None]
    assert lim.admit("a", "b", now=11.0) == pytest.approx(99.0)        # locked until 10 + 100
    assert lim.admit("a", now=12.0) is not None and lim.admit("b", now=12.0) is not None
    assert lim.admit("c", now=12.0) is None                            # an unrelated key is unaffected
    assert lim.admit("a", "b", now=111.0) is None                      # the lockout lapses


def test_admit_fails_closed_when_the_attempt_cannot_be_recorded(tmp_path, monkeypatch):
    from sigil.ui import login_ratelimit
    lim = _limiter(tmp_path / "l")
    monkeypatch.setattr(login_ratelimit.LoginRateLimiter, "_write_atomic", lambda self, m, r: False)
    assert lim.admit("a", now=1.0) == lim.base_lock_s


def test_admit_fails_closed_without_a_key_or_a_lock(tmp_path, monkeypatch):
    from sigil.ui import login_ratelimit
    lim = _limiter(tmp_path / "l")
    assert lim.admit(now=1.0) == lim.base_lock_s and lim.admit("", now=1.0) == lim.base_lock_s

    class _NoLock:
        LOCK_EX = 2

        @staticmethod
        def flock(fd, op):
            raise OSError("no lock")
    monkeypatch.setattr(login_ratelimit, "fcntl", _NoLock)
    assert lim.admit("a", now=1.0) == lim.base_lock_s


@pytest.mark.parametrize("content", ["{not json", "[]"])
def test_admit_refuses_on_a_corrupt_marker_and_does_not_reset_it(tmp_path, content):
    lim = _limiter(tmp_path / "l")
    assert lim.admit("a", "b", now=1.0) is None
    lim._marker("b").write_text(content, encoding="utf-8")
    assert lim.admit("a", "b", now=2.0) == lim.base_lock_s
    assert lim._marker("b").read_text(encoding="utf-8") == content      # never trusted, never silently reset
    assert json.loads(lim._marker("a").read_text(encoding="utf-8"))["fails"] == [1.0]   # nothing recorded


def test_admit_refuses_when_the_directory_bound_is_full(tmp_path):
    lim = _limiter(tmp_path / "l", max_keys=1)
    assert lim.admit("a", now=1.0) is None
    assert lim.admit("b", now=2.0) == lim.base_lock_s                  # cannot record a new key → refuse


def test_the_sweep_never_reaps_the_admit_lock_file(tmp_path):
    lim = _limiter(tmp_path / "l")
    assert lim.admit("a", now=1.0) is None
    lim.record_failure("z", now=10_000.0)                               # a sweep long after "a" went cold
    assert (tmp_path / "l" / ".admit.lock").exists()


_WORKER = r"""
import importlib.util, sys
spec = importlib.util.spec_from_file_location("lrl", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
lim = m.LoginRateLimiter(sys.argv[2], max_fails=10, window_s=1e6, base_lock_s=1e6)
sys.stdout.write("".join("1" if lim.admit("org", "user", now=1000.0) is None else "0" for _ in range(6)))
"""


def test_admit_is_exact_across_concurrent_processes(tmp_path):
    """8 PROCESSES x 6 attempts on one marker dir: exactly max_fails (10) are admitted — the flock serializes the
    read-check-write across processes (no lost update lets two processes admit on the same count)."""
    from sigil.ui import login_ratelimit
    d = Path(tempfile.mkdtemp(dir=tmp_path))
    procs = [subprocess.Popen([sys.executable, "-I", "-c", _WORKER, login_ratelimit.__file__, str(d)],
                              stdout=subprocess.PIPE, text=True) for _ in range(8)]
    out = "".join(p.communicate(timeout=60)[0] for p in procs)
    assert all(p.returncode == 0 for p in procs)
    assert len(out) == 48 and out.count("1") == 10, out


# --- (b) the pending plan-checkout record ---------------------------------------------------------------------

_PLAN = "vigil_pro_monthly"


def _plans_on(monkeypatch):
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")


def _audits(p):
    seen: list = []
    real = p.store.append

    def cap(**kw):
        pl = kw.get("payload")
        if isinstance(pl, dict) and pl.get("signal") == "provision.audit":
            seen.append(pl)
        return real(**kw)
    p.store.append = cap
    return seen


def test_a_second_plan_checkout_is_refused_over_the_real_hop_while_the_first_is_undrained(tmp_path, monkeypatch):
    _plans_on(monkeypatch)
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep, "plan@acme.com")
        res = [_post(op, ep, _CHECKOUT, {"price_id": _PLAN}) for _ in range(3)]
        assert [c for c, _r in res] == [200, 403, 403], res
        assert "already in progress" in json.dumps(res[1][1])
        assert [x.get("payment_plan") for x in posted] == [_PLAN]        # ONE processor subscription, not three
        assert _post(op, ep, _CHECKOUT, {"price_id": _TOPUP})[0] == 200     # top-ups are unaffected
    finally:
        sov.shutdown(); edge.shutdown()


def test_concurrent_real_hop_plan_checkouts_create_exactly_one(tmp_path, monkeypatch):
    _plans_on(monkeypatch)
    posted: list = []
    sov, edge, ep, _ = _hop_stack(tmp_path, monkeypatch, posted)
    try:
        op = _signup(ep, "planrace@acme.com")
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            codes = list(ex.map(lambda _i: _post(op, ep, _CHECKOUT, {"price_id": _PLAN})[0], range(6)))
        assert sorted(codes) == [200, 403, 403, 403, 403, 403], codes
        assert len(posted) == 1
    finally:
        sov.shutdown(); edge.shutdown()


def test_the_pending_record_expires_and_the_drained_plan_takes_over(monkeypatch):
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    ensure_owner_keypair()                                    # the deployment owner identity _org_has_live_plan reads
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S - 1)
    # the first plan's webhook drains: the DRAINED subscription now refuses a second plan, also past the TTL
    SubscriptionRegistry(p.store).subscribe(org, "pro", 2000, period_start=5000.0, period_end=100_000.0,
                                            issued_at=5001.0)
    with pytest.raises(ProvisionDenied, match="already has a plan"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert len(posted) == 1


def test_an_abandoned_plan_checkout_unblocks_after_the_ttl(monkeypatch):
    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S - 1)
    p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S)     # the abandoned checkout lapsed
    assert len(posted) == 2
    assert DEFAULT_TTL_S >= 3 * 915                           # well above the ~15 min NET-2b parking window


def test_the_ttl_is_comfortably_above_the_net2b_parking_window():
    from vigil_integration.live import net_recovery

    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    total, d = 0.0, net_recovery.DEFAULT_BASE_S
    for _ in range(8):
        total += min(d, net_recovery.DEFAULT_CAP_S)
        d *= 2
    assert DEFAULT_TTL_S >= 3 * (total + 60.0)                # + the 60 s drain timer


def test_topups_never_claim_and_another_org_is_independent(monkeypatch):
    _plans_on(monkeypatch)
    p, admin, _t, org, other, _w = _provisioner()
    p.orgs.grant_membership(other, admin, "org_admin", issued_at=5.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _TOPUP, now=5000.0)
    assert not any(Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64))   # a top-up writes no pending record
    p.billing_checkout(admin, org, _PLAN, now=5001.0)
    p.billing_checkout(admin, other, _PLAN, now=5002.0)                  # a different org is not blocked
    p.billing_checkout(admin, org, _TOPUP, now=5003.0)                   # and top-ups stay available
    assert [x.get("payment_plan") for x in posted] == [None, _PLAN, _PLAN, None]


def test_the_checkout_audit_records_the_tx_ref(monkeypatch):
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    seen = _audits(p)
    r1 = p.billing_checkout(admin, org, _PLAN, now=5000.0)
    r2 = p.billing_checkout(admin, org, _TOPUP, now=5001.0)
    created = [a for a in seen if a["outcome"] == "created"]
    assert [a["tx_ref"] for a in created] == [r1["tx_ref"], r2["tx_ref"]]
    rec = json.loads(next(Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64)).read_text(encoding="utf-8"))
    assert rec["tx_ref"] == r1["tx_ref"] == posted[0]["tx_ref"]           # the pending record names THE checkout


def _record_path(p):
    return next(Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64))


@pytest.mark.parametrize("tamper", ["backdate", "corrupt", "foreign_org", "unsigned"])
def test_a_tampered_or_corrupt_pending_record_refuses_with_an_operator_reason(monkeypatch, tamper):
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, other, _w = _provisioner()
    p.orgs.grant_membership(other, admin, "org_admin", issued_at=5.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    path = _record_path(p)
    rec = json.loads(path.read_text(encoding="utf-8"))
    if tamper == "backdate":                                  # make the live record look long expired
        rec["created_at"], rec["expires_at"] = 1.0, 2.0
        path.write_text(json.dumps(rec), encoding="utf-8")
    elif tamper == "corrupt":
        path.write_text("{truncated", encoding="utf-8")
    elif tamper == "unsigned":
        rec.pop("sig")
        rec["expires_at"] = 3.0
        path.write_text(json.dumps(rec), encoding="utf-8")
    else:                                                     # org's (valid, signed) record copied over `other`'s
        p.billing_checkout(admin, other, _PLAN, now=5000.0)
        target = next(q for q in Path(p.pending_checkouts.dir).glob("[0-9a-f]" * 64) if q != path)
        rec["expires_at"] = 3.0                               # ... and expire it, hoping to unblock
        target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        path = target
        org = other
    before = len(posted)
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="contact support"):
        p.billing_checkout(admin, org, _PLAN, now=9999.0)
    assert len(posted) == before
    a = seen[-1]
    assert a["outcome"] == "refused_pending_invalid" and path.name[:16] in a["reason"] and "remove it" in a["reason"]
    assert a["tx_ref"].startswith(f"vigil:{org}:")
    p.billing_checkout(admin, org, _TOPUP, now=9999.0)        # top-ups are unaffected by a bad plan record


def test_a_stale_unverifiable_record_is_reaped_after_the_ttl(monkeypatch):
    import os

    from sigil.ui.pending_checkout import DEFAULT_TTL_S
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5000.0)
    path = _record_path(p)
    path.write_text("{corrupt", encoding="utf-8")
    os.utime(path, (5000.0, 5000.0))                          # the (untrusted) file itself is old
    seen = _audits(p)
    p.billing_checkout(admin, org, _PLAN, now=5000.0 + DEFAULT_TTL_S + 1)
    assert len(posted) == 2 and "reaped stale pending record" in seen[-1]["reason"]


def test_a_record_from_the_future_stays_live_and_says_why(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    p._checkout_provider = lambda: _real_provider([])
    p.billing_checkout(admin, org, _PLAN, now=10_000.0)
    seen = _audits(p)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)          # the clock moved backwards
    assert seen[-1]["outcome"] == "refused_pending_plan" and "clock moved backwards" in seen[-1]["reason"]


def test_a_processor_refusal_releases_the_claim(monkeypatch):
    from sigil.governor.billing import FlutterwaveBillingProvider
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()

    def down(payload):
        raise TimeoutError("processor down")
    p._checkout_provider = lambda: FlutterwaveBillingProvider("h", lambda *a, **k: None, checkout_creator=down)
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, _PLAN, now=5001.0)                    # no link was issued: retry at once
    assert len(posted) == 1


@pytest.mark.parametrize("why", ["unwired", "no_owner_key", "unwritable"])
def test_plan_checkout_fails_closed_without_a_working_ledger(monkeypatch, tmp_path, why):
    from sigil.ui.pending_checkout import PendingPlanCheckouts
    from sigil.ui.provision import ProvisionDenied
    _plans_on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    if why == "unwired":
        p.pending_checkouts = None
    elif why == "no_owner_key":
        p.pending_checkouts = PendingPlanCheckouts(tmp_path / "pc", owner_key=None, trusted_pubkey=None)
    else:
        (tmp_path / "pc").write_text("not a directory", encoding="utf-8")
        p.pending_checkouts.dir = tmp_path / "pc"
    with pytest.raises(ProvisionDenied, match="contact support"):
        p.billing_checkout(admin, org, _PLAN, now=5000.0)
    assert posted == []
    p.billing_checkout(admin, org, _TOPUP, now=5000.0)                   # top-ups never need the ledger
    assert len(posted) == 1


def test_release_drops_only_its_own_record(tmp_path):
    from sigil.reuse import generate_keypair
    from sigil.ui.pending_checkout import PendingPlanCheckouts
    k = generate_keypair()
    led = PendingPlanCheckouts(tmp_path / "pc", owner_key=k, trusted_pubkey=k.public_key_b64)
    led.claim("org_a", _PLAN, "vigil:org_a:n1", now=100.0)
    assert led.release("org_a", "vigil:org_a:other") is False
    assert led.release("org_a", "vigil:org_a:n1") is True
    assert led.release("org_a", "vigil:org_a:n1") is False


_CLAIM_WORKER = r"""
import sys
from sigil.reuse import KeyPair
from sigil.ui.pending_checkout import PendingCheckoutRefused, PendingPlanCheckouts
kp = KeyPair(public_key_b64=sys.argv[2], private_key_b64=sys.argv[3])
led = PendingPlanCheckouts(sys.argv[1], owner_key=kp, trusted_pubkey=kp.public_key_b64)
try:
    led.claim("org_race", "vigil_pro_monthly", "vigil:org_race:" + sys.argv[4], now=1000.0)
    sys.stdout.write("1")
except PendingCheckoutRefused:
    sys.stdout.write("0")
"""


def test_racing_claims_from_separate_processes_admit_exactly_one(tmp_path):
    import os

    from sigil.reuse import generate_keypair
    k = generate_keypair()                                    # a throwaway test key, never a real owner key
    d = tmp_path / "pc"
    env = {**os.environ}
    procs = [subprocess.Popen([sys.executable, "-c", _CLAIM_WORKER, str(d), k.public_key_b64, k.private_key_b64,
                               f"n{i}"], stdout=subprocess.PIPE, text=True, env=env) for i in range(8)]
    out = "".join(p.communicate(timeout=120)[0] for p in procs)
    assert all(p.returncode == 0 for p in procs), out
    assert sorted(out) == ["0"] * 7 + ["1"], out
