"""E3c — ``settle_launch`` is exactly-once per (slug, nonce) ACROSS OS PROCESSES.

Three callers settle a launch, each in its OWN process: the settle-drain (a COMPLETED run, refund 0),
``sigil ops-sweep reservations --apply`` and the cockpit's ``launch_cancel`` (both a FULL refund). The settle's
"already settled?" check and its record used to be serialized only by a per-process lock, so a completed settle
and a full-refund settle of one lease in two processes could both take effect (a free run), two refund grants
could be written for one lease, the per-slug settlement marker lost a concurrently-recorded nonce, and a
``launch_start`` publish could land inside another process's settle.

Every test here runs REAL child processes (this file re-executed as ``python <file> worker ...``) on the same
spine file, owner key and seam directory. ``*_widened`` tests hold a window open with a TEST-ONLY delay inside the
child (``SETTLE_RACE_WIDEN_S``; it wraps the child's own seam writer), so the interleaving is deterministic;
the ``*_unwidened`` ones use no hook at all and a small iteration count (``SETTLE_RACE_ITERS``).

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_settle_cross_process_race.py
"""
from __future__ import annotations

import itertools
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
UNITS = 30
LATE = NOW + 3600.0 + 100.0                 # past a 1h lease's not_after + the sweep ttl (50)
_WAIT_S = 60.0


# =========================================================================================================
# child process
# =========================================================================================================

def _atomic_json(path: Path, obj) -> None:
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(obj), encoding="utf-8")
    os.replace(tmp, path)


def _wait_for(path: Path, stop: Path):
    while True:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
        if stop.exists():
            return None
        time.sleep(0.0005)


def _worker_main(argv: list) -> int:
    """``worker <role> <spine_path> <workdir>``: per iteration ``i`` wait for ``go-<i>-<role>.json``, spin to its
    monotonic deadline, run the job, write ``res-<i>-<role>.json``; exit when ``stop`` appears."""
    role, spine_path, workdir = argv[0], argv[1], Path(argv[2])
    import vigil_integration.live.credit_lease_broker as broker
    from sigil.spine.store import SpineStore
    from sigil.ui.launch_gate import LaunchGate

    cur = {"i": -1}
    widen = float(os.environ.get("SETTLE_RACE_WIDEN_S") or 0.0)
    if widen > 0:                       # TEST-ONLY: hold the window open inside this child's own seam writer
        # SETTLE_RACE_WIDEN_AT: a broker function name, or ``module:function``; SETTLE_RACE_WIDEN_MODE=after holds
        # the window open AFTER the call instead of before it.
        import importlib
        at = os.environ.get("SETTLE_RACE_WIDEN_AT") or "record_lease_settlement"
        mod = importlib.import_module(at.split(":", 1)[0]) if ":" in at else broker
        name = at.split(":", 1)[1] if ":" in at else at
        after = os.environ.get("SETTLE_RACE_WIDEN_MODE") == "after"
        orig = getattr(mod, name)

        def _slow(*a, **k):
            out = orig(*a, **k) if after else None
            (workdir / f"inwin-{cur['i']}-{role}").write_text("1", encoding="utf-8")
            time.sleep(widen)
            return out if after else orig(*a, **k)

        setattr(mod, name, _slow)
    store = SpineStore(spine_path)
    gate = LaunchGate(store)                            # seam base = $VIGIL_BASE_DIR, exactly like the cockpit
    (workdir / f"ready-{role}").write_text("1", encoding="utf-8")
    stop = workdir / "stop"
    for i in itertools.count():
        go = _wait_for(workdir / f"go-{i}-{role}.json", stop)
        if go is None:
            return 0
        cur["i"] = i
        job = go["job"]
        while time.monotonic() < float(go["t"]):
            pass
        if job["op"] == "settle":                       # what launch_cancel / the sweep / the drain bottom out in
            out = gate.settle_launch(signed_lease=job["lease"], consumed_units=int(job["consumed"]), now=NOW + 60)
        elif job["op"] == "publish":                    # launch_start
            out = gate.publish_lease(signed_lease=job["lease"], expect_org_id=ORG)
        elif job["op"] == "mark":                       # the settlement marker primitive itself
            out = str(broker.record_lease_settlement(os.environ["VIGIL_BASE_DIR"], job["slug"], job["nonce"]))
        elif job["op"] in ("pausemark", "clearmark"):   # the pause marker primitives themselves
            from vigil_integration.live import credit_lease_pause as P
            fn = P.record_lease_pause if job["op"] == "pausemark" else P.clear_lease_pause
            out = str(fn(os.environ["VIGIL_BASE_DIR"], job["slug"], job["nonce"]))
        elif job["op"] == "pause":                      # launch_pause
            out = gate.pause_launch(signed_lease=job["lease"], expect_org_id=ORG)
        elif job["op"] == "resume":                     # launch_resume
            out = gate.resume_launch(signed_lease=job["lease"], expect_org_id=ORG, now=NOW + 60)
        elif job["op"] == "cancel":                     # the cockpit's launch_cancel
            from sigil.ui.provision import ProvisionDenied, build_provisioner
            try:
                out = build_provisioner(store).launch_cancel("u", ORG, job["lease"], now=NOW + 60)
            except ProvisionDenied as e:
                out = {"denied": str(e)}
        elif job["op"] == "sweep":                      # the real `ops-sweep reservations --apply` body
            from sigil import ops_sweeps
            out = ops_sweeps.sweep_abandoned_reservations(gate, now=LATE, ttl_s=50, apply=True,
                                                          completion_spool=job["spool"])
        elif job["op"] == "drain":                      # the real settle-drain body
            from sigil.governor.identity import owner_pubkey
            from sigil.inbound.completion_spool import CompletionSpoolWatcher
            from vigil_core.delegation import DelegationCert
            deleg = DelegationCert.model_validate_json(Path(job["delegation"]).read_text(encoding="utf-8"))
            out = CompletionSpoolWatcher(store, spool_dir=job["spool"], owner_pubkey=owner_pubkey(),
                                         delegation=deleg, scope=job["scope"],
                                         base_dir=os.environ["VIGIL_BASE_DIR"], now_fn=lambda: LATE).drain()
        else:
            out = {"ok": False, "error": f"unknown op {job['op']!r}"}
        _atomic_json(workdir / f"res-{i}-{role}.json", {"out": out})
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "worker":
        raise SystemExit(_worker_main(sys.argv[2:]))
    raise SystemExit("run under pytest")


# =========================================================================================================
# parent (pytest)
# =========================================================================================================

import pytest  # noqa: E402

pytestmark = pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX multi-process race harness")

_iss = itertools.count(1)


def _iters() -> int:
    return int(os.environ.get("SETTLE_RACE_ITERS") or 12)


def _child_env(**extra) -> dict:
    from sigil.governor import identity
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str(Path(p).resolve()) for p in sys.path if p)
    # sigil binds its key dir to SIGIL_HOME at IMPORT: hand the children the home this process's key lives in
    env["SIGIL_HOME"] = str(Path(identity.KEYS_DIR).parent.parent)          # KEYS_DIR = <home>/spine/keys
    env.update({k: str(v) for k, v in extra.items()})
    return env


class _Rig:
    """One spine + seam base, a seated tenant, and long-lived worker processes (one per role)."""

    def __init__(self, monkeypatch, roles, *, credits: int = 1_000_000, **child_env):
        from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
        from sigil.governor.identity import ensure_owner_keypair
        from sigil.governor.orgs import OrgRegistry
        from sigil.governor.wallet import WalletRegistry
        from sigil.spine.store import SpineStore
        from sigil.ui.launch_gate import LaunchGate
        from sigil.ui.target_authorization import add_customer_target
        self.base = tempfile.mkdtemp()
        monkeypatch.setenv("VIGIL_BASE_DIR", self.base)
        self.work = Path(tempfile.mkdtemp())
        self.spine_path = str(Path(tempfile.mkdtemp()) / "spine.jsonl")
        self.store = SpineStore(self.spine_path)
        ensure_owner_keypair()
        self.credits = credits
        orgs = OrgRegistry(self.store)
        orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
        orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
        WalletRegistry(self.store).grant(ORG, credits, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
        reg = AssetOwnershipRegistry(self.store)
        ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
        reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
        assert add_customer_target(HOST, org_id=ORG, store=self.store, now=NOW)["ok"]
        self.gate = LaunchGate(self.store)
        self.roles = list(roles)
        self.i = 0
        env = _child_env(**child_env)
        self.procs = [subprocess.Popen([sys.executable, os.path.abspath(__file__), "worker", role, self.spine_path,
                                        str(self.work)], env=env) for role in self.roles]
        deadline = time.monotonic() + _WAIT_S
        while not all((self.work / f"ready-{r}").exists() for r in self.roles):
            assert time.monotonic() < deadline, "workers did not come up"
            assert all(p.poll() is None for p in self.procs), "a worker died at start-up"
            time.sleep(0.01)

    def reserve(self, *, publish: bool = False) -> dict:
        r = self.gate.reserve_launch(requester="u", org_id=ORG, host=HOST, units=UNITS, now=NOW, duration_hours=1)
        assert r["ok"], r
        if publish:
            assert self.gate.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
        return r

    def avail(self) -> int:
        from sigil.governor.wallet import WalletRegistry
        return WalletRegistry(self.store).available(ORG)

    def go(self, role: str, job: dict, *, at: float) -> None:
        _atomic_json(self.work / f"go-{self.i}-{role}.json", {"t": at, "job": job})

    def result(self, role: str):
        p = self.work / f"res-{self.i}-{role}.json"
        deadline = time.monotonic() + _WAIT_S
        while not p.exists():
            assert time.monotonic() < deadline, f"worker {role} did not answer iteration {self.i}"
            assert all(q.poll() is None for q in self.procs), "a worker died"
            time.sleep(0.0005)
        return json.loads(p.read_text(encoding="utf-8"))["out"]

    def wait_in_window(self, role: str) -> None:
        p = self.work / f"inwin-{self.i}-{role}"
        deadline = time.monotonic() + _WAIT_S
        while not p.exists():
            assert time.monotonic() < deadline, f"worker {role} never reached the widened window"
            time.sleep(0.0005)

    def race(self, jobs: dict) -> dict:
        """Release every role at the same monotonic deadline; return ``{role: result}``."""
        at = time.monotonic() + 0.02
        for role, job in jobs.items():
            self.go(role, job, at=at)
        out = {role: self.result(role) for role in jobs}
        self.i += 1
        return out

    def first_then(self, first: tuple, then: tuple) -> dict:
        """Start ``first`` and wait until it is inside its widened window, then start ``then``."""
        self.go(first[0], first[1], at=time.monotonic())
        self.wait_in_window(first[0])
        self.go(then[0], then[1], at=time.monotonic())
        out = {first[0]: self.result(first[0]), then[0]: self.result(then[0])}
        self.i += 1
        return out

    def records(self, since: int = -1) -> list:
        return [x for x in self.store.iter_records(since_seq=since)]

    def close(self) -> None:
        (self.work / "stop").write_text("1", encoding="utf-8")
        for p in self.procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


@pytest.fixture
def rig(monkeypatch):
    rigs = []

    def _make(roles, **kw):
        r = _Rig(monkeypatch, roles, **kw)
        rigs.append(r)
        return r

    yield _make
    for r in rigs:
        r.close()


@pytest.fixture(params=["", "1"], ids=["flag_off", "flag_on"])
def flag(request, monkeypatch):
    """VIGIL_SETTLE_SPINE_RECORD for the parent AND (inherited through the environment) every worker."""
    monkeypatch.setenv("VIGIL_SETTLE_SPINE_RECORD", request.param)
    return bool(request.param)


def _fresh(out) -> bool:
    return isinstance(out, dict) and bool(out.get("ok")) and out.get("action") == "launch_settled"


def _grant_records(records, prefix: str = "settle-wallet:") -> int:
    return sum(1 for x in records if str((x.payload or {}).get("entry_id", "")).startswith(prefix))


# ---- completed settle (refund 0) vs full-refund settle of ONE lease — the free-run race ------------------------
def _charge_vs_refund(r, n: int) -> None:
    for _ in range(n):
        lease = r.reserve()
        before = r.avail()
        out = r.race({"charge": {"op": "settle", "lease": lease["lease"], "consumed": UNITS},
                      "refund": {"op": "settle", "lease": lease["lease"], "consumed": 0}})
        fresh = [role for role, o in out.items() if _fresh(o)]
        assert len(fresh) == 1, f"{len(fresh)} settles took effect for one lease: {out}"
        loser = out["refund" if fresh == ["charge"] else "charge"]
        assert loser["ok"] and loser["action"] == "launch_already_settled" and loser["refunded"] == 0, loser
        assert r.avail() - before == (UNITS if fresh == ["refund"] else 0), out    # money follows the winner
    assert r.store.verify()[0]


def test_charge_vs_refund_widened_exactly_one_takes_effect(rig, flag):
    _charge_vs_refund(rig(["charge", "refund"], SETTLE_RACE_WIDEN_S=0.2), 3)


def test_charge_vs_refund_unwidened_exactly_one_takes_effect(rig, flag):
    _charge_vs_refund(rig(["charge", "refund"]), _iters())


# ---- refund vs refund: one lease, one refund grant record ------------------------------------------------------
def test_refund_vs_refund_widened_writes_one_grant(rig, flag):
    r = rig(["r1", "r2"], SETTLE_RACE_WIDEN_S=0.2)
    for _ in range(2):
        lease = r.reserve()
        tip = r.store.next_seq - 1
        out = r.race({"r1": {"op": "settle", "lease": lease["lease"], "consumed": 0},
                      "r2": {"op": "settle", "lease": lease["lease"], "consumed": 0}})
        assert sum(_fresh(o) for o in out.values()) == 1, out
        assert _grant_records(r.records(tip)) == 1
    assert r.avail() == r.credits


# ---- the per-slug settlement marker: two nonces recorded from two processes --------------------------------------
def test_two_nonces_of_one_slug_widened_neither_marker_is_lost(rig):
    from vigil_integration.live.credit_lease_broker import is_lease_settled
    r = rig(["m1", "m2"], SETTLE_RACE_WIDEN_S=0.3, SETTLE_RACE_WIDEN_AT="_atomic_write_json")
    out = r.first_then(("m1", {"op": "mark", "slug": "cust_x", "nonce": "n1"}),
                       ("m2", {"op": "mark", "slug": "cust_x", "nonce": "n2"}))
    assert all(isinstance(v, str) for v in out.values()), out
    assert is_lease_settled(r.base, "cust_x", "n1") and is_lease_settled(r.base, "cust_x", "n2")


def test_two_leases_of_one_slug_unwidened_neither_marker_is_lost(rig):
    from vigil_integration.live.credit_lease_broker import is_lease_settled
    r = rig(["charge", "refund"])
    for _ in range(_iters()):
        a, b = r.reserve(publish=True), r.reserve()     # same host => same slug, two nonces
        out = r.race({"charge": {"op": "settle", "lease": a["lease"], "consumed": UNITS},
                      "refund": {"op": "settle", "lease": b["lease"], "consumed": 0}})
        assert _fresh(out["charge"]) and _fresh(out["refund"]), out
        assert is_lease_settled(r.base, a["slug"], a["nonce"]) and is_lease_settled(r.base, b["slug"], b["nonce"])


# ---- the real callers: ops-sweep --apply vs the settle-drain ------------------------------------------------------
def test_real_sweep_vs_real_drain_widened_never_both(rig, flag):
    """The sweep (process 1) is inside its settle when the worker's `completed` signal lands and the settle-drain
    (process 2) runs. Whichever settles first decides; the run is never both refunded and charged."""
    from sigil.ui.launch_governance import provision_launch_governance
    from vigil_integration.jobs.completion_signal import emit_completion_signal
    from vigil_integration.live.governance_identity import (
        DEFAULT_GOVERNANCE_KEY_FILE, GOVERNANCE_KEY_ID, load_or_create_governance_keypair,
    )
    r = rig(["sweep", "drain"], credits=100, SETTLE_RACE_WIDEN_S=0.3)
    lease = r.reserve(publish=True)
    deleg_path = provision_launch_governance(slug=lease["slug"], not_after=9_000_000_000, base_dir=r.base)
    gov = load_or_create_governance_keypair(path=os.path.join(r.base, DEFAULT_GOVERNANCE_KEY_FILE))
    spool = tempfile.mkdtemp()
    (Path(spool) / "incoming").mkdir()
    tip = r.store.next_seq - 1
    r.go("sweep", {"op": "sweep", "spool": spool}, at=time.monotonic())
    r.wait_in_window("sweep")
    emit_completion_signal(engagement_slug=lease["slug"], nonce=lease["nonce"], outcome="completed",
                           signers=[(GOVERNANCE_KEY_ID, gov.private_key_b64)], spool_dir=spool)
    r.go("drain", {"op": "drain", "spool": spool, "delegation": str(deleg_path), "scope": lease["slug"]},
         at=time.monotonic())
    sweep, _drain = r.result("sweep"), r.result("drain")
    recs = r.records(tip)
    refunded = _grant_records(recs) > 0
    charged = any(x.kind == "assessment_outcome" for x in recs)      # the drain's FRESH-settle projection
    assert refunded != charged, f"refunded={refunded} charged={charged} sweep={sweep}"
    assert r.avail() == (100 if refunded else 70)
    assert [i["status"] for i in sweep["items"]] == (["refunded"] if refunded else ["completion_pending"])


# ---- launch_start (publish) vs a settle in another process -------------------------------------------------------
def test_publish_vs_settle_widened_never_both(rig, flag):
    """A cancel (process 1) is inside its settle when a publish of the same lease (process 2) runs: the lease is
    never both refunded and published."""
    from vigil_integration.live.credit_lease_broker import read_credit_lease
    r = rig(["cancel", "pub"], SETTLE_RACE_WIDEN_S=0.3)
    lease = r.reserve()
    out = r.first_then(("cancel", {"op": "settle", "lease": lease["lease"], "consumed": 0}),
                       ("pub", {"op": "publish", "lease": lease["lease"]}))
    assert _fresh(out["cancel"]) and out["pub"]["ok"] is False, out
    assert read_credit_lease(r.base, lease["slug"]) is None


# ---- the pause marker: per-file cross-process lock; pause linearized with settles ------------------------------
_PAUSE_WRITE = "vigil_integration.live.credit_lease_pause:_atomic_write_json"


def test_two_processes_pausing_two_nonces_of_one_slug_lose_neither(rig):
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    r = rig(["p1", "p2"], SETTLE_RACE_WIDEN_S=0.3, SETTLE_RACE_WIDEN_AT=_PAUSE_WRITE)
    out = r.first_then(("p1", {"op": "pausemark", "slug": "cust_x", "nonce": "n1"}),
                       ("p2", {"op": "pausemark", "slug": "cust_x", "nonce": "n2"}))
    assert all(isinstance(v, str) for v in out.values()), out
    assert is_lease_paused(r.base, "cust_x", "n1") and is_lease_paused(r.base, "cust_x", "n2")


def test_a_resume_and_a_pause_of_one_slug_in_two_processes_lose_neither(rig):
    from vigil_integration.live.credit_lease_pause import is_lease_paused, record_lease_pause
    r = rig(["p1", "c2"], SETTLE_RACE_WIDEN_S=0.3, SETTLE_RACE_WIDEN_AT=_PAUSE_WRITE)
    record_lease_pause(r.base, "cust_x", "n2")
    out = r.first_then(("p1", {"op": "pausemark", "slug": "cust_x", "nonce": "n1"}),
                       ("c2", {"op": "clearmark", "slug": "cust_x", "nonce": "n2"}))
    assert all(isinstance(v, str) for v in out.values()), out
    assert is_lease_paused(r.base, "cust_x", "n1") and not is_lease_paused(r.base, "cust_x", "n2")


def test_a_pause_waits_for_a_settle_in_another_process_and_is_refused(rig, flag):
    from vigil_integration.live.credit_lease_pause import is_lease_paused
    r = rig(["cancel", "pause"], SETTLE_RACE_WIDEN_S=0.3)            # the settle held inside its marker write
    lease = r.reserve()
    out = r.first_then(("cancel", {"op": "settle", "lease": lease["lease"], "consumed": 0}),
                       ("pause", {"op": "pause", "lease": lease["lease"]}))
    assert _fresh(out["cancel"]), out
    assert out["pause"]["ok"] is False and "settled" in out["pause"]["error"], out
    assert not is_lease_paused(r.base, lease["slug"], lease["nonce"])


# ---- a metered launch_start vs a customer cancel: never both; a refused cancel leaves the meter open -------------
def _metered_env(monkeypatch) -> None:
    from vigil_core import model_metering as mm
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, "0.5")                       # the meter tests' fixture input
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def test_metered_publish_vs_cancel_widened_cross_process_never_both(rig, flag, monkeypatch):
    from sigil import config
    from sigil import model_gateway as gw
    from vigil_core.model_grant import ModelGrant
    from vigil_integration.live.credit_lease_broker import read_credit_lease
    from vigil_integration.live.model_grant_broker import read_model_grant
    _metered_env(monkeypatch)
    r = rig(["pub", "cancel"], credits=1_000, SETTLE_RACE_WIDEN_S=0.3,
            SETTLE_RACE_WIDEN_AT="vigil_integration.live.credit_lease_broker:write_credit_lease")
    lease = r.reserve()                                              # reserved, not started
    out = r.first_then(("pub", {"op": "publish", "lease": lease["lease"]}),     # held inside its lease write
                       ("cancel", {"op": "cancel", "lease": lease["lease"]}))
    assert out["pub"]["ok"] is True, out
    assert "has been started" in out["cancel"].get("denied", ""), out
    assert read_credit_lease(r.base, lease["slug"]) is not None and read_model_grant(r.base, lease["slug"]) is not None
    assert r.avail() == 1_000 - UNITS
    g = ModelGrant(grant_id="9" * 32, org_id=ORG, engagement_slug=lease["slug"], nonce=lease["nonce"],
                   model="test-run-model", effort="high", cap_nano_usd=10 ** 12, not_after=NOW + 86_400,
                   issued_at=NOW - 60)
    assert gw.GrantMeter(config.MODEL_METER_DIR).reserve(g, 10 ** 6, 25_000, now=NOW)[2] != "closed"


def test_metered_publish_cancel_pause_and_resume_cross_process_never_deadlock(rig, flag, monkeypatch):
    """Four roles on one lease at once, unwidened: every role answers (no deadlock), and a launch is never both
    started and refunded."""
    _metered_env(monkeypatch)
    r = rig(["pub", "cancel", "pause", "resume"], credits=1_000_000)
    for _ in range(max(3, _iters() // 3)):
        lease = r.reserve()
        before = r.avail()
        out = r.race({"pub": {"op": "publish", "lease": lease["lease"]},
                      "cancel": {"op": "cancel", "lease": lease["lease"]},
                      "pause": {"op": "pause", "lease": lease["lease"]},
                      "resume": {"op": "resume", "lease": lease["lease"]}})
        started = bool(out["pub"].get("ok"))
        refunded = "refunded" in out["cancel"] and out["cancel"]["refunded"] == UNITS
        assert started != refunded, out                              # exactly one: started xor refunded
        assert r.avail() - before == (UNITS if refunded else 0), out
        assert out["resume"].get("ok") is True, out                  # a pause can always be lifted
        if started:                                                  # settle it so the next launch may start
            done = r.gate.settle_launch(signed_lease=lease["lease"], consumed_units=UNITS, now=NOW + 60)
            assert done["ok"], done
    assert r.store.verify()[0]


# ---- the property the lock relies on: concurrent cross-process appends keep one chain -----------------------------
_APPEND_CHILD = r"""
import json, os, sys, time
args = json.loads(sys.argv[1])
from sigil.spine.store import SpineStore
s = SpineStore(args["spine"])
while not os.path.exists(args["go"]):
    time.sleep(0.001)
for i in range(args["n"]):
    s.append(kind="event", source="race", actor=args["who"], payload={"i": i, "who": args["who"]})
"""


@pytest.mark.parametrize("segmented", [False, True])
def test_concurrent_cross_process_spine_appends_form_one_contiguous_verifying_chain(segmented):
    from sigil.spine.store import SpineStore
    d = Path(tempfile.mkdtemp())
    path = d / "spine.jsonl"
    if segmented:
        SpineStore(path, seg_max_bytes=0, seg_max_records=7).migrate()
    go = str(d / "go")
    writers, per = 3, 25
    procs = [subprocess.Popen([sys.executable, "-c", _APPEND_CHILD,
                               json.dumps({"spine": str(path), "go": go, "n": per, "who": f"w{k}"})],
                              env=_child_env(), stderr=subprocess.PIPE, text=True) for k in range(writers)]
    time.sleep(1.0)
    Path(go).write_text("go", encoding="utf-8")
    for p in procs:
        _so, se = p.communicate(timeout=120)
        assert p.returncode == 0, se[-2000:]
    s = SpineStore(path, seg_max_bytes=0, seg_max_records=7) if segmented else SpineStore(path)
    recs = list(s.iter_records())
    assert [r.seq for r in recs] == list(range(writers * per))          # no fork / gap / duplicate seq
    ok, why = s.verify()
    assert ok, why
    for k in range(writers):
        assert sorted(r.payload["i"] for r in recs if r.payload.get("who") == f"w{k}") == list(range(per))
