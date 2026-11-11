"""E3c — ``settle_launch`` must be exactly-once per (slug, nonce) ACROSS OS PROCESSES.

Three callers settle a launch, each in its OWN process: the settle-drain oneshot (a COMPLETED run ⇒
``consumed == reserved``, refund 0), ``sigil ops-sweep reservations --apply`` and the cockpit's
``launch_cancel`` (both ``consumed == 0`` ⇒ FULL refund). ``settle_launch``'s idempotency guard is a
check-then-record of the seam settlement marker (``is_lease_settled`` → ``record_lease_settlement``). If that
check-then-record is serialized only by an in-process lock, a completed settle racing a full-refund settle in
another process can BOTH pass the check: the completed run is then fully refunded (a free run; net spend 0 ≠
metered consumption) and two "fresh" settlements are reported for one reservation.

This is a REAL multi-process race: each settle runs in a separate ``subprocess`` interpreter against the same
spine file + seam dir. A start-file aligns the two children, and — test-only — each child wraps its OWN imported
``is_lease_settled`` so that, after the check reads "not settled", it sleeps a moment: that widens the
check→record window so the interleaving is deterministic rather than luck. Nothing in the shipped code is
patched from the parent. The fix must make the second settle observe the first (``launch_already_settled``)
however long that window is.

A second test pins the property the fix relies on: concurrent ``SpineStore.append`` from several processes
yields one contiguous, verifying chain (cross-process seq allocation is serialized by the store's flock).
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

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target

pytestmark = pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX multi-process race harness")

_iss = itertools.count(1)
NOW = 2000.0
UNITS = 30
ITERS = int(os.environ.get("SIGIL_SETTLE_RACE_ITERS", "3"))

# The child: settle ONE lease with a given consumed_units, after the start-file appears. The test-only delay
# hook wraps the child's own credit_lease_broker.is_lease_settled (the name settle_launch imports at call time).
_CHILD = r"""
import json, os, sys, time
args = json.loads(sys.argv[1])
import vigil_integration.live.credit_lease_broker as clb
_real = clb.is_lease_settled
def _slow(base, slug, nonce):
    out = _real(base, slug, nonce)
    if not out:
        time.sleep(args["delay"])          # TEST-ONLY: widen the check -> record window
    return out
clb.is_lease_settled = _slow
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
gate = LaunchGate(SpineStore(args["spine"]), base_dir=args["base"])
deadline = time.time() + 60
while not os.path.exists(args["go"]):
    if time.time() > deadline:
        sys.exit(3)
    time.sleep(0.001)
r = gate.settle_launch(signed_lease=args["lease"], consumed_units=args["consumed"], now=args["now"])
print(json.dumps({"ok": r.get("ok"), "action": r.get("action"), "refunded": r.get("refunded"),
                  "error": r.get("error")}))
"""


def _child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str(Path(p).resolve()) for p in sys.path if p)
    return env


def _seat(store, org, host, credits):
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=NOW)["ok"]


def _race(store_path: str, base: str, lease: dict, consumed_a: int, consumed_b: int, delay: float) -> list[dict]:
    """Launch two settle processes for the SAME lease, release them together, return both results."""
    go = os.path.join(tempfile.mkdtemp(), "go")
    procs = []
    for consumed in (consumed_a, consumed_b):
        arg = json.dumps({"spine": store_path, "base": base, "lease": lease, "consumed": consumed,
                          "now": NOW, "go": go, "delay": delay})
        procs.append(subprocess.Popen([sys.executable, "-c", _CHILD, arg], env=_child_env(),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    time.sleep(1.5)                                    # let both interpreters import + reach the start line
    Path(go).write_text("go", encoding="utf-8")
    out = []
    for p in procs:
        so, se = p.communicate(timeout=120)
        assert p.returncode == 0, f"child failed rc={p.returncode}: {se[-2000:]}"
        out.append(json.loads(so.strip().splitlines()[-1]))
    return out


@pytest.mark.parametrize("delay", [0.4])
def test_completed_settle_racing_a_full_refund_settle_in_another_process_is_exactly_once(monkeypatch, delay):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    ensure_owner_keypair()
    store_path = tempfile.mktemp(suffix=".jsonl")
    store = SpineStore(store_path)
    base = os.environ["VIGIL_BASE_DIR"]            # the seam: authority, leases, settlement markers
    org = "org_race"
    _seat(store, org, "apme.cm", credits=UNITS * ITERS)
    wallet = WalletRegistry(store)
    for i in range(ITERS):
        g = LaunchGate(store, base_dir=base)
        r = g.reserve_launch(requester="u", org_id=org, host="apme.cm", units=UNITS, now=NOW)
        assert r["ok"], r
        before = wallet.available(org)
        # A = the settle-drain's COMPLETED settle (charge everything); B = sweep / launch_cancel (full refund)
        res = _race(store_path, base, r["lease"], UNITS, 0, delay)
        fresh = [x for x in res if x["action"] == "launch_settled"]
        after = WalletRegistry(SpineStore(store_path)).available(org)
        # exactly ONE settle decides the reservation; the other observes it
        assert all(x["ok"] for x in res), res
        assert len(fresh) == 1, f"iteration {i}: {len(fresh)} fresh settlements for one (slug, nonce): {res}"
        # whichever won, net spend equals what THAT settle metered — never "completed AND refunded"
        refunded = after - before
        assert refunded == fresh[0]["refunded"], (i, res, before, after)


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
    d = Path(tempfile.mkdtemp())
    path = d / "spine.jsonl"
    if segmented:
        SpineStore(path, seg_max_bytes=0, seg_max_records=7).migrate()
    go = str(d / "go")
    writers, per = 4, 40
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
    assert ok, why                                                      # the hash chain verifies
    for k in range(writers):
        assert sorted(r.payload["i"] for r in recs if r.payload.get("who") == f"w{k}") == list(range(per))
