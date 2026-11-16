"""W2c-1 — two PROCESSES settling metered launches of ONE org chain their remainders (HANDOFF §15.2).

The org's sub-credit remainder ``r`` is read inside the settle critical section (the per-process spine lock and the
cross-process settle lock) and committed by the v3 decision appended in the same hold, so two settles of one org in
two processes decide one after the other: 600 + 700 mc used ⇒ the decisions read 0 → 600 → 300 (or 0 → 700 → 300)
and keep exactly 1 whole credit between them. Each child holds the window between its read and its append open
(``record_launch_settled`` is wrapped with a delay), and both start from one barrier, so without the lock both would
read r = 0 and keep nothing for 1.3 credits of use.

Real child processes (this file re-executed as ``python <file> child ...``) on the same spine, owner key, seam and
meter directory.

Mutation-verify target: settle without the cross-process settle lock -> this test reds (total debit 0, not 1).
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

ORG, HOSTS, NOW = "org_a", ("apme.cm", "bpme.cm"), 2000.0
WIDEN_S = 1.0


def _child_main(argv: list) -> int:
    """``child <spine> <meter_dir> <lease.json> <used_mc> <workdir> <name>``: wait for ``go``, settle exactly."""
    spine, meter_dir, lease_path, used, workdir, name = argv
    from sigil import config
    config.MODEL_METER_DIR = Path(meter_dir)
    from sigil.governor import launch_settlement as ls
    from sigil.spine.store import SpineStore
    from sigil.ui.launch_gate import LaunchGate

    real = ls.record_launch_settled

    def slow(*a, **k):                                   # TEST-ONLY: hold the read -> append window open
        time.sleep(WIDEN_S)
        return real(*a, **k)

    ls.record_launch_settled = slow
    g = LaunchGate(SpineStore(spine))
    lease = json.loads(Path(lease_path).read_text())
    work = Path(workdir)
    (work / f"ready-{name}").write_text("1")
    deadline = time.monotonic() + 60
    while not (work / "go").exists():
        if time.monotonic() > deadline:
            return 2
        time.sleep(0.001)
    out = g.settle_launch(signed_lease=lease, consumed_units=0, consumed_mc=int(used), now=NOW,
                          basis="completion:completed")
    (work / f"out-{name}.json").write_text(json.dumps(out))
    return 0


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "child":
    sys.exit(_child_main(sys.argv[2:]))


import pytest  # noqa: E402

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    from sigil import config
    from vigil_core import model_metering as mm
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    for k in ("VIGIL_SETTLE_SPINE_RECORD", "VIGIL_FOLD_CACHE_ENABLED", "VIGIL_RATE_CARD", *mm.OBSOLETE_PRICING_ENVS):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_METERED_BILLING", "1")
    monkeypatch.setenv(mm.MARGIN_ENV, "0.5")                       # a test fixture, not a pricing decision
    monkeypatch.setenv(mm.CANCEL_ENV, "metered")


def _seat(store):
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.launch_gate import LaunchGate
    from sigil.ui.target_authorization import add_customer_target
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, 100, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    for h in HOSTS:
        ch = reg.issue_challenge(ORG, h, issued_at=float(next(_iss)))
        reg.verify_and_record(ORG, h, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
        assert add_customer_target(h, org_id=ORG, store=store, now=NOW)["ok"]
    return LaunchGate(store)


def _use(r, output_tokens):
    from sigil import config
    from sigil import model_gateway as gw
    from vigil_core import model_metering as mm
    from vigil_core.model_grant import ModelGrant
    m = gw.GrantMeter(config.MODEL_METER_DIR)
    grant = ModelGrant(grant_id="0" * 32, org_id=ORG, engagement_slug=r["slug"], nonce=r["nonce"],
                       model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 13, not_after=NOW + 86_400,
                       issued_at=NOW - 60)
    rid, _res, why = m.reserve(grant, 10 ** 6, 25_000, now=NOW)
    assert why == "", why
    m.commit(grant, rid, mm.Usage(output_tokens=output_tokens), 1, request_id="r", now=NOW)


def test_two_processes_settling_one_org_chain_their_remainders(tmp_path):
    from sigil import config
    from sigil.governor import identity
    from sigil.governor import launch_settlement as ls
    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore

    spine = tempfile.mktemp(suffix=".jsonl")
    store = SpineStore(spine)
    g = _seat(store)
    work = tmp_path / "work"
    work.mkdir()
    jobs = []
    for host, tokens, used in ((HOSTS[0], 96, 600), (HOSTS[1], 112, 700)):     # 96 x 6.25 = 600; 112 x 6.25 = 700
        r = g.reserve_launch(requester="u", org_id=ORG, host=host, units=10, now=NOW)
        assert r["ok"], r
        assert g.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
        _use(r, tokens)
        lease_path = work / f"lease-{host}.json"
        lease_path.write_text(json.dumps(r["lease"]))
        jobs.append((host, str(lease_path), used))

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str(Path(p).resolve()) for p in sys.path if p)
    env["SIGIL_HOME"] = str(Path(identity.KEYS_DIR).parent.parent)            # where this process's owner key lives
    procs = [subprocess.Popen([sys.executable, os.path.abspath(__file__), "child", spine, str(config.MODEL_METER_DIR),
                               lease, str(used), str(work), host], env=env, stderr=subprocess.PIPE, text=True)
             for host, lease, used in jobs]
    try:
        deadline = time.monotonic() + 60
        while not all((work / f"ready-{h}").exists() for h, _l, _u in jobs):
            assert time.monotonic() < deadline and all(p.poll() is None for p in procs), \
                [p.stderr.read() for p in procs if p.poll() is not None]
            time.sleep(0.01)
        (work / "go").write_text("1")                                          # one barrier: both settle at once
        for p in procs:
            assert p.wait(timeout=120) == 0, p.stderr.read()
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
    outs = [json.loads((work / f"out-{h}.json").read_text()) for h, _l, _u in jobs]
    assert all(o["ok"] and o["action"] == "launch_settled" for o in outs), outs
    rows = sorted((p["remainder_before"], p["consumed_mc"], p["consumed"], p["remainder_after"])
                  for p in (r.payload for r in SpineStore(spine).iter_records())
                  if isinstance(p, dict) and p.get("signal") == ls.LAUNCH_SETTLED_SIGNAL)
    assert rows in ([(0, 600, 0, 600), (600, 700, 1, 300)], [(0, 700, 0, 700), (700, 600, 1, 300)]), rows
    b = WalletRegistry(SpineStore(spine)).balance(ORG)
    assert (b.available, b.remainder_mc) == (99, 300)                          # 1 whole credit kept, 0.3 carried
