"""E7 — "one outstanding launch per (org, host)" holds ACROSS OS PROCESSES.

``reserve_launch`` decides "is another launch of this target still outstanding?" and then debits, and the per-
process spine lock alone would let two processes on one spine both pass the check before either debit lands. The
check therefore runs under the cross-process settle lock (the flock every settle and publish already holds) from
the check through the debit.

Two REAL child processes (this file re-executed as ``python <file> worker ...``) reserve the same (org, host) on one
spine file, owner key and seam directory. The first holds its critical section open with a TEST-ONLY delay
(``ONE_LAUNCH_WIDEN_S``, wrapping the child's own ``LaunchGate._spend``, i.e. between the check and the debit); the
second is released only once the first is inside that window, so the interleaving is deterministic.

Run: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -m pytest \
     apps/sigil/tests/test_one_launch_cross_process.py
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
_WAIT_S = 60.0


def _worker_main(argv: list) -> int:
    """``worker <role> <spine_path> <workdir>``: wait for ``go-<role>``, reserve once, write ``res-<role>.json``."""
    role, spine_path, workdir = argv[0], argv[1], Path(argv[2])
    from sigil.spine.store import SpineStore
    from sigil.ui.launch_gate import LaunchGate

    widen = float(os.environ.get("ONE_LAUNCH_WIDEN_S") or 0.0)
    if widen > 0:                       # TEST-ONLY: hold the check -> debit window open inside this child
        orig = LaunchGate._spend

        def _slow(self, *a, **k):
            (workdir / f"inwin-{role}").write_text("1", encoding="utf-8")
            time.sleep(widen)
            return orig(self, *a, **k)

        LaunchGate._spend = _slow       # type: ignore[method-assign]
    gate = LaunchGate(SpineStore(spine_path))           # seam base = $VIGIL_BASE_DIR, exactly like the cockpit
    (workdir / f"ready-{role}").write_text("1", encoding="utf-8")
    while not (workdir / f"go-{role}").exists():
        time.sleep(0.001)
    out = gate.reserve_launch(requester="u", org_id=ORG, host=HOST, units=30, now=NOW, duration_hours=1)
    out.pop("lease", None)
    out.pop("trust_root", None)
    (workdir / f"res-{role}.json").write_text(json.dumps(out), encoding="utf-8")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "worker":
        raise SystemExit(_worker_main(sys.argv[2:]))
    raise SystemExit("run under pytest")


import pytest  # noqa: E402

pytestmark = pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX multi-process race harness")

_iss = itertools.count(1)


def _wait(path: Path, procs) -> None:
    deadline = time.monotonic() + _WAIT_S
    while not path.exists():
        assert time.monotonic() < deadline, f"{path.name} never appeared"
        assert all(p.poll() in (None, 0) for p in procs), "a worker died"
        time.sleep(0.001)


@pytest.mark.parametrize("flag", ["1", ""])
def test_two_processes_reserving_one_target_cannot_both_pass(monkeypatch, flag):
    from sigil.governor import identity
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore
    from sigil.ui.target_authorization import add_customer_target
    base, work = tempfile.mkdtemp(), Path(tempfile.mkdtemp())
    monkeypatch.setenv("VIGIL_BASE_DIR", base)
    spine_path = str(Path(tempfile.mkdtemp()) / "spine.jsonl")
    store = SpineStore(spine_path)
    identity.ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(ORG, 100, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
    reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(HOST, org_id=ORG, store=store, now=NOW)["ok"]
    env = dict(os.environ, VIGIL_ONE_LAUNCH_PER_HOST=flag)
    env["PYTHONPATH"] = os.pathsep.join(str(Path(p).resolve()) for p in sys.path if p)
    env["SIGIL_HOME"] = str(Path(identity.KEYS_DIR).parent.parent)      # the home this process's owner key is in
    procs = [subprocess.Popen([sys.executable, os.path.abspath(__file__), "worker", role, spine_path, str(work)],
                              env=dict(env, ONE_LAUNCH_WIDEN_S="1.5" if role == "first" else ""))
             for role in ("first", "second")]
    try:
        for role in ("first", "second"):
            _wait(work / f"ready-{role}", procs)
        (work / "go-first").write_text("1", encoding="utf-8")
        _wait(work / "inwin-first", procs)                # the first passed its check and has not debited yet
        (work / "go-second").write_text("1", encoding="utf-8")
        for role in ("first", "second"):
            _wait(work / f"res-{role}.json", procs)
        out = {role: json.loads((work / f"res-{role}.json").read_text(encoding="utf-8"))
               for role in ("first", "second")}
    finally:
        for p in procs:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()
    assert out["first"]["ok"], out
    if flag:                                              # exactly one reservation; the second never debited
        assert not out["second"]["ok"] and "finish or cancel the launch already in progress" in out["second"]["error"]
        assert WalletRegistry(store).available(ORG) == 70
    else:                                                 # flag off: unchanged — both reserve, as before
        assert out["second"]["ok"] and WalletRegistry(store).available(ORG) == 40
