"""E3bc flag-off parity — every settle path writes, with ``VIGIL_SETTLE_SPINE_RECORD`` unset, exactly what main wrote.

``GOLDEN`` was captured by running :func:`_golden` against origin/main (the merge base of this slice). Each scenario
drives a real settle path end to end and records: the spine records the settle appended (kind, signal, entry_id,
credits, outcome — in order), the caller-visible result (its keys and amounts), the seam files left behind (``*.lock``
transients excluded — the one deliberate on-disk delta) with the marker contents, and the meter files. Paths: the flat
completed / canceled / failed drain, the customer cancel, the abandoned-lease sweep refund, the postpaid settle, and —
with only metering on — the metered completed / D3 canceled / failed / failed + paused-past-expiry drains, the D4 paused
charge and the unpaused metered sweep refund.

With the flag ON the same scenarios write the SAME records plus exactly one ``governor.launch_settled`` decision per
fresh settle, and the same results and seam files.

This module uses only the API main has, so the capture can be re-run on main:
  PYTHONPATH=apps/sigil:integration:packages/core/vigil_core python -c \
    "import sys; sys.path.insert(0, 'apps/sigil/tests'); import test_settle_flag_off_golden as g, json; print(json.dumps(g._golden()))"
"""
from __future__ import annotations

import itertools
import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil import config
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import delegate_offense_governance, ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.postpaid import PostpaidRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.inbound.completion_spool import CompletionSpoolWatcher
from sigil.spine.store import SpineStore
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import AuthorizerKey, generate_keypair
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant
from vigil_integration.jobs.completion_signal import emit_completion_signal

ORG, HOST, NOW = "org_a", "apme.cm", 2000.0
LATE = NOW + 8 * 3600 + 2 * 86400                # past an 8h lease window + the 1-day sweep TTL
USAGE = mm.Usage(output_tokens=10_650)
USAGE_COST = 266_250_000
_ENV = ("VIGIL_METERED_BILLING", mm.MARGIN_ENV, mm.CANCEL_ENV, "VIGIL_RUN_FLOOR_CREDITS", "VIGIL_MODEL_PRICES",
        "VIGIL_RUN_MODEL", "VIGIL_SETTLE_SPINE_RECORD", "VIGIL_COST_LEDGER_WRITE", "VIGIL_SETTLE_LOCK_WAIT_S",
        *mm.OBSOLETE_PRICING_ENVS)


class _Env:
    """A tiny env/attr patcher usable outside pytest (the main-capture run)."""

    def __init__(self) -> None:
        self._env: dict = {}
        self._attrs: list = []

    def setenv(self, k: str, v: str) -> None:
        self._env.setdefault(k, os.environ.get(k))
        os.environ[k] = v

    def delenv(self, k: str) -> None:
        self._env.setdefault(k, os.environ.get(k))
        os.environ.pop(k, None)

    def setattr(self, obj, name: str, value) -> None:
        self._attrs.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def undo(self) -> None:
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        for obj, name, value in reversed(self._attrs):
            setattr(obj, name, value)


def _norm(rec) -> list:
    p = rec.payload if isinstance(rec.payload, dict) else {}
    return [rec.kind, p.get("signal"), p.get("entry_id"), p.get("credits"), p.get("outcome")]


def _seam(base: str) -> list:
    out = []
    for p in sorted(Path(base).rglob("*")):
        if not p.is_file() or p.name.endswith(".lock"):
            continue
        rel = str(p.relative_to(base))
        item = [rel]
        if rel.split("/")[0] in ("credit-lease-settlements", "credit-lease-pauses", "credit-lease-paused-past-expiry"):
            item.append(json.loads(p.read_text(encoding="utf-8")).get("nonces"))
        out.append(item)
    return out


def _meter(d: Path) -> list:
    return sorted(p.name for p in d.iterdir() if not p.name.endswith(".lock")) if d.is_dir() else []


_iss = itertools.count(1)


class _World:
    def __init__(self, env: _Env, *, metered: bool, postpaid: bool = False) -> None:
        self.env = env
        self.base = tempfile.mkdtemp()
        env.setenv("VIGIL_BASE_DIR", self.base)
        env.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
        self.meter_dir = Path(tempfile.mkdtemp()) / "model_meter"
        env.setattr(config, "MODEL_METER_DIR", self.meter_dir)
        if metered:
            env.setenv("VIGIL_METERED_BILLING", "1")
            env.setenv(mm.MARGIN_ENV, "0.5")                 # a test fixture (the markup the meter tests use)
            env.setenv(mm.CANCEL_ENV, "metered")
        self.store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
        self.owner = ensure_owner_keypair()
        orgs = OrgRegistry(self.store)
        orgs.create_org(ORG, ORG, owner="u", issued_at=float(next(_iss)))
        orgs.grant_membership(ORG, "u", "operator", issued_at=float(next(_iss)))
        if postpaid:
            PostpaidRegistry(self.store).set_account(ORG, 500, 30, issued_at=float(next(_iss)))
        else:
            WalletRegistry(self.store).grant(ORG, 1_000, "trial", entry_id=f"trial:{ORG}", issued_at=float(next(_iss)))
        reg = AssetOwnershipRegistry(self.store)
        ch = reg.issue_challenge(ORG, HOST, issued_at=float(next(_iss)))
        reg.verify_and_record(ORG, HOST, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
        assert add_customer_target(HOST, org_id=ORG, store=self.store, now=NOW)["ok"]
        self.gate = LaunchGate(self.store)

    def reserve(self, nonce: str, *, units: int = 100, publish: bool = True) -> dict:
        r = self.gate.reserve_launch(requester="u", org_id=ORG, host=HOST, units=units, now=NOW, nonce=nonce)
        assert r["ok"], r
        if publish:
            assert self.gate.publish_lease(signed_lease=r["lease"], expect_org_id=ORG)["ok"]
        return r

    def spend(self, r: dict) -> None:
        from sigil import model_gateway as gw
        m = gw.GrantMeter(config.MODEL_METER_DIR)
        g = ModelGrant(grant_id="0" * 32, org_id=ORG, engagement_slug=r["slug"], nonce=r["nonce"],
                       model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 12, not_after=NOW + 86_400,
                       issued_at=NOW - 60)
        rid, _reserved, reason = m.reserve(g, 10 ** 6, 25_000, now=NOW)
        assert reason == "", reason
        m.commit(g, rid, USAGE, USAGE_COST, request_id="r", now=NOW)

    def drain(self, r: dict, outcome: str) -> dict:
        gov = generate_keypair()
        deleg = delegate_offense_governance(
            self.owner, authorizers=[AuthorizerKey(key_id="gov", name="gov", public_key_b64=gov.public_key_b64)],
            threshold=1, scope=r["slug"], not_after=9_000_000_000)
        spool = tempfile.mkdtemp()
        emit_completion_signal(engagement_slug=r["slug"], nonce=r["nonce"], outcome=outcome,
                               signers=[("gov", gov.private_key_b64)], spool_dir=spool)
        w = CompletionSpoolWatcher(self.store, spool_dir=spool, owner_pubkey=self.owner.public_key_b64,
                                   delegation=deleg, scope=r["slug"], base_dir=self.base, now_fn=lambda: NOW)
        return w.drain()

    def sweep(self) -> list:
        from sigil.ops_sweeps import sweep_abandoned_reservations
        spool = tempfile.mkdtemp()
        for sub in ("incoming", "working", "rejected"):
            os.makedirs(os.path.join(spool, sub))
        rows = sweep_abandoned_reservations(self.gate, now=LATE, ttl_s=86400, apply=True,
                                            completion_spool=spool)["items"]
        return [{k: v for k, v in x.items() if k not in ("not_after", "org_id", "nonce", "slug")} for x in rows]

    def snapshot(self, tip: int, result) -> dict:
        return {"records": [_norm(x) for x in self.store.iter_records(since_seq=tip)], "result": result,
                "seam": _seam(self.base), "meter": _meter(self.meter_dir)}


def _scenario(name: str) -> dict:
    env = _Env()
    for k in _ENV:
        env.delenv(k)
    try:
        metered = name.startswith("metered_")
        w = _World(env, metered=metered, postpaid=(name == "postpaid_settle"))
        if name in ("flat_completed", "flat_canceled", "flat_failed", "metered_completed", "metered_d3_canceled",
                    "metered_failed"):
            r = w.reserve("n1")
            if metered:
                w.spend(r)
            tip = w.store.next_seq - 1
            return w.snapshot(tip, w.drain(r, name.rsplit("_", 1)[1]))
        if name == "metered_failed_past_expiry":
            from vigil_integration.live.credit_lease_pause import record_lease_pause
            r = w.reserve("n1")
            w.spend(r)
            record_lease_pause(w.base, r["slug"], r["nonce"])
            assert w.gate.resume_launch(signed_lease=r["lease"], expect_org_id=ORG, now=LATE)["expired"]
            tip = w.store.next_seq - 1
            return w.snapshot(tip, w.drain(r, "failed"))
        if name == "customer_cancel":
            from sigil.ui.provision import build_provisioner
            r = w.reserve("n1", publish=False)
            tip = w.store.next_seq - 1
            return w.snapshot(tip, build_provisioner(w.store).launch_cancel("u", ORG, r["lease"], now=NOW + 60))
        if name in ("sweep_refund", "metered_unpaused_sweep", "metered_d4_paused"):
            r = w.reserve("n1")
            if metered:
                w.spend(r)
            if name == "metered_d4_paused":
                from vigil_integration.live.credit_lease_pause import record_lease_pause
                record_lease_pause(w.base, r["slug"], r["nonce"])
            tip = w.store.next_seq - 1
            return w.snapshot(tip, w.sweep())
        if name == "postpaid_settle":
            r = w.reserve("pp1", publish=False)
            tip = w.store.next_seq - 1
            out = w.gate.settle_launch(signed_lease=r["lease"], consumed_units=40, now=NOW + 60)
            again = w.gate.settle_launch(signed_lease=r["lease"], consumed_units=0, now=NOW + 90)
            return w.snapshot(tip, [out, again])
        raise KeyError(name)
    finally:
        env.undo()


SCENARIOS = ("flat_completed", "flat_canceled", "flat_failed", "customer_cancel", "sweep_refund", "postpaid_settle",
             "metered_completed", "metered_d3_canceled", "metered_failed", "metered_failed_past_expiry",
             "metered_d4_paused", "metered_unpaused_sweep")


def _golden() -> dict:
    return {n: _scenario(n) for n in SCENARIOS}


# Captured from origin/main (see the module docstring); JSON so the literal is exactly what main produced.
GOLDEN: dict = json.loads(r"""
{
 "customer_cancel": {
  "meter": [],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    100,
    null
   ],
   [
    "event",
    "provision.audit",
    null,
    null,
    "canceled"
   ]
  ],
  "result": {
   "refunded": 100,
   "slug": "cust_5b027ea557ffed11da0e29b3"
  },
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "flat_canceled": {
  "meter": [],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    100,
    null
   ],
   [
    "assessment_outcome",
    null,
    null,
    null,
    "canceled"
   ]
  ],
  "result": {
   "deduped": 0,
   "noop": 0,
   "rejected": 0,
   "settled": 1
  },
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "flat_completed": {
  "meter": [],
  "records": [
   [
    "assessment_outcome",
    null,
    null,
    null,
    "completed"
   ]
  ],
  "result": {
   "deduped": 0,
   "noop": 0,
   "rejected": 0,
   "settled": 1
  },
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "flat_failed": {
  "meter": [],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    100,
    null
   ],
   [
    "assessment_outcome",
    null,
    null,
    null,
    "failed"
   ]
  ],
  "result": {
   "deduped": 0,
   "noop": 0,
   "rejected": 0,
   "settled": 1
  },
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "metered_completed": {
  "meter": [
   "7f9da1d4783ef61963a681e059960dfe.closed",
   "7f9da1d4783ef61963a681e059960dfe.jsonl",
   "7f9da1d4783ef61963a681e059960dfe.metered"
  ],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    46,
    null
   ],
   [
    "assessment_outcome",
    null,
    null,
    null,
    "completed"
   ]
  ],
  "result": {
   "deduped": 0,
   "noop": 0,
   "rejected": 0,
   "settled": 1
  },
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "metered_d3_canceled": {
  "meter": [
   "7f9da1d4783ef61963a681e059960dfe.closed",
   "7f9da1d4783ef61963a681e059960dfe.jsonl",
   "7f9da1d4783ef61963a681e059960dfe.metered"
  ],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    46,
    null
   ],
   [
    "assessment_outcome",
    null,
    null,
    null,
    "canceled"
   ]
  ],
  "result": {
   "deduped": 0,
   "noop": 0,
   "rejected": 0,
   "settled": 1
  },
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "metered_d4_paused": {
  "meter": [
   "7f9da1d4783ef61963a681e059960dfe.closed",
   "7f9da1d4783ef61963a681e059960dfe.jsonl",
   "7f9da1d4783ef61963a681e059960dfe.metered"
  ],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    46,
    null
   ]
  ],
  "result": [
   {
    "charged": 54,
    "metered_cost_nano": 266250000,
    "metered_requests": 1,
    "refunded": 46,
    "status": "charged_paused",
    "units_reserved": 100
   }
  ],
  "seam": [
   [
    "credit-lease-pauses/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "metered_failed": {
  "meter": [
   "7f9da1d4783ef61963a681e059960dfe.closed",
   "7f9da1d4783ef61963a681e059960dfe.jsonl",
   "7f9da1d4783ef61963a681e059960dfe.metered"
  ],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    100,
    null
   ],
   [
    "assessment_outcome",
    null,
    null,
    null,
    "failed"
   ]
  ],
  "result": {
   "deduped": 0,
   "noop": 0,
   "rejected": 0,
   "settled": 1
  },
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "metered_failed_past_expiry": {
  "meter": [
   "7f9da1d4783ef61963a681e059960dfe.closed",
   "7f9da1d4783ef61963a681e059960dfe.jsonl",
   "7f9da1d4783ef61963a681e059960dfe.metered"
  ],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    46,
    null
   ],
   [
    "assessment_outcome",
    null,
    null,
    null,
    "failed"
   ]
  ],
  "result": {
   "deduped": 0,
   "noop": 0,
   "rejected": 0,
   "settled": 1
  },
  "seam": [
   [
    "credit-lease-paused-past-expiry/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "credit-lease-pauses/cust_5b027ea557ffed11da0e29b3.json",
    []
   ],
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "metered_unpaused_sweep": {
  "meter": [
   "7f9da1d4783ef61963a681e059960dfe.closed",
   "7f9da1d4783ef61963a681e059960dfe.jsonl",
   "7f9da1d4783ef61963a681e059960dfe.metered"
  ],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    100,
    null
   ]
  ],
  "result": [
   {
    "metered_cost_nano": 266250000,
    "metered_requests": 1,
    "refunded": 100,
    "status": "refunded",
    "units_reserved": 100
   }
  ],
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "postpaid_settle": {
  "meter": [],
  "records": [
   [
    "event",
    "governor.postpaid_credit",
    "settle-postpaid:cust_5b027ea557ffed11da0e29b3:pp1",
    60,
    null
   ]
  ],
  "result": [
   {
    "action": "launch_settled",
    "net_spend": 40,
    "ok": true,
    "org_id": "org_a",
    "refunded": 60,
    "refunded_plan": 0,
    "refunded_wallet": 0,
    "slug": "cust_5b027ea557ffed11da0e29b3"
   },
   {
    "action": "launch_already_settled",
    "net_spend": 0,
    "ok": true,
    "org_id": "org_a",
    "refunded": 0,
    "refunded_plan": 0,
    "refunded_wallet": 0,
    "slug": "cust_5b027ea557ffed11da0e29b3"
   }
  ],
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "pp1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 },
 "sweep_refund": {
  "meter": [],
  "records": [
   [
    "event",
    "governor.credit_grant",
    "settle-wallet:cust_5b027ea557ffed11da0e29b3:n1",
    100,
    null
   ]
  ],
  "result": [
   {
    "refunded": 100,
    "status": "refunded",
    "units_reserved": 100
   }
  ],
  "seam": [
   [
    "credit-lease-settlements/cust_5b027ea557ffed11da0e29b3.json",
    [
     "n1"
    ]
   ],
   [
    "target-authorizations/cust_5b027ea557ffed11da0e29b3.json"
   ]
  ]
 }
}
""")


@pytest.mark.parametrize("name", SCENARIOS)
def test_flag_off_golden_spine_sequences_equal_main(name):
    got = json.loads(json.dumps(_scenario(name)))
    assert got == GOLDEN[name]
    assert "governor.launch_settled" not in [x[1] for x in got["records"]]


@pytest.mark.parametrize("name", SCENARIOS)
def test_flag_on_writes_mains_records_plus_one_decision_per_fresh_settle(name, monkeypatch):
    real = _Env.delenv

    def keep_flag(self, k):
        if k == "VIGIL_SETTLE_SPINE_RECORD":
            self._env.setdefault(k, os.environ.get(k))
            os.environ[k] = "1"
            return
        real(self, k)

    monkeypatch.setattr(_Env, "delenv", keep_flag)
    got = json.loads(json.dumps(_scenario(name)))
    decisions = [x for x in got["records"] if x[1] == "governor.launch_settled"]
    assert len(decisions) == 1, got["records"]
    assert [x for x in got["records"] if x[1] != "governor.launch_settled"] == GOLDEN[name]["records"]
    want = json.loads(json.dumps(GOLDEN[name]["result"]))
    if name == "postpaid_settle":
        want[1]["net_spend"] = 40          # flag on: a re-settle reports the RECORDED consumption, not its own 0
    assert (got["result"], got["seam"], got["meter"]) == (want, GOLDEN[name]["seam"], GOLDEN[name]["meter"])
