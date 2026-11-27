"""AEGIS AS-3c part 2 — drain FLOOD ISOLATION for the monitoring spool.

Part 1 (``test_monitoring_drain_hardening``) made the strict drain crash-durable ("killed drain loses nothing",
exactly once). Part 2 makes it FLOOD-isolated: one tenant spilling a mountain of reports into the spool must not
be able to starve — or unboundedly delay — another tenant's reports or the HEARTBEAT domain's liveness reports,
and the drain's own spine writes must stay under the operator's measured ``sigil spine append-rate`` ceiling.

Two mechanisms, both layered onto the AS-3a per-domain subtree drain (``_drain_strict`` -> ``_drr_drain``):

  * DEFICIT ROUND-ROBIN with a RESERVED heartbeat slice. Each declared domain is served ``drr_quantum`` reports
    per round, round-robin; the heartbeat domain is served FIRST every round and holds a reserved slice of the
    append budget only it may spend. So a flooded domain gets its fair share per round and no more, and the
    heartbeat always gets through (mutation: drop the round-robin / reserve and the flood eats the whole budget
    -> the other tenant and the heartbeat starve -> these tests turn red).

  * APPEND-RATE budget. The per-pass spine-``_record`` budget is derived from the REAL append-rate ceiling
    (``sigil.spine.append_rate``'s ``ceiling``, appends/s — that module builds in no target, so the number is
    the operator's injected, measured write ceiling, never a hardcoded guess) times the seconds one pass is
    allotted. A pass makes at most the budgeted number of RAW spine writes (counted like part 1's ``_raw_events``,
    which is NOT report_id-deduped), and the remainder carries over and drains next pass with nothing lost.

DETERMINISTIC: the budget derives from injected constants and the DRR schedule from a persisted integer cursor —
no wall-clock or RNG in the fairness math. FATAL-2: sovereign-only (``monitoring_spool`` imports no framework/strix).
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import os
import tempfile
from pathlib import Path

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
from sigil.inbound import monitoring_spool as ms
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
NOW = 1_000_000.0
A = ("org_a", "apme.cm")
B = ("org_b", "beta.cm")
C = ("org_c", "gamma.cm")
SECRETS = {A: b"A" * 32, B: b"B" * 32, C: b"C" * 32}
_n = itertools.count(1)


def _store() -> SpineStore:
    return SpineStore(os.path.join(tempfile.mkdtemp(), "spine.jsonl"))


def _grant(store: SpineStore, org: str, host: str) -> MonitoringAuthorityRegistry:
    own = AssetOwnershipRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    ch = own.issue_challenge(org, host, issued_at=NOW - 100)
    own.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW - 99, ttl_seconds=1e9)
    reg = MonitoringAuthorityRegistry(store, owner_key=OWNER, trusted_pubkey=OWNER.public_key_b64)
    reg.grant(org, host, not_before=NOW - 50, not_after=NOW + 1e6, now=NOW - 50)
    return reg


def _rig(domains=(A, B), grants=None, **kw):
    s = _store()
    reg = None
    for o, h in (grants if grants is not None else domains):
        reg = _grant(s, o, h)
    w = ms.MonitoringSpoolWatcher(s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
                                  authority=reg, now_fn=lambda: NOW, domains=domains, **kw)
    return s, w


def _report(org="org_a", host="apme.cm", **kw) -> dict:
    rep = {"schema": ms.REPORT_SCHEMA, "org_id": org, "host": host, "ts": NOW - 10, "decision": "confirmed",
           "attack_class": "sqli", "action": "observe", "confidence": 0.9, "provenance_tier": "certified",
           "certificate_sha256": "c" * 64, "report_id": f"r{next(_n)}"}
    rep.update(kw)
    return rep


def _seal(rep: dict) -> str:
    body = json.dumps(rep, sort_keys=True, separators=(",", ":"))
    mac = hmac.new(SECRETS[(rep["org_id"], rep["host"])], ms.REPORT_DOMAIN + body.encode(), hashlib.sha256).hexdigest()
    return json.dumps({"schema": ms.REPORT_SCHEMA, "body": body, "mac": mac})


def _raw_events(s: SpineStore) -> list[dict]:
    """Every RAW aegis.monitoring_event on the spine — NOT report_id-deduped (so a double-spine would show as a
    count of 2, and a per-pass write budget is countable exactly), exactly like the part-1 helper."""
    return [r.payload for r in s.iter_records()
            if isinstance(r.payload, dict) and r.payload.get("signal") == ms.EVENT_SIGNAL]


def _raw_ids(s: SpineStore, org: str) -> list[str]:
    """The report_ids RAW-spined for one org (with multiplicity, so a double-spine is visible)."""
    return [p.get("report_id") for p in _raw_events(s) if p.get("org_id") == org]


def _seed(w, org: str, host: str, k: int) -> list[str]:
    """Drop ``k`` fresh, valid, sealed reports into (org, host)'s own declared subtree. Returns their ids."""
    d = w.incoming / ms.domain_slug(org, host)
    d.mkdir(parents=True, exist_ok=True)
    ids = []
    for _ in range(k):
        rep = _report(org=org, host=host)
        ids.append(rep["report_id"])
        (d / f"{next(_n)}.json").write_text(_seal(rep))
    return ids


# --- the append-rate budget is keyed off the REAL ceiling, not a hardcoded guess -----------------------------
def test_append_budget_is_derived_from_the_injected_append_rate_ceiling():
    # The budget is ceiling(appends/s) * pass_window_s, floored — the ceiling being the SAME value
    # `sigil.spine.append_rate` consumes (that module builds in no target: "NO TARGET LIVES HERE"), so the drain
    # holds no hardcoded rate. floor(3.0 * 2.0) == 6; floor(2.5 * 1.0) == 2.
    _, w = _rig(domains=(A,), append_ceiling_per_s=3.0, pass_window_s=2.0)
    assert w.append_budget == 6 and w.append_ceiling_per_s == 3.0 and w.pass_window_s == 2.0
    _, w2 = _rig(domains=(A,), append_ceiling_per_s=2.5, pass_window_s=1.0)
    assert w2.append_budget == 2
    # With no ceiling declared there is NO append budget (writes bounded only by the DRR per-domain cap).
    _, w3 = _rig(domains=(A,))
    assert w3.append_budget is None and w3.drr_quantum == w3.per_domain_limit and w3._heartbeat_slug is None


@pytest.mark.parametrize("kw, msg", [
    (dict(append_ceiling_per_s=0.0), "finite number > 0"),
    (dict(append_ceiling_per_s=-1.0), "finite number > 0"),
    (dict(append_ceiling_per_s=float("inf")), "finite number > 0"),
    (dict(append_ceiling_per_s=3.0, pass_window_s=0.0), "pass_window_s"),
    (dict(append_ceiling_per_s=0.4, pass_window_s=1.0), "rounds to 0"),   # 0.4 * 1 -> floor 0 -> refuse
])
def test_append_budget_misconfig_is_fail_closed(kw, msg):
    with pytest.raises(ValueError) as e:
        _rig(domains=(A,), **kw)
    assert msg in str(e.value)


def test_append_budget_and_heartbeat_require_strict_domain_mode():
    # the flood-isolation layer is STRICT-only; declaring it in global mode (domains=None) is refused, not a
    # silent no-op (the global drain must stay byte-identical).
    s = _store()
    reg = _grant(s, *A)
    mk = lambda **kw: ms.MonitoringSpoolWatcher(  # noqa: E731
        s, spool_dir=tempfile.mkdtemp(), secret_for=lambda o, h: SECRETS.get((o, h)),
        authority=reg, now_fn=lambda: NOW, **kw)
    with pytest.raises(ValueError):
        mk(domains=None, append_ceiling_per_s=10.0)                 # budget without strict mode
    with pytest.raises(ValueError):
        mk(domains=None, heartbeat=A)                              # heartbeat without strict mode
    with pytest.raises(ValueError):
        mk(domains=(A,), heartbeat=B)                             # heartbeat not among the declared domains


# --- APPEND-RATE BUDGET: at most the budgeted writes per pass, remainder carries over, nothing lost -----------
def test_append_budget_caps_spine_writes_per_pass_and_carries_over_losslessly():
    # ceiling 3/s over a 1 s pass window => 3 spine writes/pass. Seed 10 valid reports in one domain; each pass
    # spines at most 3 (counted as RAW events), and the backlog carries over until all 10 are drained EXACTLY
    # ONCE. per_domain_limit is left high so the APPEND budget, not the per-domain cap, is what bounds the pass.
    s, w = _rig(domains=(A,), append_ceiling_per_s=3.0, pass_window_s=1.0)
    assert w.append_budget == 3
    ids = _seed(w, *A, 10)
    seen = 0
    for expect in (3, 3, 3, 1, 0):                                 # 10 reports, 3/pass => 3+3+3+1, then empty
        r = w.drain()
        assert r["recorded"] == expect
        seen += expect
        assert len(_raw_events(s)) == seen                         # a pass makes at most the budgeted RAW writes
    assert sorted(_raw_ids(s, "org_a")) == sorted(ids)             # every report spined EXACTLY once — nothing lost


# --- FLOOD ISOLATION: a flood starves neither another tenant nor the heartbeat in one pass -------------------
def test_flood_does_not_starve_another_tenant_or_the_heartbeat():
    # Three declared domains. The FLOOD is assigned to the domain whose slug sorts FIRST, so that the buggy
    # drain (plain sorted-slug order, drain each domain to the budget before the next) would let the flood eat
    # the whole per-pass budget and starve the rest. The DRR + reserved heartbeat must instead serve the
    # heartbeat and the normal tenant fully while the flood drains only its fair share this pass.
    by_slug = sorted((A, B, C), key=lambda d: ms.domain_slug(*d))
    flood, hb, norm = by_slug[0], by_slug[1], by_slug[2]
    s, w = _rig(domains=(A, B, C), heartbeat=hb,
                append_ceiling_per_s=9.0, pass_window_s=1.0,       # budget = 9 writes/pass
                drr_quantum=1, heartbeat_reserve=3)
    assert w.append_budget == 9
    hb_ids = _seed(w, *hb, 3)
    norm_ids = _seed(w, *norm, 3)
    flood_ids = _seed(w, *flood, 50)                              # one tenant floods the spool

    r = w.drain()
    # The heartbeat and the normal tenant are FULLY drained this pass — NOT starved by the 50-deep flood.
    assert sorted(_raw_ids(s, hb[0])) == sorted(hb_ids)
    assert sorted(_raw_ids(s, norm[0])) == sorted(norm_ids)
    # The flood is served only its fair round-robin share this pass (3 of 50), and the pass honoured the budget.
    assert len(_raw_ids(s, flood[0])) == 3
    assert r["recorded"] == 9 and len(_raw_events(s)) == 9
    # MUTATION: remove the reserved-heartbeat + DRR round-robin and drain in plain sorted-slug order to the
    # budget — the flood (sorts first) records all 9 and BOTH the heartbeat and the normal tenant record 0, so
    # the two "fully drained" assertions above turn red. That is the flood-isolation regression this pins.

    # ... and the flood's backlog carries over and drains to completion, each report EXACTLY once, nothing lost.
    for _ in range(12):                                           # bounded number of passes (safety cap)
        if w.drain()["recorded"] == 0:
            break
    assert sorted(_raw_ids(s, flood[0])) == sorted(flood_ids)     # all 50 flood reports, exactly once
    assert len(_raw_ids(s, hb[0])) == 3 and len(_raw_ids(s, norm[0])) == 3   # no tenant double-spined


# --- the RESERVED heartbeat slice specifically: it drains even after the flood has eaten the shared budget ----
def test_reserved_heartbeat_drains_even_when_the_flood_consumes_the_shared_budget():
    # The reserve is what guarantees the heartbeat across ROUNDS: budget 4 = reserve 3 (heartbeat-only) + shared
    # 1 (any domain). With quantum 1 the flood takes the 1 shared write in round 1, then can spend nothing more;
    # the heartbeat keeps draining from its reserved 3 over the next rounds. All 3 heartbeat reports get through.
    s, w = _rig(domains=(A, B), heartbeat=A,
                append_ceiling_per_s=4.0, pass_window_s=1.0,       # budget = 4
                drr_quantum=1, heartbeat_reserve=3)
    assert w.append_budget == 4 and w.heartbeat_reserve == 3
    hb_ids = _seed(w, *A, 3)
    _seed(w, *B, 50)                                              # the flood
    r = w.drain()
    assert sorted(_raw_ids(s, "org_a")) == sorted(hb_ids)         # the heartbeat's 3 reports ALL got through
    assert len(_raw_ids(s, "org_b")) == 1                         # the flood got only the 1 shared write this pass
    assert r["recorded"] == 4
    # MUTATION: drop the reserved pool (one shared budget of 4) — the flood interleaves and takes 2 of the 4
    # writes, so the heartbeat drains only 2 of its 3 this pass and its 3rd report is delayed by the flood. The
    # `== hb_ids` assertion (all 3) turns red. The reserved slice is exactly what makes the heartbeat immune.


def test_reserved_heartbeat_defaults_to_the_heartbeats_equal_share():
    # No explicit reserve: it defaults to the heartbeat's OWN equal share of the budget (budget // #domains, >=1),
    # so a sensible reservation holds even when the operator sets only the ceiling + heartbeat.
    _, w = _rig(domains=(A, B, C), heartbeat=A, append_ceiling_per_s=9.0, pass_window_s=1.0)
    assert w.append_budget == 9 and w.heartbeat_reserve == 3      # 9 // 3 declared domains


# --- the DRR cursor rotates, so a sustained tight budget never PERMANENTLY starves a late-sorting domain ------
def test_drr_rotation_prevents_cross_pass_starvation_under_a_tight_budget():
    # Budget of 1 write/pass, 3 declared domains, NO heartbeat. The FIRST-sorting domain holds a PERSISTENT
    # flood (5), the other two one report each. Only one domain can be served per pass, so fairness must come
    # from ROTATING which domain goes first each pass — otherwise the flood (first, never empties) is served
    # every pass and the other two starve. Over 3 passes the rotation serves the flood once and EACH of the two
    # small tenants once. (MUTATION: pin the start index -> the flood is served every pass and the two small
    # tenants starve -> the "both small tenants drained" assertion turns red.)
    by_slug = sorted((A, B, C), key=lambda d: ms.domain_slug(*d))
    flood, small1, small2 = by_slug[0], by_slug[1], by_slug[2]
    s, w = _rig(domains=(A, B, C), append_ceiling_per_s=1.0, pass_window_s=1.0, drr_quantum=1)
    assert w.append_budget == 1
    _seed(w, *flood, 5)                                          # the first-sorting domain never empties
    s1_ids = _seed(w, *small1, 1)
    s2_ids = _seed(w, *small2, 1)
    for _ in range(3):
        assert w.drain()["recorded"] == 1                        # exactly one domain served per pass (the budget)
    # The two small tenants are BOTH served within 3 passes despite the flood that sorts ahead of them.
    assert sorted(_raw_ids(s, small1[0])) == sorted(s1_ids)
    assert sorted(_raw_ids(s, small2[0])) == sorted(s2_ids)
    assert len(_raw_ids(s, flood[0])) == 1                       # the flood got only its fair one-per-three-passes


# --- strict mode without any flood params stays byte-identical to the AS-3a drain ----------------------------
def test_strict_without_flood_params_matches_as3a_drain_in_one_pass():
    # No heartbeat, no ceiling: the DRR degrades to the AS-3a order (each declared domain drains its whole
    # per-pass share, in signed-slug order) — two declared domains both fully drain in ONE pass.
    s, w = _rig(domains=(A, B))
    assert w.append_budget is None and w._heartbeat_slug is None
    a_ids = _seed(w, *A, 4)
    b_ids = _seed(w, *B, 4)
    r = w.drain()
    assert r["recorded"] == 8 and r["off_domain"] == 0 and r["rejected"] == 0
    assert sorted(_raw_ids(s, "org_a")) == sorted(a_ids)
    assert sorted(_raw_ids(s, "org_b")) == sorted(b_ids)
