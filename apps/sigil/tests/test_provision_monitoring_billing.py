"""AEGIS-SaaS AE-5 — monitoring is BILLED: monitor_authorize requires an active, in-period monitoring plan with a
free protected-host slot; mode=block requires a respond tier. The owner CATALOG decides what a plan buys."""
from __future__ import annotations

import pytest

from test_provision_monitoring import _iso, _iss, _prov, _prove, _seat, _subscribe  # noqa: F401


def _rig(plan=None, **kw):
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "alice", "org_admin")
    _seat(orgs, "org_b", "bob", "org_admin")
    for h in ("a1.cm", "a2.cm"):
        _prove(s, "org_a", h)
    _prove(s, "org_b", "b1.cm")
    if plan:
        _subscribe(s, "org_a", plan, **kw)
    return p, s


def _denied(fn):
    from sigil.ui.provision import ProvisionDenied
    with pytest.raises(ProvisionDenied) as ei:
        fn()
    return str(ei.value)


def test_catalog_monitoring_plans_are_per_host_and_tiered():
    from sigil.governor import catalog as cat
    o1, o5 = cat.monitoring_plan("aegis_observe_1h"), cat.monitoring_plan("aegis_observe_5h")
    r1 = cat.monitoring_plan("aegis_respond_1h")
    assert (o1.host_slots, o1.respond) == (1, False) and o5.host_slots == 5 and r1.respond is True
    assert cat.monitoring_plan("pro") is None and cat.monitoring_plan("") is None
    amt = cat.expected_amounts()
    assert amt["vigil_aegis_observe_5h_monthly"][0] == 5 * amt["vigil_aegis_observe_1h_monthly"][0]
    assert cat.entitlements()["vigil_aegis_observe_1h_monthly"].allotment == 0   # no credit refill


def test_catalog_rejects_malformed_monitoring_entry():
    from sigil.governor.billing import EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP
    from sigil.governor.catalog import CatalogEntry, _validate
    for bad in (CatalogEntry("t", EVENT_TOPUP, "x", 1, "USD", credits=1, monitor_hosts=1),
                CatalogEntry("s", EVENT_SUBSCRIPTION_ACTIVE, "x", 1, "USD", plan_id="p", period_s=1.0),
                CatalogEntry("s", EVENT_SUBSCRIPTION_ACTIVE, "x", 1, "USD", plan_id="p", period_s=1.0,
                             allotment=1, monitor_respond=True),
                CatalogEntry("s", EVENT_SUBSCRIPTION_ACTIVE, "x", 1, "USD", plan_id="p", period_s=1.0,
                             monitor_hosts=-1)):
        with pytest.raises(ValueError):
            _validate((bad,))


def test_no_plan_refused():
    p, _ = _rig()
    assert "monitoring plan" in _denied(lambda: p.monitor_authorize("alice", "org_a", "a1.cm"))


def test_non_monitoring_plan_refused():
    p, _ = _rig("pro")
    assert "monitoring plan" in _denied(lambda: p.monitor_authorize("alice", "org_a", "a1.cm"))


def test_lapsed_or_canceled_plan_refused():
    p, _ = _rig("aegis_observe_5h", period_end=1.0)           # period already over at now>=1000
    _denied(lambda: p.monitor_authorize("alice", "org_a", "a1.cm"))
    p, s = _rig("aegis_observe_5h")
    from sigil.governor.subscription import SubscriptionRegistry
    SubscriptionRegistry(s).cancel("org_a")
    _denied(lambda: p.monitor_authorize("alice", "org_a", "a1.cm"))


def test_host_slots_enforced_and_reauthorize_reuses_slot():
    p, _ = _rig("aegis_observe_1h")
    assert p.monitor_authorize("alice", "org_a", "a1.cm")["mode"] == "observe"
    assert p.monitor_authorize("alice", "org_a", "a1.cm")["host"] == "a1.cm"   # same host: no new slot
    assert "slot" in _denied(lambda: p.monitor_authorize("alice", "org_a", "a2.cm"))
    p.monitor_revoke("alice", "org_a", "a1.cm")                                # revoke frees the slot
    assert p.monitor_authorize("alice", "org_a", "a2.cm")["host"] == "a2.cm"


def test_block_requires_respond_tier():
    p, _ = _rig("aegis_observe_5h")
    assert "respond" in _denied(lambda: p.monitor_authorize("alice", "org_a", "a1.cm", mode="block"))
    p, _ = _rig("aegis_respond_1h")
    assert p.monitor_authorize("alice", "org_a", "a1.cm", mode="block")["mode"] == "block"


def test_plan_is_per_org_not_shared():
    p, _ = _rig("aegis_respond_5h")                          # only org_a pays
    assert p.monitor_authorize("alice", "org_a", "a1.cm")
    assert "monitoring plan" in _denied(lambda: p.monitor_authorize("bob", "org_b", "b1.cm"))
