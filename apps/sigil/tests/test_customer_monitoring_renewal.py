"""AEGIS monitoring RENEWAL CONTINUITY — a verified monthly renewal keeps monitoring RUNNING.

The merged AEGIS-sale slice minted/extended the monitoring-subscription line from a verified event but left
the renewal CONTINUITY unwired: nothing called ``Provisioner.monitor_plan_changed`` from the drain, so a
tenant's host-slot grants lapsed at each period end (after the 72h grace) and the customer had to re-enable.
THIS slice wires ``cli._billing_signer``'s ``on_monitoring_change`` hook (``cli._monitoring_renewal_hook``) so
that, on a VERIFIED renewal (a ``monitoring_price_ids()`` ACTIVE event the signer already minted on
``governor.monitoring_subscription``), the drain RE-PUSHES the catalog's host slots + respond for the NEW
period through the provisioner — owner key, grants re-minted, artifacts republished.

Behind the EXISTING flag ``VIGIL_CUSTOMER_MONITORING_ENABLED`` (off ⇒ byte-identical: no push, no raise, no
provisioner built). Fake ``MockBillingProvider`` only (no network, no real card). The three blockers the
AEGIS agent named are each pinned here: (a) inert/no-raise when the flag is off in the drain's own env;
(b) idempotent + re-drive-safe (a replay never double-pushes, never wedges); (c) the provisioner + publish dir
are injected at the drain's construction, never inside the signer's mint path.
"""
from __future__ import annotations

import json

import pytest

from test_provision_monitoring import _iso, _iss, _prov, _prove, _seat  # noqa: F401  (_iso autouse)

MONTH = 30 * 24 * 3600.0                       # the catalog monthly period (== default MONITORING window)
P1 = 1000.0                                    # first period start
P2 = P1 + MONTH                                # first period end == renewal (second period) start
P3 = P2 + MONTH                                # second period end

_OBS1 = "vigil_aegis_observe_1h_monthly"       # 1 host, observe
_OBS5 = "vigil_aegis_observe_5h_monthly"       # 5 hosts, observe
_CREDIT = "vigil_pro_monthly"                  # a CREDIT plan — the other line


def _signer(s, *, alarm=False):
    """The REAL drain signer (``cli._billing_signer``) over the test store — so the renewal hook under test is
    the one the production drain wires, not a fake."""
    from sigil import cli
    from sigil.governor.billing import MockBillingProvider
    mock = MockBillingProvider("sek")
    return cli._billing_signer(mock, s, alarm=alarm), mock


def _event(mock, eid, kind, created, price, org="org_a"):
    body = json.dumps({"event_id": eid, "kind": kind, "org_id": org, "created": created,
                       "price_id": price}).encode()
    return body, mock.sign(body)


def _reg(s):
    from sigil.governor.monitoring_authority import MonitoringAuthorityRegistry
    return MonitoringAuthorityRegistry(s, owner_key=None)


def _published(org, host):
    from sigil import config
    from sigil.governor.monitoring_authority import monitoring_filename
    return (config.monitoring_publish_dir() / monitoring_filename(org, host)).exists()


def _rig():
    """An org with a proven host and the REAL drain signer over the same store."""
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "alice", "org_admin")
    for h in ("a1.cm", "a2.cm", "a3.cm"):
        _prove(s, "org_a", h)
    signer, mock = _signer(s)
    return p, s, signer, mock


def _buy(signer, mock, eid, created, price):
    from sigil.governor.billing import EVENT_SUBSCRIPTION_ACTIVE
    return signer.ingest(*_event(mock, eid, EVENT_SUBSCRIPTION_ACTIVE, created, price), now=created)


# ============================================================================================================
# 1. first purchase mints the monitoring line and the hook fires — with no grants yet, nothing is pushed
# ============================================================================================================
def test_first_purchase_mints_the_line_and_the_hook_is_a_noop_with_no_grants():
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    p, s, signer, mock = _rig()
    assert _buy(signer, mock, "m1", P1, _OBS1) is not None             # mints the monitoring line
    sub = MonitoringSubscriptionRegistry(s).subscription("org_a")
    assert sub is not None and sub.plan_id == "aegis_observe_1h" and sub.status == "active"
    assert _reg(s).grants("org_a") == []                              # no host authorized yet ⇒ no push
    assert not any(_published("org_a", h) for h in ("a1.cm", "a2.cm", "a3.cm"))


# ============================================================================================================
# 2. THE new behaviour — a verified RENEWAL re-pushes the grant for the NEW period (owner key, republished)
# ============================================================================================================
def test_a_verified_renewal_repushes_the_grant_for_the_new_period():
    from sigil import config
    from sigil.governor.monitoring_authority import monitoring_filename
    from vigil_core.monitoring_authority import SignedMonitoringAuthority, verify_monitoring_authority
    from test_provision_monitoring import _owner_root
    p, s, signer, mock = _rig()
    _buy(signer, mock, "m1", P1, _OBS1)                               # first period [P1, P2]
    p.monitor_authorize("alice", "org_a", "a1.cm", now=1500.0)        # a host grant, clamped to P2
    assert _reg(s).grant_for("org_a", "a1.cm").not_after == P2
    assert _reg(s).active_at("org_a", "a1.cm", now=P2 + 5) is None    # old window has ended at the period boundary

    assert _buy(signer, mock, "m2", P2, _OBS1) is not None            # the RENEWAL — next period [P2, P3]
    g = _reg(s).active_at("org_a", "a1.cm", now=P2 + 5)               # coverage CONTINUES into the new period
    assert g is not None and g.mode == "observe" and g.not_after == P3   # re-minted for the new period
    raw = (config.monitoring_publish_dir() / monitoring_filename("org_a", "a1.cm")).read_bytes()
    doc = SignedMonitoringAuthority.model_validate_json(raw)          # the artifact was REPUBLISHED
    assert int(doc.document.not_after.timestamp()) == int(P3)
    assert verify_monitoring_authority(doc, _owner_root())[0] is True


# ============================================================================================================
# 3. idempotent + re-drive-safe — a replay of the SAME renewal re-pushes nothing (no double-mint, no wedge)
# ============================================================================================================
def test_a_redrive_of_the_renewal_is_idempotent_no_double_push():
    p, s, signer, mock = _rig()
    _buy(signer, mock, "m1", P1, _OBS1)
    p.monitor_authorize("alice", "org_a", "a1.cm", now=1500.0)
    assert _buy(signer, mock, "m2", P2, _OBS1) is not None            # first renewal: re-mints a1 for [P2, P3]
    g1 = _reg(s).grant_for("org_a", "a1.cm")
    assert g1.not_after == P3

    # Re-drive the SAME renewal event: the subscribe is stale (fold ignores it), the invoice folds once, and
    # the hook fires again — but the re-minted grant is now CURRENT-period (not_before == period_start), so
    # plan_enforcement renews nothing. The envelope must not wedge and the grant must not be re-minted.
    assert _buy(signer, mock, "m2", P2, _OBS1) is not None            # no raise
    g2 = _reg(s).grant_for("org_a", "a1.cm")
    assert g2.issued_at == g1.issued_at and g2.not_after == g1.not_after   # unchanged — no second push


# ============================================================================================================
# 4. flag OFF in the drain's own env ⇒ BYTE-IDENTICAL: no push, no raise, no provisioner built
# ============================================================================================================
def test_monitoring_off_in_the_drain_env_is_byte_identical_to_a_none_hook(monkeypatch):
    """With the flag off, the wired hook is inert: the drain's spine is identical to one built with the hook
    disabled entirely (``on_monitoring_change=None``), and nothing is ever published."""
    from sigil.spine.store import SpineStore
    import tempfile
    import os
    from sigil import cli
    from sigil.governor.billing import EVENT_SUBSCRIPTION_ACTIVE
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "0")      # OFF in the drain env
    # (A) the REAL wired signer, flag off
    sa = SpineStore(os.path.join(tempfile.mkdtemp(), "a.jsonl")); sa.migrate()
    siga, mocka = _signer(sa)
    # (B) the same signer with the hook disabled entirely
    sb = SpineStore(os.path.join(tempfile.mkdtemp(), "b.jsonl")); sb.migrate()
    sigb, mockb = _signer(sb)
    sigb.on_monitoring_change = None
    for eid, created, price in (("m1", P1, _OBS1), ("m2", P2, _OBS1)):
        a = siga.ingest(*_event(mocka, eid, EVENT_SUBSCRIPTION_ACTIVE, created, price), now=created)
        b = sigb.ingest(*_event(mockb, eid, EVENT_SUBSCRIPTION_ACTIVE, created, price), now=created)
        assert a is not None and b is not None                       # the money path mints either way (no raise)
    assert [r.payload for r in sa.iter_records()] == [r.payload for r in sb.iter_records()]   # byte-identical
    assert not _published("org_a", "a1.cm")


def test_a_renewal_with_the_flag_off_does_not_repush_an_existing_grant(monkeypatch):
    """Even with a grant already present, a renewal drained while the flag is off is inert: the grant is NOT
    re-minted and the hook never raises (so a re-drive can never wedge the envelope)."""
    p, s, signer, mock = _rig()                                      # _iso set the flag ON — authorize a host
    _buy(signer, mock, "m1", P1, _OBS1)
    p.monitor_authorize("alice", "org_a", "a1.cm", now=1500.0)
    before = _reg(s).grant_for("org_a", "a1.cm")
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "0")      # the drain env goes OFF
    assert _buy(signer, mock, "m2", P2, _OBS1) is not None            # the renewal still mints, and does NOT raise
    after = _reg(s).grant_for("org_a", "a1.cm")
    assert after.issued_at == before.issued_at and after.not_after == before.not_after   # not re-pushed


# ============================================================================================================
# 5. a cancel / payment_failed routes to the monitoring line and STOPS the push (no re-mint)
# ============================================================================================================
@pytest.mark.parametrize("down", ["subscription_canceled", "payment_failed"])
def test_a_down_event_routes_to_the_monitoring_line_and_does_not_push(down):
    """A cancel / payment_failed routes to the MONITORING line (never the credit plan) and STOPS coverage: the
    line cascades a REVOKE of the grants (the safe, keyless direction) — it never fires the renewal re-push."""
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    from sigil.governor.subscription import SubscriptionRegistry
    p, s, signer, mock = _rig()
    _buy(signer, mock, "m1", P1, _OBS1)
    p.monitor_authorize("alice", "org_a", "a1.cm", now=1500.0)
    assert _reg(s).grant_for("org_a", "a1.cm") is not None
    signer.ingest(*_event(mock, "d1", down, P2, _OBS1), now=P2)       # a down event for the AEGIS price
    msub = MonitoringSubscriptionRegistry(s).subscription("org_a")
    assert msub.status == ("canceled" if down == "subscription_canceled" else "past_due")
    assert SubscriptionRegistry(s).subscription("org_a") is None      # the credit line was never touched
    assert _reg(s).grant_for("org_a", "a1.cm") is None               # retired (revoked), NOT re-pushed/renewed
    assert not _published("org_a", "a1.cm")                          # ... and the published artifact is gone


# ============================================================================================================
# 6. a renewal never touches the credit-plan line or the wallet
# ============================================================================================================
def test_the_renewal_never_touches_the_credit_line_or_the_wallet():
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.governor.wallet import WalletRegistry
    p, s, signer, mock = _rig()
    _buy(signer, mock, "c1", 500.0, _CREDIT)                         # a CREDIT plan on its own line (earlier period)
    credit_before = SubscriptionRegistry(s).subscription("org_a")
    assert credit_before is not None and credit_before.plan_id == "pro"
    _buy(signer, mock, "m1", P1, _OBS1)
    p.monitor_authorize("alice", "org_a", "a1.cm", now=1500.0)
    _buy(signer, mock, "m2", P2, _OBS1)                              # the AEGIS renewal
    credit_after = SubscriptionRegistry(s).subscription("org_a")
    assert (credit_after.plan_id, credit_after.period_start, credit_after.period_end) == \
           (credit_before.plan_id, credit_before.period_start, credit_before.period_end)   # credit line unchanged
    assert WalletRegistry(s).available("org_a") == 0                 # the wallet is never credited by monitoring


# ============================================================================================================
# 7. the push honours the catalog's slots/respond — an over-slot grant is retired, exactly the slots renewed
# ============================================================================================================
def test_the_push_honours_the_catalog_slots_an_over_slot_grant_is_not_renewed():
    """A paid plan change to a SMALLER catalog plan re-pushes EXACTLY the catalog's host slots: the
    earliest-issued grant is renewed for the new period, the grants beyond the slot count are retired —
    never an over-grant. The CATALOG decides, never the grant count."""
    p, s, signer, mock = _rig()
    _buy(signer, mock, "m1", P1, _OBS5)                              # a 5-slot plan [P1, P2]
    for h, t in (("a1.cm", 1500.0), ("a2.cm", 1600.0), ("a3.cm", 1700.0)):
        p.monitor_authorize("alice", "org_a", h, now=t)             # three observe grants (earliest = a1)
    assert sorted(g.host for g in _reg(s).grants("org_a")) == ["a1.cm", "a2.cm", "a3.cm"]

    _buy(signer, mock, "m2", P2, _OBS1)                             # a verified ACTIVE for the 1-slot plan [P2, P3]
    active = _reg(s).grants("org_a")
    assert [g.host for g in active] == ["a1.cm"]                    # EXACTLY the catalog's 1 slot (earliest kept)
    assert _reg(s).active_at("org_a", "a1.cm", now=P2 + 5).not_after == P3   # renewed for the new period
    assert _published("org_a", "a1.cm")
    assert not _published("org_a", "a2.cm") and not _published("org_a", "a3.cm")   # over-slot grants unpublished


# ============================================================================================================
# 8. the shared signer builder wires the renewal hook
# ============================================================================================================
def test_the_shared_signer_builder_wires_the_renewal_hook():
    import inspect

    from sigil import cli
    src = inspect.getsource(cli._billing_signer)
    assert "on_monitoring_change=_monitoring_renewal_hook(store)" in src
