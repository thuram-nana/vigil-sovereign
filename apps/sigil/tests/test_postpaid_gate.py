"""PP-1 launch-gate integration — enterprise POSTPAID draws against the owner-signed credit line at the launch
path, instead of burning prepaid credits.

Load-bearing invariants (a false-green would let a postpaid tenant run unbounded free scans, or mis-refund a
postpaid draw into the prepaid wallet):
  * a postpaid-ENABLED tenant with ZERO prepaid credits can reserve, and the draw ACCRUES as arrears;
  * the cumulative drawn balance is capped at the owner-signed credit_limit (over-limit refuses, nothing accrues);
  * settle reverses the UNCONSUMED draw so net arrears == consumed (cancel fully reverses); idempotent per
    (slug, nonce) — a re-settle never re-reverses (no free run);
  * the postpaid reservation is detected by its OWNER-SIGNED arrears debit record, so a settle still reverses
    against arrears even if the owner disabled the line mid-engagement (never mis-refunds to the wallet);
  * a tenant with NO postpaid account takes the UNCHANGED prepaid path (byte-identical).

Runs on the integration PYTHONPATH (the authority broker + add_customer_target live across the seam), exactly
like test_launch_gate.py.

Run: PYTHONPATH=apps/sigil:integration .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_postpaid_gate.py -q
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _setup(store, org, host, *, role="operator", credits=0, proof=True, authority=True, now=1000.0,
           postpaid=None):
    """Seat a member + (optional) wallet credits + ownership proof + a minted EngagementAuthority, and
    optionally open an owner-signed postpaid credit line (postpaid=(credit_limit, net_terms_days))."""
    from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.postpaid import PostpaidRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.ui.target_authorization import add_customer_target
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", role, issued_at=float(next(_iss)))
    if credits:
        WalletRegistry(store).grant(org, credits, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    if proof or authority:
        reg = AssetOwnershipRegistry(store)
        ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
        reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=now, ttl_seconds=1e12)
        if authority:
            r = add_customer_target(host, org_id=org, store=store, now=now)
            assert r["ok"], r
        if not proof:
            reg.revoke_proof(org, host)
    if postpaid is not None:
        limit, net = postpaid
        PostpaidRegistry(store).set_account(org, limit, net, issued_at=float(next(_iss)))


def _gate(store):
    from sigil.ui.launch_gate import LaunchGate
    return LaunchGate(store)


def _avail(store, org):
    from sigil.governor.wallet import WalletRegistry
    return WalletRegistry(store).available(org)


def _accrued(store, org):
    from sigil.governor.postpaid import PostpaidArrearsLedger
    return PostpaidArrearsLedger(store).accrued(org)


# --- draw against the line, no prepaid credits needed -------------------------------------------------
def test_postpaid_launches_with_zero_prepaid_and_accrues():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(500, 30))
    assert _avail(s, "org_a") == 0 and _accrued(s, "org_a") == 0
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"], r
    assert _accrued(s, "org_a") == 30          # drawn against the credit line
    assert _avail(s, "org_a") == 0             # prepaid wallet untouched


def test_postpaid_over_limit_refused_nothing_accrued():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(50, 30))
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=80, now=2000.0)
    assert r["ok"] is False and "over postpaid credit line" in r["error"]
    assert _accrued(s, "org_a") == 0           # NOTHING accrued on refusal


def test_postpaid_cumulative_limit_enforced_across_launches():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(100, 30))
    g = _gate(s)
    r1 = g.reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=60, now=2000.0, nonce="n1")
    assert r1["ok"] and _accrued(s, "org_a") == 60
    r2 = g.reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=60, now=2000.0, nonce="n2")
    assert r2["ok"] is False and "over postpaid credit line" in r2["error"]   # 60 + 60 > 100
    assert _accrued(s, "org_a") == 60
    r3 = g.reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=40, now=2000.0, nonce="n3")
    assert r3["ok"] and _accrued(s, "org_a") == 100   # exactly at the limit is allowed


def test_postpaid_settle_reverses_unconsumed_draw():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(500, 30))
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=100, now=2000.0, nonce="nn")
    assert r["ok"] and _accrued(s, "org_a") == 100
    st = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=30, now=3000.0)
    assert st["ok"] and st["net_spend"] == 30 and st["refunded"] == 70, st
    assert _accrued(s, "org_a") == 30          # net arrears == consumed


def test_postpaid_cancel_fully_reverses_draw():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(500, 30))
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=100, now=2000.0, nonce="nc")
    assert _accrued(s, "org_a") == 100
    st = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=0, now=3000.0)   # cancel
    assert st["ok"] and st["net_spend"] == 0
    assert _accrued(s, "org_a") == 0           # the whole draw reversed


def test_postpaid_settle_idempotent_no_double_reverse():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(500, 30))
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=100, now=2000.0, nonce="ni")
    g = _gate(s)
    st1 = g.settle_launch(signed_lease=r["lease"], consumed_units=30, now=3000.0)
    assert st1["ok"] and _accrued(s, "org_a") == 30
    st2 = g.settle_launch(signed_lease=r["lease"], consumed_units=0, now=3100.0)   # re-settle (cancel) -> no-op
    assert st2["action"] == "launch_already_settled", st2
    assert _accrued(s, "org_a") == 30          # NOT re-reversed (would make a charged run free)


def test_postpaid_settle_reverses_even_if_line_disabled_midflight():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(500, 30))
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=100, now=2000.0, nonce="nd")
    assert _accrued(s, "org_a") == 100
    from sigil.governor.postpaid import PostpaidRegistry
    PostpaidRegistry(s).disable("org_a")       # owner closes the line between reserve and settle
    st = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=20, now=3000.0)
    assert st["ok"] and st["net_spend"] == 20
    assert _accrued(s, "org_a") == 20          # still reversed against arrears (detected via the debit record)


def test_settle_reverses_a_postpaid_draw_after_a_hard_prune_of_the_debit_record(monkeypatch):
    # RED-PEN HIGH (end-to-end): a hard prune drops the reserve-postpaid debit record; the snapshot seed carries
    # only the per-org balance + seen-set. settle must STILL detect the postpaid reservation (via the
    # prune-durable was_accrued discriminator) and reverse the arrears — never mint prepaid wallet credits from
    # the draw. Pre-fix (live-scan discriminator) this minted reserved-consumed wallet credits + left arrears full.
    from sigil.governor.identity import owner_pubkey
    from sigil.governor.postpaid import PostpaidArrearsLedger
    from sigil.spine.snapshot import SnapshotState, build
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(500, 30))
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=100, now=2000.0, nonce="np")
    assert r["ok"] and _accrued(s, "org_a") == 100
    recs = list(s.iter_records())
    k = recs[-1].seq + 1                                      # a boundary PAST every record (incl. the debit)
    snap = build(recs, trusted_pubkey=owner_pubkey(), base_seq=k, snapshot_seq=k - 1)

    class _Pruned:
        def __init__(self, inner, K):
            self._i, self._K = inner, K

        def iter_records(self, *, since_seq=-1):
            for rr in self._i.iter_records(since_seq=since_seq):
                if rr.seq >= self._K:
                    yield rr

        def get(self, seq):
            return self._i.get(seq)

        def append(self, **kw):
            return self._i.append(**kw)

        @property
        def path(self):
            return getattr(self._i, "path", "")

    pruned = _Pruned(s, k)                                    # hides every <k record, incl. the reserve debit
    monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, ss: snap))
    st = _gate(pruned).settle_launch(signed_lease=r["lease"], consumed_units=30, now=3000.0, expect_org_id="org_a")
    assert st["ok"] and st["net_spend"] == 30 and st["refunded_wallet"] == 0, st
    assert PostpaidArrearsLedger(pruned).accrued("org_a") == 30   # arrears reversed to consumed, via the seed
    assert _avail(s, "org_a") == 0                                # NO prepaid wallet credits minted from the draw


def test_disabled_postpaid_account_falls_back_to_prepaid():
    # an org whose line is DISABLED is not postpaid: the gate takes the prepaid path and refuses with no credits.
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(500, 30))
    from sigil.governor.postpaid import PostpaidRegistry
    PostpaidRegistry(s).disable("org_a")
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=10, now=2000.0)
    assert r["ok"] is False and "insufficient credits" in r["error"]   # prepaid path, 0 credits
    assert _accrued(s, "org_a") == 0


def test_prepaid_path_byte_identical_when_no_postpaid_record():
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=100)      # prepaid, NO postpaid account
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=30, now=2000.0)
    assert r["ok"] and _avail(s, "org_a") == 70     # prepaid debited exactly as before PP-1
    assert _accrued(s, "org_a") == 0                # no arrears
    st = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=10, now=3000.0)
    assert st["ok"] and st["net_spend"] == 10 and st["refunded"] == 20
    assert _avail(s, "org_a") == 90                 # 20 of the 30 refunded to the wallet (prepaid bucket path)


def test_postpaid_full_consumption_settle_is_recorded_and_billable():
    # RED-PEN HIGH (PP-2 FOLD): a launch that consumes its ENTIRE reservation settles with refund 0. The gate
    # must STILL record the settlement (the marker), so `in_flight_reserved` clears the reserve and PP-2 bills the
    # full consumption. Pre-fix the gate wrote the reversal only `if refund > 0`, so a fully-consumed launch left
    # NO settle record -> it looked perpetually in-flight -> net_settled_consumed read 0 -> invoiced $0 (a silent
    # revenue leak). This drives the real gate settle path (not the ledger directly), so a revert to `if refund>0`
    # reds here.
    from sigil.governor.postpaid import PostpaidArrearsLedger
    s = _store()
    _setup(s, "org_a", "apme.cm", credits=0, postpaid=(500, 30))
    r = _gate(s).reserve_launch(requester="u", org_id="org_a", host="apme.cm", units=100, now=2000.0, nonce="nf")
    assert r["ok"] and _accrued(s, "org_a") == 100
    st = _gate(s).settle_launch(signed_lease=r["lease"], consumed_units=100, now=3000.0)   # FULL consumption
    assert st["ok"] and st["net_spend"] == 100 and st["refunded"] == 0, st
    arr = PostpaidArrearsLedger(s)
    assert arr.accrued("org_a") == 100                 # refund 0 -> arrears stays at the consumed 100
    assert arr.in_flight_reserved("org_a") == 0        # the settle MARKER cleared the reserve from in-flight
    assert arr.net_settled_consumed("org_a") == 100    # ...so PP-2 bills the full 100 (NOT 0 — the leak is closed)
