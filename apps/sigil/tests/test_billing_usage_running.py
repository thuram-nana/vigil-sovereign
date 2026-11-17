"""W6 — the server figures the Billing dashboard renders (``billing_usage``, behind ``VIGIL_METERED_BILLING``).

* Per scan: ``billing_usage`` already sums a running scan's held credit into the top-level ``held_mc`` (W2c-2). W6
  exposes, per scan, ``running`` (reserved but not yet settled) and, for a running scan, ``held_mc`` — its OWN share
  of that aggregate (its reserved allowance less what it has consumed so far, or the whole allowance when its meter
  is unavailable). With ``VIGIL_METERED_BILLING`` off the per-scan shape is byte-identical (no new keys).
* Bought / trial: ``bought_mc`` is the org's ``topup`` purchases and ``trial_mc`` its ``trial`` grant, from the same
  verified grant scan as the balance-after timeline (``WalletRegistry.purchase_grants``). The wallet's ``granted``
  total is NOT "bought": every settlement returns a scan's unused reservation as a ``refund`` grant.

Drives the REAL reserve -> metered publish -> gateway meter -> settle path, like test_exact_statement.

Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the per-scan running flag (ok branch)     -> test_a_running_scan_exposes_its_live_consumption_and_hold
  * drop the per-scan held_mc (ok branch)          -> test_a_running_scan_exposes_its_live_consumption_and_hold
  * drop the per-scan held_mc (unavailable branch) -> test_an_unavailable_running_scan_holds_its_whole_allowance
  * add running even with metered off              -> test_the_per_scan_fields_are_absent_with_metered_off
  * count the trial (or a refund) as bought        -> test_bought_counts_only_topups_never_a_refund_or_the_trial
"""
from __future__ import annotations

import json

from sigil.governor.wallet import WalletRegistry
from test_exact_statement import (NOW, U500, U2502, _iso, _launch, _org, _settle, _store, _topup,  # noqa: F401
                                  _usage, _use)


def test_a_running_scan_exposes_its_live_consumption_and_hold():
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm", units=10)          # holds a 10-credit allowance
    _use(r, "org_a", U2502, at=NOW)                       # consumed 2.502, NOT settled -> still running
    out = _usage(s, "org_a", now=NOW + 100)
    scan = next(sc for sc in out["scans"] if sc["launch"] == r["nonce"])
    assert scan["running"] is True
    assert scan["status"] == "ok" and scan["credits"] == "2.502" and scan["amount_mc"] == 2502
    assert scan["held_mc"] == 7_498                       # 10,000 reserved - 2,502 consumed: this scan's own share
    assert scan["held_mc"] == out["held_mc"]              # the only running scan -> its hold == the aggregate


def test_a_settled_scan_is_not_running_and_holds_nothing():
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm")
    _use(r, "org_a", U2502, at=NOW)
    _settle(g, r)
    out = _usage(s, "org_a", now=NOW + 30_000)
    scan = out["scans"][0]
    assert scan["running"] is False and "held_mc" not in scan   # settled -> not running, holds nothing
    assert out["held_mc"] == 0


def test_an_unavailable_running_scan_holds_its_whole_allowance():
    from sigil import config
    from vigil_core.model_grant import meter_id
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm", units=10)          # 10-credit allowance, never settled
    _use(r, "org_a", U2502, at=NOW)
    p = config.MODEL_METER_DIR / f"{meter_id(r['slug'], r['nonce'])}.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[-1]); rec["usage"]["output_tokens"] = 1   # tamper -> the hash chain no longer verifies
    p.write_text("\n".join(lines[:-1] + [json.dumps(rec)]) + "\n")
    out = _usage(s, "org_a", now=NOW + 100)
    scan = out["scans"][0]
    assert scan["status"] == "unavailable" and scan["running"] is True
    # its usage cannot be read, so it holds its WHOLE allowance (no consumption is assumed against it)
    assert scan["held_mc"] == 10_000 and out["held_mc"] == 10_000


def test_the_per_scan_fields_are_absent_with_metered_off(monkeypatch):
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=100)
    r = _launch(g, "org_a", "apme.cm", units=10)
    _use(r, "org_a", U2502, at=NOW)
    on = _usage(s, "org_a", now=NOW + 100)
    assert on["scans"][0]["running"] is True and on["scans"][0]["held_mc"] == 7_498
    monkeypatch.delenv("VIGIL_METERED_BILLING", raising=False)
    off = _usage(s, "org_a", now=NOW + 100)
    assert all("running" not in sc and "held_mc" not in sc for sc in off["scans"])
    # every pre-existing scan key is identical whether or not the flag is on (byte-identical but for the two keys)
    assert [{k: v for k, v in sc.items() if k not in ("running", "held_mc")} for sc in on["scans"]] == off["scans"]


def test_bought_counts_only_topups_never_a_refund_or_the_trial():
    s = _store()
    g = _org(s, "org_a", "apme.cm", credits=50)          # a 50-credit TRIAL grant
    _topup(s, "org_a", 20, at=NOW + 5)                   # a 20-credit top-up PURCHASE
    r = _launch(g, "org_a", "apme.cm", units=10)
    _use(r, "org_a", U500, at=NOW)
    _settle(g, r)                                        # the settle GRANTS back the unused reservation (a refund)
    w = WalletRegistry(s)
    assert w.balance("org_a").granted > 70               # the wallet's granted counts that refund: it is NOT "bought"
    out = _usage(s, "org_a", now=NOW + 30_000)
    assert out["bought_mc"] == 20_000 and out["trial_mc"] == 50_000
    # one verified scan serves both: the kinds kept for the totals, the W2c-2 timeline view unchanged
    assert w.purchase_grants("org_a") == [(NOW - 1000, 50, "trial"), (NOW + 5, 20, "topup")]
    assert w.purchase_events("org_a") == [(NOW - 1000, 50), (NOW + 5, 20)]
    assert out["remaining_mc"] == 69_500 == w.balance("org_a").exact_available_mc   # I4 still holds (70 - 0.5)
