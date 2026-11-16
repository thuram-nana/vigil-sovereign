"""Pricing design §0 W1 — the customer's published rates and per-charge usage statement (credits only).

Drives the REAL reservation path (``LaunchGate.reserve_launch``) and the REAL gateway meter (``GrantMeter``), then
reads the projections the customer routes serve. Pins:
  * the published rates are the rate card, in credits, with nothing in money;
  * each metered AI request becomes one charge with per-unit lines (quantity, unit rate, credits) exact to 0.001
    credit, and the scan total is their sum;
  * the statement is tenant-scoped: another org's scan never appears;
  * a meter whose hash chain is broken is reported unavailable, never priced;
  * the customer statement never names the model and carries no money amount or estimate.

Mutation-verify targets:
  * drop the org filter (the scan's and the loop's)   -> test_the_statement_is_tenant_scoped
  * price a corrupt meter                      -> test_a_corrupt_meter_is_unavailable_not_priced
  * round a line up to a whole credit          -> test_each_request_is_one_charge_priced_from_the_rate_card
"""
from __future__ import annotations

import itertools
import json
import tempfile

import pytest

from sigil import config
from sigil import model_gateway as gw
from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import billing
from sigil.ui.launch_gate import LaunchGate
from sigil.ui.target_authorization import add_customer_target
from vigil_core import model_metering as mm
from vigil_core.model_grant import ModelGrant, meter_id

_iss = itertools.count(1)
NOW = 2000.0


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setattr(config, "MODEL_METER_DIR", tmp_path / "model_meter")
    monkeypatch.delenv("VIGIL_RATE_CARD", raising=False)


def _reserve(store, org, host):
    ensure_owner_keypair()
    orgs = OrgRegistry(store)
    orgs.create_org(org, org, owner="u", issued_at=float(next(_iss)))
    orgs.grant_membership(org, "u", "operator", issued_at=float(next(_iss)))
    WalletRegistry(store).grant(org, 1_000, "trial", entry_id=f"trial:{org}", issued_at=float(next(_iss)))
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(_iss)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=NOW, ttl_seconds=1e12)
    assert add_customer_target(host, org_id=org, store=store, now=NOW)["ok"]
    r = LaunchGate(store).reserve_launch(requester="u", org_id=org, host=host, units=100, now=NOW)
    assert r["ok"], r
    return r


def _spend(org, r, usage: mm.Usage, *, at: float = NOW) -> None:
    m = gw.GrantMeter(config.MODEL_METER_DIR)
    g = ModelGrant(grant_id="0" * 32, org_id=org, engagement_slug=r["slug"], nonce=r["nonce"],
                   model="claude-opus-4-8", effort="high", cap_nano_usd=10 ** 12, not_after=at + 86_400,
                   issued_at=at - 60)
    rid, _res, reason = m.reserve(g, 10 ** 6, 25_000, now=at)
    assert reason == "", reason
    m.commit(g, rid, usage, 1, request_id="req", now=at)


def _usage(store, org):
    return billing.billing_usage(store, org, trusted_pubkey=ensure_owner_keypair().public_key_b64,
                                 meter_dir=config.MODEL_METER_DIR)


def test_the_published_rates_are_in_credits_only():
    out = billing.billing_rates()["rates"]
    assert out["currency"] == "credits"
    assert {r["unit"]: r["credits"] for r in out["ai"]}["output_tokens"] == "6250.000"
    text = json.dumps(out).lower()
    assert "usd" not in text.replace("credits_per_usd", "") and "estimate" not in text and "claude" not in text


def test_each_request_is_one_charge_priced_from_the_rate_card():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    r = _reserve(s, "org_a", "apme.cm")
    _spend("org_a", r, mm.Usage(input_tokens=1000, output_tokens=200), at=NOW)
    _spend("org_a", r, mm.Usage(input_tokens=1), at=NOW + 5)
    out = _usage(s, "org_a")
    assert out["count"] == 2 and out["currency"] == "credits"
    newest, oldest = out["charges"]
    assert newest["ts"] == NOW + 5 and newest["credits"] == "0.002"        # 1.25 mc -> 2 mc, not a whole credit
    assert [(ln["unit"], ln["quantity"], ln["rate"], ln["credits"]) for ln in oldest["lines"]] == [
        ("input_tokens", 1000, "1250.000", "1.250"), ("output_tokens", 200, "6250.000", "1.250")]
    assert oldest["credits"] == "2.500" and oldest["operation"] == "AI analysis"
    (scan,) = out["scans"]
    assert scan["status"] == "ok" and scan["requests"] == 2 and scan["amount_mc"] == 2502
    assert out["credits"] == "2.502"
    text = json.dumps(out).lower()
    assert "claude" not in text and "opus" not in text and "usd" not in text and "estimate" not in text


def test_the_statement_is_tenant_scoped():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    ra = _reserve(s, "org_a", "apme.cm")
    rb = _reserve(s, "org_b", "bpme.cm")
    _spend("org_a", ra, mm.Usage(output_tokens=100))
    _spend("org_b", rb, mm.Usage(output_tokens=999))
    a = _usage(s, "org_a")
    assert [c["scan"] for c in a["charges"]] == [ra["slug"]] and [sc["scan"] for sc in a["scans"]] == [ra["slug"]]
    assert _usage(s, "org_c")["charges"] == []


def test_a_corrupt_meter_is_unavailable_not_priced():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    r = _reserve(s, "org_a", "apme.cm")
    _spend("org_a", r, mm.Usage(output_tokens=100))
    p = config.MODEL_METER_DIR / f"{meter_id(r['slug'], r['nonce'])}.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[-1])
    rec["usage"]["output_tokens"] = 1                                       # edit a recorded response
    p.write_text("\n".join(lines[:-1] + [json.dumps(rec)]) + "\n")
    out = _usage(s, "org_a")
    assert out["charges"] == [] and out["scans"][0]["status"] == "unavailable" and out["amount_mc"] == 0


def test_a_scan_with_no_usage_yet_is_listed_at_zero():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    _reserve(s, "org_a", "apme.cm")
    out = _usage(s, "org_a")
    assert out["scans"][0]["status"] == "ok" and out["scans"][0]["credits"] == "0.000" and out["charges"] == []
