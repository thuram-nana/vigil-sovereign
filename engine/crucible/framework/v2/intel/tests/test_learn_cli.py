"""
Phase D — cross-engagement source-yield learning and the `intel` CLI.

Learning is Bayesian-shrunk: an unknown source sits at the neutral default (never
penalised for lack of history), and only consistent yield — especially confirmed
findings — moves its prior. The CLI runs offline end-to-end against the bundled
fixtures and reads durable state back.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.v2.intel import cli as intel_cli
from framework.v2.intel import learn
from framework.v2.intel.models import IntelSourceKind
from framework.v2.intel.store import IntelStore
from framework.v2.memory.store import open_store


# ---- learning ----------------------------------------------------------------


def test_unknown_source_prior_is_the_default(tmp_path: Path) -> None:
    store = open_store(tmp_path / "mls.sqlite")
    istore = IntelStore(store)
    # no history at all → the neutral default, NOT a penalty
    assert learn.source_prior(istore, IntelSourceKind.DNS, archetype="saas", default=0.5) == 0.5
    store.close()


def test_yield_raises_prior_and_findings_dominate(tmp_path: Path) -> None:
    store = open_store(tmp_path / "mls.sqlite")
    istore = IntelStore(store)
    # a source that queried a lot and surfaced assets AND findings
    istore.bump_source_yield("cert_transparency", archetype="saas",
                             queries=10, observations=40, entities=8, findings=3)
    # a source that queried a lot but never paid off
    istore.bump_source_yield("asn_bgp", archetype="saas", queries=10, observations=2)
    store.commit()
    high = learn.source_prior(istore, IntelSourceKind.CERT_TRANSPARENCY, archetype="saas")
    low = learn.source_prior(istore, IntelSourceKind.ASN_BGP, archetype="saas")
    assert high > 0.5 > low            # yield lifts, barrenness lowers
    assert 0.05 <= low and high <= 0.95   # never absolute
    priors = learn.planner_priors(istore, [IntelSourceKind.CERT_TRANSPARENCY, IntelSourceKind.ASN_BGP],
                                  archetype="saas")
    assert priors["cert_transparency"] == high
    store.close()


def test_credit_finding_moves_prior_more_than_observations(tmp_path: Path) -> None:
    store = open_store(tmp_path / "mls.sqlite")
    istore = IntelStore(store)
    istore.bump_source_yield("dns", archetype="a", queries=5, observations=5, entities=1)
    istore.bump_source_yield("rdap_whois", archetype="a", queries=5, observations=5, entities=1)
    store.commit()
    before_dns = learn.source_prior(istore, "dns", archetype="a")
    learn.credit_finding(istore, ["dns"], archetype="a")   # a real bug downstream of a DNS-found asset
    after_dns = learn.source_prior(istore, "dns", archetype="a")
    assert after_dns > before_dns
    store.close()


# ---- CLI smoke (offline, end-to-end) ----------------------------------------


def test_cli_ingest_then_resolve_offline(tmp_path, monkeypatch, capsys) -> None:
    # point the memory DB at a temp file so the CLI's open_store() is isolated
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")

    rc = intel_cli.main(["ingest", "--seed", "company.com", "--slug", "acme",
                         "--archetype", "saas", "--max-depth", "2"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] > 0
    assert out["owned_entities"], "the worked example resolves to an owned asset"

    rc = intel_cli.main(["resolve", "--slug", "acme"])
    assert rc == 0
    ents = json.loads(capsys.readouterr().out)
    assert any(e["owned_by"] for e in ents)
    assert any(e["why"] for e in ents)          # merge explanations present


def test_cli_plan_and_predict_offline(tmp_path, monkeypatch, capsys) -> None:
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    intel_cli.main(["ingest", "--seed", "company.com", "--slug", "acme", "--max-depth", "2"])
    capsys.readouterr()

    rc = intel_cli.main(["plan", "--seed", "company.com", "--slug", "acme"])
    assert rc == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["tasks"] and "eig_per_cost" in plan["tasks"][0]

    rc = intel_cli.main(["predict", "--slug", "acme", "--top", "5"])
    assert rc == 0
    preds = json.loads(capsys.readouterr().out)
    assert preds and all(p["gated"] and p["status"] == "predicted" for p in preds)
    assert all(0.0 < p["posterior"] < 1.0 for p in preds)


def test_cli_predict_from_domains_no_store(capsys) -> None:
    rc = intel_cli.main(["predict", "--domains", "api.company.com,backend.company.com", "--top", "3"])
    assert rc == 0
    preds = json.loads(capsys.readouterr().out)
    assert preds and preds[0]["decisive_test"]


def test_cli_ingest_credits_yield_coherently(tmp_path, monkeypatch, capsys) -> None:
    # queries AND observations must land on the SAME (source, archetype) row, or
    # source_prior sees queries=0 and can never learn a rate.
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    intel_cli.main(["ingest", "--seed", "company.com", "--slug", "acme",
                    "--archetype", "saas", "--max-depth", "2"])
    capsys.readouterr()

    store = open_store(tmp_path / "mls.sqlite")
    istore = IntelStore(store)
    row = istore.source_yield("cert_transparency", archetype="saas")
    assert row["queries"] > 0 and row["observations_yielded"] > 0   # same row, both populated
    # so the prior actually moves off the default for a source that paid off
    assert learn.source_prior(istore, IntelSourceKind.CERT_TRANSPARENCY, archetype="saas") != 0.5
    store.close()
