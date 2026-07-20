"""
The honeypot oracle confirms AUTOMATED ACCESS (P1) — a fetch of a resource no human UI links —
NOT "scraping". An allowlisted known-good crawler/monitor REFUTES (does not confirm).
"""

from __future__ import annotations

from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.oracles import honeypot_hit_oracle

HP = "/__aegis_hp__/abc123"


def test_seeded_path_fetched_confirms():
    sig = honeypot_hit_oracle(HP, [HP, "/__aegis_hp__/other"])
    assert sig.fired and sig.confidence >= 0.7


def test_other_path_does_not_fire():
    sig = honeypot_hit_oracle("/index.html", [HP])
    assert not sig.fired


def test_allowlisted_crawler_refutes():
    sig = honeypot_hit_oracle(HP, [HP], crawler_allowlisted=True)
    assert not sig.fired
    assert "allowlisted" in sig.evidence.lower()


def test_confirmed_class_is_automated_access_not_scraping():
    fc = FindingContext.from_honeypot(HP, [HP])
    cf = confirm_finding({"bug_class": "automated_access"}, fc)
    assert cf is not None
    assert cf.bug_class == "automated_access"
    assert cf.confirmed_by.value == "automated_access"


def test_scraping_alias_folds_onto_automated_access():
    # `automated_scraping` must never be its own confirmed class — it aliases automated_access.
    from framework.v2.verify.verifier import normalize_bug_class
    assert normalize_bug_class("automated_scraping") == "automated_access"


def test_oracle_is_deterministic():
    a = honeypot_hit_oracle(HP, [HP])
    b = honeypot_hit_oracle(HP, [HP])
    assert a.model_dump() == b.model_dump()
