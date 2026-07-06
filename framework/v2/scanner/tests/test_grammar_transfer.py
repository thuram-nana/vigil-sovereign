"""
B3 — grammar-aware fuzzing and cross-engagement transfer, wired into the campaign.

`scanner.grammar` (a probabilistic request grammar) and `learning.seed_from_priors`
(fold past-engagement Beta evidence into a new run's bandit) were real code nothing
in the live loop called. These tests pin the wiring: grammar-fuzz synthesizes
structurally-valid, in-scope, de-duplicated NEW requests onto the audit surface, and
transfer seeds the check-ordering bandit from prior engagements' successes.
"""

from __future__ import annotations

from types import SimpleNamespace

from framework.v2.scanner.campaign import WebScanCampaign
from framework.v2.scanner.crawler import Scope
from framework.v2.scanner.insertion import HttpRequest


def _noop_send(request) -> dict:
    return {"status": 200, "body": "ok"}


def _observed() -> list[HttpRequest]:
    # two concrete requests the crawl "saw": a /user/<int> template + a ref param
    return [
        HttpRequest(method="GET", url="http://t/user/1?ref=alpha"),
        HttpRequest(method="GET", url="http://t/user/2?ref=beta"),
    ]


# --------------------------------------------------------------------------- #
# grammar-aware fuzzing
# --------------------------------------------------------------------------- #


def test_grammar_requests_synthesizes_new_inscope_deduped() -> None:
    camp = WebScanCampaign(_noop_send, scope=None, grammar_fuzz=5)
    reqs = camp._grammar_requests(_observed())
    assert reqs, "grammar fuzz produced no requests from a generalizable corpus"
    assert len(reqs) <= 5
    seen = {r.url for r in _observed()}
    # every synthesized request is NEW (not an observed URL) and unique
    urls = [r.url for r in reqs]
    assert len(urls) == len(set(urls))
    assert all(u not in seen for u in urls)
    # structurally on the same template family (/user/<int>?ref=...)
    assert all(r.url.startswith("http://t/user/") for r in reqs)


def test_grammar_requests_off_by_default_and_empty_corpus() -> None:
    camp0 = WebScanCampaign(_noop_send, scope=None, grammar_fuzz=0)
    assert camp0.grammar_fuzz == 0
    # even enabled, an empty/ungeneralizable corpus yields nothing (no crash)
    camp = WebScanCampaign(_noop_send, scope=None, grammar_fuzz=5)
    assert camp._grammar_requests([]) == []


def test_grammar_requests_are_scope_filtered() -> None:
    # a scope bound to host 't' must drop any synthesized off-scope request
    scope = Scope(host="t")
    camp = WebScanCampaign(_noop_send, scope=scope, grammar_fuzz=5)
    reqs = camp._grammar_requests(_observed())
    assert reqs, "in-scope synthesized requests should survive the scope filter"
    assert all(scope.in_scope(r.url) for r in reqs)


def test_grammar_fuzz_is_deterministic_given_seed() -> None:
    a = WebScanCampaign(_noop_send, scope=None, grammar_fuzz=4, grammar_fuzz_seed=7)
    b = WebScanCampaign(_noop_send, scope=None, grammar_fuzz=4, grammar_fuzz_seed=7)
    assert [r.url for r in a._grammar_requests(_observed())] == \
           [r.url for r in b._grammar_requests(_observed())]


# --------------------------------------------------------------------------- #
# cross-engagement transfer
# --------------------------------------------------------------------------- #


def _prior(bug_class: str, successes: int, attempts: int):
    return SimpleNamespace(bug_class=bug_class, successes=successes, attempts=attempts)


def test_transfer_seeds_bandit_from_priors() -> None:
    priors = [_prior("sqli", 9, 10), _prior("xss", 1, 10)]
    camp = WebScanCampaign(_noop_send, scope=None, bandit_context="ctx", priors=priors)
    bandit = camp._resolve_bandit()
    post = bandit.to_dict()["posteriors"]["ctx"]
    # sqli folded in as strong positive evidence, xss as weak
    assert "sqli" in post and "xss" in post
    sqli_alpha, sqli_beta = post["sqli"]
    xss_alpha, xss_beta = post["xss"]
    # 9 successes -> high alpha; 9 failures on xss -> high beta
    assert sqli_alpha > sqli_beta
    assert xss_beta > xss_alpha


def test_transfer_skips_priors_without_bug_class() -> None:
    priors = [_prior("sqli", 5, 5), SimpleNamespace(bug_class=None, successes=3, attempts=3)]
    camp = WebScanCampaign(_noop_send, scope=None, bandit_context="ctx", priors=priors)
    bandit = camp._resolve_bandit()
    arms = bandit.to_dict()["posteriors"].get("ctx", {})
    assert "sqli" in arms
    assert "None" not in arms  # a bug_class-less prior never invents an arm


def test_no_priors_leaves_bandit_untouched() -> None:
    camp = WebScanCampaign(_noop_send, scope=None, bandit_context="ctx", priors=None)
    bandit = camp._resolve_bandit()
    assert bandit.to_dict()["posteriors"] == {}
