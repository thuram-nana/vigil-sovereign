"""Wave-4.4 race / business-logic price-manipulation — the deep gated assertion against the benchmark app's
planted fixtures and their benign twins.

The default GET-only benchmark crawl never POSTs to these routes, so they add 0 scored findings and
`make gate` + the signed recall baseline stay byte-identical (they are NOT in benchmark_corpus().expected).
This test drives them directly through the SAME primitives the owner-signed live re-drive uses:

  * RACE — the RUNNER fires the fail-closed gated raw-socket burst (scanner.race.raw_race, re-gated through
    validate_action over a signed loopback charter) at the planted /race/redeem coupon, captures the raw
    {status, body}, and hands them + the operator's SEMANTIC success predicate + max_allowed to the gated
    workflow_abuse_oracle (from_race_burst). A FACT is minted ONLY when owner_signed_spec is attested AND a
    semantic predicate re-derives successes > max_allowed. The /race/redeem-locked BENIGN TWIN yields exactly
    one win (successes <= max_allowed) — the oracle must NOT fire.

  * TAMPER — a negative qty is written to /order/add and the authoritative /order/state post-state is read
    back; the operator's danger predicate (qty == -5) over that post-state fires the oracle
    (from_workflow_tamper). The /order/add-validated BENIGN TWIN rejects the value, so the danger predicate
    is false — the oracle must NOT fire.

Honesty guards proven here: no owner-signed spec ⇒ INCONCLUSIVE; a race with no semantic predicate ⇒ LEAD;
never a FACT on either.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from framework.v2.common import paths as _paths
from framework.v2.eval.benchmark_app import serve
from framework.v2.scanner.race import charter_authorize_gate, raw_race, _build_request
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.verifier import OracleVerifier

_SLUG = "race-bizlogic-bench"
_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Benchmark app | Yes |

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""

# The operator's SEMANTIC success predicate for the coupon: the body carries the real-commit marker (a
# genuine redemption), NOT merely a 2xx — this is what makes the count-based over-run a FACT, not a LEAD.
_RACE_SUCCESS_PREDICATE = {"contains": [{"var": "body"}, "COUPON-REDEEMED-OK"]}
_TAMPER_DANGER = {"eq": [{"var": "qty"}, -5]}


@pytest.fixture()
def bench_slug(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    targets_root = tmp_path / "targets"
    td = targets_root / _SLUG
    td.mkdir(parents=True)
    (td / "charter.md").write_text(_CHARTER.format(slug=_SLUG), encoding="utf-8")
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    return _SLUG


def _post(base_url: str, path: str, data: str = "") -> None:
    req = urllib.request.Request(base_url + path, data=data.encode("utf-8"), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5):  # noqa: S310 (loopback only)
            pass
    except urllib.error.HTTPError:
        pass   # a rejected write (the benign twin's 400) is a normal, expected outcome


def _get_json(base_url: str, path: str) -> dict:
    with urllib.request.urlopen(base_url + path, timeout=5) as resp:  # noqa: S310 (loopback only)
        return json.loads(resp.read().decode("utf-8", "replace"))


def _burst(base_url: str, action_path: str, slug: str, count: int = 8) -> list[dict]:
    sp = urllib.parse.urlsplit(base_url)
    host, port = sp.hostname or "127.0.0.1", sp.port or 80
    target_url = urllib.parse.urljoin(base_url + "/", action_path.lstrip("/"))
    request_bytes = _build_request(host, port, action_path)
    outcomes = raw_race(host, port, request_bytes, count, timeout=6.0,
                        authorize=charter_authorize_gate(slug), target_url=target_url)
    return [{"status": s, "body": b} for s, b, _ in outcomes]


def test_planted_race_coupon_mints_a_fact_owner_signed_with_semantic_predicate(bench_slug: str) -> None:
    with serve() as base_url:
        _post(base_url, "/race/reset")
        responses = _burst(base_url, "/race/redeem", bench_slug, count=8)
    # ground truth: the non-atomic coupon over-redeemed under the burst (more than one commit marker).
    wins = sum(1 for r in responses if b"COUPON-REDEEMED-OK" in (r["body"] or b""))
    assert wins > 1, "the planted coupon failed to exhibit the race"
    ctx = FindingContext.from_race_burst(responses, max_allowed=1, owner_signed_spec=True,
                                         success_predicate=_RACE_SUCCESS_PREDICATE, bug_class="request_race")
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert result.confirmed, "owner-signed + semantic predicate + over-count must mint a race FACT"
    assert result.confirming_signals[0].confidence >= 0.7


def test_locked_coupon_benign_twin_never_fires(bench_slug: str) -> None:
    with serve() as base_url:
        _post(base_url, "/race/reset")
        responses = _burst(base_url, "/race/redeem-locked", bench_slug, count=8)
    ctx = FindingContext.from_race_burst(responses, max_allowed=1, owner_signed_spec=True,
                                         success_predicate=_RACE_SUCCESS_PREDICATE, bug_class="request_race")
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert not result.confirmed, "the correctly-locked benign twin must NOT mint a race FACT"
    assert result.signals[0].conclusive, "a properly-locked resource is a channel-confirmed clean"


def test_race_without_owner_signed_spec_is_inconclusive(bench_slug: str) -> None:
    with serve() as base_url:
        _post(base_url, "/race/reset")
        responses = _burst(base_url, "/race/redeem", bench_slug, count=8)
    ctx = FindingContext.from_race_burst(responses, max_allowed=1, owner_signed_spec=False,
                                         success_predicate=_RACE_SUCCESS_PREDICATE, bug_class="request_race")
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert not result.confirmed, "no owner-signed spec must be INCONCLUSIVE, never a FACT"
    assert not result.signals[0].conclusive, "INCONCLUSIVE is not a channel-confirmed clean"


def test_race_without_semantic_predicate_is_a_lead(bench_slug: str) -> None:
    with serve() as base_url:
        _post(base_url, "/race/reset")
        responses = _burst(base_url, "/race/redeem", bench_slug, count=8)
    ctx = FindingContext.from_race_burst(responses, max_allowed=1, owner_signed_spec=True,
                                         success_predicate=None, bug_class="request_race")
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert not result.confirmed, "a bare any-2xx count without a semantic predicate is a LEAD, never a FACT"
    assert not result.signals[0].conclusive, "a LEAD is not a channel-confirmed clean"


def test_planted_price_tampering_mints_a_fact_owner_signed(bench_slug: str) -> None:
    with serve() as base_url:
        _post(base_url, "/order/reset")
        _post(base_url, "/order/add", "qty=-5")     # the vulnerable route persists the negative qty
        state = _get_json(base_url, "/order/state")
    assert state == {"qty": -5}, "the planted order route failed to persist the tampered qty"
    ctx = FindingContext.from_workflow_tamper(state, _TAMPER_DANGER, owner_signed_spec=True,
                                              bug_class="business_logic")
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert result.confirmed, "owner-signed + danger predicate over the post-state must mint a tamper FACT"


def test_validated_order_benign_twin_never_fires(bench_slug: str) -> None:
    with serve() as base_url:
        _post(base_url, "/order/reset")
        _post(base_url, "/order/add-validated", "qty=-5")   # the twin rejects the negative qty
        state = _get_json(base_url, "/order/state")
    assert state == {"qty": 0}, "the benign twin must have rejected the tampered qty"
    ctx = FindingContext.from_workflow_tamper(state, _TAMPER_DANGER, owner_signed_spec=True,
                                              bug_class="business_logic")
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert not result.confirmed, "the correctly-priced benign twin must NOT mint a tamper FACT"
    assert result.signals[0].conclusive, "a validating flow is a channel-confirmed clean"


def test_tamper_without_owner_signed_spec_is_inconclusive(bench_slug: str) -> None:
    with serve() as base_url:
        _post(base_url, "/order/reset")
        _post(base_url, "/order/add", "qty=-5")
        state = _get_json(base_url, "/order/state")
    ctx = FindingContext.from_workflow_tamper(state, _TAMPER_DANGER, owner_signed_spec=False,
                                              bug_class="business_logic")
    result = OracleVerifier().confirm(ctx.to_verifier_context())
    assert not result.confirmed, "no owner-signed spec must be INCONCLUSIVE, never a FACT"
    assert not result.signals[0].conclusive
