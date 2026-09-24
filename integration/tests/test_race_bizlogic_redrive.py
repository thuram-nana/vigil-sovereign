"""
Wave-4.4 race / business-logic price-manipulation — STD-WIRING: owner-signed WorkflowSpec verification ->
admission -> certify_admitted -> offline re-verify -> tamper reject, over the registered
request_race.limit_overrun / business_logic.price_manipulation ACHIEVED_STATE evidence branches.

This is the claim-discipline half of slice 4.4. A race limit-overrun (COUNT-based, never timing) or an
accepted price/parameter tampering is minted ONLY through the admission choke (``verdict.admit`` -> the
FACT-capable branch -> ``oracle_adapter.certify_admitted(provenance="live_redrive")``), gated behind an
OWNER-SIGNED WorkflowSpec attestation the runner cryptographically verified. The offline
``framework.v2 verify`` path re-fires the retained ``oracle_context`` and a tampered value is rejected. No
owner-signed spec ⇒ INCONCLUSIVE; a race with no semantic success predicate ⇒ LEAD. Never a FACT on either.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
for _p in (str(_ROOT / "engine" / "crucible"), str(_ROOT / "integration"),
           str(_ROOT / "packages" / "core" / "vigil_core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from framework.v2.common import paths as _paths
from framework.v2.eval.benchmark_app import serve
from framework.v2.scanner.bizlogic import TamperProbe, WorkflowSpec, WorkflowStep
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.reverify import reverify_finding
from framework.v2.verify.verifier import OracleVerifier

from vigil_core import canonical_json, generate_keypair, sign
from vigil_integration.live.race_bizlogic_redrive import (
    RaceTarget,
    _BRANCH_FOR,
    _WORKFLOW_SPEC_DOMAIN,
    race_bizlogic_redrive,
    verify_owner_signed_spec,
)
from vigil_integration.live.verdict import Verdict, admit, branch_ids
from vigil_integration.live.wiring import _redrive_branch_for
from vigil_integration.oracle_adapter import certify_admitted

_RACE_MARKER = "COUPON-REDEEMED-OK"
_RACE_SUCCESS_PREDICATE = {"contains": [{"var": "body"}, _RACE_MARKER]}
_TAMPER_DANGER = {"eq": [{"var": "qty"}, -5]}


def _signers():
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _demo_spec() -> WorkflowSpec:
    return WorkflowSpec(
        name="wave44-order-workflow",
        steps=(WorkflowStep(name="add", path="/order/add", params={"qty": 1},
                            effect={"gt": [{"var": "qty"}, 0]}),),
        tamper_probes=(TamperProbe(step="add", overrides={"qty": -5}, danger=_TAMPER_DANGER,
                                   label="negative cart quantity"),),
    )


def _sign_spec(spec: WorkflowSpec) -> "tuple[str, str]":
    """Return (signature_b64, owner_public_key_b64) for the canonical, domain-separated spec."""
    kp = generate_keypair()
    message = _WORKFLOW_SPEC_DOMAIN + canonical_json(spec.model_dump(mode="json"))
    return sign(kp.private_key_b64, message), kp.public_key_b64


# ---------------------------------------------------------------------------
# owner-signed spec verification (pure)
# ---------------------------------------------------------------------------


def test_owner_signed_spec_verifies_and_rejects_forgery() -> None:
    spec = _demo_spec()
    sig, pub = _sign_spec(spec)
    assert verify_owner_signed_spec(spec, sig, pub) is True
    # a different key does not verify
    other = generate_keypair()
    assert verify_owner_signed_spec(spec, sig, other.public_key_b64) is False
    # a tampered spec (a different max intent) does not verify under the original signature
    tampered = WorkflowSpec(name="wave44-order-workflow", steps=spec.steps,
                            tamper_probes=(TamperProbe(step="add", overrides={"qty": -9},
                                                       danger={"eq": [{"var": "qty"}, -9]}),))
    assert verify_owner_signed_spec(tampered, sig, pub) is False
    # a missing signature / key is fail-closed False
    assert verify_owner_signed_spec(spec, "", pub) is False
    assert verify_owner_signed_spec(spec, sig, "") is False


# ---------------------------------------------------------------------------
# branch registration + mapping
# ---------------------------------------------------------------------------


def test_the_branches_are_registered_and_classes_map_to_them() -> None:
    for cls, branch in _BRANCH_FOR.items():
        assert branch in branch_ids(), f"{branch} not registered"
        assert _redrive_branch_for(cls) == branch
    # a workflow-abuse spelling alias resolves to the business_logic branch
    assert _redrive_branch_for("workflow_abuse") == "business_logic.price_manipulation"


# ---------------------------------------------------------------------------
# admission -> certify -> offline re-verify (built contexts)
# ---------------------------------------------------------------------------


def _race_finding(*, owner_signed: bool, semantic: bool):
    responses = [{"status": 200, "body": f"ok {_RACE_MARKER}"}] * 3 + [{"status": 409, "body": "already"}] * 5
    ctx = FindingContext.from_race_burst(
        responses, max_allowed=1, owner_signed_spec=owner_signed,
        success_predicate=(_RACE_SUCCESS_PREDICATE if semantic else None), bug_class="request_race")
    context = ctx.to_verifier_context()
    finding = {"check_id": "rb:request_race:0", "bug_class": "request_race",
               "title": "limit-overrun race", "surface": "POST /redeem",
               "summary": "burst over-ran the atomic limit", "oracle_context": context}
    return finding, context


def test_owner_signed_race_with_semantic_predicate_mints_a_signed_fact() -> None:
    finding, context = _race_finding(owner_signed=True, semantic=True)
    result = OracleVerifier().confirm(context)
    assert result.confirmed
    admitted = admit("request_race.limit_overrun", fired=True, conclusive=True,
                     observed={"channel_established": True, "owner_signed_workflow_spec": True})
    assert admitted.verdict is Verdict.FACT
    res = certify_admitted(finding, admitted, engagement_slug="alpha",
                           signers=_signers(), provenance="live_redrive")
    assert res.is_fact, res.reason
    assert res.confirmed_by == OracleKind.ACHIEVED_STATE.value
    assert res.signed is not None


def test_race_without_owner_signed_spec_does_not_confirm() -> None:
    _finding, context = _race_finding(owner_signed=False, semantic=True)
    result = OracleVerifier().confirm(context)
    assert not result.confirmed, "no owner-signed spec must be INCONCLUSIVE, never confirmed"


def test_race_without_semantic_predicate_does_not_confirm() -> None:
    _finding, context = _race_finding(owner_signed=True, semantic=False)
    result = OracleVerifier().confirm(context)
    assert not result.confirmed, "an any-2xx count with no semantic predicate is a LEAD, never a FACT"


def test_offline_reverify_re_fires_and_rejects_tamper() -> None:
    finding, _context = _race_finding(owner_signed=True, semantic=True)
    finding["confirmed_by"] = OracleKind.ACHIEVED_STATE.value
    finding["confidence"] = 0.9
    good = reverify_finding(finding)
    assert good.reproduced and good.matches_claim is not False
    # tamper: flip the owner-signed attestation off -> the oracle no longer confirms
    octx = finding["oracle_context"]
    tampered_wa = {**octx["workflow_abuse"], "owner_signed_spec": False}
    tampered = {**finding, "oracle_context": {**octx, "workflow_abuse": tampered_wa}}
    bad = reverify_finding(tampered)
    assert not bad.reproduced or bad.matches_claim is False


def test_owner_signed_tamper_mints_a_fact_and_benign_twin_does_not() -> None:
    ctx = FindingContext.from_workflow_tamper({"qty": -5}, _TAMPER_DANGER, owner_signed_spec=True,
                                              bug_class="business_logic")
    assert OracleVerifier().confirm(ctx.to_verifier_context()).confirmed
    # benign twin: a correctly-priced flow (qty clamped to 0) fails the danger predicate
    twin = FindingContext.from_workflow_tamper({"qty": 0}, _TAMPER_DANGER, owner_signed_spec=True,
                                               bug_class="business_logic")
    assert not OracleVerifier().confirm(twin.to_verifier_context()).confirmed


# ---------------------------------------------------------------------------
# end-to-end: the runner-owned re-drive against the benchmark app's planted fixtures
# ---------------------------------------------------------------------------

_SLUG = "race-bizlogic-redrive-e2e"
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
"""


@pytest.fixture()
def e2e_slug(tmp_path, monkeypatch):
    targets_root = tmp_path / "targets"
    td = targets_root / _SLUG
    td.mkdir(parents=True)
    (td / "charter.md").write_text(_CHARTER.format(slug=_SLUG), encoding="utf-8")
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets_root / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets_root / s / "charter.md")
    return _SLUG


def test_runner_redrive_mints_a_race_fact_against_the_benchmark_fixture(e2e_slug) -> None:
    import urllib.request

    spec = _demo_spec()
    sig, pub = _sign_spec(spec)
    with serve() as base_url:
        urllib.request.urlopen(urllib.request.Request(base_url + "/race/reset", data=b"", method="POST"),
                               timeout=5).close()
        res = race_bizlogic_redrive(
            base_url, slug=e2e_slug, engagement_slug="alpha", signers=_signers(),
            workflow_spec=spec, spec_signature_b64=sig, owner_public_key_b64=pub,
            race_targets=(RaceTarget(action_path="/race/redeem", max_allowed=1, count=8,
                                     success_predicate=_RACE_SUCCESS_PREDICATE),),
        )
    assert res.owner_signed_spec is True
    assert res.n_facts >= 1, f"the owner-signed race re-drive minted no FACT; notes={res.notes}"


def test_runner_redrive_without_owner_signature_mints_nothing(e2e_slug) -> None:
    spec = _demo_spec()
    with serve() as base_url:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(base_url + "/race/reset", data=b"", method="POST"),
                               timeout=5).close()
        res = race_bizlogic_redrive(
            base_url, slug=e2e_slug, engagement_slug="alpha", signers=_signers(),
            workflow_spec=spec, spec_signature_b64="", owner_public_key_b64="",   # NOT signed
            race_targets=(RaceTarget(action_path="/race/redeem", max_allowed=1, count=8,
                                     success_predicate=_RACE_SUCCESS_PREDICATE),),
        )
    assert res.owner_signed_spec is False
    assert res.n_facts == 0, "an unsigned WorkflowSpec must mint NO FACT (INCONCLUSIVE)"
