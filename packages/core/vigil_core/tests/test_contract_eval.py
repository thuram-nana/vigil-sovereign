"""AEGIS AS-4b — the protection-contract EVALUATOR (fill + grade) and the enforce/observe PREVIEW.

Load-bearing invariants a false-green would break (a half-built contract reading as "enforcing"; a
preview promising an outcome the registry cannot reach; a preview claiming a release is permitted when the
sovereign would refuse it; a non-deterministic preview breaking a cross-plane digest; the module reaching
out of ``vigil_core``):

  * the headline is the FLOOR of the six dimensions — one ``unsupported`` axis caps the whole claim;
  * ``effective`` enforcement is the fail-closed AND of EVERY term, and ``reasons`` names what withholds it;
  * ``grade_contract`` FILLS the headline + grades enforcement, read-only (the input is never mutated);
  * the preview's "what enforce would add" is DERIVED from the provider registry's own outcome classes
    (never hard-coded), so an un-shipped provider cannot make the preview over-claim;
  * ``enforce_permitted`` is the AS-29 release gate as a preview — permitted ONLY for an armed, Respond-
    entitled host whose proof is current and still in Observe; every other case names an honest blocker;
  * a preview round-trips byte-identically (determinism) and carries no secret;
  * the module is FATAL-2 clean — no ``framework`` / ``sigil`` import.
"""
from __future__ import annotations

import ast
import importlib
import inspect

import pytest

from vigil_core.aegis_schemas import OutcomeClass
from vigil_core.contract_eval import (
    BLOCKER_ALREADY_ENFORCING,
    BLOCKER_NOT_ARMED,
    BLOCKER_PROOF_LAPSED,
    BLOCKER_RESPOND_NOT_IN_PLAN,
    NOT_OBSERVED_BASELINE,
    HostProtectionPreview,
    enforcement_reasons,
    grade_contract,
    grade_enforcement,
    grade_headline,
    headline_floor,
    preview_host,
)
from vigil_core.monitoring_authority import MonitoringMode
from vigil_core.protection_contract import (
    AssetRef,
    Dimensions,
    EnforcementTerms,
    EnforceReleaseProjection,
    Headline,
    OriginBlock,
    OriginTuple,
    ProtectionContract,
    ProviderDescriptor,
    ProviderRegistry,
    ReleaseState,
    baseline_provider_registry,
)
from vigil_core.aegis_schemas import AdapterCapability, EffectVerification


def _imported_roots(module_name: str) -> set[str]:
    mod = importlib.import_module(module_name)
    tree = ast.parse(inspect.getsource(mod))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


# --- FATAL-2 -------------------------------------------------------------------------------------------------
def test_module_is_fatal_2_clean():
    roots = _imported_roots("vigil_core.contract_eval")
    assert "framework" not in roots and "sigil" not in roots, roots
    assert roots <= {"__future__", "typing", "pydantic"}, roots   # stdlib + pydantic + (relative) siblings only


# --- the general grading -------------------------------------------------------------------------------------
def test_headline_is_the_floor_of_the_dimensions():
    assert headline_floor([]) is Headline.UNSUPPORTED                 # empty => fail-closed floor
    assert headline_floor([Headline.ENFORCING]) is Headline.ENFORCING
    # a single unsupported axis caps the whole claim at unsupported
    dims = Dimensions(asset_placement=Headline.ENFORCING, edge=Headline.ENFORCING, origin_lock=Headline.ENFORCING,
                      telemetry=Headline.ENFORCING, detection_enforcement=Headline.ENFORCING,
                      authority_release=Headline.UNSUPPORTED)
    assert grade_headline(dims) is Headline.UNSUPPORTED
    # otherwise the floor is the weakest rung actually reached
    dims2 = Dimensions(asset_placement=Headline.OBSERVING, edge=Headline.ENFORCING, origin_lock=Headline.ENFORCING,
                       telemetry=Headline.UNVERIFIED, detection_enforcement=Headline.OBSERVING,
                       authority_release=Headline.ENFORCING)
    assert grade_headline(dims2) is Headline.UNVERIFIED
    assert grade_headline(Dimensions()) is Headline.UNSUPPORTED        # all-default contract reads "no protection"


def test_effective_enforcement_is_the_fail_closed_and_of_every_term():
    # a fully-enforcing conjunction => effective, no reasons
    full = EnforcementTerms(grant_block=True, enforce_release=EnforceReleaseProjection(state=ReleaseState.RELEASED),
                            flag=True, mode=MonitoringMode.BLOCK, entitlement=True)
    graded = grade_enforcement(full)
    assert graded.effective is True and graded.reasons == []
    assert enforcement_reasons(full) == ()
    # drop ANY one term and it is no longer effective, and the reason is named
    g2 = grade_enforcement(full.model_copy(update={"flag": False}))
    assert g2.effective is False and "flag_off" in g2.reasons
    # a tripped kill switch or an active override withholds enforcement even with every positive term
    killed = grade_enforcement(full.model_copy(update={"kill_switch_tripped": True}))
    assert killed.effective is False and "kill_switch_tripped" in killed.reasons
    overridden = grade_enforcement(full.model_copy(update={"override_active": True}))
    assert overridden.effective is False and "override_active" in overridden.reasons
    # the default (fail-closed) terms are NOT effective, and name every missing term
    empty = grade_enforcement(EnforcementTerms())
    assert empty.effective is False
    assert set(empty.reasons) == {"grant_not_block", "not_released", "flag_off", "mode_not_block", "not_entitled"}
    assert empty.reasons == sorted(empty.reasons)                     # deterministic ordering


def _contract() -> ProtectionContract:
    return ProtectionContract(asset=AssetRef(ref="asset-1", instance_id="inst-1"),
                              origin=OriginBlock(tuple=OriginTuple(scheme="https", host="shop.example")))


def test_grade_contract_fills_the_headline_and_grades_enforcement_read_only():
    c = _contract()
    graded = grade_contract(c)
    assert graded.headline is Headline.UNSUPPORTED                    # floor of all-default dimensions
    assert graded.enforcement_terms.effective is False and graded.enforcement_terms.reasons
    # read-only: the input contract is untouched (its own headline default stays as parsed)
    assert c.headline is Headline.UNSUPPORTED and c.enforcement_terms.effective is False
    assert graded is not c


# --- the customer-facing preview -----------------------------------------------------------------------------
def test_an_armed_observe_host_with_a_current_proof_and_respond_can_be_released():
    p = preview_host("a.example", mode=MonitoringMode.OBSERVE, armed=True, proof_current=True, respond_entitled=True)
    assert p.headline is Headline.OBSERVING
    assert p.enforce_permitted is True and p.enforce_blockers == ()
    # observe reaches detect-only; enforce ADDS prevent + withhold — DERIVED from the baseline provider registry
    assert p.observe_outcomes == (OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,)   # armed => detection is LIVE now
    assert p.observe_adds_outcomes == ()                             # armed => nothing is only "would be detected"
    assert p.enforce_adds_outcomes == (OutcomeClass.PREVENTED_BEFORE_EXECUTION,
                                       OutcomeClass.RESPONSE_WITHHELD_AFTER_EXECUTION)
    assert p.not_observed == NOT_OBSERVED_BASELINE                    # the honest coverage limitation surfaced


def test_a_proven_but_unmonitored_host_does_not_claim_live_detection():
    # RED-PEN AS-4b: a host whose ownership proof is current but which is NOT armed (no live monitoring grant) is
    # not being monitored — the preview must NOT claim live detection is in effect for it. "What AEGIS does now"
    # is empty; the detection arming would make live is carried, honestly, as a preview-only "would be" instead.
    p = preview_host("proven.example", mode=MonitoringMode.OBSERVE, armed=False, proof_current=True,
                     respond_entitled=True)
    assert p.headline is Headline.INACTIVE                            # not monitored
    assert p.observe_outcomes == ()                                  # NO live-detection claim on an unmonitored host
    assert p.observe_adds_outcomes == (OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,)   # would be detected once armed
    assert BLOCKER_NOT_ARMED in p.enforce_blockers
    # the customer-safe projection the edge ships carries the same honest split — no "detected" value under "now"
    cs = p.customer_safe()
    assert cs["observe_outcomes"] == []
    assert cs["observe_adds_outcomes"] == ["detected_without_enforcement"]


def test_the_preview_names_an_honest_blocker_whenever_a_release_would_be_refused():
    # already enforcing — nothing to release
    enforcing = preview_host("b.example", mode=MonitoringMode.BLOCK, armed=True, proof_current=True,
                             respond_entitled=True)
    assert enforcing.headline is Headline.ENFORCING
    assert enforcing.enforce_permitted is False and enforcing.enforce_blockers == (BLOCKER_ALREADY_ENFORCING,)
    # armed but proof lapsed — capped at unverified, release blocked, no plan either => BOTH blockers, sorted
    lapsed = preview_host("c.example", mode=MonitoringMode.OBSERVE, armed=True, proof_current=False,
                          respond_entitled=False)
    assert lapsed.headline is Headline.UNVERIFIED and lapsed.enforce_permitted is False
    assert lapsed.enforce_blockers == tuple(sorted((BLOCKER_PROOF_LAPSED, BLOCKER_RESPOND_NOT_IN_PLAN)))
    # not armed at all — inactive, must be turned on first
    off = preview_host("d.example", mode=MonitoringMode.OBSERVE, armed=False, proof_current=True,
                       respond_entitled=True)
    assert off.headline is Headline.INACTIVE and off.enforce_blockers == (BLOCKER_NOT_ARMED,)
    # Respond not in plan, but otherwise releasable — the plan is the only blocker
    noplan = preview_host("e.example", mode=MonitoringMode.OBSERVE, armed=True, proof_current=True,
                          respond_entitled=False)
    assert noplan.enforce_permitted is False and noplan.enforce_blockers == (BLOCKER_RESPOND_NOT_IN_PLAN,)


def test_the_preview_never_over_claims_beyond_the_registry_it_is_given():
    # an observe-only registry (one provider that only detects) can add NOTHING under enforce — honesty by construction
    observe_only = ProviderRegistry(providers=(ProviderDescriptor(
        provider_id="observe_only", title="detect only",
        capabilities=[AdapterCapability(kind="observe_alert",
                                        outcome_class=OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,
                                        effect_verification=EffectVerification.REPORTED)]),))
    p = preview_host("a.example", mode=MonitoringMode.OBSERVE, armed=True, proof_current=True,
                     respond_entitled=True, registry=observe_only)
    assert p.observe_outcomes == (OutcomeClass.DETECTED_WITHOUT_ENFORCEMENT,)
    assert p.enforce_adds_outcomes == ()                             # nothing to add — the registry reaches no enforcement


def test_the_preview_is_deterministic_and_customer_safe():
    a = preview_host("a.example", mode=MonitoringMode.OBSERVE, armed=True, proof_current=True, respond_entitled=True)
    b = preview_host("a.example", mode=MonitoringMode.OBSERVE, armed=True, proof_current=True, respond_entitled=True)
    assert a.canonical_bytes() == b.canonical_bytes()                 # no wallclock, no RNG — byte-identical
    assert HostProtectionPreview.parse(a.model_dump()).canonical_bytes() == a.canonical_bytes()   # round-trips
    cs = a.customer_safe()
    assert set(cs) == {"host", "headline", "mode", "armed", "proof_current", "respond_entitled",
                       "observe_outcomes", "observe_adds_outcomes", "enforce_adds_outcomes", "enforce_permitted",
                       "enforce_blockers", "not_observed"}
    assert all(isinstance(v, (str, bool, list)) for v in cs.values())  # enum values / booleans / token lists only
    # the default registry is the shared baseline (prevent + withhold + detect)
    assert preview_host("x.example", mode=MonitoringMode.OBSERVE, armed=True, proof_current=True,
                        respond_entitled=True).enforce_adds_outcomes == \
        preview_host("x.example", mode=MonitoringMode.OBSERVE, armed=True, proof_current=True,
                     respond_entitled=True, registry=baseline_provider_registry()).enforce_adds_outcomes


def test_the_preview_rejects_a_bad_host():
    with pytest.raises(ValueError):
        preview_host("not a host!!", mode=MonitoringMode.OBSERVE, armed=True, proof_current=True,
                     respond_entitled=True)
