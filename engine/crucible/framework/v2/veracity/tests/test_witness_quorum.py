"""
M4.4 — the OPTIONAL, DEFAULT-OFF, DEMOTE-ONLY N-of-M oracle-witness quorum admission conjunct.

Real positive + safe-negative controls, no green-washing. The two fixtures below produce a GENUINE
multi-witness and a GENUINE single-witness ``oracle_context`` for ``error_based_sqli`` — the merged
context fires BOTH the ERROR_SIGNATURE oracle (a datastore error the payload provoked) and the
SIDE_EFFECT oracle (a unique canary reaching the sink), while the single context fires only
ERROR_SIGNATURE. Everything is re-derived by RE-EXECUTING the deterministic oracle; nothing trusts a
claimed corroboration set.

Properties proven here:
  * OFF (the default) ⇒ the admit path is BYTE-IDENTICAL (same signed certificate bytes, no witness
    fields on the certificate);
  * ON for a critical class ⇒ a FACT with >= N distinct oracle-witness kinds is admitted (and the cert
    records the quorum); a FACT backed by only 1 oracle kind is DEMOTED to a LEAD;
  * MONOTONE: a non-FACT admission can never be promoted to a FACT by the quorum;
  * a critic / LLM "vote" is NOT counted as a witness (only re-fired oracle signals count);
  * offline re-verify HONORS the quorum and REJECTS a tampered / over-claimed witness record;
  * the firewall demotes a quorum-failing claim to UNGROUNDED (a LEAD on every render path);
  * no new OracleKind (``_ALL_ORACLES`` stays exactly 15).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence.certify import build_certificate, sign_certificate, verify_certificate
from framework.v2.evidence.models import EvidenceCertificate
from framework.v2.verify import reverify
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.verifier import OracleVerifier, _ALL_ORACLES
from framework.v2.veracity.claims import Claim, VeracityVerdict
from framework.v2.veracity.firewall import admit as fw_admit
from framework.v2.veracity.tokens import GroundingToken
from framework.v2.veracity.witness_quorum import (
    DISABLED,
    WitnessQuorumConfig,
    distinct_witness_kinds,
    evaluate,
    load_quorum_config,
    witnesses_reconfirm,
)

_ROOT = Path(__file__).resolve().parents[6]   # .../engine/crucible/framework/v2/veracity/tests -> repo root
_CLASS = "error_based_sqli"
_ON = WitnessQuorumConfig(enabled=True, quorum_n=2, critical_classes=frozenset({_CLASS}))


# --------------------------------------------------------------------------- fixtures


def _ctx_two_witness() -> FindingContext:
    """A GENUINE 2-witness context: a datastore error (ERROR_SIGNATURE) AND a unique canary reaching
    the sink (SIDE_EFFECT), merged under error_based_sqli (which maps to both oracle kinds)."""
    err = FindingContext.from_error_signature(
        observed_body="You have an error in your SQL syntax; check the manual that corresponds to "
                      "your MySQL server version near ''' at line 1",
        control_body="OK normal page with results", bug_class=_CLASS)
    se = FindingContext.from_side_effect(
        marker="OBSIDIANCANARY7Z9Q",
        observed_sink="row: OBSIDIANCANARY7Z9Q reflected into the SQL error output OBSIDIANCANARY7Z9Q",
        control_sink="row: normal content, no canary here", bug_class=_CLASS)
    return err.merge(se)


def _ctx_one_witness() -> FindingContext:
    """A GENUINE single-witness context: only the ERROR_SIGNATURE oracle fires."""
    return FindingContext.from_error_signature(
        observed_body="You have an error in your SQL syntax; check the manual that corresponds to "
                      "your MySQL server version near ''' at line 1",
        control_body="OK normal page with results", bug_class=_CLASS)


def _finding(ctx: FindingContext, **extra) -> dict:
    f = {"check_id": "ebsqli-1", "bug_class": _CLASS, "oracle_context": ctx.model_dump(mode="json")}
    f.update(extra)
    return f


def _trust_root(threshold: int = 2, n: int = 3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _import_mint():
    """certify_admitted lives in integration/ (the no-hallucinated-findings mint choke). Import it the
    same way the claim-discipline guard does, so this offense-side test drives the real mint path."""
    integration = str(_ROOT / "integration")
    if integration not in sys.path:
        sys.path.insert(0, integration)
    from vigil_integration.live.verdict import admit as vadmit
    from vigil_integration.oracle_adapter import certify_admitted
    return vadmit, certify_admitted


def _admitted_fact(vadmit):
    """A FACT-capable AdmittedVerdict over the registered error_signature branch (its precondition held)."""
    return vadmit("error_signature.datastore_error", fired=True, conclusive=True,
                  observed={"channel_established": True})


# --------------------------------------------------------------------------- the pure conjunct


def test_distinct_witness_kinds_counts_only_refired_oracle_kinds():
    assert distinct_witness_kinds(_finding(_ctx_two_witness())["oracle_context"], bug_class=_CLASS) == \
        ("error_signature", "side_effect")
    assert distinct_witness_kinds(_finding(_ctx_one_witness())["oracle_context"], bug_class=_CLASS) == \
        ("error_signature",)
    # a malformed / empty context establishes NO witness (fail-closed → the quorum can only withhold)
    assert distinct_witness_kinds({}, bug_class=_CLASS) == ()
    assert distinct_witness_kinds(None, bug_class=_CLASS) == ()


def test_evaluate_inapplicable_when_disabled_or_non_critical():
    # disabled policy → inapplicable, ok=True, required=0 (caller unchanged)
    q = evaluate(_finding(_ctx_two_witness())["oracle_context"], bug_class=_CLASS, config=DISABLED)
    assert q.applicable is False and q.ok is True and q.required == 0
    # enabled but a class NOT designated critical → inapplicable
    other = WitnessQuorumConfig(enabled=True, quorum_n=2, critical_classes=frozenset({"xss"}))
    q2 = evaluate(_finding(_ctx_one_witness())["oracle_context"], bug_class=_CLASS, config=other)
    assert q2.applicable is False and q2.ok is True


def test_evaluate_applicable_meets_and_fails_quorum():
    met = evaluate(_finding(_ctx_two_witness())["oracle_context"], bug_class=_CLASS, config=_ON)
    assert met.applicable and met.ok and met.required == 2 and met.got == 2
    assert met.kinds == ("error_signature", "side_effect")
    short = evaluate(_finding(_ctx_one_witness())["oracle_context"], bug_class=_CLASS, config=_ON)
    assert short.applicable and not short.ok and short.required == 2 and short.got == 1


def test_config_from_dict_is_fail_safe_off():
    assert WitnessQuorumConfig.from_dict(None) is DISABLED
    assert WitnessQuorumConfig.from_dict({"enabled": False}) is DISABLED
    assert WitnessQuorumConfig.from_dict({"enabled": True}) is DISABLED            # no critical classes
    assert WitnessQuorumConfig.from_dict({"enabled": True, "quorum_n": 0,
                                          "critical_classes": ["x"]}) is DISABLED  # n < 1
    good = WitnessQuorumConfig.from_dict({"enabled": True, "quorum_n": 3,
                                          "critical_classes": ["Error-Based-SQLi"]})
    assert good.enabled and good.quorum_n == 3 and good.applies_to(_CLASS)         # alias-normalised


def test_load_quorum_config_default_off(monkeypatch, tmp_path):
    load_quorum_config.cache_clear() if hasattr(load_quorum_config, "cache_clear") else None
    from framework.v2.veracity import witness_quorum as wq
    wq._load_cached.cache_clear()
    monkeypatch.delenv("CRUCIBLE_WITNESS_QUORUM_CONFIG", raising=False)
    assert load_quorum_config() is DISABLED
    # an operator file switches it on (operator-set, not model-set)
    cfg = tmp_path / "wq.json"
    cfg.write_text('{"enabled": true, "quorum_n": 2, "critical_classes": ["error_based_sqli"]}')
    monkeypatch.setenv("CRUCIBLE_WITNESS_QUORUM_CONFIG", str(cfg))
    wq._load_cached.cache_clear()
    loaded = load_quorum_config()
    assert loaded.enabled and loaded.applies_to(_CLASS)
    wq._load_cached.cache_clear()


# --------------------------------------------------------------------------- the mint path (certify_admitted)


def test_mint_off_is_byte_identical():
    """DEFAULT-OFF ⇒ the signed certificate is byte-identical to a mint with NO quorum param, and carries
    NO witness fields. Proven by executing the admit path with the flag absent vs an explicit DISABLED."""
    vadmit, certify_admitted = _import_mint()
    _tr, signers = _trust_root()
    admitted = _admitted_fact(vadmit)

    r_default = certify_admitted(_finding(_ctx_two_witness()), admitted, engagement_slug="acme",
                                 signers=signers, provenance="reproduced", seq=7)
    r_disabled = certify_admitted(_finding(_ctx_two_witness()), admitted, engagement_slug="acme",
                                  signers=signers, provenance="reproduced", seq=7, witness_quorum=DISABLED)
    assert r_default.is_fact and r_disabled.is_fact
    c_default = r_default.signed.certificate.model_dump(mode="json")
    c_disabled = r_disabled.signed.certificate.model_dump(mode="json")
    # no witness fields leak into the canonical form when off
    assert "witness_quorum_required" not in c_default and "witness_kinds" not in c_default
    # flag-absent and explicit-DISABLED produce byte-identical certificates
    assert c_default == c_disabled


def test_mint_on_two_witness_admits_and_records_quorum():
    vadmit, certify_admitted = _import_mint()
    _tr, signers = _trust_root()
    admitted = _admitted_fact(vadmit)
    r = certify_admitted(_finding(_ctx_two_witness()), admitted, engagement_slug="acme",
                         signers=signers, provenance="reproduced", witness_quorum=_ON)
    assert r.is_fact, r.reason
    cj = r.signed.certificate.model_dump(mode="json")
    assert cj["witness_quorum_required"] == 2
    assert cj["witness_kinds"] == ["error_signature", "side_effect"]


def test_mint_on_single_witness_is_demoted_to_lead():
    vadmit, certify_admitted = _import_mint()
    _tr, signers = _trust_root()
    admitted = _admitted_fact(vadmit)
    r = certify_admitted(_finding(_ctx_one_witness()), admitted, engagement_slug="acme",
                         signers=signers, provenance="reproduced", witness_quorum=_ON)
    assert not r.is_fact and r.status == "lead" and r.signed is None
    assert r.outcome == "unsupported"
    assert "witness quorum" in r.reason.lower()


def test_quorum_is_monotone_demote_only_never_promotes():
    """A non-FACT admission must stay a LEAD even with the quorum ON and an abundantly-corroborated
    context — the conjunct can only subtract. (Here admission returns INCONCLUSIVE because the branch
    precondition did not hold; the quorum is never even consulted.)"""
    vadmit, certify_admitted = _import_mint()
    _tr, signers = _trust_root()
    inconclusive = vadmit("error_signature.datastore_error", fired=False, conclusive=True, observed={})
    assert inconclusive.verdict.value != "FACT"
    r = certify_admitted(_finding(_ctx_two_witness()), inconclusive, engagement_slug="acme",
                         signers=signers, provenance="reproduced", witness_quorum=_ON)
    assert not r.is_fact and r.signed is None     # the 2-witness evidence did NOT get promoted to a FACT


def test_mint_on_lead_provenance_stays_lead_with_quorum_on():
    """A finding the deterministic layer demotes for LLM provenance stays a LEAD with the quorum ON —
    the quorum never rescues a non-FACT (monotone)."""
    vadmit, certify_admitted = _import_mint()
    _tr, signers = _trust_root()
    admitted = _admitted_fact(vadmit)
    r = certify_admitted(_finding(_ctx_two_witness()), admitted, engagement_slug="acme",
                         signers=signers, provenance="llm", witness_quorum=_ON)
    assert not r.is_fact and r.signed is None


def test_a_critic_or_llm_vote_is_not_counted_as_a_witness():
    """A claimed corroboration set / critic votes on the finding are NOT witnesses. A single-witness
    context carrying bogus ``corroborating_kinds`` and ``critic_votes`` is STILL demoted under N=2,
    because the quorum re-derives witnesses by RE-EXECUTION over oracle_context — never from claims."""
    vadmit, certify_admitted = _import_mint()
    _tr, signers = _trust_root()
    admitted = _admitted_fact(vadmit)
    finding = _finding(
        _ctx_one_witness(),
        corroborating_kinds=["error_signature", "critic_panel", "llm_judge", "reflection"],
        confirmed_by_kinds=["error_signature", "side_effect", "timing"],
        critic_votes=[{"critic": "grounding", "verdict": "endorse"}],
    )
    r = certify_admitted(finding, admitted, engagement_slug="acme",
                         signers=signers, provenance="reproduced", witness_quorum=_ON)
    assert not r.is_fact and r.status == "lead"
    assert r.reason.lower().count("1 independent oracle") >= 1   # exactly one re-fired oracle kind counted


# --------------------------------------------------------------------------- offline re-verification


def test_witnesses_reconfirm_positive_and_negatives():
    oc2 = _finding(_ctx_two_witness())["oracle_context"]
    ok, got, _ = witnesses_reconfirm(oc2, bug_class=_CLASS, required=2,
                                     expected_kinds=["error_signature", "side_effect"])
    assert ok and set(got) == {"error_signature", "side_effect"}
    # too few re-fire (the 1-witness context under a recorded quorum of 2)
    oc1 = _finding(_ctx_one_witness())["oracle_context"]
    bad_count, _, note = witnesses_reconfirm(oc1, bug_class=_CLASS, required=2,
                                             expected_kinds=["error_signature", "side_effect"])
    assert not bad_count and "FAILED offline" in note
    # a recorded witness that does not re-fire (a forged / tampered witness record), even with enough count
    tampered, _, note2 = witnesses_reconfirm(oc2, bug_class=_CLASS, required=2,
                                             expected_kinds=["error_signature", "oob_callback"])
    assert not tampered and "no longer re-fire" in note2


def test_verify_certificate_honors_quorum_and_rejects_overclaimed_witness():
    tr, signers = _trust_root()
    oc = _finding(_ctx_two_witness())["oracle_context"]
    base = {"check_id": "ebsqli-1", "bug_class": _CLASS, "confirmed_by": "error_signature",
            "confidence": 0.95, "oracle_context": oc}

    # genuine 2-witness cert → ok + quorum met
    genuine = sign_certificate(build_certificate(
        base, engagement_slug="acme", witness_quorum_required=2,
        witness_kinds=["error_signature", "side_effect"]), signers)
    v = verify_certificate(genuine, oracle_context=oc, trust_root=tr)
    assert v.ok and v.witness_quorum_met and v.bound and v.reproduced

    # a cert that RECORDS a witness the evidence does not support (over-claimed / forged) is rejected by
    # the independent re-check EVEN THOUGH binding + reproduction pass — the quorum gate is independent.
    forged = sign_certificate(build_certificate(
        base, engagement_slug="acme", witness_quorum_required=3,
        witness_kinds=["error_signature", "side_effect", "oob_callback"]), signers)
    vf = verify_certificate(forged, oracle_context=oc, trust_root=tr)
    assert vf.bound and vf.reproduced          # binding + reproduction still hold over the real evidence
    assert not vf.witness_quorum_met and not vf.ok   # but the quorum re-check refuses it


def test_verify_certificate_without_quorum_is_unaffected():
    tr, signers = _trust_root()
    oc = _finding(_ctx_two_witness())["oracle_context"]
    base = {"check_id": "ebsqli-1", "bug_class": _CLASS, "confirmed_by": "error_signature",
            "confidence": 0.95, "oracle_context": oc}
    cert = sign_certificate(build_certificate(base, engagement_slug="acme"), signers)
    v = verify_certificate(cert, oracle_context=oc, trust_root=tr)
    assert v.ok and v.witness_quorum_met is True    # no recorded quorum → gate is a no-op


def test_reverify_finding_honors_recorded_quorum():
    # a finding that records a quorum of 2 but whose retained context only re-fires 1 witness is REJECTED
    bad = _finding(_ctx_one_witness(), confirmed_by="error_signature", confidence=0.95,
                   witness_quorum_required=2, witness_kinds=["error_signature", "side_effect"])
    r = reverify.reverify_finding(bad)
    assert not r.reproduced and not r.ok and "witness quorum" in r.note.lower()
    # the genuine 2-witness finding under the same recorded quorum reproduces
    good = _finding(_ctx_two_witness(), confirmed_by="error_signature", confidence=0.95,
                    witness_quorum_required=2, witness_kinds=["error_signature", "side_effect"])
    rg = reverify.reverify_finding(good)
    assert rg.reproduced and rg.ok


def test_reverify_finding_without_quorum_is_byte_identical():
    # a finding with no recorded quorum re-verifies exactly as before (the gate is skipped)
    f = _finding(_ctx_two_witness(), confirmed_by="error_signature", confidence=0.95)
    r = reverify.reverify_finding(f)
    assert r.reproduced and r.ok and r.confirmed_by == "error_signature"


# --------------------------------------------------------------------------- the firewall (every render path)


def _oracle_claim(ctx: FindingContext) -> Claim:
    oc = ctx.model_dump(mode="json")
    return Claim(text="error-based SQLi confirmed", source="scanner", bug_class=_CLASS,
                 tokens=[GroundingToken.oracle(oc, bug_class=_CLASS)])


def test_firewall_off_is_unchanged():
    assert fw_admit(_oracle_claim(_ctx_two_witness())).is_fact
    assert fw_admit(_oracle_claim(_ctx_one_witness())).is_fact      # OFF: a single oracle still grounds


def test_firewall_on_demotes_sub_quorum_claim_everywhere():
    # 2-witness claim passes the quorum and renders as a fact
    two = fw_admit(_oracle_claim(_ctx_two_witness()), witness_quorum=_ON)
    assert two.is_fact and two.render_as == "fact"
    # 1-witness claim is demoted to UNGROUNDED → a LEAD ("analyst-commentary") on every render path
    one = fw_admit(_oracle_claim(_ctx_one_witness()), witness_quorum=_ON)
    assert not one.is_fact and one.verdict is VeracityVerdict.UNGROUNDED
    assert one.render_as == "analyst-commentary"
    assert "witness quorum" in one.reason.lower()


def test_firewall_quorum_never_promotes():
    """An ungrounded claim (no re-firing oracle) stays ungrounded with the quorum ON — the conjunct is
    only reached on a claim that already grounds at fact strength, so it can never promote."""
    empty = Claim(text="x", source="scanner", bug_class=_CLASS,
                  tokens=[GroundingToken.oracle({}, bug_class=_CLASS)])
    assert not fw_admit(empty, witness_quorum=_ON).is_fact
    assert not fw_admit(empty).is_fact


# --------------------------------------------------------------------------- invariants


def test_all_oracles_stays_exactly_fifteen_no_new_kind():
    assert len(_ALL_ORACLES) == 15


def test_empty_cert_drops_witness_fields_for_byte_identity():
    empty = EvidenceCertificate(finding_ref="x", oracle_context_digest="sha256:deadbeef")
    dumped = empty.model_dump(mode="json")
    assert "witness_quorum_required" not in dumped and "witness_kinds" not in dumped


# --------------------------------------------------------------------------- O4: the SHIPPED default policy


def test_default_policy_enabled_covers_critical_classes_n2():
    from framework.v2.veracity.witness_quorum import DEFAULT_CRITICAL_CLASSES, default_critical_policy
    pol = default_critical_policy()
    assert pol.enabled and pol.quorum_n == 2
    assert pol is not DISABLED
    for c in DEFAULT_CRITICAL_CLASSES:
        assert pol.applies_to(c), c
    # a non-critical class is still admitted exactly as today, even under the default policy
    assert not pol.applies_to("xss")


def test_default_policy_classes_are_satisfiable_not_blanket_suppression():
    """Every default critical class must map to >= quorum_n DISTINCT oracle kinds, else the policy would
    be a class the quorum can never clear (blanket suppression, not corroboration). Guards the default
    from silently becoming a suppress-all list if the oracle map changes."""
    from framework.v2.verify.verifier import BUG_CLASS_ORACLES, normalize_bug_class
    from framework.v2.veracity.witness_quorum import DEFAULT_CRITICAL_CLASSES, default_critical_policy
    n = default_critical_policy().quorum_n
    for c in DEFAULT_CRITICAL_CLASSES:
        kinds = BUG_CLASS_ORACLES.get(normalize_bug_class(c)) or BUG_CLASS_ORACLES.get(c) or ()
        assert len(set(kinds)) >= n, f"{c} maps to < {n} oracle kinds — default quorum unsatisfiable"


def test_shipped_default_json_matches_builtin_policy():
    """The committed witness_quorum.default.json must deserialise to EXACTLY the built-in default policy,
    so the two cannot drift."""
    import json

    from framework.v2.veracity.witness_quorum import default_critical_policy
    p = _ROOT / "engine" / "crucible" / "framework" / "v2" / "veracity" / "witness_quorum.default.json"
    doc = json.loads(p.read_text())
    assert WitnessQuorumConfig.from_dict(doc) == default_critical_policy()


def test_sentinel_selects_default_env_unset_stays_disabled(monkeypatch):
    from framework.v2.veracity import witness_quorum as wq
    monkeypatch.delenv("CRUCIBLE_WITNESS_QUORUM_CONFIG", raising=False)
    wq._load_cached.cache_clear()
    assert wq.load_quorum_config() is DISABLED                         # env-unset ⇒ byte-identical
    monkeypatch.setenv("CRUCIBLE_WITNESS_QUORUM_CONFIG", "default")    # the sentinel
    wq._load_cached.cache_clear()
    loaded = wq.load_quorum_config()
    assert loaded == wq.default_critical_policy() and loaded.applies_to("sqli")
    wq._load_cached.cache_clear()


def test_default_policy_evaluate_demotes_single_witness_admits_two():
    from framework.v2.veracity.witness_quorum import default_critical_policy
    pol = default_critical_policy()
    two = evaluate(_finding(_ctx_two_witness())["oracle_context"], bug_class=_CLASS, config=pol)
    assert two.applicable and two.ok and two.got == 2                 # corroborated → admitted
    one = evaluate(_finding(_ctx_one_witness())["oracle_context"], bug_class=_CLASS, config=pol)
    assert one.applicable and not one.ok and one.got == 1            # single witness → withheld


def test_default_policy_mint_demotes_single_and_mints_two_never_promotes():
    """The VALIDATE proof driven through the real mint choke (certify_admitted): under the shipped default
    policy a critical-class FACT lacking quorum is DEMOTED to a LEAD; a corroborated one still mints; and
    a non-FACT is never promoted."""
    from framework.v2.veracity.witness_quorum import default_critical_policy
    vadmit, certify_admitted = _import_mint()
    _tr, signers = _trust_root()
    admitted = _admitted_fact(vadmit)
    pol = default_critical_policy()

    short = certify_admitted(_finding(_ctx_one_witness()), admitted, engagement_slug="acme",
                             signers=signers, provenance="reproduced", witness_quorum=pol)
    assert not short.is_fact and short.status == "lead" and short.signed is None    # demoted

    full = certify_admitted(_finding(_ctx_two_witness()), admitted, engagement_slug="acme",
                            signers=signers, provenance="reproduced", witness_quorum=pol)
    assert full.is_fact                                                             # corroborated → mints
    assert full.signed.certificate.model_dump(mode="json")["witness_quorum_required"] == 2

    inconclusive = vadmit("error_signature.datastore_error", fired=False, conclusive=True, observed={})
    never = certify_admitted(_finding(_ctx_two_witness()), inconclusive, engagement_slug="acme",
                             signers=signers, provenance="reproduced", witness_quorum=pol)
    assert not never.is_fact and never.signed is None                              # never promoted
