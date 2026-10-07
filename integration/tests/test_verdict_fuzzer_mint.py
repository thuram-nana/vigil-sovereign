"""End-to-end mint-choke companion to the deterministic verdict fuzzer.

``test_verdict_fuzzer`` (framework side) proves the structural grammar is sound and byte-identical across the
three re-execution engines. This file closes the loop at the REAL MINT CHOKE: it drives a representative
subset of the grammar's shapes through ``confirm_and_certify`` AND ``certify_admitted`` with real governance
signers, over BOTH reproduced provenances, and asserts the end-to-end consequence:

  * an INELIGIBLE grammar shape (a bare match, a floor, a ``not``-wrapped PD, a bare liveness flag, a mixed
    ``any`` with one unsound disjunct, a short-needle "differential", a tautology) mints NOTHING — through
    either entrypoint: ``status != "fact"``, ``signed is None``, AND it does not reproduce offline
    (``reverify_finding(...).ok`` is False);
  * an ELIGIBLE shape (the real KEEP-class predicates — PD2 canary, PD3 reduction + liveness corroborator,
    PD4 present/absent differential) mints + signs + re-verifies offline, under BOTH ``reproduced`` and
    ``live_redrive`` provenance;
  * CLASS-BINDING — a context that confirms class A cannot mint or reverify as class B, by TWO independent
    routes: (i) a class whose oracle is not the firing oracle (``achieved_state`` does not confirm ``xss``),
    and (ii) a retained context carrying its own ``bug_class`` that disagrees with the declared class (the
    step-0 relabel refusal).

This is the same split-leg precedent as ``test_lane_s_mint_choke``: it drives ``oracle_adapter``'s lazy
``import framework`` (the offense verification layer), so it RUNS in the offense CI leg (engine/crucible on
PYTHONPATH) and SKIPs cleanly in the keyless boundary leg via the module-level ``importorskip`` below. It is
added to the offense-leg list in ``.github/workflows/ci.yml`` (additive — no branch-protection change).
"""
from __future__ import annotations

import pytest

# Two-env boundary: drives the lazy offense ``import framework`` — runs in the offense leg, skips cleanly in
# the keyless boundary leg. Listed in the offense-leg invocation in .github/workflows/ci.yml so it is not
# silently skipped everywhere (enforced by test_ci_framework_tests_run_in_offense_leg.py).
pytest.importorskip("framework.v2")

from vigil_core import generate_keypair  # noqa: E402
from vigil_integration.live.verdict import Verdict, admit  # noqa: E402
from vigil_integration.oracle_adapter import certify_admitted, confirm_and_certify  # noqa: E402

_PROVENANCES = ("reproduced", "live_redrive")


def _signers():
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _admit_fact():
    adm = admit("open_redirect.location_header", fired=True, conclusive=True,
                observed={"channel_established": True})
    assert adm.verdict is Verdict.FACT
    return adm


def _reverify_ok(finding: dict) -> bool:
    from framework.v2.verify.reverify import reverify_finding  # noqa: PLC0415 (FATAL-2: function-local)
    return reverify_finding(finding).ok


_REALBODY = 'HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n{"secret":"abcde"}'


# ===========================================================================
# ELIGIBLE subset — the real KEEP-class predicates, one per positive-discriminator kind. Each mints a signed
# FACT and re-verifies offline, through BOTH entrypoints and BOTH reproduced provenances.
# ===========================================================================
_ELIGIBLE = {
    # PD2 — a VIGIL-injected canary the producer cannot author (open_redirect, cors).
    "open_redirect": {"predicate": {"all": [
        {"in": [{"var": "status"}, [301, 302, 303, 307, 308]]},
        {"eq": [{"var": "location_host"}, {"var": "canary_host"}]}]},
        "observed_evidence": {"status": 302, "location_host": "canary.test", "canary_host": "canary.test"},
        "provenance_refs": {"canary_host": "canary"}},
    "cors": {"predicate": {"all": [
        {"eq": [{"var": "acao"}, {"var": "evil_origin"}]},
        {"ieq": [{"var": "acac"}, "true"]}]},
        "observed_evidence": {"acao": "https://evil", "acac": "true", "evil_origin": "https://evil"},
        "provenance_refs": {"evil_origin": "canary"}},
    # PD3 — a strict reduction floor on a VIGIL-injected count; the liveness flag rides as a mere corroborator
    # (demoted by step 1) and costs nothing because the PD3 is the real discriminator.
    "graphql_introspection": {"predicate": {"all": [
        {"eq": [{"var": "body_available"}, True]},
        {"gt": [{"var": "introspection_type_count"}, 0]}]},
        "observed_evidence": {"body_available": True, "introspection_type_count": 7},
        "provenance_refs": {"introspection_type_count": "reduction"}},
    # PD4 — a present/absent differential over two distinct captured bodies sharing one distinctive needle.
    "idor": {"predicate": {"all": [
        {"min_len": [{"var": "discriminator"}, 6]},
        {"contains": [{"var": "victim_body"}, {"var": "discriminator"}]},
        {"contains": [{"var": "attacker_body"}, {"var": "discriminator"}]},
        {"not": {"contains": [{"var": "attacker_own_body"}, {"var": "discriminator"}]}}]},
        "observed_evidence": {"discriminator": "acct-7FA91C33", "victim_body": "owner acct-7FA91C33",
                              "attacker_body": "leaked acct-7FA91C33", "attacker_own_body": "your own"}},
    "exposure": {"predicate": {"all": [
        {"icontains": [{"var": "body"}, "DB_PASSWORD="]},
        {"not": {"icontains": [{"var": "control_body"}, "DB_PASSWORD="]}}]},
        "observed_evidence": {"body": "...DB_PASSWORD=hunter2...", "control_body": "404 Not Found"}},
}

# ===========================================================================
# INELIGIBLE subset — one shape per refused family. Each is declared a KNOWN oracle-mapped class
# (open_redirect) so the ONLY reason it fails to mint is the structural grammar, not an unknown class.
# ===========================================================================
_INELIGIBLE = {
    "bare_contains_lit": {"predicate": {"all": [{"icontains": [{"var": "body"}, "DB_PASSWORD="]}]},
                          "observed_evidence": {"body": "set DB_PASSWORD=hunter2"}},
    "bare_eq_lit": {"predicate": {"eq": [{"var": "body"}, "decoy-value"]},
                    "observed_evidence": {"body": "decoy-value"}},
    "min_len_floor": {"predicate": {"min_len": [{"var": "body"}, 1]}, "observed_evidence": {"body": _REALBODY}},
    "ge_vs_lit": {"predicate": {"ge": [{"var": "body"}, "!"]}, "observed_evidence": {"body": _REALBODY}},
    "not_wrapped_pd": {"predicate": {"not": {"eq": [{"var": "a"}, {"var": "b"}]}},
                       "observed_evidence": {"a": "x", "b": "y"}},
    "liveness_sole_eq": {"predicate": {"eq": [{"var": "body_available"}, True]},
                         "observed_evidence": {"body_available": True}},
    "liveness_sole_gt": {"predicate": {"gt": [{"var": "probe_count"}, 0]},
                         "observed_evidence": {"probe_count": 3}},
    "any_mixed_one_unsound": {"predicate": {"any": [
        {"eq": [{"var": "location_host"}, {"var": "canary_host"}]},   # eligible disjunct (PD2)
        {"icontains": [{"var": "body"}, "DB_PASSWORD="]}]},           # ineligible disjunct => whole any refused
        "observed_evidence": {"location_host": "c.test", "canary_host": "c.test", "body": "DB_PASSWORD=x"},
        "provenance_refs": {"canary_host": "canary"}},
    "pd4_short_needle": {"predicate": {"all": [
        {"contains": [{"var": "a"}, "ab"]},
        {"not": {"contains": [{"var": "b"}, "ab"]}}]},
        "observed_evidence": {"a": "xxabyy", "b": "clean"}},
    "tautology_self_eq": {"predicate": {"eq": [{"var": "k"}, {"var": "k"}]}, "observed_evidence": {"k": "v"}},
    "vacuous_ge_count": {"predicate": {"all": [{"ge": [{"var": "introspection_type_count"}, 0]}]},
                         "observed_evidence": {"introspection_type_count": 0},
                         "provenance_refs": {"introspection_type_count": "reduction"}},
}


# ---------------------------------------------------------------------------
# ELIGIBLE — mints + signs + re-verifies, through both entrypoints and both reproduced provenances.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("prov", _PROVENANCES)
@pytest.mark.parametrize("cls", sorted(_ELIGIBLE), ids=sorted(_ELIGIBLE))
def test_eligible_mints_and_reverifies_via_confirm_and_certify(cls, prov):
    f = {"check_id": f"e-{cls}-{prov}", "bug_class": cls, "oracle_context": _ELIGIBLE[cls]}
    r = confirm_and_certify(f, engagement_slug="vf", signers=_signers(), provenance=prov)
    assert r.is_fact and r.signed is not None, (cls, prov, r.reason)
    assert _reverify_ok(f), (cls, prov)


@pytest.mark.parametrize("cls", sorted(_ELIGIBLE), ids=sorted(_ELIGIBLE))
def test_eligible_mints_via_certify_admitted(cls):
    f = {"check_id": f"ea-{cls}", "bug_class": cls, "oracle_context": _ELIGIBLE[cls]}
    r = certify_admitted(f, _admit_fact(), engagement_slug="vf", signers=_signers(), provenance="reproduced")
    assert r.is_fact and r.signed is not None, (cls, r.reason)


# ---------------------------------------------------------------------------
# INELIGIBLE — mints NOTHING through either entrypoint and does not reproduce offline.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("label", sorted(_INELIGIBLE), ids=sorted(_INELIGIBLE))
def test_ineligible_mints_nothing_via_both_entrypoints_and_does_not_reverify(label):
    f = {"check_id": f"n-{label}", "bug_class": "open_redirect", "oracle_context": _INELIGIBLE[label]}
    r1 = confirm_and_certify(f, engagement_slug="vf", signers=_signers(), provenance="reproduced")
    assert not r1.is_fact and r1.signed is None, (label, "confirm_and_certify", r1.status)
    r2 = certify_admitted(f, _admit_fact(), engagement_slug="vf", signers=_signers(), provenance="reproduced")
    assert not r2.is_fact and r2.signed is None, (label, "certify_admitted", r2.status)
    assert not _reverify_ok(f), (label, "offline reverify unexpectedly ok")


# ---------------------------------------------------------------------------
# CLASS-BINDING — a context confirming class A cannot mint or reverify as class B.
# ---------------------------------------------------------------------------
def test_class_binding_wrong_oracle_class_mints_nothing():
    """The open_redirect predicate fires via the ``achieved_state`` oracle, which does NOT confirm ``xss``
    (xss rides the DOM-execution oracle). Declared as xss it mints nothing and does not reproduce offline —
    a fired oracle that does not prove the declared class is a LEAD, never a signed fact."""
    f = {"check_id": "cb-xss", "bug_class": "xss", "oracle_context": _ELIGIBLE["open_redirect"]}
    r = confirm_and_certify(f, engagement_slug="vf", signers=_signers(), provenance="reproduced")
    assert not r.is_fact and r.signed is None, r.reason
    assert not _reverify_ok(f)


def test_class_binding_embedded_context_class_relabel_mints_nothing():
    """A retained context that carries its OWN ``bug_class`` (idor) cannot be laundered under a different
    declared class (open_redirect): the step-0 relabel refusal catches the disagreement before any mint."""
    oc = dict(_ELIGIBLE["idor"], bug_class="idor")
    f = {"check_id": "cb-relabel", "bug_class": "open_redirect", "oracle_context": oc}
    r = confirm_and_certify(f, engagement_slug="vf", signers=_signers(), provenance="reproduced")
    assert not r.is_fact and r.signed is None
    assert "does not match the retained evidence" in r.reason
    assert not _reverify_ok(f)


def test_eligible_positive_control_still_mints_so_the_file_cannot_pass_by_refusing_everything():
    """Guard against a vacuous pass: at least one eligible shape must still mint a signed, offline-verifiable
    FACT, or every refusal above is satisfied by a mint path that is simply broken."""
    f = {"check_id": "pc-or", "bug_class": "open_redirect", "oracle_context": _ELIGIBLE["open_redirect"]}
    r = confirm_and_certify(f, engagement_slug="vf", signers=_signers(), provenance="reproduced")
    assert r.is_fact and r.signed is not None and r.confirmed_by == "achieved_state"
    assert _reverify_ok(f)
