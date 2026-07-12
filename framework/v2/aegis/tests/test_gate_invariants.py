"""
Gate-invariant TRIPWIRE (roadmap #2) — fail loudly the moment the two byte-identity guarantees drift.

The whole AEGIS discipline is that every append is additive and default-OFF, so `make gate` stays
byte-identical. Two things must never move without a deliberate, reviewed change:

  1. The unknown-class fallback ``verify.verifier._ALL_ORACLES`` is FROZEN to exactly the 15 pre-AEGIS
     OracleKind members. If a NEW oracle kind (AEGIS telemetry, the request-side parse-proof kinds, the
     k8s-posture kind, or a future one) ever leaks into it, every unknown-class benchmark finding would
     begin running that oracle and the serialized gate output would drift. This file hardcodes the
     exact 15 names so a drift fails with an explicit diff — not a silently-recomputed set.
     (``test_gate_byte_identical.py`` asserts the same count via set arithmetic; this is the
     name-pinned twin that survives even if the enum or the arithmetic is refactored.)

  2. The in-process benchmark tally is byte-identical: crucible tp=9, fp=0, fn=0, precision=recall=
     f1=1.0, 853 requests, 9 findings reported — the exact row `make gate` prints and gates on.

Colocated with ``test_gate_byte_identical.py`` under ``aegis/tests/`` so ``make test`` collects it.
"""

from __future__ import annotations

import pytest

from framework.v2.verify import verifier as V
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import BUG_CLASS_ORACLES

# The 15 pre-AEGIS oracle kinds — the ONLY members allowed in the frozen unknown-class fallback.
# Hardcoded by NAME so any rename/add/remove fails loudly with an explicit diff.
_FROZEN_15 = frozenset({
    "DIFFERENTIAL_RESPONSE", "ACHIEVED_STATE", "SIDE_EFFECT", "OOB_CALLBACK", "SANITIZER_SIGNAL",
    "TIMING", "BOOLEAN_INFERENCE", "REFLECTION_CONTEXT", "EVALUATION", "ERROR_SIGNATURE",
    "DOM_EXECUTION", "SERVICE_REACHABILITY", "TLS_WEAKNESS", "VERSION_RANGE", "POLICY_PATH",
})

# The 11 additive kinds (4 AEGIS telemetry + 3 request-side parse-proof [sqli/cmdi/nosql] + 1 WS-3
# k8s-posture + 1 WS-B sso-assertion-forgery + 1 NW-1 saml-structural-forgery + 1 Wave-F1 cloud/CSPM
# achieved-state posture) that MUST stay OUT of the frozen fallback — reachable only via their explicit
# BUG_CLASS_ORACLES rows.
_ADDITIVE_11 = frozenset({
    "PROMPT_INJECTION", "SYSTEM_PROMPT_DISCLOSURE", "AUTOMATED_ACCESS", "CREDENTIAL_STUFFING",
    "SQL_INJECTION_BREAKOUT", "COMMAND_INJECTION_BREAKOUT", "NOSQL_INJECTION_BREAKOUT", "K8S_POSTURE",
    "SSO_ASSERTION_FORGERY", "SAML_STRUCTURAL_FORGERY", "CLOUD_POSTURE",
})


def test_all_oracles_fallback_is_exactly_the_frozen_15_by_name():
    got = {k.name for k in V._ALL_ORACLES}
    assert len(V._ALL_ORACLES) == 15, f"_ALL_ORACLES size drifted: {sorted(got)}"
    assert got == _FROZEN_15, (
        "the frozen unknown-class fallback membership drifted; "
        f"added={sorted(got - _FROZEN_15)} removed={sorted(_FROZEN_15 - got)}")
    # no accidental duplicate row bloated the tuple.
    assert len(V._ALL_ORACLES) == len(set(V._ALL_ORACLES))


def test_every_additive_oraclekind_is_excluded_from_the_fallback():
    frozen_names = {k.name for k in V._ALL_ORACLES}
    for name in _ADDITIVE_11:
        member = OracleKind[name]
        assert member not in V._ALL_ORACLES, f"{name} leaked into the frozen fallback"
        assert name not in frozen_names
    # the enum is exactly the 15 frozen + 11 additive = 26; a new frozen member (or a new additive one
    # not accounted for here) fails this, forcing an explicit review of the byte-identity impact.
    assert len(OracleKind) == 26
    assert {k.name for k in OracleKind} == _FROZEN_15 | _ADDITIVE_11
    assert set(V._ALL_ORACLES) == set(OracleKind) - {OracleKind[n] for n in _ADDITIVE_11}


def test_unknown_class_falls_back_to_the_frozen_15_after_importing_aegis():
    import framework.v2.aegis  # noqa: F401  — importing AEGIS must not grow the fallback
    fallback = V.OracleVerifier().oracles_for("a_class_no_oracle_maps_to")
    assert fallback == V._ALL_ORACLES
    assert {k.name for k in fallback} == _FROZEN_15


def test_xxe_mapping_is_unchanged_and_adds_no_new_kind():
    """AEGIS emits in-band XXE as a request-side LEAD (never an inline block — the review proved a
    single inline exchange cannot soundly confirm it). The offensive ``xxe`` -> (OOB_CALLBACK,
    SIDE_EFFECT) mapping is UNCHANGED and both kinds are pre-existing frozen members, so nothing about
    XXE introduced a new OracleKind or touched the frozen fallback."""
    assert BUG_CLASS_ORACLES["xxe"] == (OracleKind.OOB_CALLBACK, OracleKind.SIDE_EFFECT)
    assert OracleKind.SIDE_EFFECT in V._ALL_ORACLES
    assert "SIDE_EFFECT" in _FROZEN_15


# ---------------------------------------------------------------------------
# Byte-identical benchmark tally — the exact row `make gate` prints and gates on.
# In-process + loopback-only (no Docker / no external tool), so it is a real unit test.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def crucible_measured():
    from framework.v2.eval.benchmark_run import run_benchmark_measured
    boards = run_benchmark_measured(incumbents=False)
    return next(mb for mb in boards if mb.scoreboard.tool == "crucible")


def test_benchmark_tally_is_byte_identical(crucible_measured):
    sb = crucible_measured.scoreboard
    assert (sb.true_positives, sb.false_positives, sb.false_negatives) == (9, 0, 0), (
        f"accuracy tally drifted: tp={sb.true_positives} fp={sb.false_positives} "
        f"fn={sb.false_negatives} (gate requires 9/0/0)")
    assert sb.precision == 1.0 and sb.recall == 1.0 and sb.f1 == 1.0


def test_benchmark_cost_row_is_byte_identical(crucible_measured):
    m = crucible_measured.metrics
    assert m.requests_sent == 853, f"request budget drifted: {m.requests_sent} (gate requires 853)"
    assert m.findings_reported == 9, f"findings reported drifted: {m.findings_reported} (gate requires 9)"
