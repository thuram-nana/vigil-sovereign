"""The mutation gate has REAL sensitivity — proven fast, unconditionally, in a required job (W11-3, #484).

Full mutation testing (mutmut / cosmic-ray) re-runs the whole suite once per mutant and needs the tools
installed; it cannot run on an ordinary PR runner, so it is wired as a SCHEDULED job
(.github/workflows/mutation-fuzz.yml). What CAN and MUST be proven on every PR is that the mutation
gate's kill/survive verdict measures something real:

  * an ADEQUATE test KILLS a boundary mutant of a real security-critical function (sensitivity — the
    gate has teeth); and
  * a deliberately-WEAK test lets the SAME mutant SURVIVE (the negative control — a surviving mutant
    reliably signals a weak test, which is the whole point of a mutation score).

The critical function under mutation is the REAL WARDEN gate decision, ``vigil_core.warden_tiers.gate``
(the sovereign kernel's Python port of the Rust ``tiers::gate``): it maps an autonomy tier to
auto/queued/explicit-required, and its ``tier <= A1`` boundary is exactly the kind of off-by-one a
mutation tester flips. We mutate its own source (via the stdlib ``tools/mutation/mutation_probe.py``),
so this is a mutation of production code, not of a toy.

STDLIB + vigil_core ONLY — no ``framework``/``strix`` import — so it runs in the sovereign leg of the
required "integration two-env boundary (P5)" job (and never trips ``assert_no_offense``).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "tools" / "mutation"))

import mutation_probe  # noqa: E402 — path is prepended just above.
from mutation_probe import KILLED, SURVIVED, evaluate, mutate_boundary  # noqa: E402

# The real security-critical function under test. vigil_core is the offense-free shared substrate,
# installed in the sovereign leg; importing it here does not cross the two-env boundary.
from vigil_core.warden_tiers import Tier, gate  # noqa: E402

_NS = {"Tier": Tier}


def _strong(g) -> None:
    """An ADEQUATE test: it probes the ``<= A1`` boundary that separates auto from queued/explicit."""
    assert g(Tier.A0) == "auto"
    assert g(Tier.A1) == "auto"                 # the boundary case the `<=` covers
    assert g(Tier.A2) == "queued"
    assert g(Tier.A3) == "explicit-required"


def _weak(g) -> None:
    """A deliberately-WEAK test: it only ever probes A0, so it cannot see a `<=` -> `<` boundary flip."""
    assert g(Tier.A0) == "auto"


# --------------------------------------------------------------------------------------------------
# Premise checks — the specimen is a real, faithful, mutable critical function.
# --------------------------------------------------------------------------------------------------
def test_the_specimen_is_the_real_warden_gate_contract():
    """Ground the mutation in reality: the live gate has the auto/queued/explicit contract we mutate."""
    assert gate(Tier.A0) == "auto"
    assert gate(Tier.A1) == "auto"
    assert gate(Tier.A2) == "queued"
    assert gate(Tier.A3) == "explicit-required"


def test_both_tests_pass_on_the_unmutated_function():
    """Baseline (the 'healthy home' control): both tests are VALID on the real function, so a later
    KILLED verdict is caused by the mutation, not by a broken test."""
    _strong(gate)
    _weak(gate)


def test_the_probe_actually_mutates_production_source():
    mutated_src, applied = mutate_boundary(gate, index=0)
    assert applied, "the probe found no boundary comparator to mutate in gate() — it must have one"
    original_src = mutate_boundary(gate, index=99)[0]  # index out of range -> unchanged source
    assert mutated_src != original_src, "the mutated source must differ from the original"
    assert "<" in mutated_src  # the flipped operator is present


# --------------------------------------------------------------------------------------------------
# The sensitivity theorem: strong KILLS, weak SURVIVES (the negative control).
# --------------------------------------------------------------------------------------------------
def test_adequate_test_kills_the_boundary_mutant():
    """SENSITIVITY: an adequate suite detects the mutant. If this could not hold, a green mutation
    score would be worthless."""
    mutant, applied = mutate_boundary(gate, index=0)
    assert applied
    assert evaluate(mutant, "gate", _NS, _strong) == KILLED


def test_weak_test_lets_the_mutant_survive_the_negative_control():
    """NEGATIVE CONTROL: the deliberately-weak test CANNOT catch the mutant, so it is reported as
    SURVIVING — exactly what the mutation programme must surface as 'your test here is weak'."""
    mutant, applied = mutate_boundary(gate, index=0)
    assert applied
    assert evaluate(mutant, "gate", _NS, _weak) == SURVIVED


def test_identity_mutant_survives_even_the_strong_test_so_KILLED_is_load_bearing():
    """Prove the KILLED verdict above is caused by the mutation, not by an always-KILLED harness: feed
    the UNMUTATED source to `evaluate` and the strong test must report SURVIVED. If `evaluate` returned
    KILLED here, `test_adequate_test_kills_the_boundary_mutant` would be a rubber stamp."""
    unchanged, applied = mutate_boundary(gate, index=99)  # no such site -> original source
    assert not applied
    assert evaluate(unchanged, "gate", _NS, _strong) == SURVIVED


def test_the_kill_survive_verdicts_are_not_constant():
    """Belt and braces: over the two tests the mutant is BOTH killed and survived, so the harness is
    not wired to a constant verdict."""
    mutant, _ = mutate_boundary(gate, index=0)
    verdicts = {evaluate(mutant, "gate", _NS, _strong), evaluate(mutant, "gate", _NS, _weak)}
    assert verdicts == {KILLED, SURVIVED}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
