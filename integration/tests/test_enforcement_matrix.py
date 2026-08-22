"""W13-1 — the enforcement coverage matrix, MEASURED BY EXECUTION (not by grep).

For each declared sensitive execution path the matrix RUNS the real gate of record under a line tracer and
asserts, by execution, that (a) the enforcing code traversed on an authorized action and ALLOWed, and
(b) a deliberately unauthorized action was REFUSED — the negative control. A path with no refusal proof is
recorded as an OPEN BYPASS, not as covered.

Where each test runs (FATAL-2 two-env boundary):
  * The pure/data tests and the sovereign-plane execution tests need only vigil_core + vigil_gateway +
    the import-clean vigil_integration seam, so they run in BOTH integration CI legs.
  * ``test_entitlement_gate_is_traversed_and_refused`` measures ``framework.v2.entitlement`` and is guarded
    by ``pytest.importorskip("framework...")`` — it SKIPS in the sovereign leg and RUNS in the offense leg.
    That importorskip is why this file is on the offense-leg explicit run-list in .github/workflows/ci.yml
    (pinned by test_ci_framework_tests_run_in_offense_leg.py).

This file lives in the required ``integration two-env boundary (P5)`` CI job.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vigil_integration.enforcement_matrix import (
    CONTROLS,
    _CORE_GATE_FUNCTIONS,
    ControlRow,
    ResolvedControl,
    build_execution_matrix,
    evaluate_control,
    open_bypasses,
    render_matrix_markdown,
    scan_core_gate_functions,
    traced_call,
)

_REPO = Path(__file__).resolve().parents[2]
_MATRIX_DOC = _REPO / "docs" / "ENFORCEMENT-COVERAGE-MATRIX.md"

_SOVEREIGN = tuple(r for r in CONTROLS if r.plane == "sovereign")
_OFFENSE = tuple(r for r in CONTROLS if r.plane == "offense")


# ── the committed artifact is TRUE of the code (adding a path without a row turns this red) ──────────

def test_committed_matrix_is_true_of_the_code():
    """The checked-in matrix artifact must equal what the live registry renders. A new sensitive path
    (a new ControlRow) that is not reflected in the committed doc — or a stale committed doc — fails here,
    so a sensitive path can never be added without its matrix row appearing in the artifact."""
    assert _MATRIX_DOC.exists(), f"the committed matrix artifact is missing: {_MATRIX_DOC}"
    committed = _MATRIX_DOC.read_text(encoding="utf-8")
    assert committed == render_matrix_markdown(), (
        "docs/ENFORCEMENT-COVERAGE-MATRIX.md has drifted from the enforcement_matrix registry — "
        "regenerate it (render_matrix_markdown) so the artifact stays true of the code"
    )


def test_every_control_declares_a_negative_control():
    """AC: a path with no refusal proof is an OPEN BYPASS, not covered. Every row must DECLARE a negative
    control; the execution tests below then PROVE the declared negative control actually refuses."""
    missing = [r.id for r in CONTROLS if not r.negative_control]
    assert not missing, f"these controls declare no negative-control (refusal) proof — OPEN BYPASS: {missing}"


# ── RED-PEN #494 regression: the matrix must NOT overclaim per-PATH coverage ─────────────────────────

def test_matrix_does_not_overclaim_request_path_coverage():
    """RED-PEN HIGH (#494, overclaim): every resolver drives the gate FUNCTION directly with synthesized
    inputs and never executes a real request PATH — so the matrix must NOT assert that the named paths
    (worker / adapter / proxy egress, the tool bridge, …) are traversed. It must state HONESTLY that it
    measures the GATE-OF-RECORD LAYER — the shared primitive executes-and-refuses. Reverting the honest
    wording (back to 'Each row is a sensitive execution path … proven by RUNNING the real gate') fails here.

    This reproduces the red-pen 'attack': an auditor reading the artifact must be unable to conclude that a
    named request path was itself exercised."""
    md = render_matrix_markdown()

    # (a) the honest scope framing is present: it measures the LAYER, and it explicitly DISCLAIMS the path.
    assert "GATE-OF-RECORD LAYER" in md, "the matrix must state it measures the gate-of-record LAYER"
    assert "does NOT drive a real end-to-end request path" in md, (
        "the matrix must explicitly disclaim traversing the real request path"
    )
    assert "not that the named call site" in md and "actually reaches the gate" in md, (
        "the matrix must say the proof is the SHARED GATE refusing, not that the named call site reaches it"
    )

    # (b) the load-bearing OVERCLAIM wording is gone. Its return would resurrect the red-pen defect.
    assert "Each row is a sensitive execution path and the gate of record it traverses" not in md, (
        "the overclaiming 'sensitive execution path … it traverses' wording must not return"
    )
    assert "Sensitive execution path |" not in md, (
        "the column must not be titled 'Sensitive execution path' (implies the path is traversed)"
    )

    # (c) every row carries an explicit, honest proof scope, surfaced in the rendered table.
    assert "Proof scope" in md, "the rendered matrix must carry a Proof scope column"
    for r in CONTROLS:
        assert r.proof_scope == "gate function", (
            f"{r.id}: shipped rows are proven at 'gate function' scope only; a 'request path' scope "
            f"requires the resolver to actually drive the live call site end-to-end (got {r.proof_scope!r})"
        )
    # the committed artifact reflects the per-row proof scope for every gate row.
    assert md.count("| gate function |") == len(CONTROLS), (
        "every matrix row must render its proof scope so no row silently implies path-level coverage"
    )


def test_committed_doc_carries_the_honest_scope_disclaimer():
    """Belt-and-braces on the pinned artifact itself: the file a reader opens must carry the honest
    disclaimer, not just the generator. Guards against the doc being hand-edited back to the overclaim."""
    committed = _MATRIX_DOC.read_text(encoding="utf-8")
    assert "does NOT drive a real end-to-end request path" in committed
    assert "GATE-OF-RECORD LAYER" in committed
    assert "Sensitive execution path |" not in committed


def test_core_gate_functions_are_all_rowed():
    """Adding a NEW gate-decision function to a clean core gate module (vigil_core.gate / warden_tiers /
    hard_guardrail) turns CI red until it is either given a matrix row or documented as a non-gate helper.
    This is the 'a new sensitive path cannot appear un-inventoried' guard for the pure gate-of-record core."""
    scanned = scan_core_gate_functions()
    for module, funcs in scanned.items():
        declared = _CORE_GATE_FUNCTIONS.get(module, frozenset())
        undeclared = sorted(funcs - declared)
        assert not undeclared, (
            f"{module} exposes gate-shaped public function(s) {undeclared} not represented in the "
            f"enforcement matrix; add a ControlRow (or list it as a non-gate helper in _KNOWN_NON_GATE)"
        )
        stale = sorted(declared - funcs)
        assert not stale, f"{module}: matrix declares {stale} but the module no longer defines them"

    # and every declared core-gate function is actually reflected by a control row's gate_label
    labels = " ".join(r.gate_label for r in CONTROLS)
    for module, funcs in _CORE_GATE_FUNCTIONS.items():
        assert module in labels, f"no control row references core gate module {module}"


# ── measured by execution: each SOVEREIGN gate is traversed on allow AND refuses the bad action ─────

@pytest.mark.parametrize("row", _SOVEREIGN, ids=[r.id for r in _SOVEREIGN])
def test_sovereign_gate_is_traversed_and_refuses(row: ControlRow):
    result = evaluate_control(row)
    assert result.status == "COVERED", f"{row.id}: {result.status} — {result.detail}"

    # POSITIVE: the gate's own code executed (the execution marker) and the authorized action ALLOWed.
    assert result.positive is not None
    assert result.positive.traversed, f"{row.id}: authorized probe did not TRAVERSE the gate's code"
    assert result.positive.outcome == "allow"

    # NEGATIVE CONTROL: the gate's own code executed AND the unauthorized action was REFUSED (not a no-op).
    assert result.negative is not None
    assert result.negative.traversed, f"{row.id}: negative-control probe did not TRAVERSE the gate's code"
    assert result.negative.outcome == "refuse"


def test_no_open_bypasses_among_loadable_controls():
    """Across every control loadable in this environment, there is ZERO OPEN BYPASS. (Any control whose
    gate is not loadable here is reported OFFENSE_LEG and proven in the other CI leg, never counted here.)"""
    results = build_execution_matrix()
    bypasses = open_bypasses(results)
    assert not bypasses, "OPEN BYPASSES found: " + "; ".join(
        f"{r.row.id} ({r.detail})" for r in bypasses
    )
    # nothing may be silently ERROR (a resolver that could not bind its gate)
    errored = [r for r in results if r.status == "ERROR"]
    assert not errored, "controls that failed to resolve their gate: " + "; ".join(
        f"{r.row.id} ({r.detail})" for r in errored
    )


# ── the OFFENSE-plane gate: proven in the offense CI leg (skips in the sovereign leg) ────────────────

def test_entitlement_gate_is_traversed_and_refused():
    pytest.importorskip("framework.v2.entitlement", reason="offense engine not on the path (sovereign leg)")
    assert _OFFENSE, "expected an offense-plane control (require_capability)"
    for row in _OFFENSE:
        result = evaluate_control(row)
        assert result.status == "COVERED", f"{row.id}: {result.status} — {result.detail}"
        assert result.positive is not None and result.positive.traversed and result.positive.outcome == "allow"
        assert result.negative is not None and result.negative.traversed and result.negative.outcome == "refuse"


# ── the harness has TEETH: it flags a no-op gate as an OPEN BYPASS (fails without a real refusal) ────

def test_matrix_flags_a_noop_gate_as_open_bypass():
    """A test that would FAIL on a tree whose gate had regressed to a no-op: if the 'gate' allows even the
    deliberately-unauthorized action, the harness must record OPEN BYPASS, not COVERED. This proves the
    negative control is not itself a no-op and that the matrix catches a real bypass rather than green-
    washing it."""
    def _noop_gate(_authorized: bool) -> str:
        return "allow-always"  # a broken gate that never refuses anything

    def _resolver() -> ResolvedControl:
        return ResolvedControl(
            target_code=_noop_gate.__code__,
            authorized=lambda: _noop_gate(True),
            unauthorized=lambda: _noop_gate(False),
            interpret=lambda result, raised: "allow",  # always allows — a no-op gate
        )

    broken = ControlRow(
        id="synthetic-noop", path="synthetic broken gate", plane="sovereign",
        gate_label="test._noop_gate", resolver=_resolver,
    )
    result = evaluate_control(broken)
    assert result.status == "OPEN_BYPASS", (
        "the matrix must flag a gate that never refuses as an OPEN BYPASS; it did not — the negative "
        "control has no teeth"
    )
    assert result.negative is not None and result.negative.outcome == "allow"


def test_matrix_flags_a_missing_negative_control_as_open_bypass():
    """A path that offers no refusal proof at all is an OPEN BYPASS, not covered (AC)."""
    def _gate() -> str:
        return "ok"

    def _resolver() -> ResolvedControl:
        return ResolvedControl(
            target_code=_gate.__code__,
            authorized=lambda: _gate(),
            unauthorized=None,  # NO negative control
            interpret=lambda result, raised: "allow",
        )

    row = ControlRow(
        id="synthetic-no-negative", path="synthetic gate with no refusal proof", plane="sovereign",
        gate_label="test._gate", resolver=_resolver, negative_control=False,
    )
    result = evaluate_control(row)
    assert result.status == "OPEN_BYPASS"


# ── the execution marker is real: it requires the gate to actually RUN, not merely exist ────────────

def test_execution_marker_requires_the_gate_to_actually_run():
    def _gate(x: int) -> int:
        y = x + 1
        return y

    # called → the marker records executed lines of _gate
    ran = traced_call(_gate.__code__, lambda: _gate(1))
    assert ran.traversed and ran.result == 2 and len(ran.executed) >= 1

    # NOT called → zero executed lines of _gate, so 'traversed' is False (grep-presence is not execution)
    idle = traced_call(_gate.__code__, lambda: 41 + 1)
    assert not idle.traversed and idle.executed == frozenset()


def test_tracer_records_a_refusal_by_raise():
    def _gate(bad: bool) -> str:
        if bad:
            raise PermissionError("refused")
        return "ok"

    out = traced_call(_gate.__code__, lambda: _gate(True))
    assert out.traversed and isinstance(out.raised, PermissionError)
