"""
analysis.smt — bounded constraint / path-condition feasibility (WS-G, OPT-IN z3).

An **advisory** reasoning aid, not an oracle. It answers "is there an integer
assignment to these bounded parameters that satisfies this conjunction of
linear constraints?" — the kind of question that helps the planner decide
whether a parameter region is worth probing (e.g. a validation rule says
``0 <= id <= 100`` and a business rule triggers only when ``id == victim_id``:
is there a value satisfying both?) or refute a dead path cheaply.

DOCTRINE — read before using (CLAUDE.md / metacognition):

  * This is a LEAD/advisory analyzer. A feasible verdict means "worth probing",
    an infeasible verdict means "provably no assignment in this bounded region".
    Neither promotes a finding. Only a fired oracle over data a real target
    produced confirms anything. This helper must never feed the deterministic
    oracle / SCE / calibration inputs.
  * DEFAULT PATH IS DETERMINISTIC AND DEP-FREE. When the domain is small enough
    to enumerate (``<= max_enum`` assignments) the verdict comes from an exact,
    ordered pure-Python bounded search — the same answer whether or not z3 is
    installed, with a deterministic witness (variables sorted, values ascending).
  * z3 only EXTENDS reach. When importable it is used solely for domains too
    large to enumerate (and to answer such cases exactly instead of refusing).
    It never changes a verdict the bounded search already decides, so an
    environment that has z3 stays byte-identical on the enumerable path.
  * FAIL CLOSED / REFUSE HONESTLY. A domain too large to enumerate with no z3
    yields ``feasible=None`` (UNKNOWN) — never a guess.

Nothing on the default engagement path imports z3 or calls this module; it is
additive. See the roadmap note at the bottom for deeper concolic/DAA plans.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import prod

from ..common.capabilities import has_z3

# Inclusive integer bounds per variable: {name: (lo, hi)}.
Bounds = Mapping[str, tuple[int, int]]

_OPS = frozenset({"<=", ">=", "==", "<", ">", "!="})

# Safety cap: never enumerate more than this many assignments in pure Python.
DEFAULT_MAX_ENUM = 1_000_000


@dataclass(frozen=True)
class LinearConstraint:
    """A linear integer constraint ``sum(coeff_i * var_i)  <op>  rhs``.

    ``coeffs`` maps variable name -> integer coefficient (an empty mapping is a
    constant constraint, e.g. ``0 <= 1``). ``op`` is one of ``<= >= == < > !=``.
    """

    coeffs: Mapping[str, int]
    op: str
    rhs: int

    def __post_init__(self) -> None:
        if self.op not in _OPS:
            raise ValueError(f"unsupported op {self.op!r}; expected one of {sorted(_OPS)}")


def linear(coeffs: Mapping[str, int], op: str, rhs: int) -> LinearConstraint:
    """Convenience constructor for a :class:`LinearConstraint`."""
    return LinearConstraint(coeffs=dict(coeffs), op=op, rhs=rhs)


@dataclass(frozen=True)
class SmtResult:
    """Outcome of a feasibility query.

    feasible   — True (a satisfying assignment exists), False (none exists in
                 the bounded region), or None (UNKNOWN: could not decide).
    model      — a satisfying assignment when feasible is True, else None.
    backend    — "bounded-enum" or "z3": which decided it.
    exhaustive — True iff the verdict is exact over the whole bounded region.
    reason     — human-readable explanation (esp. for None).
    """

    feasible: bool | None
    model: dict[str, int] | None = None
    backend: str = "bounded-enum"
    exhaustive: bool = True
    reason: str = ""

    # convenience predicates
    @property
    def is_feasible(self) -> bool:
        return self.feasible is True

    @property
    def is_infeasible(self) -> bool:
        return self.feasible is False

    @property
    def is_unknown(self) -> bool:
        return self.feasible is None


# --------------------------------------------------------------------------
# Validation + pure-Python evaluation
# --------------------------------------------------------------------------


def _validate(variables: Bounds, constraints: Sequence[LinearConstraint]) -> None:
    for name, bound in variables.items():
        lo, hi = bound
        if lo > hi:
            raise ValueError(f"variable {name!r} has empty domain ({lo} > {hi})")
    known = set(variables)
    for c in constraints:
        unknown = set(c.coeffs) - known
        if unknown:
            raise ValueError(
                f"constraint references unbounded variable(s) {sorted(unknown)}; "
                "every variable must have an integer bound"
            )


def _satisfies(c: LinearConstraint, assignment: Mapping[str, int]) -> bool:
    lhs = sum(coeff * assignment[v] for v, coeff in c.coeffs.items())
    op, rhs = c.op, c.rhs
    if op == "<=":
        return lhs <= rhs
    if op == ">=":
        return lhs >= rhs
    if op == "==":
        return lhs == rhs
    if op == "<":
        return lhs < rhs
    if op == ">":
        return lhs > rhs
    return lhs != rhs  # "!="


def _domain_size(variables: Bounds) -> int:
    return prod((hi - lo + 1) for lo, hi in variables.values()) if variables else 1


def _enumerate(
    variables: Bounds, constraints: Sequence[LinearConstraint]
) -> SmtResult:
    """Exact ordered bounded search. Deterministic witness: variables in sorted
    name order, values ascending."""
    names = sorted(variables)
    ranges = [range(variables[n][0], variables[n][1] + 1) for n in names]
    for combo in itertools.product(*ranges):
        assignment = dict(zip(names, combo))
        if all(_satisfies(c, assignment) for c in constraints):
            return SmtResult(
                feasible=True,
                model=assignment,
                backend="bounded-enum",
                exhaustive=True,
                reason="satisfying assignment found by bounded enumeration",
            )
    return SmtResult(
        feasible=False,
        model=None,
        backend="bounded-enum",
        exhaustive=True,
        reason="no satisfying assignment in the bounded region (exhaustive)",
    )


# --------------------------------------------------------------------------
# z3 extension (only reached for domains larger than max_enum)
# --------------------------------------------------------------------------


def _z3_solve(variables: Bounds, constraints: Sequence[LinearConstraint]) -> SmtResult:
    import z3  # local import: never touched on the default path

    solver = z3.Solver()
    zvars = {name: z3.Int(name) for name in variables}
    for name, (lo, hi) in variables.items():
        solver.add(zvars[name] >= lo, zvars[name] <= hi)
    for c in constraints:
        lhs = z3.Sum([coeff * zvars[v] for v, coeff in c.coeffs.items()]) if c.coeffs else z3.IntVal(0)
        op = c.op
        if op == "<=":
            solver.add(lhs <= c.rhs)
        elif op == ">=":
            solver.add(lhs >= c.rhs)
        elif op == "==":
            solver.add(lhs == c.rhs)
        elif op == "<":
            solver.add(lhs < c.rhs)
        elif op == ">":
            solver.add(lhs > c.rhs)
        else:  # "!="
            solver.add(lhs != c.rhs)
    verdict = solver.check()
    if verdict == z3.sat:
        m = solver.model()
        model = {name: m[zvars[name]].as_long() for name in variables}
        return SmtResult(
            feasible=True,
            model=model,
            backend="z3",
            exhaustive=True,
            reason="satisfying assignment found by z3",
        )
    if verdict == z3.unsat:
        return SmtResult(
            feasible=False,
            model=None,
            backend="z3",
            exhaustive=True,
            reason="z3 proved the constraints unsatisfiable in the bounded region",
        )
    return SmtResult(
        feasible=None,
        model=None,
        backend="z3",
        exhaustive=False,
        reason="z3 returned 'unknown'",
    )


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def is_feasible(
    variables: Bounds,
    constraints: Sequence[LinearConstraint],
    *,
    max_enum: int = DEFAULT_MAX_ENUM,
    force_backend: str | None = None,
) -> SmtResult:
    """Decide whether the bounded linear-integer constraint system is satisfiable.

    variables      — {name: (lo, hi)} inclusive integer bounds.
    constraints    — conjunction of :class:`LinearConstraint`.
    max_enum       — largest domain the pure-Python search will enumerate.
    force_backend  — testing/advanced: "enum" or "z3" to pin the backend
                     (default None = auto: enumerate when small, z3 when large).

    Auto backend policy (default):
      * domain size <= max_enum      → exact bounded enumeration (deterministic).
      * domain size >  max_enum, z3  → z3 (extends reach exactly).
      * domain size >  max_enum, no z3 → UNKNOWN (honest refusal).
    """
    _validate(variables, constraints)

    if force_backend == "enum":
        return _enumerate(variables, constraints)
    if force_backend == "z3":
        if not has_z3():
            raise RuntimeError("force_backend='z3' but z3 is not importable")
        return _z3_solve(variables, constraints)
    if force_backend is not None:
        raise ValueError(f"force_backend must be None, 'enum', or 'z3'; got {force_backend!r}")

    size = _domain_size(variables)
    if size <= max_enum:
        return _enumerate(variables, constraints)
    if has_z3():
        return _z3_solve(variables, constraints)
    return SmtResult(
        feasible=None,
        model=None,
        backend="bounded-enum",
        exhaustive=False,
        reason=(
            f"domain of {size} assignments exceeds max_enum={max_enum} and z3 is not "
            "installed; install the 'smt' extra (z3-solver) for exact large-domain solving"
        ),
    )


def backend_name() -> str:
    """Which large-domain backend is available: 'z3' or 'bounded-enum-only'."""
    return "z3" if has_z3() else "bounded-enum-only"


__all__ = [
    "Bounds",
    "LinearConstraint",
    "SmtResult",
    "linear",
    "is_feasible",
    "backend_name",
    "has_z3",
    "DEFAULT_MAX_ENUM",
]


# ---------------------------------------------------------------------------
# ROADMAP (deeper SMT / concolic — out of scope for this additive slice):
#   * Concolic execution over the DAA symbol index (analysis.index): collect
#     path conditions along a source->sink dataflow and ask z3 for a concrete
#     input that drives the sink — turning a static taint LEAD into a
#     candidate PoC input for the oracle to then CONFIRM against a live target.
#   * Non-linear / bitvector / string constraints (z3 BitVec/Seq) for parser
#     and format-string reasoning.
#   * Quantified/array theories for policy-graph reachability cross-checks.
# In every case z3 stays ADVISORY: it proposes inputs; the oracle confirms.
# ---------------------------------------------------------------------------
