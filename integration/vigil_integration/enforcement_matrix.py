"""Enforcement coverage matrix — MEASURED BY EXECUTION, not by grep (W13-1, ANTIC programme).

The problem this closes: nobody could state, per sensitive execution path, which gate is actually
traversed. Reading the code ("grep says the deny branch exists") does not prove the branch RUNS, and
"a skipped proof and a passing proof are the same colour on a dashboard." This module inventories the
gates-of-record and, for each, RUNS the real gate function and observes — via a line tracer, a genuine
execution marker — that the enforcing code executed, and that a deliberately unauthorized action is
REFUSED. A path with no refusal proof is recorded as an OPEN BYPASS, never as covered.

Programme constraint (honoured here): this is a MEASUREMENT facade over the EXISTING gates, never a
second policy engine. Every probe drives the real, already-shipped gate function; this module adds no
authorization logic of its own. It imports nothing offense- or sovereign-specific at module scope — the
pure gate-of-record primitives it measures (``vigil_core.gate`` / ``vigil_core.warden_tiers`` /
``vigil_core.hard_guardrail`` / ``vigil_gateway.denylist`` / ``vigil_integration.warden_gate``) are leaves
both environments load. The one OFFENSE-only gate (``framework.v2.entitlement.require_capability``) is
imported LAZILY inside its resolver, so this module stays import-clean in the sovereign environment
(FATAL-2) and its execution proof runs only in the offense CI leg.

Design:
  * A ``ControlRow`` DECLARES a sensitive execution path, the gate of record it traverses, and its plane.
    The declaration is pure data — rendering the matrix (``render_matrix_markdown``) never runs a gate,
    so the committed artifact is leg-independent and a doc-truth test can pin it (adding a path without a
    row makes that test go red).
  * A ``resolver`` binds the row to the LIVE gate: the code object to trace, an authorized thunk, an
    unauthorized (negative-control) thunk, and an interpreter mapping the gate's real return/raise to
    ALLOW / REFUSE. Resolving is lazy so the offense row does not import ``framework`` at module load.
  * ``build_execution_matrix`` runs each resolvable row's probes under the tracer and records, by
    EXECUTION, whether the gate was traversed (positive) and whether the negative control was refused.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from types import CodeType
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------------------------------
# The execution marker: a line tracer scoped to ONE code object.
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TraceOutcome:
    """What running a thunk under the tracer observed. ``executed`` is the set of line numbers of
    ``target_code`` that actually ran — a non-empty set is the execution marker that the enforcing
    function was TRAVERSED (not merely present in the source)."""

    result: Any
    raised: Optional[BaseException]
    executed: frozenset[int]

    @property
    def traversed(self) -> bool:
        """The gate's own code executed at least one line during the call."""
        return len(self.executed) > 0


def traced_call(target_code: CodeType, thunk: Callable[[], Any]) -> TraceOutcome:
    """Run ``thunk`` while recording which lines of ``target_code`` execute.

    Uses ``sys.settrace`` with a global trace that returns a per-frame line tracer ONLY for a frame whose
    code object IS ``target_code`` (identity). So the marker cannot be forged by a wrapper or a look-alike
    helper: the gate-of-record function itself must run. A raised refusal is captured (not propagated) so a
    negative control that DENIES-by-raising is measured the same way as one that denies-by-return.
    """
    executed: set[int] = set()

    def _local(frame, event, arg):  # type: ignore[no-untyped-def]
        if event == "line":
            executed.add(frame.f_lineno)
        return _local

    def _global(frame, event, arg):  # type: ignore[no-untyped-def]
        if event == "call" and frame.f_code is target_code:
            return _local
        return None

    prev = sys.gettrace()
    sys.settrace(_global)
    result: Any = None
    raised: Optional[BaseException] = None
    try:
        result = thunk()
    except BaseException as exc:  # noqa: BLE001 — a refusal-by-raise IS the measured outcome
        raised = exc
    finally:
        sys.settrace(prev)
    return TraceOutcome(result=result, raised=raised, executed=frozenset(executed))


# ---------------------------------------------------------------------------------------------------
# Control declaration + resolution.
# ---------------------------------------------------------------------------------------------------

Interpret = Callable[[Any, Optional[BaseException]], str]  # -> "allow" | "refuse"


@dataclass(frozen=True)
class ResolvedControl:
    """A row bound to the LIVE gate: what to trace, how to drive it authorized / unauthorized, and how to
    read the gate's real return / raise as ALLOW or REFUSE."""

    target_code: CodeType
    authorized: Callable[[], Any]
    unauthorized: Optional[Callable[[], Any]]
    interpret: Interpret


@dataclass(frozen=True)
class ControlRow:
    """One sensitive execution path and the gate of record it traverses. Pure data — safe to enumerate in
    either environment. ``resolver`` binds it to the live gate lazily (may import an env-specific module)."""

    id: str
    path: str                       # the sensitive execution path, in plain language
    plane: str                      # "sovereign" (reachable without framework) | "offense" (needs framework)
    gate_label: str                 # module:function of the gate of record (stable; for the artifact)
    resolver: Callable[[], ResolvedControl]
    negative_control: bool = True   # is a refusal proof DECLARED for this path? False => OPEN BYPASS


@dataclass
class ProbeResult:
    outcome: str            # "allow" | "refuse"
    traversed: bool         # did the gate's own code execute?
    executed_lines: int


@dataclass
class ControlResult:
    row: ControlRow
    status: str                                 # "COVERED" | "OPEN_BYPASS" | "OFFENSE_LEG" | "ERROR"
    positive: Optional[ProbeResult] = None
    negative: Optional[ProbeResult] = None
    detail: str = ""


class ControlNotResolvableHere(Exception):
    """The gate for this row cannot be loaded in the current environment (e.g. an offense-only gate in the
    sovereign leg). Its execution proof runs in the OTHER CI leg; it is NOT an open bypass."""


# ---------------------------------------------------------------------------------------------------
# The gate-of-record inventory. Each resolver drives the REAL gate; no policy logic lives here.
# ---------------------------------------------------------------------------------------------------


def _resolve_warden_tier() -> ResolvedControl:
    from vigil_core import warden_tiers

    def _decide(name: str) -> str:
        return warden_tiers.gate(warden_tiers.classify(name))

    def _interpret(result: Any, raised: Optional[BaseException]) -> str:
        return "allow" if raised is None and result == "auto" else "refuse"

    return ResolvedControl(
        target_code=warden_tiers.classify.__code__,
        authorized=lambda: _decide("fs.read"),        # a safe observe verb → A0 → auto
        unauthorized=lambda: _decide("prod.delete"),  # danger token → A3 → NOT auto
        interpret=_interpret,
    )


def _resolve_warden_tool_gate() -> ResolvedControl:
    from vigil_core import warden_tiers
    from vigil_integration.warden_gate import decide_tool

    def classify(name: str) -> str:
        return warden_tiers.classify(name).label

    def _interpret(result: Any, raised: Optional[BaseException]) -> str:
        return "allow" if raised is None and getattr(result, "outcome", None) == "auto" else "refuse"

    return ResolvedControl(
        target_code=decide_tool.__code__,
        # a read-shaped tool on a staging floor auto-runs; the empty name fail-closes to a hard DENY.
        authorized=lambda: decide_tool("fs.read", classify=classify, floor="A1", ceiling="A1"),
        unauthorized=lambda: decide_tool("", classify=classify, floor="A1", ceiling="A1"),
        interpret=_interpret,
    )


def _resolve_conjunctive_gate() -> ResolvedControl:
    from vigil_core.gate import CrucibleResult, conjunctive_decide
    from vigil_integration.warden_gate import ToolDecision

    def _interpret(result: Any, raised: Optional[BaseException]) -> str:
        return "allow" if raised is None and getattr(result, "allowed", False) is True else "refuse"

    return ResolvedControl(
        target_code=conjunctive_decide.__code__,
        authorized=lambda: conjunctive_decide(
            crucible_authorize=lambda: CrucibleResult(True, "in-envelope"),
            warden_decide=lambda: ToolDecision("http.get", "A1", "auto", "ok"),
        ),
        # out-of-envelope: CRUCIBLE denies, first-failure-wins → DENY before WARDEN is even reached.
        unauthorized=lambda: conjunctive_decide(
            crucible_authorize=lambda: CrucibleResult(False, "out_of_scope"),
            warden_decide=lambda: ToolDecision("http.get", "A1", "auto", "ok"),
        ),
        interpret=_interpret,
    )


def _resolve_destruction_conjunct() -> ResolvedControl:
    from vigil_core.gate import CrucibleResult, DestructionOutcome, conjunctive_decide
    from vigil_integration.warden_gate import ToolDecision

    def _interpret(result: Any, raised: Optional[BaseException]) -> str:
        return "allow" if raised is None and getattr(result, "allowed", False) is True else "refuse"

    return ResolvedControl(
        target_code=conjunctive_decide.__code__,
        # a destructive action WITH an owner-inclusive m-of-n authorization present → allowed.
        authorized=lambda: conjunctive_decide(
            crucible_authorize=lambda: CrucibleResult(True, "in-envelope"),
            warden_decide=lambda: ToolDecision("db.drop", "A1", "auto", "ok"),
            destructive=True,
            destruction_authorize=lambda: DestructionOutcome(True, "owner-inclusive quorum"),
        ),
        # a destructive action with NO threshold gate wired → fail-closed DENY (the load-bearing branch).
        unauthorized=lambda: conjunctive_decide(
            crucible_authorize=lambda: CrucibleResult(True, "in-envelope"),
            warden_decide=lambda: ToolDecision("db.drop", "A1", "auto", "ok"),
            destructive=True,
            destruction_authorize=None,
        ),
        interpret=_interpret,
    )


def _resolve_egress_denylist() -> ResolvedControl:
    from vigil_gateway.denylist import is_egress_denied

    def _interpret(result: Any, raised: Optional[BaseException]) -> str:
        if raised is not None:
            return "refuse"
        denied, _reason = result
        return "refuse" if denied else "allow"

    return ResolvedControl(
        target_code=is_egress_denied.__code__,
        authorized=lambda: is_egress_denied("8.8.8.8"),                 # globally routable → allowed
        unauthorized=lambda: is_egress_denied("169.254.169.254"),      # cloud metadata → never liftable
        interpret=_interpret,
    )


def _resolve_hard_guardrail() -> ResolvedControl:
    from vigil_core.hard_guardrail import HardBlockError, assert_not_hard_blocked

    def _interpret(result: Any, raised: Optional[BaseException]) -> str:
        if isinstance(raised, HardBlockError):
            return "refuse"
        return "allow" if raised is None else "refuse"

    return ResolvedControl(
        target_code=assert_not_hard_blocked.__code__,
        authorized=lambda: assert_not_hard_blocked("example.com"),  # ordinary target → passes the floor
        unauthorized=lambda: assert_not_hard_blocked("army.mil"),   # protected .mil → categorical block
        interpret=_interpret,
    )


def _resolve_entitlement() -> ResolvedControl:
    # OFFENSE-only: imported lazily so this module stays import-clean in the sovereign environment.
    try:
        from framework.v2.common.errors import EntitlementViolation
        from framework.v2.entitlement import require_capability, set_policy
        from framework.v2.entitlement.models import Capability, CapabilityTier
        from framework.v2.entitlement.policy import EntitlementPolicy, _State
    except Exception as exc:  # noqa: BLE001 — framework absent (sovereign leg)
        raise ControlNotResolvableHere(str(exc)) from exc

    def _state(caps: frozenset) -> Any:
        return _State(
            enforced=True, granted_tier=CapabilityTier.STANDARD, effective_caps=caps,
            entitlement_id="w13-1", institution="w13-1", denial_error=None, denial_reason="", summary="probe",
        )

    def _authorized() -> Any:
        set_policy(EntitlementPolicy(_state(frozenset({Capability.ACTIVE_RECON}))))
        try:
            return require_capability(Capability.ACTIVE_RECON)
        finally:
            set_policy(None)

    def _unauthorized() -> Any:
        set_policy(EntitlementPolicy(_state(frozenset())))  # tier present but capability NOT granted
        try:
            return require_capability(Capability.ACTIVE_RECON)
        finally:
            set_policy(None)

    def _interpret(result: Any, raised: Optional[BaseException]) -> str:
        if isinstance(raised, EntitlementViolation):
            return "refuse"
        if raised is not None:
            return "refuse"
        return "allow" if getattr(result, "allowed", False) is True else "refuse"

    return ResolvedControl(
        target_code=EntitlementPolicy.assert_capability.__code__,
        authorized=_authorized,
        unauthorized=_unauthorized,
        interpret=_interpret,
    )


CONTROLS: tuple[ControlRow, ...] = (
    ControlRow(
        id="warden-tier-classifier",
        path="agent → tool bridge: every tool-name is classified to an autonomy tier (danger-first, "
             "fail-closed to A3) before it may auto-run",
        plane="sovereign",
        gate_label="vigil_core.warden_tiers.classify/gate",
        resolver=_resolve_warden_tier,
    ),
    ControlRow(
        id="warden-tool-gate",
        path="offense tool call: the raise-only A2 floor gate decides auto / queue-for-owner-approval / "
             "deny by tool class",
        plane="sovereign",
        gate_label="vigil_integration.warden_gate.decide_tool",
        resolver=_resolve_warden_tool_gate,
    ),
    ControlRow(
        id="conjunctive-offense-gate",
        path="every target-touching offense action: CRUCIBLE-authority AND WARDEN, first-failure-wins, "
             "fail-closed",
        plane="sovereign",
        gate_label="vigil_core.gate.conjunctive_decide",
        resolver=_resolve_conjunctive_gate,
    ),
    ControlRow(
        id="destruction-threshold-conjunct",
        path="destructive / irreversible action: the extra m-of-n threshold conjunct — no wired gate is a "
             "fail-closed DENY even when WARDEN would auto-allow the class",
        plane="sovereign",
        gate_label="vigil_core.gate.conjunctive_decide[destructive]",
        resolver=_resolve_destruction_conjunct,
    ),
    ControlRow(
        id="egress-denylist",
        path="worker / adapter / proxy egress: the destination-IP floor (metadata / link-local / loopback "
             "/ private) that no charter scope can lift",
        plane="sovereign",
        gate_label="vigil_gateway.denylist.is_egress_denied",
        resolver=_resolve_egress_denylist,
    ),
    ControlRow(
        id="protected-domain-guardrail",
        path="any domain target the agent proposes: the categorical government / military / educational / "
             "intergovernmental scope floor, evaluated before the charter",
        plane="sovereign",
        gate_label="vigil_core.hard_guardrail.assert_not_hard_blocked",
        resolver=_resolve_hard_guardrail,
    ),
    ControlRow(
        id="capability-entitlement",
        path="gated offense subsystem entry (active-recon / exploit / deep-static / evasion): the "
             "entitlement gate wired at require_capability() sites",
        plane="offense",
        gate_label="framework.v2.entitlement.require_capability",
        resolver=_resolve_entitlement,
    ),
)


# ---------------------------------------------------------------------------------------------------
# The gate-of-record manifest — pins the pure core gates so a rename / removal turns CI red, and the
# module-scan below turns a NEW gate-decision function in those modules red until it is rowed.
# ---------------------------------------------------------------------------------------------------

# Public decision functions in the CLEAN core gate modules that MUST be represented by a control row.
# (warden_gate / denylist / entitlement carry many helpers, so they are pinned by resolver-resolvability
#  + the doc-truth guard rather than a module scan; documented in the W13-1 decision record.)
_CORE_GATE_MODULES: tuple[str, ...] = (
    "vigil_core.gate",
    "vigil_core.warden_tiers",
    "vigil_core.hard_guardrail",
)

# Public callables in those modules that are helpers / predicates, NOT a gate-of-record decision point.
# Anything public in a scanned module that is neither here nor covered by a row fails the guard.
_KNOWN_NON_GATE: dict[str, frozenset[str]] = {
    "vigil_core.gate": frozenset(),
    "vigil_core.warden_tiers": frozenset({"tokens", "has_danger_token"}),
    "vigil_core.hard_guardrail": frozenset({
        "normalize_domain", "candidate_hosts", "is_hard_blocked", "protected_guard_enabled",
    }),
}

# The decision functions each core gate module contributes to the matrix (by bare function name).
_CORE_GATE_FUNCTIONS: dict[str, frozenset[str]] = {
    "vigil_core.gate": frozenset({"conjunctive_decide"}),
    "vigil_core.warden_tiers": frozenset({"classify", "gate"}),
    "vigil_core.hard_guardrail": frozenset({"assert_not_hard_blocked"}),
}


def scan_core_gate_functions() -> dict[str, set[str]]:
    """For each clean core gate module, the set of PUBLIC functions defined there that are neither a
    documented helper nor absent — i.e. the functions that MUST be a gate-of-record decision point. A new
    public function added to one of these modules lands here and fails the guard until it is rowed or
    explicitly documented as a non-gate helper."""
    import importlib
    import inspect

    found: dict[str, set[str]] = {}
    for modname in _CORE_GATE_MODULES:
        mod = importlib.import_module(modname)
        names: set[str] = set()
        for name, obj in vars(mod).items():
            if name.startswith("_"):
                continue
            if not inspect.isfunction(obj):
                continue
            if getattr(obj, "__module__", None) != modname:
                continue  # re-exported leaf (e.g. conjunctive_decide re-export) counted in its home module
            if name in _KNOWN_NON_GATE.get(modname, frozenset()):
                continue
            names.add(name)
        found[modname] = names
    return found


# ---------------------------------------------------------------------------------------------------
# Build + render.
# ---------------------------------------------------------------------------------------------------


def _probe(target_code: CodeType, thunk: Callable[[], Any], interpret: Interpret) -> ProbeResult:
    t = traced_call(target_code, thunk)
    return ProbeResult(
        outcome=interpret(t.result, t.raised),
        traversed=t.traversed,
        executed_lines=len(t.executed),
    )


def evaluate_control(row: ControlRow) -> ControlResult:
    """Run one row's probes under the tracer and classify the row by what EXECUTED.

    COVERED     — positive probe traversed the gate and ALLOWed, AND the negative probe traversed the gate
                  and was REFUSED (the refusal proof).
    OPEN_BYPASS — no negative control declared, OR the negative control did not refuse (the gate is a
                  no-op on the bad input), OR the positive probe never traversed the gate.
    OFFENSE_LEG — the gate is not loadable in this environment; its proof runs in the offense CI leg.
    """
    try:
        rc = row.resolver()
    except ControlNotResolvableHere as exc:
        return ControlResult(row=row, status="OFFENSE_LEG", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 — a resolver that cannot bind the gate is a real, loud error
        return ControlResult(row=row, status="ERROR", detail=f"resolver failed: {exc!r}")

    pos = _probe(rc.target_code, rc.authorized, rc.interpret)

    neg: Optional[ProbeResult] = None
    if rc.unauthorized is not None:
        neg = _probe(rc.target_code, rc.unauthorized, rc.interpret)

    if neg is None or not row.negative_control:
        status = "OPEN_BYPASS"
        detail = "no refusal proof declared for this path"
    elif not neg.traversed or neg.outcome != "refuse":
        status = "OPEN_BYPASS"
        detail = "the deliberately unauthorized action was NOT refused by the gate (possible no-op)"
    elif not pos.traversed or pos.outcome != "allow":
        status = "OPEN_BYPASS"
        detail = "the authorized action did not traverse-and-allow the gate (path not actually gated here)"
    else:
        status = "COVERED"
        detail = "gate traversed by execution on both the authorized and the unauthorized action"

    return ControlResult(row=row, status=status, positive=pos, negative=neg, detail=detail)


def build_execution_matrix(rows: tuple[ControlRow, ...] = CONTROLS) -> list[ControlResult]:
    return [evaluate_control(r) for r in rows]


def open_bypasses(results: list[ControlResult]) -> list[ControlResult]:
    return [r for r in results if r.status == "OPEN_BYPASS"]


def _md_escape(s: str) -> str:
    return s.replace("|", r"\|")


def render_matrix_markdown(rows: tuple[ControlRow, ...] = CONTROLS) -> str:
    """Render the DECLARED matrix from pure data (no gate runs) so the committed artifact is identical in
    both CI legs and a doc-truth test can pin it: adding a sensitive path without a matrix row makes the
    committed file drift from this render, turning that test red."""
    lines: list[str] = []
    lines.append("# Enforcement coverage matrix — measured by execution (W13-1)")
    lines.append("")
    lines.append(
        "GENERATED, DO NOT EDIT BY HAND. Regenerated and pinned by "
        "`integration/tests/test_enforcement_matrix.py`. Each row is a sensitive execution path and the "
        "gate of record it traverses; the row is proven by RUNNING the real gate under a line tracer "
        "(`vigil_integration.enforcement_matrix`), asserting the enforcing code executed on an authorized "
        "action (ALLOW) and that a deliberately unauthorized action is REFUSED (the negative control). A "
        "path with no refusal proof is an OPEN BYPASS, not covered."
    )
    lines.append("")
    lines.append("| # | Sensitive execution path | Plane | Gate of record | Negative control |")
    lines.append("|---|--------------------------|-------|----------------|------------------|")
    for i, r in enumerate(rows, 1):
        nc = "yes" if r.negative_control else "**NONE → OPEN BYPASS**"
        lines.append(
            f"| {i} | {_md_escape(r.path)} | {r.plane} | `{_md_escape(r.gate_label)}` | {nc} |"
        )
    lines.append("")
    lines.append(
        "Planes: a `sovereign` row's gate loads without the offense engine and is proven by execution in "
        "BOTH integration CI legs; the `offense` row's gate (`require_capability`) needs `framework`, so "
        "its execution proof runs only in the offense leg (FATAL-2 two-env boundary)."
    )
    lines.append("")
    return "\n".join(lines)
