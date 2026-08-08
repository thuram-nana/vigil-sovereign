"""conformance — a reusable ToolSpec acceptance battery (integration criterion 10).

Before a tool is marked ``fact_capable`` in the capability matrix, its ToolSpec must pass this battery through
the REAL gated runner (``run_external_tool``) — never a mock of it. The battery exercises the distinct
outcomes the 12-point standard requires and returns a report of which held, so onboarding a tool is a
falsifiable check, not an assertion:

  * POSITIVE      — a positive fixture mints ≥1 signed FACT that re-verifies OFFLINE (verify_certificate).
  * DECEPTIVE     — a fixture where the tool PROPOSES an endpoint the runner's own re-drive CANNOT reproduce
                    mints NO fact (the criterion-6 property: a scanner's say-so never confirms).
  * TOOL-ERROR    — a timed-out/failed tool run yields the typed ERROR outcome and NO fact (criterion 7).
  * KILL-SWITCH   — a tripped kill-switch refuses BEFORE any traffic (criterion 11).
  * OUT-OF-SCOPE  — an out-of-scope target refuses BEFORE any traffic (criterion 11).

The caller supplies the fixtures (backends + a live target for the positive re-drive), because a positive
requires the tool's real oracle re-drive to fire; the battery is tool-agnostic. FATAL-2: framework/runner
imports are function-local.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


# The REQUIRED properties for a tool to be certified conformant (integration criteria 6, 7, 10, 11). A
# report is conformant ONLY if EVERY one is present AND True — a missing property is NON-conformant, never
# vacuously satisfied. (Red-pen BLOCK-1: without a fixed required set, omitting the kill-switch callables
# silently dropped the crit-11 property and all() passed over the remainder.)
REQUIRED_PROPERTIES = frozenset({
    "positive_fact",
    "positive_verified_offline",
    "deceptive_proposed",              # the deceptive fixture actually PROPOSED an endpoint (crit-6 substance)
    "deceptive_no_fact",
    "tool_error_typed",
    "killswitch_refused_no_traffic",
    "out_of_scope_refused_no_traffic",
})


@dataclass
class ConformanceReport:
    tool: str
    checks: dict = field(default_factory=dict)   # property -> bool
    notes: list = field(default_factory=list)

    @property
    def conformant(self) -> bool:
        # EVERY required property must be present AND True. A required property never run (e.g. kill-switch
        # callables omitted) makes the report NON-conformant — it is not silently skipped.
        missing = REQUIRED_PROPERTIES - set(self.checks)
        if missing:
            return False
        return all(self.checks[p] for p in REQUIRED_PROPERTIES)

    def summary(self) -> str:
        status = "CONFORMANT" if self.conformant else "NON-CONFORMANT"
        missing = sorted(REQUIRED_PROPERTIES - set(self.checks))
        failed = sorted(k for k, v in self.checks.items() if not v)
        bits = []
        if missing:
            bits.append(f"missing: {', '.join(missing)}")
        if failed:
            bits.append(f"failed: {', '.join(failed)}")
        return f"{self.tool}: {status}" + (f" ({'; '.join(bits)})" if bits else "")


class _SpyBackend:
    """A backend recording whether run() was called — proves a refusal blocked BEFORE traffic."""
    name = "conformance-spy"

    def __init__(self) -> None:
        self.runs: list = []

    def available(self):
        return True, "spy"

    def run(self, argv, *, timeout=0):
        from .external_tool import ToolOutcome
        self.runs.append(list(argv))
        return ToolOutcome(list(argv), 0, "", "", self.name)


def run_toolspec_conformance(
    *,
    tool_name: str,
    positive_spec: Any,
    positive_backend: Any,
    deceptive_spec: Any,
    deceptive_backend: Any,
    target: str,
    scope_gate_in: Any,
    scope_gate_out: Any,
    engagement_slug: str,
    signers: list,
    trust_root: Any,
    contexts_sink: "dict | None" = None,
    trip_killswitch: "Callable[[], None] | None" = None,
    clear_killswitch: "Callable[[], None] | None" = None,
    timeout: float = 60.0,
) -> ConformanceReport:
    """Run the acceptance battery for one ToolSpec through the real gated runner. Returns a
    :class:`ConformanceReport`. Never raises on a failed check — it records the failure so a caller can gate
    ``fact_capable`` on ``report.conformant``."""
    from .external_tool import BackendUnavailable, run_external_tool

    r = ConformanceReport(tool=tool_name)

    def _run(spec, backend, gate, slug=engagement_slug):
        try:
            return run_external_tool(spec, target, scope_gate=gate, backend=backend,
                                     engagement_slug=slug, signers=signers, timeout=timeout), None
        except BackendUnavailable as e:
            return None, e

    # 1. POSITIVE — a signed FACT that re-verifies offline
    try:
        from framework.v2.evidence.certify import verify_certificate
        res, err = _run(positive_spec, positive_backend, scope_gate_in)
        facts = list(getattr(res, "facts", []) or []) if res else []
        ok = bool(facts)
        verified = False
        if ok:
            f = facts[0]
            ctx = (res.contexts or {}).get(f.finding_ref, {})
            verified = bool(verify_certificate(f.signed, oracle_context=ctx, trust_root=trust_root).ok)
        r.checks["positive_fact"] = ok
        r.checks["positive_verified_offline"] = verified
        if contexts_sink is not None and res is not None:
            contexts_sink.update(res.contexts or {})
    except Exception as e:  # noqa: BLE001
        r.checks["positive_fact"] = False
        r.checks["positive_verified_offline"] = False
        r.notes.append(f"positive raised: {type(e).__name__}: {e}")

    # 2. DECEPTIVE — the tool must actually PROPOSE an endpoint (deceptive_proposed), and the runner's own
    #    re-drive must then refuse it → NO fact (deceptive_no_fact). Both are required: a backend that
    #    proposes NOTHING would make "no fact" vacuously true and never exercise the crit-6 firewall
    #    property ("a scanner's say-so never confirms") — red-pen BLOCK-2.
    try:
        res, _ = _run(deceptive_spec, deceptive_backend, scope_gate_in)
        proposed = list(getattr(res, "proposed", []) or []) if res else []
        r.checks["deceptive_proposed"] = len(proposed) > 0
        r.checks["deceptive_no_fact"] = bool(res) and len(proposed) > 0 and not (getattr(res, "facts", []) or [])
        if not proposed:
            r.notes.append("deceptive backend proposed NOTHING — the crit-6 property was not exercised")
    except Exception as e:  # noqa: BLE001
        r.checks["deceptive_proposed"] = False
        r.checks["deceptive_no_fact"] = False
        r.notes.append(f"deceptive raised: {type(e).__name__}: {e}")

    # 3. TOOL-ERROR — a timed-out tool → typed ERROR outcome + no fact
    try:
        from .external_tool import ToolOutcome

        class _Timeout:
            name = "conformance-timeout"

            def available(self):
                return True, ""

            def run(self, argv, *, timeout=0):
                return ToolOutcome(list(argv), None, "", "", self.name, timed_out=True)

        res, _ = _run(positive_spec, _Timeout(), scope_gate_in)
        errored = bool(getattr(res, "tool_errored", False))
        has_error_outcome = any(o.get("outcome") == "error" for o in (getattr(res, "outcomes", []) or []))
        r.checks["tool_error_typed"] = errored and has_error_outcome and not (getattr(res, "facts", []) or [])
    except Exception as e:  # noqa: BLE001
        r.checks["tool_error_typed"] = False
        r.notes.append(f"tool-error raised: {type(e).__name__}: {e}")

    # 4. KILL-SWITCH — tripped → refused before traffic
    if trip_killswitch is not None and clear_killswitch is not None:
        try:
            trip_killswitch()
            spy = _SpyBackend()
            res, _ = _run(positive_spec, spy, scope_gate_in)
            r.checks["killswitch_refused_no_traffic"] = bool(getattr(res, "refused", False)) and spy.runs == []
        except Exception as e:  # noqa: BLE001
            r.checks["killswitch_refused_no_traffic"] = False
            r.notes.append(f"killswitch raised: {type(e).__name__}: {e}")
        finally:
            clear_killswitch()

    # 5. OUT-OF-SCOPE — refused before traffic
    try:
        spy = _SpyBackend()
        res, _ = _run(positive_spec, spy, scope_gate_out)
        r.checks["out_of_scope_refused_no_traffic"] = bool(getattr(res, "refused", False)) and spy.runs == []
    except Exception as e:  # noqa: BLE001
        r.checks["out_of_scope_refused_no_traffic"] = False
        r.notes.append(f"out-of-scope raised: {type(e).__name__}: {e}")

    return r
