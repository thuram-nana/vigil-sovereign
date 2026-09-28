"""
scanner.check_synthesis — eval-gated declarative check synthesis (guarded SIL).

The self-improvement loop can PROPOSE a new check for a coverage gap, but a
self-improving offensive tool that silently ships its own checks is exactly what
must not happen. This module makes synthesis safe and real: it produces a
concrete, RUNNABLE check (a payload template + an oracle shape + a bug class — not
arbitrary code), then EVALUATES it against a vulnerable fixture and its safe twin
BEFORE it can be proposed. A synthesized check is eval-green only if it confirms
on the vulnerable target AND does NOT confirm on the safe one.

Safety is structural: the oracle still adjudicates every confirmation, so a bad
synthesized check cannot manufacture a false positive — it can only waste budget,
which the eval gate (zero false confirmations) catches. Arbitrary-code self-
modification remains out of scope. Approval still flows through the existing
``self_improve.MergeGate`` (eval-green + threshold approvals; the production SIL
adds Ed25519 m-of-n signatures).
"""

from __future__ import annotations

from typing import Callable

from pydantic import BaseModel, ConfigDict

from ..verify import BUG_CLASS_ORACLES, OracleKind, normalize_bug_class
from ..verify.verifier import DIFFERENTIAL_LEAD_ONLY_CLASSES
from ..verify.confirmation import confirm_finding
from ..verify.verifier import OracleVerifier
from .checks import Check, DifferentialCheck, MarkerReflectionCheck, Send, TimingCheck
from .insertion import HttpRequest, InsertionPoint, RequestTemplate


def synthesize_check(bug_class: str, *, injected_ms: float = 500.0) -> Check | None:
    """Build a concrete, runnable check for ``bug_class`` from its primary oracle
    shape. Differential -> a tautology differential; side-effect/reflection -> a
    break-out marker reflection; timing -> a sleep-injection check. Classes whose
    confirmation needs a target-specific predicate/OOB/sanitizer spec return None
    (not auto-synthesizable here) — and so do the TRUTH-VALUE-ATTRIBUTION classes.

    WHY THOSE ARE DECLINED. This used to synthesize a single-shot ``DifferentialCheck`` for any
    class whose primary oracle was DIFFERENTIAL_RESPONSE **or BOOLEAN_INFERENCE**, i.e. it answered
    "I need a sound SPRT truth-value test" with "here is a bare benign-vs-payload differential".
    That inference has no attribution step and minted High FACTs at rate 1.0 against a static page
    behind a WAF tautology rule and against strict input validation, on targets with no database
    (verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES). A sound boolean check is a
    ``BooleanInferenceCheck`` with a clause family, which is not something this synthesizer can
    derive from a class name alone — so it declines rather than emitting something that cannot
    confirm (or, worse, something that could)."""
    norm = normalize_bug_class(bug_class)
    if norm in DIFFERENTIAL_LEAD_ONLY_CLASSES:
        return None
    kinds = BUG_CLASS_ORACLES.get(norm, ())
    primary = kinds[0] if kinds else None
    cid = f"synth-{norm}"

    if primary is OracleKind.DIFFERENTIAL_RESPONSE:
        return DifferentialCheck(id=cid, bug_class=norm, benign="crucible-benign-term",
                                 probe_payload="x' OR '1'='1")
    if primary in (OracleKind.SIDE_EFFECT, OracleKind.REFLECTION_CONTEXT):
        return MarkerReflectionCheck(id=cid, bug_class=norm, payload_template="\"'><x{marker}>")
    if primary is OracleKind.TIMING:
        return TimingCheck(id=cid, bug_class=norm, benign="1", sleep_payload="1 SLEEP",
                           injected_ms=injected_ms, samples=8)
    return None


class CheckEval(BaseModel):
    """The eval verdict for a synthesized check against a fixture pair."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str
    confirmed_on_vuln: bool
    confirmed_on_safe: bool

    @property
    def eval_green(self) -> bool:
        """A check earns its place only if it confirms the real bug AND does not
        false-confirm on the safe twin."""
        return self.confirmed_on_vuln and not self.confirmed_on_safe


def evaluate_check(
    check: Check,
    *,
    request: HttpRequest,
    point: InsertionPoint,
    vuln_send: Send,
    safe_send: Send,
    verifier: OracleVerifier | None = None,
) -> CheckEval:
    """Run ``check`` (via its own probe -> oracle) against a vulnerable and a safe
    ``send``, returning whether it confirmed on each. The oracle is the authority,
    so this measures real confirmations, not the check's own opinion."""
    v = verifier or OracleVerifier()
    tpl = RequestTemplate(request)

    def _confirms(send: Send) -> bool:
        try:
            ctx = check.probe(tpl, point, send)
        except Exception:
            return False
        if ctx is None:
            return False
        return confirm_finding({"bug_class": check.bug_class}, ctx, v) is not None

    return CheckEval(
        bug_class=check.bug_class,
        confirmed_on_vuln=_confirms(vuln_send),
        confirmed_on_safe=_confirms(safe_send),
    )
