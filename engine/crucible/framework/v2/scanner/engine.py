"""
scanner.engine — the autonomous audit engine.

This is the zero-manual replacement for a human driving Burp's Scanner + Intruder
by hand. Given one request, it enumerates every insertion point (``insertion``),
fires every applicable check (``checks``) into each, and hands the observed
responses to the deterministic oracle layer (``verify``) for confirmation. A
finding is emitted only when a real oracle signal fires — no LLM say-so, no
heuristic — so the output is precision-anchored.

It sends nothing itself: a ``send`` callable is injected. In production that is
the scope/charter/kill-switch/egress/rate-gated executor, so authorization stays
enforced; in tests it is a loopback client against an operator-owned target. A
request budget bounds the sweep so an autonomous run cannot blow up.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..verify.confirmation import adjudicate_finding, confirmed_from_result
from ..verify.models import VerificationResult
from ..verify.oob import OOBReceiver
from ..verify.verifier import OracleVerifier
from .checks import DEFAULT_CHECKS, Check, Send
from .insertion import HttpRequest, InsertionKind, InsertionPoint, RequestTemplate
from .learning import ContextualBandit

# A selector prioritises which checks to run at one insertion point (see
# scanner.targeting). It returns a subset (or reorder) of the given checks.
CheckSelector = Callable[[InsertionPoint, "tuple[Check, ...]"], "list[Check]"]


def _context_dump(ctx: object) -> dict | None:
    """Serialise a verify.FindingContext to a JSON-safe dict for retention (the
    re-verifiable certificate). Never fatal: an unserialisable context just
    yields None, and the confirmed finding still stands on its own confidence."""
    try:
        dump = getattr(ctx, "model_dump", None)
        if callable(dump):
            return dump(mode="json")
    except Exception:
        pass
    return None


class AuditFinding(BaseModel):
    """One oracle-confirmed finding: the check that produced it, the exact
    insertion point, and the deterministic proof (which oracle fired, its
    calibrated confidence, and the rationale)."""

    model_config = ConfigDict(extra="forbid")

    check_id: str
    bug_class: str
    insertion_point: str = Field(description="The point id (kind:locator) the payload hit.")
    param: str = Field(description="Human name of the point (param/header/cookie/pointer).")
    endpoint: str = Field(
        default="",
        description="The request URL the finding sits on — what makes it locatable "
        "on a multi-endpoint app (and gives the report/SARIF a real location). "
        "Empty only on legacy/hand-built findings.",
    )
    confidence: float = Field(ge=0.0, le=1.0)
    confirmed_by: str = Field(description="The oracle kind that fired.")
    rationale: str = ""
    # The serialized verify.FindingContext the oracle adjudicated — the retained
    # evidence that lets this finding be re-verified offline (the certificate the
    # Wave-3 re-verifier re-runs the pure oracle over). None only for legacy paths.
    oracle_context: dict | None = None


class ProbeRecord(BaseModel):
    """One EXERCISED (surface, insertion_point, check) probe and its adjudicated
    verdict — the negative-and-positive coverage evidence the audit used to DROP.

    Deterministic by construction: no wall-clock, no rng. ``verdict`` is the core
    honesty distinction (see :func:`probe_verdict`):

      * ``finding``      — an applicable oracle FIRED at/above threshold (a fact).
      * ``clean``        — at least one APPLICABLE oracle actually RAN over the
                           observed data and did NOT fire (exercised-and-clean).
      * ``inconclusive`` — the payload was sent but NO applicable oracle adjudicated
                           (no observable data / oracle abstained). NEVER ``clean``.

    ``oracle_kinds_run`` is the SORTED tuple of oracle kinds that genuinely ran over
    the observed data — the evidence backing a ``clean`` verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    insertion_point: str = Field(description="The point id (kind:locator) or request:<check> anchor.")
    param: str = Field(description="Human name of the point (param/header/cookie/pointer) or (request).")
    check_id: str
    bug_class: str
    oracle_kinds_run: tuple[str, ...] = Field(
        default=(), description="SORTED oracle kinds that RAN over the observed data.")
    verdict: Literal["finding", "clean", "inconclusive"]


def probe_verdict(result: VerificationResult) -> tuple[str, tuple[str, ...]]:
    """Decide a probe's coverage verdict from its oracle adjudication — THE honesty rule.

    ``result.signals`` are exactly the applicable oracle kinds that RAN over the
    observed data (a kind whose inputs were absent is skipped, never a signal). So:

      * confirmed          -> ``finding``      (an oracle fired at/above threshold)
      * ran, none fired    -> ``clean``        (applicable oracle(s) ran, said clean)
      * nothing ran        -> ``inconclusive`` (payload sent, no oracle adjudicated)

    A surface is ``clean`` ONLY when ``result.signals`` is non-empty — i.e. an
    applicable oracle genuinely rendered a verdict. This is the line M2 exists to
    hold: a payload sent with no adjudicating oracle is inconclusive, never clean."""
    kinds = tuple(sorted({s.kind.value for s in result.signals}))
    if result.confirmed:
        return "finding", kinds
    if result.signals:
        return "clean", kinds
    return "inconclusive", kinds


class BudgetExceeded(RuntimeError):
    """Raised internally when the request budget is hit; the audit returns what
    it has confirmed so far rather than sending more traffic."""


class AuditEngine:
    """Drives checks across a request's insertion points, confirming via oracles.

    ``send(HttpRequest) -> {status, body, latency_ms?}`` is the only I/O; it is
    injected so the engine stays testable and so production runs funnel through
    the gated executor. ``max_requests`` caps the sweep (0 = unbounded)."""

    def __init__(
        self,
        send: Send,
        *,
        verifier: OracleVerifier | None = None,
        max_requests: int = 0,
        oob: OOBReceiver | None = None,
        bandit: ContextualBandit | None = None,
        bandit_context: str = "default",
        waf_adaptive: bool = False,
    ) -> None:
        self._send = send
        self.verifier = verifier or OracleVerifier()
        self.max_requests = max_requests
        # Opt-in adaptive WAF-bypass: when a check's canonical payload is filtered
        # but the sink is plausibly reachable, checks that implement `adapt` get a
        # second chance to SYNTHESIZE a bypassing form (evasion ladder, then a small
        # GA over encodings) that still fires the oracle. Off by default — it spends
        # extra requests — and confirmation stays with the same oracle, so a bypass
        # that does not fire the oracle is never a finding.
        self.waf_adaptive = waf_adaptive
        # A started OOBReceiver enables the blind (OOB) checks; without one they
        # are skipped — a blind class is never guessed, only callback-confirmed.
        self.oob = oob
        # Optional self-learning: a ContextualBandit reorders checks by learned
        # per-target value and is rewarded on each probe's outcome. It only ORDERS
        # effort (never drops a check), so coverage is unchanged; without it the
        # engine behaves exactly as before.
        self.bandit = bandit
        self.bandit_context = bandit_context
        self.requests_sent = 0
        # M2 coverage/completeness: every probe that actually adjudicated over
        # observed data leaves a ProbeRecord here (both the positive and the
        # otherwise-discarded negative branch), so a REACHED-and-oracle-cleared
        # surface is provable, not merely untested. Accumulated across the whole
        # campaign (one engine per campaign); audit()'s return type is unchanged
        # and campaign reads this back after the loop (mirrors requests_sent).
        self.exercised: list[ProbeRecord] = []

    def _counted_send(self, request: HttpRequest) -> dict:
        if self.max_requests and self.requests_sent >= self.max_requests:
            raise BudgetExceeded()
        self.requests_sent += 1
        return self._send(request)

    def _record_probe(
        self, *, endpoint: str, insertion_point: str, param: str,
        check_id: str, bug_class: str, result: VerificationResult,
    ) -> None:
        """Retain one adjudicated probe. Called ONLY when an oracle layer actually
        ran over observed data (a real VerificationResult), so the record honestly
        reflects an EXERCISED surface — never a check that never engaged."""
        verdict, kinds = probe_verdict(result)
        self.exercised.append(ProbeRecord(
            endpoint=endpoint, insertion_point=insertion_point, param=param,
            check_id=check_id, bug_class=bug_class,
            oracle_kinds_run=kinds, verdict=verdict,
        ))

    def audit(
        self,
        request: HttpRequest,
        checks: tuple[Check, ...] = DEFAULT_CHECKS,
        *,
        insertion_kinds: tuple[InsertionKind, ...] | None = None,
        selector: CheckSelector | None = None,
        request_checks: tuple = (),
    ) -> list[AuditFinding]:
        """Sweep ``checks`` across ``request``'s insertion points and return the
        oracle-confirmed findings, de-duplicated per (bug_class, insertion point).

        Deterministic given ``send``: insertion points and checks are iterated in
        a stable order. Stops early (returning what is confirmed) if the request
        budget is exhausted."""
        template = RequestTemplate(request)
        points = template.insertion_points(kinds=insertion_kinds)
        seen: set[tuple[str, str]] = set()
        findings: list[AuditFinding] = []
        try:
            # Request-level checks (CORS, host-header, …): run once on the whole
            # request, not per insertion point.
            for rcheck in request_checks:
                try:
                    ctx = rcheck.probe(template, self._counted_send)
                except BudgetExceeded:
                    raise  # budget is a hard stop for the whole audit
                except Exception:
                    # A single check erroring on an odd response (a 501 to its
                    # POST, a malformed body) must never kill the whole scan.
                    continue
                if ctx is None:
                    continue
                rfinding = {
                    "bug_class": rcheck.bug_class,
                    "title": f"{rcheck.bug_class} on the request",
                    "severity": "High", "surface": f"request:{rcheck.id}",
                    "summary": f"{rcheck.id} request-level probe fired an oracle",
                }
                rresult = adjudicate_finding(rfinding, ctx, self.verifier)
                # Retain the coverage evidence (both branches) BEFORE the None-drop.
                self._record_probe(
                    endpoint=request.url, insertion_point=f"request:{rcheck.id}",
                    param="(request)", check_id=rcheck.id, bug_class=rcheck.bug_class,
                    result=rresult,
                )
                confirmed = confirmed_from_result(rresult, rfinding, self.verifier)
                if confirmed is not None:
                    kind = confirmed.confirmed_by
                    findings.append(AuditFinding(
                        check_id=rcheck.id, bug_class=rcheck.bug_class,
                        insertion_point=f"request:{rcheck.id}", param="(request)",
                        # No endpoint: a request-level check probes its own path (e.g.
                        # /.git/config), not this host-anchor request's URL, so the
                        # insertion_point token stays the location — matching the
                        # exposure ground truth as before.
                        confidence=confirmed.confidence,
                        confirmed_by=kind.value if hasattr(kind, "value") else str(kind),
                        rationale=confirmed.rationale,
                        oracle_context=_context_dump(ctx),
                    ))
            for point in points:
                point_checks = selector(point, checks) if selector is not None else checks
                if self.bandit is not None:
                    # order effort by learned value (posterior mean); ties keep
                    # the original order. Never drops a check — coverage intact.
                    order = {bc: i for i, bc in enumerate(
                        self.bandit.rank(self.bandit_context, [c.bug_class for c in point_checks]))}
                    point_checks = sorted(point_checks, key=lambda c: order.get(c.bug_class, len(order)))
                for check in point_checks:
                    key = (check.bug_class, point.id)
                    if key in seen:
                        continue
                    try:
                        if getattr(check, "wants_oob", False):
                            if self.oob is None:
                                continue  # no receiver -> blind check is skipped, not guessed
                            ctx = check.probe(template, point, self._counted_send, self.oob)
                        else:
                            ctx = check.probe(template, point, self._counted_send)
                    except BudgetExceeded:
                        raise  # budget is a hard stop for the whole audit
                    except Exception:
                        # Isolate a check failure to that check — a scan must be
                        # robust to one probe erroring on a hostile response.
                        continue
                    adaptive = self.waf_adaptive and hasattr(check, "adapt")
                    if ctx is None and not adaptive:
                        continue

                    finding_payload = {
                        "bug_class": check.bug_class,
                        "title": f"{check.bug_class} via {point.name}",
                        "severity": "High",
                        "surface": point.id,
                        "summary": f"{check.id} probe fired an oracle at {point.name}",
                    }

                    def _adjudicate(c: FindingContext) -> VerificationResult:
                        return adjudicate_finding(finding_payload, c, self.verifier)

                    # One oracle pass; the VerificationResult carries BOTH the positive
                    # (confirmed_from_result) and the retained negative (coverage) evidence.
                    result = _adjudicate(ctx) if ctx is not None else None
                    confirmed = (
                        confirmed_from_result(result, finding_payload, self.verifier)
                        if result is not None else None
                    )
                    # WAF-adaptive fallback: the canonical payload did not fire (blocked
                    # or filtered). Synthesize a form that slips past AND fires the SAME
                    # oracle, then confirm that — precision is unchanged (a bypass that
                    # does not fire the oracle is never a finding).
                    if confirmed is None and adaptive:
                        try:
                            actx = check.adapt(template, point, self._counted_send)
                        except BudgetExceeded:
                            raise
                        except Exception:
                            actx = None
                        if actx is not None:
                            ares = _adjudicate(actx)
                            ac = confirmed_from_result(ares, finding_payload, self.verifier)
                            # Record the adaptive adjudication as the probe's outcome
                            # (it superseded the blocked canonical attempt).
                            result, ctx = ares, actx
                            if ac is not None:
                                confirmed = ac
                    # reward the bandit on every probe that actually ran: a fired
                    # oracle is a hit, an exhausted probe is a miss.
                    if self.bandit is not None:
                        self.bandit.update(self.bandit_context, check.bug_class, reward=confirmed is not None)
                    # Retain the coverage evidence for every probe that actually
                    # adjudicated over observed data (result is not None) — BEFORE the
                    # None-drop below discards the negative branch as it always has.
                    if result is not None:
                        self._record_probe(
                            endpoint=request.url, insertion_point=point.id, param=point.name,
                            check_id=check.id, bug_class=check.bug_class, result=result,
                        )
                    if confirmed is None:
                        continue
                    seen.add(key)
                    kind = confirmed.confirmed_by
                    findings.append(AuditFinding(
                        check_id=check.id,
                        bug_class=check.bug_class,
                        insertion_point=point.id,
                        param=point.name,
                        endpoint=request.url,
                        confidence=confirmed.confidence,
                        confirmed_by=kind.value if hasattr(kind, "value") else str(kind),
                        rationale=confirmed.rationale,
                        oracle_context=_context_dump(ctx),
                    ))
        except BudgetExceeded:
            pass
        return findings
