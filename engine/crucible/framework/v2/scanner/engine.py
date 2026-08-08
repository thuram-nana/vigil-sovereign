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


def reexecutable_evidence(ctx: object) -> dict | None:
    """The MINIMAL, deterministic evidence a standalone (VIGIL-free) verifier re-runs the oracle over —
    for the RE-EXECUTABLE posture tier (Proof-of-Posture). Today: the ``predicate`` + ``observed_evidence``
    of a predicate-oracle probe (open_redirect / CORS / host-header / IDOR / …), which the pure JSON-AST
    ``predicate_oracle`` re-derives byte-for-byte with no framework — so a relying party re-derives the
    VERDICT itself from the retained (producer-supplied) values, not merely trusts the signed verdict. Returns
    ``None`` for any probe whose retained
    context carries no such re-runnable kernel input (those stay the ``binding`` tier — honest).

    Only these two keys are retained (never the whole context): they are a small, deterministic JSON AST
    plus the raw observed values the oracle judged, so embedding them keeps the certificate compact and the
    re-derivation faithful. This is OPT-IN (``AuditEngine.retain_evidence``); with it off, nothing is
    retained and every certificate is byte-identical to before (the make-gate invariant)."""
    dump = _context_dump(ctx)
    if not isinstance(dump, dict):
        return None
    pred = dump.get("predicate")
    obs = dump.get("observed_evidence")
    if isinstance(pred, dict) and isinstance(obs, dict):
        return {"predicate": pred, "observed_evidence": obs}
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
      * ``clean``        — at least one applicable oracle CONCLUSIVELY adjudicated the
                           negative: it proved it had an observable channel and rendered
                           a decisive verdict (exercised-and-provably-clean), not merely
                           a one-sided oracle that failed to fire with no channel.
      * ``inconclusive`` — the payload was sent but NO oracle had a channel to adjudicate
                           (no observable data / one-sided non-signal / oracle abstained).
                           NEVER ``clean``.

    ``oracle_kinds_run`` is the SORTED tuple of oracle kinds that CONCLUSIVELY adjudicated
    over the observed data — the evidence backing a ``clean`` verdict (empty for
    ``inconclusive``; see :func:`probe_verdict`)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    method: str = Field(default="GET", description=(
        "HTTP method. With the surface it is the FULL probe identity — a GET and a POST to "
        "one path+query are DISTINCT surfaces, so a method-aware skip diff (M3 plan-integrity) "
        "does not hide an unprobed POST behind a probed GET."))
    insertion_point: str = Field(description="The point id (kind:locator) or request:<check> anchor.")
    param: str = Field(description="Human name of the point (param/header/cookie/pointer) or (request).")
    check_id: str
    bug_class: str
    oracle_kinds_run: tuple[str, ...] = Field(
        default=(), description="SORTED oracle kinds that RAN over the observed data.")
    verdict: Literal["finding", "clean", "inconclusive"]
    evidence: dict | None = Field(
        default=None, description=(
            "OPT-IN re-executable-tier evidence (Proof-of-Posture): the minimal, deterministic kernel "
            "input (a predicate + the observed values) a VIGIL-FREE verifier re-runs the oracle over to "
            "re-derive this probe's verdict from the retained (producer-supplied) values. ``None`` (default) unless "
            "``AuditEngine.retain_evidence`` is set — so a certificate is byte-identical to before when "
            "retention is off. Never emitted into a certificate row when falsy (see "
            "``coverage_oracle.build_coverage_certificate``), so the make-gate byte-identity holds."))


def probe_verdict(result: VerificationResult) -> tuple[str, tuple[str, ...]]:
    """Decide a probe's coverage verdict from its oracle adjudication — THE honesty rule.

    ``result.signals`` are the applicable oracle kinds that RAN over the observed data
    (a kind whose inputs were absent is skipped, never a signal). But an oracle merely
    RUNNING is not enough to certify ``clean``: a ONE-SIDED oracle (a single-shot
    differential, a marker/error/callback simply absent) emits a non-firing signal
    even when it had NO observable channel — a surface that ignores its input, or a
    blind/second-order sink, looks identical to a safe one. Treating that non-signal as
    ``clean`` is the coverage overclaim M2 must not make.

    So a probe is ``clean`` only when at least one signal is CONCLUSIVE — the oracle
    proved it had a channel and rendered a decisive verdict (``OracleSignal.conclusive``:
    a positive fire, an SPRT refute, an adequate-sample timing test, a definite
    predicate, or a payload OBSERVED reaching the sink but neutralised):

      * confirmed                         -> ``finding``      (an oracle fired at/above threshold)
      * a conclusive signal, none fired   -> ``clean``        (channel-confirmed negative)
      * only non-conclusive non-signals   -> ``inconclusive`` (payload sent, no oracle
                                             had a channel to adjudicate — NEVER clean)

    ``oracle_kinds_run`` for a ``clean`` verdict names only the oracles that CONCLUSIVELY
    adjudicated (the evidence backing the verdict); ``inconclusive`` carries none. This is
    the line M2 exists to hold: a payload sent with no adjudicating channel is
    inconclusive, never clean."""
    if result.confirmed:
        kinds = tuple(sorted({s.kind.value for s in result.signals}))
        return "finding", kinds
    conclusive = [s for s in result.signals if s.conclusive]
    if conclusive:
        return "clean", tuple(sorted({s.kind.value for s in conclusive}))
    return "inconclusive", ()


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
        retain_evidence: bool = False,
    ) -> None:
        self._send = send
        self.verifier = verifier or OracleVerifier()
        self.max_requests = max_requests
        # OPT-IN re-executable-tier evidence retention (Proof-of-Posture). Default OFF: no probe carries
        # `evidence`, so every coverage/posture certificate is byte-identical to before (the make-gate
        # invariant). When ON, a predicate-oracle probe retains its minimal, deterministic kernel input
        # (predicate + observed values) so a VIGIL-FREE verifier can re-derive the NEGATIVE itself.
        self.retain_evidence = retain_evidence
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
        method: str = "GET", ctx: object | None = None,
    ) -> None:
        """Retain one adjudicated probe. Called ONLY when an oracle layer actually
        ran over observed data (a real VerificationResult), so the record honestly
        reflects an EXERCISED surface — never a check that never engaged.

        When ``retain_evidence`` is set (OPT-IN), a predicate-oracle probe also retains its minimal,
        deterministic re-execution kernel input (``predicate`` + ``observed_evidence``) so a VIGIL-free
        verifier can re-derive the verdict from the retained (producer-supplied) values (the re-executable posture tier). With
        the flag off (the default), ``evidence`` stays ``None`` and the certificate is byte-identical."""
        verdict, kinds = probe_verdict(result)
        evidence = reexecutable_evidence(ctx) if self.retain_evidence else None
        self.exercised.append(ProbeRecord(
            endpoint=endpoint, method=method, insertion_point=insertion_point, param=param,
            check_id=check_id, bug_class=bug_class,
            oracle_kinds_run=kinds, verdict=verdict, evidence=evidence,
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
                    endpoint=request.url, method=request.method, insertion_point=f"request:{rcheck.id}",
                    param="(request)", check_id=rcheck.id, bug_class=rcheck.bug_class,
                    result=rresult, ctx=ctx,
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
                            endpoint=request.url, method=request.method, insertion_point=point.id, param=point.name,
                            check_id=check.id, bug_class=check.bug_class, result=result, ctx=ctx,
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
