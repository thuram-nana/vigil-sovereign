"""
redpen.certify — translate a twice-fired sandbox reproduction to a signed FACT, or an honest LEAD.

This is the "refute-by-reproduction -> certify" tail of the Red-Pen pipeline (design §7.2 steps 3-4).
Given a :class:`~vigil_integration.redpen.reproduce.Reproduction` that FIRED in the sandbox TWICE
(no flakes), it builds the per-class ``FindingContext`` the oracle judges — strictly from the
EXECUTOR-captured bytes, the SAME single bridge the Proof Studio mint uses
(:func:`framework.v2.verify.poc_translate.context_from_exchanges`) — and drives the existing veracity
firewall :func:`vigil_integration.oracle_adapter.confirm_and_certify` with ``provenance="reproduced"``.
It invents no FACT any other way: the deterministic oracle is the sole authority.

O-1 (orchestrator decision, 2026-11-16) — **only the offline/static oracle set earns a posted FACT**:

  * the request-side ``*_BREAKOUT`` oracles (SQL / COMMAND / NOSQL / PATH_TRAVERSAL / SSRF / XXE,
    judged on the request value alone),
  * the sandbox process-output signals (sanitizer/ASAN crash, error-signature, side-effect marker),
  * the existing DAA ``static_oracle_confirmed`` static facts (``static_rule``).

Every other oracle kind — a differential/boolean/timing blind, an achieved-state authz read, an
out-of-band callback, an SSTI evaluation, a DOM execution, any posture/AEGIS kind — stays a **LEAD**
(the dashboard surfaces it; it is NEVER posted). The gate is the ACTUAL oracle kind that fired
(``AdapterResult.confirmed_by``), re-checked against :data:`_FACT_ELIGIBLE_ORACLE_KINDS` on the signed
result — NEVER ``verified_by_oracle`` (which ``codescan`` sets for every DAA match by design, so it is
no evidence of reproduction at all).

Two independent refusals back the twice-fire requirement: gate-0 here demotes a reproduction that did
not fire twice / is not reproduced-provenanced BEFORE any oracle runs, and ``confirm_and_certify``'s
own G4 provenance gate demotes anything whose ``provenance`` is not a non-LLM channel. An
LLM-provenanced context is always a LEAD.

FATAL-2: every ``framework`` / ``oracle_adapter`` import here is LAZY (function-local), so importing
this module never pulls ``framework`` into the sovereign env. Determinism: no wallclock / rng — ``seq``
is passed in.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

# Channel families (mirror framework.v2.verify.poc_translate — duplicated as bare strings so this module
# stays import-clean / framework-free at module scope). Only these three are reproducible from the R1
# process sandbox; the oracle, not the channel, is the authority on whether anything fires.
REQUEST_PAYLOAD = "request_payload"   # a single decoded request-parameter value -> the *_BREAKOUT oracles
PROCESS = "process"                   # captured stdout/stderr -> SANITIZER_SIGNAL (ASAN/UBSAN/panic/abort)
ERROR_SIGNATURE = "error_signature"   # a datastore/parser error a payload provoked -> ERROR_SIGNATURE

# O-1: the channels R1 can reproduce into the FACT-eligible oracle set. A candidate on any other channel
# (http_differential / evaluation / ...) is surfaced as a LEAD — it is not reproducible from the process
# sandbox and its oracle family is outside the v1 posted-FACT set.
_FACT_ELIGIBLE_CHANNELS = frozenset({REQUEST_PAYLOAD, PROCESS, ERROR_SIGNATURE})

# O-1: the AUTHORITATIVE allowlist — the OracleKind ``.value`` strings whose FIRE earns a posted FACT in
# v1. This is the faithful encoding of the offline/static oracle set. A confirmed finding whose fired
# oracle kind is NOT in this set is demoted to a LEAD here even though the deterministic oracle fired and
# ``confirm_and_certify`` signed a certificate — new code-oracle kinds are a later funded slice.
_FACT_ELIGIBLE_ORACLE_KINDS = frozenset({
    # request-side parse-proof (judged on the request value alone)
    "sql_injection_breakout", "command_injection_breakout", "nosql_injection_breakout",
    "path_traversal_breakout", "ssrf_breakout", "xxe_breakout",
    # sandbox process-output signals
    "sanitizer_signal", "error_signature", "side_effect",
    # the existing DAA static_oracle_confirmed static facts
    "static_rule",
})

# Provenance of a context that may back a signed FACT (mirror oracle_adapter._REPRODUCED_PROVENANCE). A
# reproduction that did not run the sandbox twice carries "" and is refused here; an LLM-provenanced
# context ("llm") is refused by confirm_and_certify's own G4 gate.
_REPRODUCED_PROVENANCE = frozenset({"reproduced", "live_redrive"})

# The confirm seam: confirm_and_certify-compatible. Injected in tests so the O-1 kind gate can be exercised
# against an arbitrary ``confirmed_by`` without a live oracle; the default lazy-loads the real adapter.
ConfirmFn = Callable[..., Any]


@dataclass(frozen=True)
class _Exchange:
    """A duck-typed ``CapturedExchange`` — ``poc_translate`` reads attributes, not the pydantic type, so
    this stays framework-free. ``response_bytes_ref`` / ``request_bytes_ref`` are keys into a resolve
    map of the EXECUTOR-captured bytes (never LLM text)."""

    channel: str
    role: str = ""
    request_bytes_ref: str = ""
    response_bytes_ref: str = ""
    bug_class: str = ""
    status: "int | None" = None


@dataclass(frozen=True)
class CertifyResult:
    """The honest disposition of one certification attempt.

      * ``"fact"`` — a FACT-eligible oracle (O-1) fired over the twice-reproduced context and
        ``confirm_and_certify`` signed a proof-carrying certificate (``signed`` is a ``SignedEvidence``).
      * ``"lead"`` — not reproduced twice, an unreproducible channel, no oracle fired, an unmapped class,
        an LLM-provenanced context, OR a fired oracle kind outside the v1 FACT-eligible set. Never signed,
        never posted.
    """

    status: str
    bug_class: str
    finding_ref: str
    reason: str
    confirmed_by: str = ""
    confidence: float = 0.0
    outcome: str = ""
    signed: Any = None

    @property
    def is_fact(self) -> bool:
        return self.status == "fact"


def _lead(bug_class: str, ref: str, reason: str, *, confirmed_by: str = "", outcome: str = "",
          confidence: float = 0.0) -> CertifyResult:
    return CertifyResult("lead", bug_class, ref, reason, confirmed_by=confirmed_by, outcome=outcome,
                         confidence=confidence)


def _build_exchanges(candidate: Any, reproduction: Any) -> "tuple[list[_Exchange], dict[str, bytes]]":
    """Per-class bridge: turn the candidate + the captured bytes into the ``poc_translate`` exchanges +
    a resolve map. Only the three reproducible channels are built; the caller has already refused any
    other channel. The captured bytes come from :class:`reproduce.Reproduction` (the executor-owned,
    non-LLM channel), never from the model."""
    ch = candidate.channel
    blobs: dict[str, bytes] = {}
    if ch == REQUEST_PAYLOAD:
        # The *_BREAKOUT oracles judge the decoded request value ALONE; the twice-fired reproduction
        # proved that value reaches the changed sink.
        blobs["req"] = (reproduction.request_value or "").encode("utf-8")
        return ([_Exchange(channel=ch, role=(candidate.param or "value"), request_bytes_ref="req",
                           bug_class=candidate.bug_class)], blobs)
    # PROCESS / ERROR_SIGNATURE: the captured stdout+stderr IS the response the oracle adjudicates.
    blobs["out"] = ((reproduction.stdout or "") + (reproduction.stderr or "")).encode("utf-8")
    if ch == PROCESS:
        return ([_Exchange(channel=ch, role="", response_bytes_ref="out",
                           bug_class=candidate.bug_class)], blobs)
    # ERROR_SIGNATURE — the captured output is the "mutated" observation; an optional benign control
    # value (captured on the same insertion point) refutes a signature already present in the baseline.
    exs = [_Exchange(channel=ch, role="mutated", response_bytes_ref="out", bug_class=candidate.bug_class)]
    ctrl = getattr(candidate, "control_value", "") or ""
    if ctrl:
        blobs["ctrl"] = ctrl.encode("utf-8")
        exs.append(_Exchange(channel=ch, role="control", response_bytes_ref="ctrl",
                             bug_class=candidate.bug_class))
    return (exs, blobs)


def _default_confirm(*args: Any, **kwargs: Any) -> Any:
    """The real veracity firewall — lazy-imported (FATAL-2) so this module never pulls framework on import."""
    from ..oracle_adapter import confirm_and_certify  # noqa: PLC0415 (FATAL-2: function-local)

    return confirm_and_certify(*args, **kwargs)


def certify_candidate(
    candidate: Any,
    reproduction: Any,
    *,
    engagement_slug: str,
    signers: "Sequence[tuple[str, str]]",
    seq: int = 0,
    verifier: Any = None,
    confirm: "ConfirmFn | None" = None,
) -> CertifyResult:
    """Certify one twice-fired reproduction, or return an honest LEAD.

    ``candidate`` is the lens's :class:`reproduce.LensCandidate` (``bug_class``, ``channel``, ``param``,
    optional ``control_value``, ``finding_ref``). ``reproduction`` is the sandbox outcome: it must carry
    ``fired_twice`` + ``provenance == "reproduced"`` + the captured ``stdout`` / ``stderr`` /
    ``request_value``. ``signers`` are the governance authorisers (empty is refused fail-closed by
    ``confirm_and_certify``). ``confirm`` is the injectable firewall seam (default: the real adapter).
    """
    ref = str(getattr(candidate, "finding_ref", "") or getattr(candidate, "bug_class", "") or "finding")
    bug_class = str(getattr(candidate, "bug_class", "") or "")

    # Gate 0 (first independent refusal for the twice-fire). A reproduction that did not fire TWICE, or
    # whose provenance is not the reproduced non-LLM channel, is a LEAD BEFORE any oracle runs — this also
    # catches the LLM-provenanced case (provenance="llm") and the sandbox-unavailable case (provenance="").
    if not getattr(reproduction, "fired_twice", False) or \
            getattr(reproduction, "provenance", "") not in _REPRODUCED_PROVENANCE:
        return _lead(bug_class, ref,
                     f"not reproduced twice from a non-LLM channel "
                     f"(provenance={getattr(reproduction, 'provenance', '')!r}, "
                     f"status={getattr(reproduction, 'status', '')!r}) — surfaced as a LEAD")

    # Gate 1: the channel must be one R1 can reproduce into the FACT-eligible oracle set (O-1).
    if candidate.channel not in _FACT_ELIGIBLE_CHANNELS:
        return _lead(bug_class, ref,
                     f"channel {candidate.channel!r} is not in the v1 reproducible oracle set (O-1) — "
                     f"surfaced as a LEAD")

    # Build the oracle_context strictly from the captured bytes, via the SAME bridge the mint uses.
    from framework.v2.verify.poc_translate import context_from_exchanges  # noqa: PLC0415 (FATAL-2)

    exchanges, blobs = _build_exchanges(candidate, reproduction)
    ctx = context_from_exchanges(exchanges, bug_class=bug_class, resolve=blobs.get)
    if ctx is None:
        return _lead(bug_class, ref,
                     "no reproducible oracle_context from the captured bytes — surfaced as a LEAD")
    oracle_context = ctx.model_dump(mode="json")

    # Oracle authority + provenance (G4) — the SOLE path to a signed certificate. The provenance passed is
    # the reproduction's own (reproduced); dropping it would default to "llm" and demote to a LEAD.
    confirm = confirm or _default_confirm
    res = confirm(
        {"check_id": ref, "bug_class": bug_class, "oracle_context": oracle_context},
        engagement_slug=engagement_slug, signers=list(signers), seq=seq, verifier=verifier,
        provenance=reproduction.provenance,
    )
    confirmed_by = str(getattr(res, "confirmed_by", "") or "")

    # O-1 AUTHORITATIVE GATE — a FACT requires the firewall to have confirmed AND the FIRED oracle kind to
    # be in the offline/static FACT-eligible set. This gates on the reproduced oracle result, NEVER on
    # ``verified_by_oracle``. Anything else is a labelled LEAD (honest, retained, never posted).
    fact_ok = res.is_fact and confirmed_by in _FACT_ELIGIBLE_ORACLE_KINDS
    if not fact_ok:
        reason = (getattr(res, "reason", "") or "no oracle fired over the reproduced context") \
            if not res.is_fact else \
            (f"oracle {confirmed_by!r} confirmed the finding but is NOT in the v1 FACT-eligible "
             f"offline/static oracle set (O-1) — surfaced as a LEAD")
        return _lead(str(getattr(res, "bug_class", "") or bug_class), ref, reason,
                     confirmed_by=confirmed_by, outcome=str(getattr(res, "outcome", "") or ""),
                     confidence=float(getattr(res, "confidence", 0.0) or 0.0))

    return CertifyResult(
        "fact", str(getattr(res, "bug_class", "") or bug_class), str(getattr(res, "finding_ref", "") or ref),
        str(getattr(res, "reason", "") or "oracle-confirmed and signed"),
        confirmed_by=confirmed_by, confidence=float(getattr(res, "confidence", 0.0) or 0.0),
        outcome=str(getattr(res, "outcome", "") or "positive"), signed=getattr(res, "signed", None),
    )
