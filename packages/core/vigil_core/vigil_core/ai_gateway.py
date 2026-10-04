"""vigil_core.ai_gateway — the ONE mandatory chokepoint every LLM egress routes through (M4.1).

Before this module the pieces of a disciplined model egress were scattered across EVERY model-touching
call site and were ASYMMETRIC: the URK backend layer (``framework.v2.kernel.llm``) asserted sovereignty
and stamped a call trace but sent the prompt to the provider WITHOUT masking secrets; the live think step
(``vigil_integration.live.think_claude``) framed and redacted but kept its own copy of the discipline;
and the console chat / terminal router (``framework.v2.console.chat`` / ``.actions``) and the codebase-edit
coders (``vigil_integration.live.dev_edit`` / ``.codefix_runner``) each reached the provider SDK directly,
with no classification, no symmetric redaction, and no shared audit. There was no single place that
composed classify -> redact -> authorize -> route -> provenance -> output-verify -> audit, and no unified
provenance record spanning the paths.

``egress(payload, *, case)`` is that single place, and EVERY LLM-egress call site now routes through it:
the URK completion (auto-failover and an explicitly-pinned backend), the live think step (cloud +
loopback-local), the console chat reasoning (blocking cloud, streaming cloud, loopback-local), the terminal
capability router, both codebase-edit coders (cloud + loopback-local), AND the SIGIL sovereign plane's cloud
LLM egress (the frontier vision upload and the cloud memory-consolidation call). It is a PURE composition:
every environment-specific step (the sovereignty ladder, the
authorization gate, the actual model call — blocking or streaming — the audit sink) is INJECTED through the
:class:`EgressCase`, so this module imports nothing but the standard library and the shared
``vigil_core.redact`` masker. Because ``vigil_core`` imports no ``framework.*`` / ``strix.*`` / ``sigil.*``,
both the offense framework and the sovereign plane load the SAME chokepoint without crossing the
keyless two-environment boundary (FATAL-2); each side supplies a thin adapter that wires its own
sovereignty policy and its own model call.

SCOPE — "every LLM egress", precisely. This chokepoint covers LLM (model-completion) egress on all three
planes. The sovereign plane ALSO has NON-LLM provider egress this gateway does NOT cover: its VOICE provider
(ElevenLabs TTS text / STT audio / voice-library lookup) and its credential-validation probes, which are
governed by the SIGIL sovereignty tier (``sigil.sovereignty.assert_endpoint_permitted``) but are not
gateway-redacted — a different egress class, registered as a documented limitation
(``docs/limitations/inventory.json``: ``LIMIT-sigil-voice-probe-egress-not-gatewayed``). A sovereign-plane
on-box/loopback model call (local Ollama vision / memory consolidation) stays on the host under that same
endpoint gate and is not routed here.

A model call that must STREAM its output (the chat streaming path, the live think streaming SDK call) is
supported without buffering: the injected ``invoke`` closure does the streaming round-trip itself — handing
each delta to its own sink AS IT ARRIVES, inside the egress context — and returns the assembled final result
for the record. The gateway never holds the whole response; it only brackets the streamed call with the
classify/redact/authorize/route steps before and the provenance/audit steps after.

The seven composed steps, in order:

  1. classify       — label the payload's sensitivity (does it carry a secret shape?) and the bug-class.
  2. minimize/redact — mask every credential SHAPE THE SHARED MASKER RECOGNISES in the outbound payload:
                       ``Bearer`` tokens, credential-header values, and secret-named ``key=value`` assignments
                       (see ``vigil_core.redact``), so a recognised credential shape never leaves the host in a
                       prompt (the symmetric guarantee the URK path previously lacked). HONEST LIMIT: the
                       masker does NOT recognise a bare AWS key, a PEM block, a bare JWT, a GitHub/Slack token,
                       a raw high-entropy string, or inline db-URL creds — such a value rides through like any
                       other text. This is "every credential shape the masker recognises", never "every
                       conceivable secret".
  3. case-authorize — consult the injected case gate; a deny refuses BEFORE any model call.
  4. model-route    — assert the sovereignty policy permits this backend, and that the provider identity
                       is not a trust anchor; a refusal happens BEFORE the invoke closure runs, hence
                       before any provider SDK is imported (the SDK import lives inside invoke).
  5. provenance     — run the injected invoke closure inside the egress context and record the call.
  6. output-verify  — confirm the produced record attributes the output to an UNTRUSTED provider: the
                       provider is never authoritative and never in the trust root.
  7. audit          — emit one unified :class:`EgressRecord` (to the shared ring and the injected sink)
                       for both paths.

The chokepoint is mandatory, not advisory, and that is enforced two ways. At RUNTIME the invoke closures
guard themselves with :func:`assert_in_egress`, so a direct call that skips :func:`egress` fails closed
(:class:`EgressBypass`). STATICALLY a structural no-bypass guard (``integration/tests/test_egress_no_bypass_guard.py``)
walks the offense + integration trees and fails CI if any ``messages.create`` / ``messages.stream`` /
backend ``.complete`` call appears in a function that does not assert the egress context — so a newly added
provider call outside the chokepoint reds the build. Together they make "the gateway is the only egress
path" a falsifiable claim, not a hope. Everything here is deterministic and offline-re-verifiable; the
record carries metadata and counts, never the raw payload or any credential.
"""

from __future__ import annotations

import contextvars
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Mapping, Optional

from .redact import MASK, redact_log_message, scrub_log_event

__all__ = [
    "EgressBypass",
    "EgressClassification",
    "EgressRecord",
    "EgressResult",
    "EgressCase",
    "egress",
    "assert_in_egress",
    "in_egress",
    "audit_log",
    "reset_audit",
    "classify_payload",
    "redact_payload",
]


# ---------------------------------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------------------------------


class EgressBypass(RuntimeError):
    """Raised when a model egress is attempted outside :func:`egress`. The invoke closures assert the
    egress context at their first line, so skipping the chokepoint fails closed rather than quietly
    sending bytes that were never classified, redacted, authorized or audited."""


# ---------------------------------------------------------------------------------------------------
# the one-and-only egress context — a direct-call bypass fails closed
# ---------------------------------------------------------------------------------------------------

# A depth counter rather than a bool so a legitimately re-entrant egress (a model-specific fallback that
# issues a second call while the first is still on the stack) does not clear the flag early. It is a
# contextvar so concurrent engagements in separate tasks never see each other's state.
_EGRESS_DEPTH: contextvars.ContextVar[int] = contextvars.ContextVar("vigil_ai_egress_depth", default=0)


def in_egress() -> bool:
    """True while control is inside :func:`egress` (between model-route and output-verify). Total."""
    try:
        return _EGRESS_DEPTH.get() > 0
    except Exception:  # noqa: BLE001 — a missing/odd contextvar reads as "not in egress" (fail closed)
        return False


def assert_in_egress(where: str = "") -> None:
    """Raise :class:`EgressBypass` unless called from inside :func:`egress`. Every adapter's invoke
    closure (and the raw model-touching helper it wraps) calls this FIRST, so a caller that reaches the
    provider without routing through the gateway fails closed — the gateway is the only egress path."""
    if not in_egress():
        raise EgressBypass(
            f"LLM egress attempted outside the gateway chokepoint ({where!r}); route the call through "
            "vigil_core.ai_gateway.egress so it is classified, redacted, authorized, routed and audited "
            "(fail-closed)."
        )


# ---------------------------------------------------------------------------------------------------
# the unified records
# ---------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class EgressClassification:
    """Step 1 output: what kind of egress this is. ``sensitivity`` is 'secret-bearing' when the raw
    payload carries a credential shape the redactor recognises, else 'ordinary'."""

    path: str
    sensitivity: str
    bug_class: Optional[str] = None
    has_structured: bool = False


# The outcomes the gateway can record. A refusal never reaches the provider; 'completed' means the invoke
# closure ran and returned; 'error' means it raised (re-raised to the caller after the audit).
_OUTCOMES = ("completed", "refused_case", "refused_sovereignty", "refused_trust_root", "error")


@dataclass(frozen=True)
class EgressRecord:
    """The ONE provenance/audit record produced for every egress on BOTH paths. It carries metadata and
    counts only — never the raw prompt, never a credential — so it is safe to log, ring-buffer and ship."""

    path: str
    backend: str
    classification: EgressClassification
    redaction_applied: bool
    redaction_count: int
    case_authorized: bool
    sovereignty_permitted: bool
    invoked: bool
    provider_authoritative: bool          # ALWAYS False — a model's output is a proposal, never a fact
    provider_in_trust_root: bool          # verified False in step 6 — the provider is never a trust anchor
    outcome: str
    reason: str
    timestamp: str
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "backend": self.backend,
            "classification": {
                "path": self.classification.path,
                "sensitivity": self.classification.sensitivity,
                "bug_class": self.classification.bug_class,
                "has_structured": self.classification.has_structured,
            },
            "redaction_applied": self.redaction_applied,
            "redaction_count": self.redaction_count,
            "case_authorized": self.case_authorized,
            "sovereignty_permitted": self.sovereignty_permitted,
            "invoked": self.invoked,
            "provider_authoritative": self.provider_authoritative,
            "provider_in_trust_root": self.provider_in_trust_root,
            "outcome": self.outcome,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "extra": dict(self.extra),
        }


@dataclass
class EgressResult:
    """What :func:`egress` returns. ``output`` is the invoke closure's return value (``None`` on any
    refusal); ``record`` is always populated; ``redacted`` is the exact payload that was (or would have
    been) sent, so a caller/test can confirm the symmetric redaction held."""

    ok: bool
    refused: bool
    refusal_kind: str          # "" | "case" | "sovereignty" | "trust_root"
    refusal_reason: str
    output: Any
    record: EgressRecord
    redacted: Mapping[str, Any]


# ---------------------------------------------------------------------------------------------------
# the case — every environment-specific step is injected here (FATAL-2: no framework import in the core)
# ---------------------------------------------------------------------------------------------------


@dataclass
class EgressCase:
    """The per-call policy + injected hooks that specialise the generic chokepoint for one path.

    Required:
      * ``path``   — a stable label for the record ("urk", "live_think", ...).
      * ``invoke`` — performs the actual model call on the REDACTED payload and returns its raw result.
                     It must call :func:`assert_in_egress` first so a bypass fails closed.

    Optional hooks (all fail-closed where a failure could permit egress):
      * ``backend``          — the backend/provider name for the sovereignty assertion + the record.
      * ``bug_class``        — a classification hint, recorded for provenance.
      * ``authorize``        — the case gate: ``() -> (allowed, reason)``; a deny or raise refuses.
      * ``assert_permitted`` — the sovereignty ladder: ``(backend) -> None``, raising to refuse. Only
                               consulted when ``backend`` is non-empty (an auto-selected backend enforces
                               its own per-candidate assertion inside ``invoke``).
      * ``provenance``       — ``(output) -> Mapping`` extracting extra provenance (answering backend,
                               token counts) merged into the record's ``extra``; best-effort.
      * ``audit_sink``       — ``(record) -> None`` receiving the unified record; best-effort.
      * ``trust_root_ids``   — identities currently in the active trust root; the provider identity must
                               not be among them (step 6).
      * ``provider_identity``— the provider's identity for the trust-root check (defaults to ``backend``).
    """

    path: str
    invoke: Callable[[Mapping[str, Any]], Any]
    backend: str = ""
    bug_class: Optional[str] = None
    authorize: Optional[Callable[[], tuple[bool, str]]] = None
    assert_permitted: Optional[Callable[[str], None]] = None
    provenance: Optional[Callable[[Any], Mapping[str, Any]]] = None
    audit_sink: Optional[Callable[["EgressRecord"], None]] = None
    trust_root_ids: frozenset[str] = frozenset()
    provider_identity: str = ""

    def identity(self) -> str:
        return (self.provider_identity or self.backend or "").strip()


# ---------------------------------------------------------------------------------------------------
# the shared audit ring — one unified record stream for both paths (secret-free)
# ---------------------------------------------------------------------------------------------------

_AUDIT: Deque[EgressRecord] = deque(maxlen=256)


def audit_log() -> list[EgressRecord]:
    """The recent unified egress records (both paths), oldest first. Secret-free; for operators/tests."""
    return list(_AUDIT)


def reset_audit() -> None:
    """Clear the shared audit ring (tests use this to isolate assertions)."""
    _AUDIT.clear()


# ---------------------------------------------------------------------------------------------------
# step 1 (classify) + step 2 (redact) — pure, shared redactor
# ---------------------------------------------------------------------------------------------------

_TEXT_KEYS = ("system", "user")


def _redact_text(value: str) -> tuple[str, int]:
    """Mask credential shapes in one free-text field; return (masked, new_masks_added)."""
    masked = redact_log_message(value)
    return masked, max(0, masked.count(MASK) - value.count(MASK))


def _struct_mask_count(before: Any, after: Any) -> int:
    # A telemetry count only (the security property is proven by the conformance tests on real output).
    try:
        return max(0, str(after).count(MASK) - str(before).count(MASK))
    except Exception:  # noqa: BLE001
        return 0


def redact_payload(payload: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    """Step 2. Return (redacted_payload, total_masks_added). Free-text ``system``/``user`` run through the
    message-level masker; a ``structured`` dict runs through the structured scrubber. Non-str / absent
    fields pass through unchanged. Deterministic."""
    red: dict[str, Any] = {}
    total = 0
    for k in _TEXT_KEYS:
        v = payload.get(k)
        if isinstance(v, str):
            rv, n = _redact_text(v)
            red[k] = rv
            total += n
        else:
            red[k] = v
    st = payload.get("structured")
    if isinstance(st, dict):
        rst = scrub_log_event(st)
        red["structured"] = rst
        total += _struct_mask_count(st, rst)
    elif st is not None:
        red["structured"] = st
    # preserve any other keys verbatim (the core does not interpret them)
    for k, v in payload.items():
        if k not in red:
            red[k] = v
    return red, total


def classify_payload(payload: Mapping[str, Any], case: "EgressCase") -> EgressClassification:
    """Step 1. Label the egress. ``sensitivity`` is 'secret-bearing' when redaction WOULD change the
    payload (a credential shape is present), else 'ordinary'. Pure."""
    _red, n = redact_payload(payload)
    return EgressClassification(
        path=case.path,
        sensitivity="secret-bearing" if n > 0 else "ordinary",
        bug_class=case.bug_class,
        has_structured=isinstance(payload.get("structured"), dict),
    )


# ---------------------------------------------------------------------------------------------------
# the composition
# ---------------------------------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _emit(case: "EgressCase", record: EgressRecord) -> None:
    """Step 7. Append to the shared ring and forward to the injected sink. Audit never breaks egress."""
    _AUDIT.append(record)
    sink = case.audit_sink
    if sink is not None:
        try:
            sink(record)
        except Exception:  # noqa: BLE001 — an audit sink error must never fail the egress
            pass


def egress(payload: Mapping[str, Any], *, case: "EgressCase") -> EgressResult:
    """The ONE egress chokepoint. Compose classify -> redact -> case-authorize -> model-route ->
    provenance -> output-verify -> audit, driving the environment-specific steps through ``case``.

    Returns an :class:`EgressResult`. A refusal (case gate, sovereignty ladder, or provider-in-trust-root)
    returns ``refused=True`` with ``output=None`` and NO model call. A model call that raises is recorded
    then re-raised to the caller (so the URK contract of propagating backend errors is preserved); the
    live adapter's invoke never raises. The produced :class:`EgressRecord` is always emitted."""
    if not isinstance(payload, Mapping):
        payload = {}
    backend = (case.backend or "").strip()

    # 1. classify
    cls = classify_payload(payload, case)

    # 2. minimize / secrets-redact
    redacted, n_masked = redact_payload(payload)

    def _record(*, outcome: str, reason: str, invoked: bool,
                sovereignty_permitted: bool, case_authorized: bool,
                provider_in_trust_root: bool, extra: Optional[Mapping[str, Any]] = None) -> EgressRecord:
        return EgressRecord(
            path=case.path, backend=backend or "auto", classification=cls,
            redaction_applied=n_masked > 0, redaction_count=n_masked,
            case_authorized=case_authorized, sovereignty_permitted=sovereignty_permitted,
            invoked=invoked, provider_authoritative=False,
            provider_in_trust_root=provider_in_trust_root, outcome=outcome, reason=reason,
            timestamp=_now(), extra=dict(extra or {}),
        )

    def _refuse(kind: str, outcome: str, reason: str, *, sov: bool, case_ok: bool, in_root: bool) -> EgressResult:
        rec = _record(outcome=outcome, reason=reason, invoked=False,
                      sovereignty_permitted=sov, case_authorized=case_ok, provider_in_trust_root=in_root)
        _emit(case, rec)
        return EgressResult(ok=False, refused=True, refusal_kind=kind, refusal_reason=reason,
                            output=None, record=rec, redacted=redacted)

    # 3. case-authorize (gate) — a deny or a raised gate refuses before any model call.
    if case.authorize is not None:
        try:
            allowed, areason = case.authorize()
        except Exception as exc:  # noqa: BLE001 — a gate that errors is a DENY, never caught-and-continued
            return _refuse("case", "refused_case", f"case gate error (fail-closed): {exc}",
                           sov=False, case_ok=False, in_root=False)
        if not allowed:
            return _refuse("case", "refused_case", f"case gate refused: {areason}",
                           sov=False, case_ok=False, in_root=False)

    # 4. model-route — sovereignty ladder + the provider-is-not-a-trust-anchor invariant, BEFORE invoke
    #    (hence before any provider SDK import, which lives inside the invoke closure).
    identity = case.identity()
    if identity and identity in case.trust_root_ids:
        return _refuse("trust_root", "refused_trust_root",
                       f"provider identity {identity!r} is in the trust root — a model provider is never "
                       "a trust anchor (fail-closed)", sov=True, case_ok=True, in_root=True)
    if backend and case.assert_permitted is not None:
        try:
            case.assert_permitted(backend)
        except Exception as exc:  # noqa: BLE001 — a sovereignty refusal (or any error) refuses, pre-invoke
            return _refuse("sovereignty", "refused_sovereignty", str(exc) or type(exc).__name__,
                           sov=False, case_ok=True, in_root=False)

    # 5. provenance — run the injected model call INSIDE the egress context so a bypass fails closed.
    token = _EGRESS_DEPTH.set(_EGRESS_DEPTH.get() + 1)
    try:
        try:
            output = case.invoke(redacted)
        except Exception as exc:  # noqa: BLE001 — record the error, then re-raise (URK propagates it)
            rec = _record(outcome="error", reason=f"{type(exc).__name__}: {exc}", invoked=True,
                          sovereignty_permitted=True, case_authorized=True, provider_in_trust_root=False)
            _emit(case, rec)
            raise
    finally:
        _EGRESS_DEPTH.reset(token)

    # best-effort provenance extraction (answering backend, tokens, ...)
    extra: dict[str, Any] = {}
    if case.provenance is not None:
        try:
            got = case.provenance(output)
            if isinstance(got, Mapping):
                extra = dict(got)
        except Exception:  # noqa: BLE001 — provenance extraction is best-effort, never a gate
            extra = {}

    # 6. output-verify — the output is attributed to an UNTRUSTED provider: never authoritative, never a
    #    trust anchor. Both are guaranteed by construction + step 4; asserting them is the structural
    #    confirmation that nothing flipped the attribution.
    provider_in_root = bool(identity and identity in case.trust_root_ids)
    rec = _record(outcome="completed", reason="egress completed", invoked=True,
                  sovereignty_permitted=True, case_authorized=True,
                  provider_in_trust_root=provider_in_root, extra=extra)
    if rec.provider_authoritative or rec.provider_in_trust_root:
        # unreachable given step 4, but fail closed if a future change ever lets it through.
        bad = _record(outcome="error", reason="output-verify: provider wrongly marked a trust anchor",
                      invoked=True, sovereignty_permitted=True, case_authorized=True,
                      provider_in_trust_root=True, extra=extra)
        _emit(case, bad)
        raise EgressBypass("output-verify failed: a model provider was marked authoritative / a trust anchor")

    # 7. audit
    _emit(case, rec)
    return EgressResult(ok=True, refused=False, refusal_kind="", refusal_reason="",
                        output=output, record=rec, redacted=redacted)
