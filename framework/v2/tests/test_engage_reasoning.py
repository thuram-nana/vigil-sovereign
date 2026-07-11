"""
Tests for framework.v2.engage_reasoning — the LLM-in-the-loop reasoning hook.

Every test pins an explicit DryRunBackend() so the reasoning is deterministic and
network-free (per the workstream determinism guardrail: the default/replayed path
must be deterministic; a live-LLM call is never made in a test). The properties
under test are the load-bearing contract of the hook:

  * it returns structured ADVICE (never a verdict / confirmation);
  * identical inputs → byte-identical advice (determinism);
  * it never mutates findings/verdicts (read-only);
  * it degrades to a safe abstaining no-op on backend failure;
  * it is defensive over the shape of world/findings/ctx (objects, dicts, None).
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass

from framework.v2.engage_reasoning import ReasoningAdvice, reason_step
from framework.v2.kernel.backends.dryrun import DryRunBackend
from framework.v2.kernel.llm import LLMBackend, Prompt, LLMResult


# --- lightweight finding-like fixtures -----------------------------------


@dataclass
class _Finding:
    surface: str
    bug_class: str


def _findings_with(*pairs: tuple[str, str]) -> list[_Finding]:
    return [_Finding(surface=s, bug_class=b) for s, b in pairs]


class _BoomBackend(LLMBackend):
    """A backend whose completion always raises — exercises the degrade path."""

    name = "boom"

    def is_available(self) -> tuple[bool, str]:
        return True, "boom (always raises on complete)"

    def complete(self, prompt: Prompt) -> LLMResult:  # noqa: ARG002
        raise RuntimeError("simulated backend failure")


# --- basic shape ----------------------------------------------------------


def test_reason_step_returns_advice_under_dryrun() -> None:
    advice = reason_step(None, [], {}, backend=DryRunBackend())
    assert isinstance(advice, ReasoningAdvice)
    # DryRun produces the 5-hypothesis catalogue; a focus + rationale come out.
    assert advice.hypotheses, "expected candidate hypotheses from the dry-run kernel"
    assert advice.next_focus
    assert advice.rationale
    assert advice.is_dryrun is True
    # DryRun samples are identical → the self-consistency layer agrees → no abstain.
    assert advice.abstain is False
    assert advice.consistency["agreement"] == 1.0


def test_advice_carries_no_verdict_field() -> None:
    """Prove-don't-guess: the advice object exposes no confirmation/verdict — it
    can never be mistaken for an oracle promoting a finding."""
    advice = reason_step(None, [], {}, backend=DryRunBackend())
    d = advice.to_dict()
    for forbidden in ("confirmed", "verified", "verdict", "oracle_fired", "severity"):
        assert forbidden not in d
        assert not hasattr(advice, forbidden)


# --- determinism ----------------------------------------------------------


def test_reason_step_is_byte_identical_for_identical_inputs() -> None:
    findings = _findings_with(("/api/orders/{id}", "IDOR"))
    ctx = {"surface": "/api/orders/{id}", "posture": "TEST"}

    a1 = reason_step(None, findings, ctx, backend=DryRunBackend())
    a2 = reason_step(None, findings, ctx, backend=DryRunBackend())

    j1 = json.dumps(a1.to_dict(), sort_keys=True)
    j2 = json.dumps(a2.to_dict(), sort_keys=True)
    assert j1 == j2, "identical inputs must yield byte-identical advice"


def test_stuck_pivots_are_byte_identical() -> None:
    ctx = {"stuck": True, "posture": "TEST", "blockers": ["WAF", "rate-limit"]}
    a1 = reason_step(None, [], ctx, backend=DryRunBackend())
    a2 = reason_step(None, [], ctx, backend=DryRunBackend())
    assert a1.pivots, "stuck thread should yield lateral moves"
    assert json.dumps(a1.to_dict(), sort_keys=True) == json.dumps(a2.to_dict(), sort_keys=True)


# --- read-only over inputs ------------------------------------------------


def test_reason_step_does_not_mutate_findings() -> None:
    findings = _findings_with(("/login", "auth-bypass"), ("/api/orders/{id}", "IDOR"))
    before = copy.deepcopy([f.__dict__ for f in findings])

    reason_step(None, findings, {}, backend=DryRunBackend())

    after = [f.__dict__ for f in findings]
    assert after == before, "reason_step must never mutate the findings it reads"
    assert len(findings) == 2


def test_reason_step_does_not_mutate_dict_findings() -> None:
    findings = [{"surface": "/x", "bug_class": "SSRF"}]
    before = copy.deepcopy(findings)
    reason_step(None, findings, None, backend=DryRunBackend())
    assert findings == before


# --- stateful ranking: prioritise not-yet-confirmed classes ---------------


def test_next_focus_prioritises_novel_bug_class() -> None:
    """A bug class already confirmed in findings is ranked LAST; the recommended
    focus is a class not yet confirmed."""
    findings = _findings_with(("/api/orders/{id}", "IDOR"))
    advice = reason_step(None, findings, {}, backend=DryRunBackend())
    assert advice.focus is not None
    assert advice.focus["bug_class"] != "IDOR", (
        "an already-confirmed class must not be the top recommendation"
    )
    # IDOR is still present as a (lower-ranked) candidate — coverage never gated out.
    assert any(h["bug_class"] == "IDOR" for h in advice.hypotheses)


def test_stuck_thread_produces_pivots() -> None:
    advice = reason_step(None, [], {"stuck": True}, backend=DryRunBackend())
    assert advice.pivots, "a stuck thread should propose lateral moves"
    kinds = {p["kind"] for p in advice.pivots}
    assert kinds, "pivots should carry a kind each"


def test_not_stuck_when_findings_present() -> None:
    findings = _findings_with(("/x", "SSRF"))
    advice = reason_step(None, findings, {}, backend=DryRunBackend())
    assert advice.pivots == ()


# --- defensiveness / degrade ---------------------------------------------


def test_reason_step_defensive_over_input_shapes() -> None:
    # world=None, findings=None, ctx=None must not crash.
    advice = reason_step(None, None, None, backend=DryRunBackend())
    assert isinstance(advice, ReasoningAdvice)


def test_backend_supplied_via_ctx() -> None:
    advice = reason_step(None, [], {"backend": DryRunBackend()})
    assert isinstance(advice, ReasoningAdvice)
    assert advice.hypotheses


def test_reason_step_degrades_on_backend_failure() -> None:
    advice = reason_step(None, [], {}, backend=_BoomBackend())
    assert isinstance(advice, ReasoningAdvice)
    assert advice.next_focus == ""
    assert advice.abstain is True
    assert advice.hypotheses == ()
    assert "degraded" in advice.rationale
