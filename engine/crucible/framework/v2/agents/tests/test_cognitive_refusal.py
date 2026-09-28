"""
Nervous-System N4 — the reasoning-layer cognitive refusal.

Refuse to CONCLUDE a finding that claims oracle verification but will not re-ground under live
re-execution; record every refusal as a typed spine event. Demote-only; reuses the veracity
firewall; never promotes.
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.agents.blackboard import open_blackboard
from framework.v2.agents.cognitive_refusal import emit_refusal, epistemic_refusal
from framework.v2.agents.models import FindingPayload
from framework.v2.agents.spine_sink import SpineSink
from framework.v2.verify.adapter import FindingContext


# ATTRIBUTED evidence. The confirmable fixture below is a path_traversal FILE-CONTENT signature with
# its benign CONTROL retained: the signature is present under the payload and ABSENT from the
# control, so the read is attributable. It used to be a boolean_sqli benign-vs-payload differential,
# which is LEAD-only now — that inference has no attribution step (its control is a DIFFERENT
# STRING, not a same-shape negative) and minted High FACTs at rate 1.0 against a static page behind
# a WAF tautology rule and against strict input validation, on targets with no database. See
# verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES. Nothing under test here changes — only the
# evidence it is anchored to.
_SIGNATURE = "root:x:0:0:"
_READ_SINK = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
_CONTROL_SINK = "<p>ordinary document</p>"
_PT = "path_traversal"


def _pt_ctx(*, firing: bool = True) -> "FindingContext":
    """A path_traversal side-effect context. ``firing=False`` puts the signature in the CONTROL too,
    so it is not attributable and the oracle stays silent."""
    return FindingContext.from_side_effect(
        _SIGNATURE, _READ_SINK, bug_class=_PT,
        control_sink=_READ_SINK if not firing else _CONTROL_SINK)


_BASE = _READ_SINK          # the NON-attributable control value (signature already present)
_DIVERGENT = _CONTROL_SINK  # the genuine control: the signature is ABSENT from it


def _ctx(mutated=_CONTROL_SINK) -> dict:
    return FindingContext.from_side_effect(
        _SIGNATURE, _READ_SINK, bug_class=_PT, control_sink=mutated).model_dump(mode="json")


def _finding(**kw) -> FindingPayload:
    base = dict(finding_slug="1", title="t", severity="High", bug_class="path_traversal",
                surface="q", summary="s", verified_by_oracle=True, oracle_kind="differential_response",
                confidence=0.87, oracle_context=_ctx())
    base.update(kw)
    return FindingPayload(**base)


def test_no_refusal_for_a_grounding_finding() -> None:
    assert epistemic_refusal(_finding()) is None                       # re-grounds → conclude normally


def test_no_refusal_when_no_verification_is_claimed() -> None:
    assert epistemic_refusal(_finding(verified_by_oracle=False)) is None


def test_refuses_a_finding_that_claims_verification_but_cannot_reground() -> None:
    # claims verified_by_oracle but the retained proof does not re-fire → refuse to conclude
    stale = _finding(oracle_context=_ctx(_BASE))
    d = epistemic_refusal(stale)
    assert d is not None and d.gate == "epistemic" and "does not re-ground" in d.reason
    unbacked = _finding(oracle_context=None)                           # claims verification, no proof
    assert epistemic_refusal(unbacked) is not None


def test_emit_refusal_records_it_on_the_spine(tmp_path: Path) -> None:
    b = open_blackboard(db_path=tmp_path / "bb.sqlite")
    b.engagement_id("e")
    sink = SpineSink(b, "e")
    emit_refusal(sink, epistemic_refusal(_finding(oracle_context=None)))
    refusals = b.read(engagement="e", kinds=["refusal"])
    assert len(refusals) == 1 and refusals[0].payload["gate"] == "epistemic"
    # a grounding finding produces no refusal event
    emit_refusal(sink, epistemic_refusal(_finding()))
    assert len(b.read(engagement="e", kinds=["refusal"])) == 1
    b.close()
