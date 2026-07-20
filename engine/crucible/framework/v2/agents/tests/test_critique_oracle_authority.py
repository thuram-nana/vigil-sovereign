"""
Oracle-authoritative confirmation — the deterministic oracle, not the LLM,
decides whether a Finding is promoted to `confirmed`.

Historically the critique-agent stamped a Finding `confirmed` purely on the
LLM's `critique().decision`. CRUCIBLE Wave 3 demotes that LLM verdict to
ADVISORY whenever the Finding carries oracle evidence (`oracle_context`, a
serialized `verify.adapter.FindingContext`). These tests pin the new authority:

  (a) oracle FIRES + an OBJECTING LLM stub  -> confirmed, verified_by_oracle
      True (the oracle wins over a hostile LLM).
  (b) oracle does NOT fire + a CONFIRMING LLM stub -> NOT confirmed
      (the oracle vetoes the LLM; a fired signal is mandatory).
  (c) oracle_context is None -> the legacy LLM-only path, byte-for-byte
      unchanged, with verified_by_oracle False.

The LLM is stubbed by monkeypatching `critique_agent.urk_critique`, so the
decision is fully under test control and no backend is exercised.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents import critique_agent as critique_mod
from framework.v2.agents.blackboard import Blackboard, open_blackboard
from framework.v2.agents.critique_agent import CritiqueAgent
from framework.v2.agents.models import FindingPayload
from framework.v2.kernel.models import CallTrace, CritiqueResult, Objection
from framework.v2.verify.adapter import FindingContext


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def bb(tmp_path: Path) -> Blackboard:
    db = tmp_path / "bb.sqlite"
    b = open_blackboard(db_path=db)
    b.engagement_id("oracle-authority")
    yield b
    b.close()


def _stub_urk(decision: str, *, objections: list[str] | None = None):
    """Build a drop-in replacement for `urk_critique` returning a fixed verdict."""

    def _fake(claim: str, *, evidence: str = "", context: str = "", backend=None):
        cr = CritiqueResult(
            claim=claim,
            decision=decision,
            deception_check="stubbed for test",
            objections=[
                Objection(concern=o, severity="major", evidence_request="n/a")
                for o in (objections or [])
            ],
        )
        trace = CallTrace(
            backend="stub",
            is_dryrun=True,
            cognitive_doc="self-critique",
            cognitive_sections=[],
            timestamp="2026-07-03T00:00:00+00:00",
        )
        return cr, trace

    return _fake


def _firing_context() -> dict:
    """A boolean-SQLi differential that fires: benign term returns no rows, the
    tautology returns every row — a large status/length/lexical delta."""
    return FindingContext.from_http_responses(
        {"status": 200, "body": "No results found."},
        {
            "status": 200,
            "body": (
                "id=1 name=alice role=user\n"
                "id=2 name=bob role=admin\n"
                "id=3 name=carol role=user"
            ),
        },
        bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump()


def _non_firing_context() -> dict:
    """Identical baseline and mutated responses — no differential, oracle silent."""
    same = {"status": 200, "body": "No results found."}
    return FindingContext.from_http_responses(
        same, dict(same),
        bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    ).model_dump()


def _post_finding(bb: Blackboard, payload: FindingPayload) -> int:
    return bb.post(
        engagement="oracle-authority", kind="finding",
        agent_name="exploit", payload=payload.model_dump(),
    )


def _latest_finding(bb: Blackboard, slug: str) -> dict:
    """Return the current (non-superseded) finding payload for `slug`."""
    rows = bb.read(engagement="oracle-authority", kinds=["finding"])
    matches = [r.payload for r in rows if r.payload.get("finding_slug") == slug]
    assert matches, f"no live finding row for {slug}"
    assert len(matches) == 1, "expected exactly one non-superseded finding row"
    return matches[0]


# ---------------------------------------------------------------------------
# (a) oracle fires, LLM objects -> oracle wins
# ---------------------------------------------------------------------------


def test_oracle_fires_overrides_objecting_llm(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        critique_mod, "urk_critique",
        _stub_urk("objections", objections=["the LLM is unconvinced"]),
    )

    finding = FindingPayload(
        finding_slug="001-boolean-sqli",
        title="Boolean-based blind SQL injection in /search",
        severity="High",
        bug_class="boolean_sqli",
        surface="GET /search?q=",
        summary="Tautology returns every row; benign term returns none.",
        oracle_context=_firing_context(),
    )
    fid = _post_finding(bb, finding)

    agent = CritiqueAgent(bb, "oracle-authority")
    assert agent.should_run()
    agent.step()

    live = _latest_finding(bb, "001-boolean-sqli")
    assert live["critique_status"] == "confirmed", "oracle fired but finding not confirmed"
    assert live["verified_by_oracle"] is True

    # The advisory LLM verdict is STILL recorded, it just did not override.
    crits = bb.read(engagement="oracle-authority", kinds=["critique"])
    advisory = [c for c in crits if c.payload.get("target_event_id") == fid]
    assert len(advisory) == 1
    assert advisory[0].payload["decision"] == "objections", (
        "the objecting LLM verdict must be preserved as advisory"
    )


# ---------------------------------------------------------------------------
# (b) oracle does not fire, LLM confirms -> oracle vetoes
# ---------------------------------------------------------------------------


def test_oracle_silent_vetoes_confirming_llm(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("confirm"))

    finding = FindingPayload(
        finding_slug="002-no-differential",
        title="Claimed SQLi with no observable differential",
        severity="High",
        bug_class="boolean_sqli",
        surface="GET /search?q=",
        summary="LLM says exploitable, but baseline and mutated are identical.",
        oracle_context=_non_firing_context(),
    )
    _post_finding(bb, finding)

    agent = CritiqueAgent(bb, "oracle-authority")
    agent.step()

    live = _latest_finding(bb, "002-no-differential")
    assert live["critique_status"] == "objections", (
        "no oracle fired, so a confirming LLM must NOT promote the finding"
    )
    assert live["verified_by_oracle"] is False


# ---------------------------------------------------------------------------
# (c) no oracle_context -> legacy LLM-only path, unchanged
# ---------------------------------------------------------------------------


def test_no_oracle_context_uses_llm_advisory_path(
    bb: Blackboard, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No oracle backs this finding, so the LLM's `confirm` can NEVER reach
    # "confirmed" (that word is oracle-only). It becomes "llm_advisory": recorded and
    # shown, but never promoted/reported as a confirmed fact. An `objections` verdict
    # still yields `objections`. Both carry verified_by_oracle=False.
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("confirm"))
    confirmed_finding = FindingPayload(
        finding_slug="003-llm-confirm",
        title="Legacy finding the LLM confirms",
        severity="Medium",
        bug_class="xss",
        surface="/profile",
        summary="No oracle evidence attached; the LLM signs off.",
    )
    _post_finding(bb, confirmed_finding)

    CritiqueAgent(bb, "oracle-authority").step()
    live = _latest_finding(bb, "003-llm-confirm")
    assert live["critique_status"] == "llm_advisory"
    assert live["verified_by_oracle"] is False
    assert live.get("oracle_context") is None

    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("objections"))
    objected_finding = FindingPayload(
        finding_slug="004-llm-objects",
        title="Legacy finding the LLM objects to",
        severity="Low",
        bug_class="xss",
        surface="/profile",
        summary="No oracle evidence attached; the LLM pushes back.",
    )
    _post_finding(bb, objected_finding)

    CritiqueAgent(bb, "oracle-authority").step()
    live2 = _latest_finding(bb, "004-llm-objects")
    assert live2["critique_status"] == "objections"
    assert live2["verified_by_oracle"] is False
