"""
Producer -> oracle_context wire-in, end to end (Wave 4, item 1).

This closes the "prove-don't-guess" loop on a REAL run, not just in the
confirmation unit. Before this, the critique-agent treated `oracle_context` as
the confirmation authority but no PRODUCER populated it, so a full
exploit -> critique run still fell back to the LLM. Here the `OracleProbeExecutor`
differential-probes a loopback target, the exploit-agent attaches the observed
baseline/mutated responses as `oracle_context`, and the critique-agent confirms
the finding ONLY because the differential oracle fired.

Two hermetic cases, both against localhost, operator-owned demo targets:

  (a) DifferentialDemoHandler (boolean-blind SQLi): the probe pair diverges, the
      oracle FIRES, and the finding is confirmed with verified_by_oracle=True —
      even though the LLM is stubbed to OBJECT. A real target drove a real
      confirmed finding via a fired signal.
  (b) SafeDemoHandler (parameterised twin): the probe pair is identical, the
      oracle stays SILENT, and the finding is NOT confirmed — even though the LLM
      is stubbed to CONFIRM. The oracle vetoes the LLM; no fired signal, no
      confirmation.

The differential is content-only (status/length/lexical), so both verdicts are
deterministic and independent of machine timing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents import critique_agent as critique_mod
from framework.v2.agents.blackboard import Blackboard, open_blackboard
from framework.v2.agents.critique_agent import CritiqueAgent
from framework.v2.agents.exploit_agent import ExploitAgent
from framework.v2.agents.models import HypothesisPayload
from framework.v2.agents.oracle_probe_executor import OracleProbeExecutor
from framework.v2.kernel.models import CallTrace, CritiqueResult, Objection
from framework.v2.verify.confirmation import (
    DifferentialDemoHandler,
    SafeDemoHandler,
    _local_server,
)

_SLUG = "producer-oracle"
_FINDING_SLUG = "h-001-oracle-probe"  # OracleProbeExecutor._slug("H-001")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _stub_urk(decision: str, *, objections: list[str] | None = None):
    """Drop-in replacement for `critique_agent.urk_critique` with a fixed verdict,
    so the LLM path is fully under test control and no backend is exercised."""

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


def _hypothesis(surface: str) -> HypothesisPayload:
    return HypothesisPayload(
        handle="H-001",
        surface=surface,
        bug_class="boolean_sqli",
        given="the /search endpoint reflects a `q` parameter into a query",
        if_action="send a benign term and a boolean tautology",
        then_observation="the tautology returns markedly more rows than the benign term",
        because_model="`q` is string-built into a SQL WHERE clause",
        refute_on="benign and tautology responses are identical",
        cheap_test="GET /search?q=' OR '1'='1",
    )


def _open_bb(tmp_path: Path) -> Blackboard:
    bb = open_blackboard(db_path=tmp_path / "bb.sqlite")
    bb.engagement_id(_SLUG)
    return bb


def _seed_hypothesis(bb: Blackboard, surface: str) -> None:
    bb.post(
        engagement=_SLUG, kind="hypothesis", agent_name="hyp",
        payload=_hypothesis(surface).model_dump(),
    )


def _live_finding(bb: Blackboard) -> dict:
    rows = bb.read(engagement=_SLUG, kinds=["finding"])
    matches = [r.payload for r in rows if r.payload.get("finding_slug") == _FINDING_SLUG]
    assert matches, f"no live finding row for {_FINDING_SLUG}"
    assert len(matches) == 1, "expected exactly one non-superseded finding row"
    return matches[0]


# ---------------------------------------------------------------------------
# (a) real vulnerable target -> oracle fires -> confirmed (LLM objects, loses)
# ---------------------------------------------------------------------------


def test_real_local_target_drives_oracle_confirmed_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stub the LLM to OBJECT: if the finding is confirmed, it can only be the
    # oracle's doing, not the LLM's.
    monkeypatch.setattr(
        critique_mod, "urk_critique",
        _stub_urk("objections", objections=["the LLM is unconvinced"]),
    )

    with _local_server(DifferentialDemoHandler) as base_url:
        bb = _open_bb(tmp_path)
        try:
            _seed_hypothesis(bb, surface=f"{base_url}/search?q=")

            exploit = ExploitAgent(
                bb, _SLUG, executor=OracleProbeExecutor(base_url=base_url),
            )
            assert exploit.should_run()
            exploit.step()

            # The PRODUCER attached oracle evidence gathered from REAL traffic.
            pending = _live_finding(bb)
            assert pending["critique_status"] == "pending"
            assert pending["oracle_context"] is not None, (
                "producer did not attach oracle_context from the probe"
            )
            assert pending["oracle_context"]["baseline"], "no baseline response captured"
            assert pending["oracle_context"]["mutated"], "no mutated response captured"

            # The oracle adjudicates and CONFIRMS via a fired differential signal.
            CritiqueAgent(bb, _SLUG).step()
            confirmed = _live_finding(bb)
            assert confirmed["critique_status"] == "confirmed", (
                "real differential fired but the finding was not confirmed"
            )
            assert confirmed["verified_by_oracle"] is True

            # And the objecting LLM verdict is preserved as advisory, not lost.
            crits = bb.read(engagement=_SLUG, kinds=["critique"])
            assert crits and crits[-1].payload["decision"] == "objections"
        finally:
            bb.close()


# ---------------------------------------------------------------------------
# (b) safe target -> no differential -> not confirmed (LLM confirms, vetoed)
# ---------------------------------------------------------------------------


def test_safe_local_target_not_confirmed_despite_confirming_llm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stub the LLM to CONFIRM: only a fired oracle may promote the finding, so a
    # silent oracle must keep it unconfirmed regardless of the LLM.
    monkeypatch.setattr(critique_mod, "urk_critique", _stub_urk("confirm"))

    with _local_server(SafeDemoHandler) as base_url:
        bb = _open_bb(tmp_path)
        try:
            _seed_hypothesis(bb, surface=f"{base_url}/search?q=")

            exploit = ExploitAgent(
                bb, _SLUG, executor=OracleProbeExecutor(base_url=base_url),
            )
            exploit.step()

            pending = _live_finding(bb)
            # The producer still attaches evidence — it just does not fire.
            assert pending["oracle_context"] is not None
            assert pending["critique_status"] == "pending"

            CritiqueAgent(bb, _SLUG).step()
            live = _live_finding(bb)
            assert live["critique_status"] == "objections", (
                "no oracle signal fired, so a confirming LLM must NOT promote it"
            )
            assert live["verified_by_oracle"] is False
        finally:
            bb.close()
