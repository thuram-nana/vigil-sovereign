"""
Anti-hallucination P4 — the reporter RE-EXECUTES each finding's oracle at report time
instead of trusting the stored ``verified_by_oracle`` flag.

A genuinely-confirmed finding whose retained proof still re-fires renders exactly as
before (default-safe). A finding recorded as oracle-confirmed whose proof no longer
reproduces — its evidence altered, or its bug_class relabelled to claim more than the
evidence proves — is DEMOTED in the report to an "unverified at report time" lead, never
asserted as a deterministic-oracle fact. The report can no longer inherit a stale flag.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.blackboard import Blackboard, open_blackboard
from framework.v2.agents.models import FindingPayload
from framework.v2.agents.reporter_agent import ReporterAgent
from framework.v2.verify.adapter import FindingContext

_SLUG = "reporter-gate"
_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200, "body": "id=1 name=alice role=user\nid=2 name=bob role=admin"}


def _ctx(mutated) -> dict:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]}).model_dump(mode="json")


def _confirmed_payload(slug, *, bug_class="boolean_sqli", oracle_context=None) -> dict:
    """A finding recorded (by the scan/critique path) as oracle-confirmed."""
    return FindingPayload(
        finding_slug=slug, title=f"finding {slug}", severity="High",
        bug_class=bug_class, surface="GET /search?q=", summary="s",
        verified_by_oracle=True, oracle_kind="differential_response",
        confidence=0.87, oracle_rationale="differential fired across status+length+lexical",
        critique_status="confirmed", oracle_context=oracle_context,
    ).model_dump()


@pytest.fixture()
def bb(tmp_path: Path) -> Blackboard:
    b = open_blackboard(db_path=tmp_path / "bb.sqlite")
    b.engagement_id(_SLUG)
    yield b
    b.close()


def _rows(bb: Blackboard):
    return [r for r in bb.read(engagement=_SLUG, kinds=["finding"])
            if r.payload.get("critique_status") in ("confirmed", "llm_advisory")]


def _render(bb: Blackboard) -> str:
    return ReporterAgent(bb, _SLUG)._render(_rows(bb))


def test_genuine_confirmed_finding_renders_the_oracle_block(bb: Blackboard) -> None:
    bb.post(engagement=_SLUG, kind="finding", agent_name="exploit",
            payload=_confirmed_payload("001", oracle_context=_ctx(_DIVERGENT)))
    md = _render(bb)
    assert "Verification (deterministic oracle)" in md
    assert "differential_response" in md and "0.870" in md      # unchanged, byte-for-byte
    assert "unverified at report time" not in md


def test_finding_whose_proof_no_longer_refires_is_demoted(bb: Blackboard) -> None:
    # recorded as oracle-confirmed, but the retained evidence is non-divergent → the
    # oracle does NOT re-fire at report time → demoted to a lead, not asserted as fact.
    bb.post(engagement=_SLUG, kind="finding", agent_name="exploit",
            payload=_confirmed_payload("002", oracle_context=_ctx(_BASE)))
    md = _render(bb)
    assert "unverified at report time" in md
    assert "Verification (deterministic oracle)" not in md
    # header counts the LIVE verdict: NOT oracle-confirmed, NOT lumped into LLM-advisory,
    # but its own honest 'demoted' category.
    assert "**0** oracle-confirmed" in md
    assert "demoted (recorded oracle, failed re-verification)" in md
    assert "LLM-advisory (unconfirmed) finding(s)" not in md      # header segment absent (n_advisory==0)


def test_relabelled_bug_class_is_demoted(bb: Blackboard) -> None:
    # the finding claims 'rce' but its oracle_context only proves boolean_sqli — the
    # P3 class binding refuses it, so the report will not assert an RCE fact.
    bb.post(engagement=_SLUG, kind="finding", agent_name="exploit",
            payload=_confirmed_payload("003", bug_class="rce", oracle_context=_ctx(_DIVERGENT)))
    md = _render(bb)
    assert "unverified at report time" in md
    assert "Verification (deterministic oracle)" not in md


def test_missing_oracle_context_is_demoted(bb: Blackboard) -> None:
    # 'verified_by_oracle' with NO retained evidence cannot re-execute → never a fact.
    bb.post(engagement=_SLUG, kind="finding", agent_name="exploit",
            payload=_confirmed_payload("004", oracle_context=None))
    md = _render(bb)
    assert "unverified at report time" in md
    assert "Verification (deterministic oracle)" not in md
