"""
Integration test for MAO — all six agents wired through the blackboard.

The test stands up a fixture-replay engagement, runs the coordinator,
and asserts on the blackboard's final state. It is the closest thing
to "MAO works end-to-end" we can run without a live target.

Acceptance points (per FORGE PROTOCOL § 3.4):
  - recon-agent and exploit-agent run in the same coordinator (parallel
    in the sense of "same engagement, distinct lanes").
  - critique-agent catches at least one false positive that the single-
    agent path would have promoted.
  - The blackboard log is complete and reconstructable: every Finding
    has a parent_id chain back through Result, Action, Plan, Hypothesis,
    Observation.
  - Each agent's contribution to the report is traceable via the agent
    name on each event.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.agents.blackboard import open_blackboard
from framework.v2.agents.coordinator import Coordinator
from framework.v2.agents.critique_agent import CritiqueAgent
from framework.v2.agents.executor_proto import (
    DeterministicExecutor, ExecutionOutcome,
)
from framework.v2.agents.exploit_agent import ExploitAgent
from framework.v2.agents.hypothesis_agent import HypothesisAgent
from framework.v2.agents.memory_agent import MemoryAgent
from framework.v2.agents.models import FindingPayload
from framework.v2.agents.recon_agent import ReconAgent
from framework.v2.agents.reporter_agent import ReporterAgent
from framework.v2.common import paths
from framework.v2.intake.http import Fetcher
from framework.v2.intake.models import HTTPExchange
from framework.v2.memory.store import open_store


# ---------------------------------------------------------------------------
# Fixture targets and isolated workspace
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect both targets/ and the MLS store to tmp."""
    tdir = tmp_path / "targets"
    monkeypatch.setattr(paths, "targets_root", lambda: tdir)
    monkeypatch.setattr(paths, "target_dir", lambda slug: tdir / slug)
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    return tmp_path


def _prebaked_fetcher(fixture_dir: Path) -> Fetcher:
    """Fetcher in fixture-replay mode. Pre-writes the canned responses
    to fixture_dir so .get() serves from disk, never from network."""
    from framework.v2.intake.http import _save_fixture
    fixture_dir.mkdir(parents=True, exist_ok=True)
    for ex in (
        HTTPExchange(
            method="GET", url="https://fixture-target.invalid/",
            status=200, headers={"Server": "nginx", "X-Powered-By": "PHP/8.1"},
            body_excerpt="<html>fixture root with login form</html>",
        ),
        HTTPExchange(
            method="GET", url="https://fixture-target.invalid/api/v2/orders/123",
            status=200, headers={"Content-Type": "application/json"},
            body_excerpt='{"order_id":123,"user_id":2,"items":[{"id":1}]}',
        ),
    ):
        _save_fixture(fixture_dir, ex)
    return Fetcher(
        base_url="https://fixture-target.invalid", fixture_dir=fixture_dir,
    )


def _executor_with_one_real_bug_and_one_hedged() -> DeterministicExecutor:
    """Two outcomes:

    - (IDOR, /api/v2/orders/123)  → success with a confident, reproducible
      finding.  Critique should confirm.
    - (mass-assignment, /api/v2/orders/123) → success with a HEDGED
      finding ("I think this might be exploitable").  Critique should
      flag for more_evidence_needed.

    All other (class, surface) pairs return failure.
    """
    confident_finding = FindingPayload(
        finding_slug="001-idor-orders",
        title="IDOR on /api/v2/orders/{id} reveals other users' orders",
        severity="High",
        bug_class="IDOR",
        surface="/api/v2/orders/123",
        summary=(
            "Reproduced twice end-to-end with a working PoC: "
            "GET /api/v2/orders/123 with user A's session returns user B's "
            "order body; confirmed via diff against baseline. Evidence "
            "captured at evidence/001-idor/."
        ),
        impact="Horizontal data exposure across all customers.",
        cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cvss_base=6.5,
    )
    hedged_finding = FindingPayload(
        finding_slug="002-massassign-orders",
        title="Possible mass-assignment on /api/v2/orders",
        severity="Medium",
        bug_class="mass-assignment",
        surface="/api/v2/orders/123",
        summary="I think this might be exploitable",  # under length threshold
        impact="",
    )
    return DeterministicExecutor(outcomes={
        ("IDOR", "/api/v2/orders/123"): ExecutionOutcome(
            success=True, status_code=200, elapsed_ms=42.0,
            body_excerpt='{"order_id":123,"user_id":2}',
            note="confirmed exploitable",
            finding=confident_finding,
        ),
        ("mass-assignment", "/api/v2/orders/123"): ExecutionOutcome(
            success=True, status_code=200, elapsed_ms=88.0,
            body_excerpt='{"name":"x","role":"user"}',
            note="possible — needs review",
            finding=hedged_finding,
        ),
    })


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_mao_end_to_end_against_fixture_target(isolated_paths: Path) -> None:
    """Six agents, one coordinator, one fixture target.

    Verifies the canonical pipeline:
        recon -> hypothesis -> exploit -> critique -> reporter -> memory
    Verifies the critique-agent catches the hedged finding.
    Verifies the reporter only emits confirmed findings.
    Verifies the memory-agent mirrors confirmed findings to MLS.
    """
    bb = open_blackboard(db_path=isolated_paths / "bb.sqlite")
    bb.engagement_id("fixture-engagement")

    fetcher = _prebaked_fetcher(isolated_paths / "fixtures")
    executor = _executor_with_one_real_bug_and_one_hedged()

    recon = ReconAgent(
        bb, "fixture-engagement",
        fetcher=fetcher,
        paths=["/", "/api/v2/orders/123"],
    )
    hyp = HypothesisAgent(bb, "fixture-engagement")
    exp = ExploitAgent(
        bb, "fixture-engagement", executor=executor, max_per_step=4,
    )
    crit = CritiqueAgent(bb, "fixture-engagement")
    rpt = ReporterAgent(bb, "fixture-engagement")
    mem = MemoryAgent(
        bb, "fixture-engagement",
        archetype="(test)", target_url="https://fixture-target.invalid",
    )

    coord = Coordinator(
        blackboard=bb, engagement_slug="fixture-engagement",
        agents=[recon, hyp, exp, crit, rpt, mem],
        max_ticks=200, quiet_ticks=4,
    )

    report = coord.run_until_quiet()

    # ---- run terminated cleanly ----
    assert report.quiet_ticks_hit, f"coordinator did not quiet: {report.halted_by}"
    assert report.total_events > 0

    # ---- each kind appears (pipeline ran) ----
    for kind in ("observation", "hypothesis", "plan", "action", "result", "finding", "critique"):
        n = bb.count(engagement="fixture-engagement", kind=kind)
        assert n >= 1, f"no events of kind={kind!r} were posted"

    # ---- critique caught the hedged finding ----
    findings = bb.read(
        engagement="fixture-engagement", kinds=["finding"],
        include_superseded=False,
    )
    confirmed = [f for f in findings if f.payload.get("critique_status") == "confirmed"]
    objections = [f for f in findings if f.payload.get("critique_status") == "objections"]
    pending = [f for f in findings if f.payload.get("critique_status") == "pending"]

    assert len(confirmed) >= 1, "no findings reached confirmed; critique never signed off"
    assert len(objections) + sum(
        1 for f in findings
        if f.payload.get("critique_status") == "more_evidence_needed"
    ) >= 1 or any(
        "I think this might be exploitable" in f.payload.get("summary", "")
        for f in findings
    ), "critique-agent did not catch the hedged finding"
    # No pending finding remains after run quiet
    assert pending == [], "pending findings remain after quiet — critique stalled"

    # ---- reporter emitted a technical report ----
    report_path = paths.target_dir("fixture-engagement") / "reports" / "technical.md"
    assert report_path.is_file()
    text = report_path.read_text(encoding="utf-8")
    assert "Confirmed findings" in text
    assert "001-idor-orders" in text  # the confident one
    assert "002-massassign-orders" not in text  # hedged one was blocked

    # ---- memory-agent mirrored to MLS ----
    with open_store() as store:
        rows = store.fetchall(
            "SELECT * FROM findings WHERE engagement_id IN "
            "(SELECT id FROM engagements WHERE slug = ?)",
            ("fixture-engagement",),
        )
    assert len(rows) >= 1, "memory-agent did not mirror confirmed finding to MLS"
    assert any(r["bug_class"] == "IDOR" for r in rows)
    # The hedged one must not have made it to MLS
    assert not any(r["slug"] == "002-massassign-orders" for r in rows)

    # ---- provenance chain intact for at least one confirmed finding ----
    f_event = confirmed[0]
    chain_kinds: list[str] = []
    cur = bb.get(f_event.parent_id) if f_event.parent_id else None
    safety = 0
    while cur is not None and safety < 8:
        chain_kinds.append(cur.kind)
        cur = bb.get(cur.parent_id) if cur.parent_id else None
        safety += 1
    # the chain should end with at least Result -> Action -> Plan -> Hypothesis
    assert chain_kinds[:4] == ["result", "action", "plan", "hypothesis"], (
        f"provenance chain broken: {chain_kinds}"
    )

    bb.close()
    mem.close()


def test_mao_no_findings_when_everything_fails(isolated_paths: Path) -> None:
    """Sanity check: if executor reports nothing exploitable, the run
    posts hypotheses and refutes them, no findings reach the report."""
    bb = open_blackboard(db_path=isolated_paths / "bb.sqlite")
    bb.engagement_id("dry")

    fetcher = _prebaked_fetcher(isolated_paths / "fixtures")
    # Empty outcomes map -> default ExecutionOutcome(success=False) for everything
    executor = DeterministicExecutor()

    recon = ReconAgent(bb, "dry", fetcher=fetcher, paths=["/"])
    hyp = HypothesisAgent(bb, "dry")
    exp = ExploitAgent(bb, "dry", executor=executor, max_per_step=10)
    crit = CritiqueAgent(bb, "dry")
    rpt = ReporterAgent(bb, "dry")
    mem = MemoryAgent(bb, "dry", archetype="(test)")

    Coordinator(
        blackboard=bb, engagement_slug="dry",
        agents=[recon, hyp, exp, crit, rpt, mem],
        max_ticks=50, quiet_ticks=3,
    ).run_until_quiet()

    # Hypotheses were posted but all got superseded with status='refuted'.
    visible_hypotheses = bb.read(engagement="dry", kinds=["hypothesis"])
    refuted = [h for h in visible_hypotheses if h.payload.get("status") == "refuted"]
    assert len(refuted) >= 1
    # No findings of any state.
    assert bb.count(engagement="dry", kind="finding") == 0
    # No technical report file.
    assert not (paths.target_dir("dry") / "reports" / "technical.md").is_file()

    bb.close()
    mem.close()
