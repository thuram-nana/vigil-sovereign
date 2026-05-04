"""
Full v2 integration test: UTI → ACP → MAO → reports → MLS.

The closest thing in this session to "drop a URL, run the framework
end-to-end" without a live target. Replaces the original FORGE
PROTOCOL § 4.9 (intake against three real public targets) with the
operator-revised acceptance: fixture-replay + the existing in-scope
mrbeanpanel.com (skipped here in the offline default).

Pipeline exercised:
  1. UTI: authorise + scaffold from a fixture corpus
  2. seed_tree from the classified archetype (and MLS priors if any)
  3. ACP: plan, dispatch, prune
  4. MAO: agents run hypotheses through the deterministic executor
  5. reporter writes targets/<slug>/reports/technical.md
  6. memory_agent mirrors confirmed findings into MLS

Asserts at every stage that the artefact exists and is well-formed.
"""

from __future__ import annotations

import json
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
from framework.v2.agents.reporter_agent import ReporterAgent
from framework.v2.common import ethics, paths
from framework.v2.intake import intake as intake_mod
from framework.v2.intake.http import _save_fixture
from framework.v2.intake.models import HTTPExchange
from framework.v2.memory.store import open_store
from framework.v2.planner import (
    Budget, Planner, Pruner, Watchdog, seed_tree,
)


@pytest.fixture()
def isolated_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    tdir = tmp_path / "targets"
    real_template = paths.target_template_dir()
    monkeypatch.setattr(paths, "targets_root", lambda: tdir)
    monkeypatch.setattr(paths, "target_template_dir", lambda: real_template)
    monkeypatch.setattr(paths, "target_dir", lambda slug: tdir / slug)
    monkeypatch.setattr(paths, "charter_path",
                        lambda slug: tdir / slug / "charter.md")
    monkeypatch.setattr(paths, "charter_draft_path",
                        lambda slug: tdir / slug / "charter.draft.md")
    monkeypatch.setattr(paths, "threat_model_path",
                        lambda slug: tdir / slug / "threat-model.md")
    monkeypatch.setattr(paths, "attack_tree_path",
                        lambda slug: tdir / slug / "attack-tree.md")
    monkeypatch.setattr(paths, "endpoints_path",
                        lambda slug: tdir / slug / "notes" / "endpoints.md")
    monkeypatch.setattr(paths, "fingerprint_path",
                        lambda slug: tdir / slug / "recon" / "fingerprint.json")
    monkeypatch.setattr(paths, "memory_db", lambda: tmp_path / "mls.sqlite")
    monkeypatch.setattr(paths, "planner_state",
                        lambda slug: tdir / slug / ".planner-state.json")
    monkeypatch.setattr(paths, "authorization_ledger",
                        lambda: tmp_path / "intake-auth.txt")
    return tmp_path


def _write_fixture_corpus(fixture_dir: Path) -> None:
    """Pre-bake a small SMM-panel-shaped fixture set."""
    fixture_dir.mkdir(parents=True, exist_ok=True)
    for ex in (
        HTTPExchange(
            method="GET", url="https://fix-target.invalid/",
            status=200,
            headers={"Server": "nginx", "X-Powered-By": "PHP/7.4"},
            body_excerpt=(
                "<html>"
                '<script src="https://cdn.glycon.net/panel/main.js"></script>'
                '<a href="https://api.cryptomus.com/v1">Cryptomus</a>'
                "</html>"
            ),
        ),
        HTTPExchange(
            method="GET", url="https://fix-target.invalid/login",
            status=200, headers={"Content-Type": "text/html"},
            body_excerpt='<form action="/login"><input type="password" name="pw"></form>',
        ),
        HTTPExchange(
            method="GET", url="https://fix-target.invalid/api/",
            status=404, headers={"Content-Type": "text/html"},
            body_excerpt="not found",
        ),
    ):
        _save_fixture(fixture_dir, ex)


def test_full_pipeline_url_to_report(
    isolated_paths: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    slug = "fix-target-uti"
    target_url = "https://fix-target.invalid"

    # ---- 1. authorise the host in the test ledger ----
    led = ethics.authorization_ledger()
    led.parent.mkdir(parents=True, exist_ok=True)
    led.write_text(
        f"{ethics.now_iso()} | testbot | fix-target.invalid\n", encoding="utf-8",
    )

    # ---- 2. UTI: scaffold from fixture-replay ----
    fixture_dir = isolated_paths / "fixtures"
    _write_fixture_corpus(fixture_dir)
    monkeypatch.setenv("CRUCIBLE_INTAKE_FIXTURE_DIR", str(fixture_dir))

    out = intake_mod.run(
        target_url, slug=slug,
        operator_name="testbot",
        business_context="Full-pipeline integration test target.",
    )
    assert Path(out.charter_draft_path).is_file()
    assert Path(out.threat_model_path).is_file()
    assert Path(out.attack_tree_path).is_file()
    archetype_slug = out.classification.primary.archetype.slug
    # The fixture corpus advertises Perfect Panel CDN signatures, so
    # the classifier should pick the SMM panel archetype.
    assert archetype_slug == "php-smarty-smm-panel-fork"

    # ---- 3. ACP: seed the goal tree ----
    # Use a small surface set so the tree is bounded; include
    # /api/v2/orders/123 because that's where the deterministic
    # executor's success outcome lives.
    surfaces = ["/", "/api/v2/orders/123"]

    with open_store() as store:
        tree = seed_tree(
            archetype_slug=archetype_slug,
            target_url=target_url,
            surfaces=surfaces,
            mls_store=store,
        )
    assert tree.stats()["leaves"] >= 1

    # ---- 4. MAO: stand up agents + executor ----
    confirming_finding = FindingPayload(
        finding_slug="fix-001-webhook-forgery",
        title="Forged Cryptomus webhook credits balance to attacker user",
        severity="Critical",
        bug_class="webhook-forgery",
        surface="/api/v2/orders/123",
        summary=(
            "Reproduced twice end-to-end with a working PoC: POST to "
            "/payment/cryptomus/callback with arbitrary user_id credits "
            "balance; signature verification absent."
        ),
        impact="Direct unbounded balance creation.",
    )
    outcomes = {
        ("webhook-forgery", "/api/v2/orders/123"): ExecutionOutcome(
            success=True, status_code=200, finding=confirming_finding,
            note="confirmed",
        ),
    }
    bb = open_blackboard(db_path=isolated_paths / "bb.sqlite")
    bb.engagement_id(slug)

    executor = DeterministicExecutor(outcomes=outcomes)
    hyp = HypothesisAgent(bb, slug)
    exp = ExploitAgent(bb, slug, executor=executor, max_per_step=2)
    crit = CritiqueAgent(bb, slug)
    rpt = ReporterAgent(bb, slug)
    mem = MemoryAgent(bb, slug, archetype=archetype_slug, target_url=target_url)
    coord = Coordinator(
        blackboard=bb, engagement_slug=slug,
        agents=[hyp, exp, crit, rpt, mem],
        max_ticks=200, quiet_ticks=2,
    )

    # ---- 5. Planner runs ----
    budget = Budget(
        request_max=2000, token_max=200_000.0,
        wall_clock_max_seconds=30.0,
    )
    pruner = Pruner(max_failures_per_node=2)
    watchdog = Watchdog(engagement_slug=slug, tree=tree, budget=budget)
    planner = Planner(
        blackboard=bb, coordinator=coord, engagement_slug=slug,
        tree=tree, budget=budget, pruner=pruner, watchdog=watchdog,
        coordinator_ticks_per_step=4,
        scope_check=False,  # synthetic surfaces in the fixture
        checkpoint_interval_s=0.5,
    )
    report = planner.run(max_steps=200)

    # ---- 6. Assertions on the run ----
    assert report.steps > 0
    assert report.dispatched > 0
    # at least one webhook-forgery leaf succeeded
    assert report.succeeded >= 1
    # report file emitted by reporter-agent
    tech_path = paths.target_dir(slug) / "reports" / "technical.md"
    assert tech_path.is_file()
    text = tech_path.read_text(encoding="utf-8")
    assert "fix-001-webhook-forgery" in text
    assert "webhook-forgery" in text

    # ---- 7. MLS mirrored the confirmed finding ----
    with open_store() as store:
        rows = store.fetchall(
            "SELECT severity, bug_class, slug FROM findings "
            "WHERE engagement_id IN (SELECT id FROM engagements WHERE slug = ?)",
            (slug,),
        )
    assert any(r["bug_class"] == "webhook-forgery" for r in rows)

    # ---- 8. Checkpoint exists ----
    ckpt = paths.planner_state(slug)
    assert ckpt.is_file()
    payload = json.loads(ckpt.read_text(encoding="utf-8"))
    assert payload["slug"] == slug
    assert "tree" in payload and "budget" in payload

    bb.close()
    mem.close()
