"""
Full v2 integration test: UTI → ACP → MAO → reports → MLS.

The closest thing in this session to "drop a URL, run the framework
end-to-end" without a live target. Replaces the original FORGE
PROTOCOL § 4.9 (intake against three real public targets) with the
operator-revised acceptance: fixture-replay + an optional live test
against any operator-authorised URL (skipped here in the offline default).

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
import os
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


# ===========================================================================
# Live URK pipeline test  —  closes the Session-3 reporter-emission gap
# ===========================================================================
#
# The test above (DryRun + DeterministicExecutor) verifies the wiring of
# UTI -> ACP -> MAO -> reports without needing an LLM.  Under live URK,
# the same wiring did not reach reporter emission in Session 3 because
# the DeterministicExecutor's Result objects had empty body_excerpt and
# one-line notes — the live critique-agent walked the parent_id chain,
# saw thin evidence, and correctly returned `objections`.
#
# This live test uses RealisticExecutor (multi-step reproduction in
# body_excerpt + note, the shape a real engagement records).  Critique
# under live URK confirms the strong-evidence finding, the reporter
# emits technical.md, and MLS records the confirmed finding.
#
# Opt-in only: set CRUCIBLE_LIVE_FULL_PIPELINE=1.  Skipped by default
# because each run costs ~$0.50 of subscription quota and ~5 minutes
# wall-clock.  The skip mark also requires a live LLM backend to be
# selectable (claude-code or anthropic).


@pytest.mark.skipif(
    os.environ.get("CRUCIBLE_LIVE_FULL_PIPELINE") != "1",
    reason="set CRUCIBLE_LIVE_FULL_PIPELINE=1 to run the live full-pipeline test",
)
def test_full_pipeline_url_to_report_live_realistic(
    isolated_paths: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same pipeline as `test_full_pipeline_url_to_report` but with:

      - live URK (caller must set CRUCIBLE_LLM_BACKEND=claude-code or
        leave it unset so anthropic auto-picks; conftest now respects
        the choice),
      - RealisticExecutor with the strong-evidence webhook scenario,
      - budgets sized for live URK latency (~3-min UTI threat-model
        drafter call + ~50s critique-agent call per finding).

    The test exercises the path Session 3 left at "partial".  It
    asserts the reporter actually emits technical.md and MLS records
    a confirmed finding.
    """
    from framework.v2.agents.realistic_executor import (
        BUILT_IN_SCENARIOS, RealisticExecutor,
    )
    from framework.v2.kernel.llm import get_backend, reset_cache

    # Honour the operator's backend choice; refuse to run in dryrun.
    reset_cache()
    backend = get_backend()
    if backend.is_dryrun:
        pytest.skip(
            "live test requires a non-dryrun backend; "
            "set CRUCIBLE_LLM_BACKEND=claude-code (or anthropic) and rerun"
        )

    slug = "live-realistic-pipeline"
    target_url = "https://fix-target.invalid"

    # ---- 1. authorise + UTI fixture corpus (same as the offline test) ----
    led = ethics.authorization_ledger()
    led.parent.mkdir(parents=True, exist_ok=True)
    led.write_text(
        f"{ethics.now_iso()} | testbot | fix-target.invalid\n", encoding="utf-8",
    )

    fixture_dir = isolated_paths / "fixtures"
    _write_fixture_corpus(fixture_dir)
    monkeypatch.setenv("CRUCIBLE_INTAKE_FIXTURE_DIR", str(fixture_dir))

    # ---- 2. UTI runs live (fires URK threat_model_drafter) ----
    out = intake_mod.run(
        target_url, slug=slug,
        operator_name="testbot",
        business_context=(
            "Synthetic SMM-panel-shaped target for live-URK pipeline "
            "verification under the realistic-evidence harness."
        ),
    )
    assert Path(out.threat_model_path).is_file()
    archetype_slug = out.classification.primary.archetype.slug

    # ---- 3. seed the goal tree against surfaces RealisticExecutor knows ----
    realistic = RealisticExecutor()
    surfaces = sorted({surface for _, surface in realistic.keys()})

    with open_store() as store:
        tree = seed_tree(
            archetype_slug=archetype_slug, target_url=target_url,
            surfaces=surfaces, mls_store=store,
        )
    assert tree.stats()["leaves"] >= len(surfaces)

    # ---- 4. MAO + planner ----
    bb = open_blackboard(db_path=isolated_paths / "bb.sqlite")
    bb.engagement_id(slug)

    hyp = HypothesisAgent(bb, slug)
    exp = ExploitAgent(bb, slug, executor=realistic, max_per_step=2)
    crit = CritiqueAgent(bb, slug)
    rpt = ReporterAgent(bb, slug)
    mem = MemoryAgent(bb, slug, archetype=archetype_slug, target_url=target_url)
    coord = Coordinator(
        blackboard=bb, engagement_slug=slug,
        agents=[hyp, exp, crit, rpt, mem],
        max_ticks=400, quiet_ticks=3,
    )

    budget = Budget(
        request_max=2000,
        token_max=400_000.0,
        wall_clock_max_seconds=900.0,
    )
    pruner = Pruner(max_failures_per_node=2)
    watchdog = Watchdog(engagement_slug=slug, tree=tree, budget=budget)
    planner = Planner(
        blackboard=bb, coordinator=coord, engagement_slug=slug,
        tree=tree, budget=budget, pruner=pruner, watchdog=watchdog,
        coordinator_ticks_per_step=6,
        scope_check=False,  # synthetic surfaces
        checkpoint_interval_s=2.0,
    )
    report = planner.run(max_steps=30)

    # ---- 5. reporter must emit technical.md ----
    assert report.steps > 0
    assert report.dispatched > 0
    assert report.succeeded >= 1

    tech_path = paths.target_dir(slug) / "reports" / "technical.md"
    assert tech_path.is_file(), (
        f"reporter did not emit technical.md after {report.steps} steps "
        f"({report.succeeded} successes); halt_reason={report.halt_reason!r}; "
        f"tree_stats={report.final_stats}; "
        f"this is the Session-3 gap — see V2-LIMITATIONS § 0"
    )
    text = tech_path.read_text(encoding="utf-8")
    # Strong-evidence webhook finding should appear; weak-evidence
    # robots.txt finding should NOT (gate still discriminates).
    assert "real-001-webhook-forgery" in text
    assert "real-002-robots-disclosure" not in text, (
        "weak-evidence finding reached the report — the critique gate "
        "is now permissive, which is a regression"
    )

    # ---- 6. MLS recorded the confirmed finding ----
    with open_store() as store:
        rows = store.fetchall(
            "SELECT severity, bug_class, slug FROM findings "
            "WHERE engagement_id IN (SELECT id FROM engagements WHERE slug = ?)",
            (slug,),
        )
    assert any(r["bug_class"] == "webhook-forgery" for r in rows)

    # ---- 7. checkpoint ----
    ckpt = paths.planner_state(slug)
    assert ckpt.is_file()

    # ---- 8. capture as regression fixture ----
    fixture_out = (
        Path("framework/v2/agents/tests/fixtures/live-run/realistic-pipeline")
    )
    fixture_out.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy2(tech_path, fixture_out / "technical.md")
    shutil.copy2(ckpt, fixture_out / "planner-state.json")
    if Path(out.threat_model_path).is_file():
        shutil.copy2(Path(out.threat_model_path), fixture_out / "uti-threat-model.md")
    (fixture_out / "run-summary.json").write_text(json.dumps({
        "backend": backend.name,
        "model": getattr(backend, "model", "?"),
        "intake_archetype": archetype_slug,
        "planner_steps": report.steps,
        "planner_succeeded": report.succeeded,
        "planner_halt_reason": report.halt_reason,
        "tree_stats": report.final_stats,
        "blackboard_event_counts": {
            k: bb.count(engagement=slug, kind=k)
            for k in ("observation", "hypothesis", "plan", "action",
                      "result", "finding", "critique")
        },
    }, indent=2, default=str), encoding="utf-8")

    bb.close()
    mem.close()


# ---------------------------------------------------------------------------
# Live HTTP pipeline test — opt-in only.
# ---------------------------------------------------------------------------
#
# Gated on CRUCIBLE_LIVE_HTTP=<https://your-authorised-target>. Runs the
# full pipeline (UTI -> planner -> MAO -> reports) with HttpExecutor
# pointed at the supplied URL. Skipped by default. The operator runs it
# explicitly when ready.
#
# Requirements before invoking this test:
#   1. Set CRUCIBLE_LIVE_HTTP=<https://your-authorised-target>.
#   2. Append the target host to framework/v2/.intake-authorizations.txt.
#   3. Run UTI to scaffold targets/<slug>/, then sign charter.md.
#   4. Set CRUCIBLE_LLM_BACKEND to a non-dryrun backend (claude-code
#      or anthropic) — UTI's drafters call URK.
#
# Acceptance: pipeline completes, at least one Result event recorded,
# every action passed through the scope gate, no out-of-scope requests
# were made, evidence captured under targets/<slug>/evidence/.


@pytest.mark.skipif(
    not os.environ.get("CRUCIBLE_LIVE_HTTP"),
    reason="set CRUCIBLE_LIVE_HTTP=<https://your-authorised-target> to run the live HTTP pipeline",
)
def test_full_pipeline_url_to_report_live_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full pipeline driven by HttpExecutor against an operator-supplied URL.

    This is the first test that puts real HTTP traffic on the wire.
    Every action passes through scope_gate; out-of-scope traffic is
    impossible by construction. Destructive prompts default-deny.
    """
    from urllib.parse import urlparse
    from framework.v2.agents.http_executor import HttpExecutor
    from framework.v2.kernel.llm import get_backend, reset_cache

    reset_cache()
    backend = get_backend()
    if backend.is_dryrun:
        pytest.skip(
            "live HTTP pipeline test requires a non-dryrun LLM backend; "
            "set CRUCIBLE_LLM_BACKEND=claude-code (or anthropic)"
        )

    target_url = os.environ["CRUCIBLE_LIVE_HTTP"]
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    if not host:
        pytest.skip(f"could not parse host from {target_url!r}")

    # The slug is operator-controlled. Default convention: derive from
    # the host (alpha.example -> alpha-example), but operator can
    # override via CRUCIBLE_LIVE_HTTP_SLUG.
    slug = os.environ.get("CRUCIBLE_LIVE_HTTP_SLUG") or host.replace(".", "-")

    # The operator must have prepared the engagement: signed charter,
    # ledger entry, etc. We do NOT auto-create those — that would
    # defeat the gates we just built.
    cp = paths.charter_path(slug)
    if not cp.is_file():
        pytest.skip(
            f"no charter at {cp}; run UTI on {target_url} and sign the "
            f"charter before exercising HttpExecutor"
        )
    signed, sig_reason = ethics.is_charter_signed(slug)
    if not signed:
        pytest.skip(
            f"charter at {cp} is not signed ({sig_reason}); "
            f"sign before invoking the live HTTP pipeline"
        )
    if not ethics.is_authorized_for_intake(target_url):
        pytest.skip(
            f"host {host} is not in framework/v2/.intake-authorizations.txt; "
            f"add an attestation line and rerun"
        )

    # ---- 1. seed the goal tree from the archetype recorded by UTI ----
    fp_path = paths.fingerprint_path(slug)
    if not fp_path.is_file():
        pytest.skip(
            f"no fingerprint at {fp_path}; run UTI to scaffold the "
            f"engagement before exercising HttpExecutor"
        )
    fp = json.loads(fp_path.read_text(encoding="utf-8"))
    archetype_slug = fp.get("classification", {}).get("archetype_slug", "generic-web")

    # The HttpExecutor only ships GET-by-default request derivation.
    # Pick surfaces the executor can actually exercise without an
    # operator-supplied request library.
    surfaces = ["/", "/robots.txt", "/sitemap.xml"]

    with open_store() as store:
        tree = seed_tree(
            archetype_slug=archetype_slug, target_url=target_url,
            surfaces=surfaces, mls_store=store,
        )

    # ---- 2. wire HttpExecutor and the agent loop ----
    bb = open_blackboard()
    bb.engagement_id(slug)

    http_executor = HttpExecutor(
        engagement_slug=slug,
        base_url=target_url,
        request_budget=20,
        timeout_seconds=15.0,
        # Default-deny destructive prompts in this opt-in test;
        # operator can override by re-running with a custom callback.
        prompt_callback=lambda _q, _t: False,
    )

    hyp = HypothesisAgent(bb, slug)
    exp = ExploitAgent(bb, slug, executor=http_executor, max_per_step=1)
    crit = CritiqueAgent(bb, slug)
    rpt = ReporterAgent(bb, slug)
    mem = MemoryAgent(bb, slug, archetype=archetype_slug, target_url=target_url)
    coord = Coordinator(
        blackboard=bb, engagement_slug=slug,
        agents=[hyp, exp, crit, rpt, mem],
        max_ticks=200, quiet_ticks=3,
    )

    budget = Budget(
        request_max=50,
        token_max=200_000.0,
        wall_clock_max_seconds=600.0,
    )
    pruner = Pruner(max_failures_per_node=2)
    watchdog = Watchdog(engagement_slug=slug, tree=tree, budget=budget)
    planner = Planner(
        blackboard=bb, coordinator=coord, engagement_slug=slug,
        tree=tree, budget=budget, pruner=pruner, watchdog=watchdog,
        coordinator_ticks_per_step=4,
        scope_check=True,  # MUST be True for live HTTP
        checkpoint_interval_s=5.0,
    )
    report = planner.run(max_steps=15)

    # ---- 3. acceptance assertions ----
    assert report.steps > 0
    results = bb.read(engagement=slug, kinds=["result"])
    assert len(results) >= 1, "no Result events posted; pipeline never reached executor"

    stats = http_executor.stats()
    print(f"http_executor stats: {stats}")

    evidence_root = paths.target_dir(slug) / "evidence"
    if evidence_root.is_dir():
        captured = list(evidence_root.iterdir())
        assert captured, "no evidence dirs written"

    http_executor.close()
    bb.close()
    mem.close()
