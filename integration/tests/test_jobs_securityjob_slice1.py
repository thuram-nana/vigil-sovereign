"""
SecurityJob spine — Slice 1 (repo-connect + PR-bot wave).

Pins the load-bearing architecture invariants the operator specified:
  * NORMALIZED EVENT + CANONICAL DEDUP — every trigger emits one SecurityJob; the fingerprint is a
    deterministic, order-independent sha256 of the work tuple; the queue dedups by delivery_id (exactly
    once) AND by fingerprint (coalesce identical in-flight work).
  * DURABLE SINGLE-WINNER QUEUE — claim_next hands a job to exactly one worker (reusing the scheduler's
    atomic rename); completion clears the work fingerprint so a later commit re-scans.
  * HARD PRE-EXECUTION GATE, FAIL-CLOSED — a job runs ONLY if the tenant boundary AND the authorization
    gate both allow; a denied/erroring gate, a tenant-boundary failure, or an unverifiable authority all
    REFUSE and the worker is never invoked.
  * ONE EXECUTION PATH — only JobRunner.run_one ever invokes the worker; no trigger/queue method does.
  * FATAL-2 — the offense-side job code imports no sigil.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest

from vigil_integration.jobs.authorize import (
    GateOutcome,
    JobAuthorization,
    authorize_job,
    build_repo_gate,
)
from vigil_integration.jobs.model import (
    SECURITY_JOB_SOURCES,
    ManualTrigger,
    SecurityJob,
    drain,
)
from vigil_integration.jobs.queue import SecurityJobQueue
from vigil_integration.jobs.runner import JobRunner, make_codescan_worker, make_diff_codescan_worker

# The queue/runner/gate drive the offense engine (EngagementScheduler, SlugLease, authority gate) via LAZY
# imports, so this module COLLECTS in the sovereign (framework-free) CI leg but its tests would ERROR there.
# Skip the whole file where `framework` is absent; it runs in the OFFENSE leg (which lists it explicitly) —
# test_ci_framework_tests_run_in_offense_leg.py enforces that listing, so this never silently stops running.
pytest.importorskip("framework.v2.engagement_scheduler",
                    reason="jobs spine drives the offense engine; executes in the offense CI leg")

_ALLOW = lambda job: GateOutcome(True, "test-allow")          # noqa: E731
_DENY = lambda job: GateOutcome(False, "test-deny", "policy")  # noqa: E731


def _job(**kw) -> SecurityJob:
    base = dict(source="manual", repo="github.com/acme/widget", commit="c0ffee", delivery_id="d1")
    base.update(kw)
    return SecurityJob.normalize(**base)


# ============================================================ model: normalize + fingerprint + slug


def test_fingerprint_is_canonical_and_order_independent() -> None:
    a = SecurityJob.normalize(source="webhook", repo="github.com/acme/widget", commit="abc",
                              delivery_id="D1", pr_number=7, profile="diff", policy_version="v2")
    b = SecurityJob.normalize(source="manual", repo="github.com/acme/widget", commit="abc",
                              delivery_id="D2", pr_number=99, profile="diff", policy_version="v2")
    # same WORK tuple (tenant,repo,commit,profile,policy) → same fingerprint, regardless of source/pr/delivery
    assert a.fingerprint == b.fingerprint
    # a different commit is different work
    assert a.fingerprint != SecurityJob.normalize(
        source="webhook", repo="github.com/acme/widget", commit="def", delivery_id="D3",
        profile="diff", policy_version="v2"
    ).fingerprint
    assert len(a.fingerprint) == 64 and all(c in "0123456789abcdef" for c in a.fingerprint)


def test_normalize_validates_source_and_repo() -> None:
    assert SECURITY_JOB_SOURCES == {"webhook", "manual", "api", "scheduled", "ci", "reconciliation"}
    for src in SECURITY_JOB_SOURCES:
        # a delivery_id is supplied so the provider-sourced (webhook/ci) requirement is satisfied here;
        # that requirement has its own dedicated test below
        assert SecurityJob.normalize(source=src, repo="github.com/a/b", delivery_id="d").source == src
    with pytest.raises(ValueError):
        SecurityJob.normalize(source="not-a-source", repo="github.com/a/b")
    with pytest.raises(ValueError):
        SecurityJob.normalize(source="manual", repo="")


def test_slug_is_a_safe_single_component_and_deterministic() -> None:
    j = _job(repo="github.com/acme/Widget")
    assert j.slug == j.slug and j.slug.startswith("repo-")
    assert "/" not in j.slug and "\\" not in j.slug and ".." not in j.slug and len(j.slug) <= 64
    assert j.slug == j.slug.lower()                                  # lowercased, path-safe


def test_to_from_params_roundtrips_and_is_total_on_garbage() -> None:
    j = _job(pr_number=12, extra={"installation_id": 42})
    assert SecurityJob.from_params(j.to_params()) == j
    junk = SecurityJob.from_params({"source": "evil", "pr_number": "NaN", "extra": "not-a-dict"})
    assert junk.source == "manual" and junk.pr_number is None and junk.extra == {}   # defaults, never raises


def test_manual_trigger_emits_then_drains_empty() -> None:
    t = ManualTrigger()
    t.submit(_job())
    assert len(t.poll()) == 1 and t.poll() == []                     # emitted once, then empty
    t.submit(_job(commit="x"))
    t.submit(_job(commit="y"))
    assert len(drain([t, ManualTrigger()])) == 2                     # drain collects across adapters


# ============================================================ queue: durable, idempotent, deduplicated


def test_enqueue_dedups_by_delivery_id(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    assert q.enqueue(_job(delivery_id="dup", commit="c1")).enqueued is True
    # a REDELIVERY (same delivery_id) is dropped even though the work differs — exactly-once idempotency
    r = q.enqueue(_job(delivery_id="dup", commit="c2"))
    assert r.enqueued is False and r.reason == "duplicate_delivery"
    assert q.pending_count() == 1


def test_enqueue_dedups_by_fingerprint(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    assert q.enqueue(_job(delivery_id="a", commit="c1")).enqueued is True
    # same WORK, different delivery → coalesced by fingerprint (don't scan the same commit twice)
    r = q.enqueue(_job(delivery_id="b", commit="c1"))
    assert r.enqueued is False and r.reason == "duplicate_fingerprint"
    assert q.pending_count() == 1
    # genuinely different work (new commit) IS enqueued
    assert q.enqueue(_job(delivery_id="c", commit="c2")).enqueued is True
    assert q.pending_count() == 2


def test_claim_next_is_a_single_winner(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    q.enqueue(_job(commit="only"))
    first = q.claim_next()
    second = q.claim_next()
    assert first is not None and first.job.commit == "only"
    assert second is None                                            # the one job is claimed exactly once


def test_complete_clears_fingerprint_so_a_later_scan_requeues(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    q.enqueue(_job(delivery_id="d1", commit="c1"))
    claimed = q.claim_next()
    q.complete(claimed)
    # the SAME work can be scanned again after completion (fingerprint marker cleared); new delivery id
    assert q.enqueue(_job(delivery_id="d2", commit="c1")).enqueued is True
    assert q.pending_count() == 1


def test_requeue_stale_is_delegated_and_safe_on_empty(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    assert q.requeue_stale() == 0                                    # nothing stale → 0, never raises


# ============================================================ authorize: fail-closed composition


def test_authorize_allows_only_when_tenant_and_gate_both_pass() -> None:
    ok = authorize_job(_job(), gate=_ALLOW, assert_tenant=lambda: None)
    assert ok.allowed and ok.state == "allowed"


def test_authorize_refuses_when_gate_denies() -> None:
    r = authorize_job(_job(), gate=_DENY, assert_tenant=lambda: None)
    assert r.refused and r.denial_code == "policy" and "test-deny" in r.reason


def test_authorize_is_fail_closed_on_a_gate_error() -> None:
    def _boom(job):
        raise RuntimeError("gate blew up")
    r = authorize_job(_job(), gate=_boom, assert_tenant=lambda: None)
    assert r.refused and r.denial_code == "gate_error"               # an erroring gate NEVER passes


def test_authorize_is_fail_closed_on_tenant_boundary_and_skips_the_gate() -> None:
    calls = {"gate": 0}

    def _spy_gate(job):
        calls["gate"] += 1
        return GateOutcome(True)

    def _bad_tenant():
        raise RuntimeError("worker not isolated")

    r = authorize_job(_job(), gate=_spy_gate, assert_tenant=_bad_tenant)
    assert r.refused and r.denial_code == "tenant_isolation"
    assert calls["gate"] == 0                                        # tenant boundary fails BEFORE the gate


def test_build_repo_gate_refuses_without_a_trust_root(monkeypatch) -> None:
    from framework.v2.authority import store as authz_store
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: None)
    out = build_repo_gate()(_job())
    assert out.allowed is False and out.denial_code == "no_trust_root"


def test_build_repo_gate_refuses_an_unverifiable_authority(monkeypatch) -> None:
    from framework.v2.authority import store as authz_store

    def _raise(slug, root, path=None):
        raise ValueError("signature does not verify against the pinned trust root")
    monkeypatch.setattr(authz_store, "load_verified_authority", _raise)
    out = build_repo_gate(trust_root=object())(_job())
    assert out.allowed is False and out.denial_code == "unverified_authority"


def _authority(slug: str, scope: list[str]):
    """A minimal valid EngagementAuthority (constructed directly; the gate's verify step is monkeypatched
    to RETURN it, so we exercise the REAL authorize_action scope conjunct over it)."""
    from framework.v2.authority.models import EngagementAuthority
    now = _dt.datetime.now(_dt.timezone.utc)
    return EngagementAuthority(
        engagement_slug=slug, environment="twin", scope=scope,
        not_before=now - _dt.timedelta(hours=1), not_after=now + _dt.timedelta(hours=1))


def test_build_repo_gate_allows_in_scope_and_refuses_out_of_scope(monkeypatch) -> None:
    from framework.v2.authority import store as authz_store

    in_scope = _job(repo="github.com/acme/widget")
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _authority(slug, ["github.com"]))
    allowed = build_repo_gate(trust_root=object())(in_scope)
    assert allowed.allowed is True                                   # github.com host matches scope

    # the SAME verified authority (scope github.com) must REFUSE a repo on another host
    off = _job(repo="evil.example/acme/widget")
    refused = build_repo_gate(trust_root=object())(off)
    assert refused.allowed is False                                  # out of the signed scope


# ============================================================ runner: the ONLY execution path


def _authorized_runner(q: SecurityJobQueue, worker):
    return JobRunner(queue=q, gate=_ALLOW, worker=worker, assert_tenant=lambda: None)


def test_runner_runs_an_authorized_job_exactly_once(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    q.enqueue(_job(commit="c1"))
    seen: list[SecurityJob] = []
    out = _authorized_runner(q, lambda job: seen.append(job) or {"ok": True}).run_one()
    assert out.state == "done" and out.result == {"ok": True}
    assert len(seen) == 1 and seen[0].commit == "c1"
    assert q.claim_next() is None                                    # drained


def test_runner_refuses_and_NEVER_invokes_the_worker(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    q.enqueue(_job(commit="c1"))
    calls = {"n": 0}
    runner = JobRunner(queue=q, gate=_DENY,
                       worker=lambda job: calls.__setitem__("n", calls["n"] + 1),
                       assert_tenant=lambda: None)
    out = runner.run_one()
    assert out.state == "refused" and out.denial_code == "policy"
    assert calls["n"] == 0                                           # the worker was NEVER called
    assert q.claim_next() is None                                    # refused job is completed, not left pending


def test_runner_worker_error_is_an_outcome_not_a_crash(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    q.enqueue(_job(commit="c1"))

    def _boom(job):
        raise RuntimeError("scanner exploded")
    out = _authorized_runner(q, _boom).run_one()
    assert out.state == "failed" and "scanner exploded" in out.reason
    assert q.claim_next() is None                                    # still completed (no auto-retry loop)


def test_failed_scan_releases_delivery_so_it_is_readmittable(tmp_path: Path) -> None:
    # repo-connect Slice 3a (red-pen M2): a FAILED scan must not be permanently suppressed by its delivery
    # marker — releasing it lets a re-delivery / the reconciliation safety-net re-drive the same work.
    q = SecurityJobQueue(tmp_path)
    q.enqueue(_job(delivery_id="D-fail", commit="c1"))

    def _boom(job):
        raise RuntimeError("scanner exploded")
    assert _authorized_runner(q, _boom).run_one().state == "failed"
    # the same delivery can be re-enqueued (the marker was released) — a DONE scan would NOT re-admit
    assert q.enqueue(_job(delivery_id="D-fail", commit="c1")).enqueued is True


def test_diff_worker_fails_closed_on_empty_or_nonset_scope(tmp_path: Path) -> None:
    # make_diff_codescan_worker must refuse a silent clean when the changed-files scope is empty or not a set
    import pytest as _pytest
    job = _job(commit="c1")
    empty = make_diff_codescan_worker(base_dir=str(tmp_path), checkout=lambda j: str(tmp_path),
                                      changed_files=lambda j: set())
    with _pytest.raises(ValueError):
        empty(job)
    nonset = make_diff_codescan_worker(base_dir=str(tmp_path), checkout=lambda j: str(tmp_path),
                                       changed_files=lambda j: ["a.py"])   # a list, not a set
    with _pytest.raises(TypeError):
        nonset(job)


def test_runner_empty_queue_is_empty(tmp_path: Path) -> None:
    assert _authorized_runner(SecurityJobQueue(tmp_path), lambda j: None).run_one().state == "empty"


def test_drain_processes_every_queued_job(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    for c in ("c1", "c2", "c3"):
        q.enqueue(_job(delivery_id=c, commit=c))
    ran: list[str] = []
    outs = _authorized_runner(q, lambda job: ran.append(job.commit)).drain()
    assert len(outs) == 3 and all(o.state == "done" for o in outs)
    assert sorted(ran) == ["c1", "c2", "c3"] and q.pending_count() == 0


def test_no_queue_method_runs_the_worker_only_the_runner_does(tmp_path: Path) -> None:
    # Structural proof of the architecture rule: driving the queue directly (claim/complete) NEVER invokes
    # a worker — execution happens solely through JobRunner.run_one (which gates first).
    q = SecurityJobQueue(tmp_path)
    q.enqueue(_job(commit="c1"))
    calls = {"n": 0}
    worker = make_codescan_worker(base_dir=str(tmp_path), checkout=lambda j: calls.__setitem__("n", 1))
    claimed = q.claim_next()          # claim WITHOUT a runner
    q.complete(claimed)               # complete WITHOUT a runner
    assert calls["n"] == 0            # the worker/checkout was never touched — queue methods don't execute
    assert worker is not None         # the worker exists but is only ever called inside run_one


# ============================================================ FATAL-2: no sigil import in the job code


def test_jobs_modules_do_not_import_sigil() -> None:
    import vigil_integration.jobs as jobs_pkg
    pkg_dir = Path(jobs_pkg.__file__).parent
    for src in pkg_dir.glob("*.py"):
        text = src.read_text(encoding="utf-8")
        assert "import sigil" not in text and "from sigil" not in text, f"{src.name} imports sigil (FATAL-2)"


def test_jobs_modules_import_framework_lazily_not_at_module_scope() -> None:
    # Two-env doctrine (mirrors the offense-side codescan.py pattern): importing the jobs package must NOT
    # eagerly pull the offense engine, so the modules stay sovereign-importable. Checked in a FRESH
    # interpreter (sys.modules in-process would be polluted by earlier tests).
    import os
    import subprocess
    import sys
    probe = (
        "import sys;"
        "import vigil_integration.jobs.model, vigil_integration.jobs.queue,"
        " vigil_integration.jobs.authorize, vigil_integration.jobs.runner;"
        "assert 'framework' not in sys.modules and 'framework.v2.engagement_scheduler' not in sys.modules,"
        " 'jobs imports framework at module scope (must be lazy)';"
        "print('ok')"
    )
    proc = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                          env={**os.environ}, timeout=60)
    assert proc.returncode == 0, f"lazy-import probe failed:\n{proc.stderr}"


# ============================================================ red-pen hardening (Slice-1 fixes)


def test_slug_is_injective_and_never_path_traversing() -> None:
    # Distinct repos / hosts → distinct slugs: two repos (or two tenants' repos) must NEVER share a slug,
    # or they would share a verified authority and a per-slug run-lease (the original collision bug).
    a = _job(repo="github.com/acme/widget")
    b = _job(repo="github.com/acme/gadget")
    c = _job(repo="gitlab.com/acme/widget")
    assert len({a.slug, b.slug, c.slug}) == 3
    # a trailing slash / casing / surrounding space is the SAME repo → the SAME slug (canonicalized)
    assert _job(repo="github.com/acme/widget/").slug == a.slug
    assert _job(repo="  GitHub.com/ACME/Widget  ").slug == a.slug
    # even a hostile repo string collapses to ONE safe path component — no separators, parent-refs, or nulls
    evil = _job(repo="../../etc/passwd\x00/..%2f/.git").slug
    assert "/" not in evil and "\\" not in evil and ".." not in evil and "\x00" not in evil
    assert evil == evil.lower() and len(evil) <= 64 and evil.startswith("repo-")


def test_normalize_requires_delivery_id_for_provider_sourced_triggers() -> None:
    # webhook + ci carry a provider delivery id → it is REQUIRED (the exactly-once idempotency key); without
    # it, replay-protection silently degrades to at-least-once.
    for src in ("webhook", "ci"):
        with pytest.raises(ValueError):
            SecurityJob.normalize(source=src, repo="github.com/a/b")
        assert SecurityJob.normalize(source=src, repo="github.com/a/b", delivery_id="D1").delivery_id == "D1"
    # operator/CLI/api/reconciliation triggers have no provider id → no requirement
    for src in ("manual", "api", "scheduled", "reconciliation"):
        assert SecurityJob.normalize(source=src, repo="github.com/a/b").source == src


def test_from_params_bounds_oversized_and_control_char_fields() -> None:
    # An on-disk queue row is untrusted-at-rest: from_params must be TOTAL and bounded (never raise), even
    # on hostile field sizes / control chars — it degrades to safe, clipped values.
    hostile = {
        "tenant_id": "t" * 10_000, "source": "webhook", "delivery_id": "d\x00\n\r" + "x" * 10_000,
        "repo": "r" * 10_000, "commit": "c" * 10_000, "pr_number": "99", "profile": "p" * 10_000,
        "policy_version": "v" * 10_000, "extra": {"k": "v"},
    }
    j = SecurityJob.from_params(hostile)
    assert len(j.tenant_id) <= 64 and len(j.delivery_id) <= 512 and len(j.repo) <= 512
    assert len(j.commit) <= 128 and len(j.profile) <= 64 and len(j.policy_version) <= 64
    assert "\x00" not in j.delivery_id and "\n" not in j.delivery_id and "\r" not in j.delivery_id
    assert j.pr_number == 99 and j.source == "webhook" and j.extra == {"k": "v"}
    assert j.slug.startswith("repo-") and "/" not in j.slug and len(j.slug) <= 64   # still a safe component


def test_delivery_idempotency_is_permanent_across_completion(tmp_path: Path) -> None:
    q = SecurityJobQueue(tmp_path)
    assert q.enqueue(_job(delivery_id="D1", commit="c1")).enqueued is True
    q.complete(q.claim_next())               # fingerprint cleared on complete — but the delivery marker is PERMANENT
    r = q.enqueue(_job(delivery_id="D1", commit="c1"))
    assert r.enqueued is False and r.reason == "duplicate_delivery"   # a replay AFTER completion is still dropped
    assert q.pending_count() == 0


def test_enqueue_rolls_back_markers_when_the_durable_insert_fails(tmp_path: Path) -> None:
    # Atomicity: if the scheduler insert raises, BOTH markers this call created must be rolled back, so a
    # transient failure neither permanently burns the delivery id nor wedges the fingerprint.
    q = SecurityJobQueue(tmp_path)
    real_enqueue = q._sched.enqueue
    state = {"fail": True}

    def _flaky(slug, *a, **k):
        if state["fail"]:
            raise OSError("disk full")
        return real_enqueue(slug, *a, **k)

    q._sched.enqueue = _flaky  # type: ignore[assignment]
    with pytest.raises(OSError):
        q.enqueue(_job(delivery_id="D1", commit="c1"))
    assert q.pending_count() == 0                       # nothing queued
    # a retry (now succeeding) enqueues cleanly — proving neither marker survived the failed insert
    state["fail"] = False
    r = q.enqueue(_job(delivery_id="D1", commit="c1"))
    assert r.enqueued is True and q.pending_count() == 1


def test_prune_delivery_removes_only_markers_older_than_the_window(tmp_path: Path) -> None:
    import os
    import time

    from vigil_integration.jobs.queue import _safe_key
    q = SecurityJobQueue(tmp_path)
    q.enqueue(_job(delivery_id="old", commit="c1"))
    q.enqueue(_job(delivery_id="new", commit="c2"))
    old = tmp_path / "delivery" / _safe_key("old")
    past = time.time() - 10_000
    os.utime(old, (past, past))                         # age the "old" marker past the window
    assert q.prune_delivery(older_than_seconds=3600) == 1
    assert not old.exists() and (tmp_path / "delivery" / _safe_key("new")).exists()
    # retention is not a leak: a pruned delivery id is acceptable again
    assert q.enqueue(_job(delivery_id="old", commit="c3")).enqueued is True


def test_claim_next_single_winner_under_threaded_race(tmp_path: Path) -> None:
    # The atomic O_EXCL/rename claim must hold under REAL thread contention: every job claimed exactly once,
    # none claimed twice, none lost (a lost race transparently advances to the next entry).
    import threading
    q = SecurityJobQueue(tmp_path)
    n = 60
    for i in range(n):
        q.enqueue(_job(delivery_id=f"d{i}", commit=f"c{i}"))
    claimed: list[str] = []
    lock = threading.Lock()
    start = threading.Barrier(8)

    def _hammer() -> None:
        start.wait()
        while True:
            c = q.claim_next()
            if c is None:
                return
            with lock:
                claimed.append(c.job.commit)

    threads = [threading.Thread(target=_hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(claimed) == n == len(set(claimed))        # exactly once each, no duplicates, no losses
    assert sorted(claimed) == sorted(f"c{i}" for i in range(n))


def test_runner_reports_busy_and_requeues_when_the_slug_is_leased(tmp_path: Path) -> None:
    # Two same-repo jobs must NOT run the slug's spine concurrently. While the per-slug lease is held (a live
    # run), the runner returns 'busy' and RE-QUEUES the job (never runs the worker, never completes it); once
    # the lease frees, the same job runs.
    q = SecurityJobQueue(tmp_path)
    q.enqueue(_job(commit="c1"))
    held = _job(commit="c1")
    token = q.try_lease(held.slug, run_id="live-holder")
    assert token is not None
    calls = {"n": 0}
    out = _authorized_runner(q, lambda j: calls.__setitem__("n", calls["n"] + 1)).run_one()
    assert out.state == "busy" and calls["n"] == 0        # worker NEVER ran while the slug was busy
    assert q.pending_count() == 1                          # requeued, not completed
    q.release_lease(held.slug, token)
    out2 = _authorized_runner(q, lambda j: calls.__setitem__("n", calls["n"] + 1)).run_one()
    assert out2.state == "done" and calls["n"] == 1 and q.pending_count() == 0


def test_only_run_one_invokes_the_worker_ast_guard() -> None:
    # Structural (AST) proof of the sole-executor rule: across the whole jobs package, the ONLY site that
    # calls a ``.worker(...)`` attribute is JobRunner.run_one. A gate-bypass (e.g. the queue gaining a method
    # that runs the worker) or a second runner call site would fail this.
    import ast
    import vigil_integration.jobs as jobs_pkg
    pkg_dir = Path(jobs_pkg.__file__).parent
    sites: list[str] = []
    for src in sorted(pkg_dir.glob("*.py")):
        tree = ast.parse(src.read_text(encoding="utf-8"), filename=src.name)
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child._parent = parent  # type: ignore[attr-defined]
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "worker":
                fn: object = node
                while fn is not None and not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn = getattr(fn, "_parent", None)
                sites.append(f"{src.name}:{getattr(fn, 'name', '<module>')}")
    assert sites == ["runner.py:run_one"], f"worker must be invoked ONLY by JobRunner.run_one; found: {sites}"


def test_build_repo_gate_defaults_the_killswitch_and_a_tripped_one_halts(monkeypatch, tmp_path: Path) -> None:
    # The kill-switch defaults to the per-slug one: authorize_action SKIPS the halt check when killswitch is
    # None, so without this default a tripped switch would NOT stop a repo job (fail-open). Here the switch
    # path is redirected into tmp so the test is hermetic.
    from framework.v2.authority import killswitch as ks_mod
    from framework.v2.authority import store as authz_store

    monkeypatch.setattr(ks_mod.paths, "killswitch_path", lambda slug: tmp_path / f"ks-{slug}.json")
    monkeypatch.setattr(authz_store, "load_verified_authority",
                        lambda slug, root, path=None: _authority(slug, ["github.com"]))
    job = _job(repo="github.com/acme/widget")
    # untripped → the in-scope job is allowed (default kill-switch exists but is not tripped)
    assert build_repo_gate(trust_root=object())(job).allowed is True
    # trip the PER-SLUG switch at its default path; the gate (killswitch=None → defaulted) must now HALT
    ks_mod.KillSwitch(job.slug).trip("owner halted repo scans")
    out = build_repo_gate(trust_root=object())(job)
    assert out.allowed is False and out.denial_code == "halted"
