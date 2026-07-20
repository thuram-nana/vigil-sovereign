"""
Dockerized-corpus lifecycle (A2) — tested WITHOUT Docker.

The Docker calls sit behind a Launcher seam, so the orchestration — descriptor
loading, ground-truth resolution, the tuned CRUCIBLE adapter, health polling, and
the measured scoreboard — is exercised end-to-end against the real in-process
benchmark app via a fake launcher. A separate slow test that needs a real daemon
lives behind a docker_available() skip.
"""

from __future__ import annotations

import pytest

from framework.v2.eval.benchmark_app import benchmark_corpus, serve
from framework.v2.eval.corpus_run import (
    Container,
    CorpusApp,
    CorpusRunError,
    GroundTruth,
    ScanTuning,
    class_key_for,
    load_corpus_apps,
    resolve_ground_truth,
    run_corpus_app,
    wait_healthy,
)
from framework.v2.eval.models import _normalize_class
from framework.v2.eval.owasp_benchmark import owasp_class_key


class _FakeLauncher:
    """Returns a Container pointing at an already-running base_url; no Docker."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url
        self.stopped = False

    def up(self, app: CorpusApp) -> Container:
        return Container(
            container_id="fake",
            base_url=self._base_url,
            stopper=lambda: setattr(self, "stopped", True),
        )


def _curated_app(expected) -> CorpusApp:
    return CorpusApp(
        name="bench",
        role="vulnerable",
        image="unused/in-fake",
        container_port=8080,
        ground_truth=GroundTruth(kind="curated", expected=expected),
        scan=ScanTuning(max_pages=25, max_depth=4, use_library=True),
    )


def test_run_corpus_app_scores_crucible_against_curated_truth() -> None:
    # Stand up the real labelled benchmark app; feed its manifest as curated truth;
    # drive the whole corpus lifecycle through the fake launcher.
    with serve() as base_url:
        expected = benchmark_corpus(base_url).expected
        app = _curated_app(expected)
        launcher = _FakeLauncher(base_url)
        boards = run_corpus_app(app, launcher=launcher)

    assert len(boards) == 1
    board = boards[0].scoreboard
    assert board.tool == "crucible"
    assert board.false_positives == 0
    assert board.precision == 1.0
    assert board.true_positives >= 5
    # the measured side is populated: CRUCIBLE reports its exact request budget
    assert boards[0].metrics.requests_sent is not None
    assert boards[0].metrics.elapsed_s >= 0.0
    # teardown ran
    assert launcher.stopped is True


def test_heavy_app_refuses_autolaunch() -> None:
    app = _curated_app([])
    app.heavy = True
    with pytest.raises(CorpusRunError, match="heavy"):
        run_corpus_app(app)  # no launcher -> must refuse, never auto-pull


def test_resolve_ground_truth_kinds(tmp_path) -> None:
    none_app = _curated_app([])
    none_app.ground_truth = GroundTruth(kind="none")
    assert resolve_ground_truth(none_app) == []

    owasp_app = _curated_app([])
    owasp_app.ground_truth = GroundTruth(kind="owasp", owasp_csv="er.csv")
    (tmp_path / "er.csv").write_text(
        "# test name, category, real vulnerability, cwe\nBenchmarkTest01,sqli,true,89\n",
        encoding="utf-8",
    )
    got = resolve_ground_truth(owasp_app, base_dir=tmp_path)
    assert len(got) == 1 and got[0].bug_class == "sqli"


def test_class_key_selection() -> None:
    # owasp AND curated score with the family key (a subclass detection matches a
    # coarse family label); only a manifest-less 'none' target uses the plain key.
    curated = _curated_app([])
    assert class_key_for(curated) is owasp_class_key
    owasp = _curated_app([])
    owasp.ground_truth = GroundTruth(kind="owasp", owasp_csv="x.csv")
    assert class_key_for(owasp) is owasp_class_key
    none_app = _curated_app([])
    none_app.ground_truth = GroundTruth(kind="none")
    assert class_key_for(none_app) is _normalize_class


def test_wait_healthy_polls_until_accepted_status() -> None:
    # a fake clock + a status sequence: down, down, then 200
    seq = iter([None, 503, 200])
    import framework.v2.eval.corpus_run as cr

    orig = cr._http_status
    cr._http_status = lambda url, timeout=5.0: next(seq)
    try:
        ticks = iter([0.0, 1.0, 2.0, 3.0, 4.0, 5.0])
        wait_healthy("http://127.0.0.1:1", "/health", [200], 10,
                     sleep=lambda s: None, now=lambda: next(ticks))
    finally:
        cr._http_status = orig


def test_wait_healthy_times_out() -> None:
    import framework.v2.eval.corpus_run as cr

    orig = cr._http_status
    cr._http_status = lambda url, timeout=5.0: None  # never healthy
    try:
        ticks = iter([0.0, 1.0, 2.0, 3.0])
        with pytest.raises(CorpusRunError, match="never became healthy"):
            wait_healthy("http://127.0.0.1:1", "/", [200], 2,
                         sleep=lambda s: None, now=lambda: next(ticks))
    finally:
        cr._http_status = orig


def test_run_corpus_aggregates_and_filters(tmp_path) -> None:
    # A whole-corpus run over a temp descriptor dir, docker-free via the fake
    # launcher: results are aggregated per app and the names filter is honoured.
    import json

    from framework.v2.eval.corpus_run import run_corpus

    with serve() as base_url:
        expected = [e.model_dump() for e in benchmark_corpus(base_url).expected]
        for nm in ("app-a", "app-b"):
            (tmp_path / f"{nm}.json").write_text(json.dumps({
                "name": nm, "role": "vulnerable", "image": "unused",
                "container_port": 8080, "health_path": "/", "seed_path": "/",
                "ground_truth": {"kind": "curated", "expected": expected},
                "scan": {"max_pages": 25, "use_library": True},
                "heavy": False, "notes": "test",
            }), encoding="utf-8")

        launcher = _FakeLauncher(base_url)
        # names filter: only app-a runs
        out = run_corpus(names=["app-a"], apps_dir=tmp_path, launcher=launcher)
        assert set(out.results) == {"app-a"}
        assert not out.skipped
        assert out.results["app-a"][0].scoreboard.precision == 1.0

        # no filter: both run (a launcher is provided, so 'heavy' gating is moot here)
        out2 = run_corpus(apps_dir=tmp_path, launcher=launcher)
        assert set(out2.results) == {"app-a", "app-b"}


def test_run_corpus_skips_heavy_without_launcher_or_docker(tmp_path, monkeypatch) -> None:
    import json

    import framework.v2.eval.corpus_run as cr
    from framework.v2.eval.corpus_run import run_corpus

    (tmp_path / "big.json").write_text(json.dumps({
        "name": "big", "role": "real-enterprise", "image": "x", "container_port": 80,
        "health_path": "/", "seed_path": "/", "ground_truth": {"kind": "none"},
        "scan": {}, "heavy": True, "notes": "heavy",
    }), encoding="utf-8")
    # docker present but the app is heavy and no launcher -> skipped with a reason
    monkeypatch.setattr(cr, "docker_available", lambda *a, **k: True)
    out = run_corpus(apps_dir=tmp_path)
    assert "big" in out.skipped and "heavy" in out.skipped["big"]
    assert not out.results


def _image_present(tag: str) -> bool:
    import subprocess

    try:
        return subprocess.run(["docker", "image", "inspect", tag],
                              capture_output=True, timeout=20).returncode == 0
    except Exception:
        return False


def test_real_cve_st_is_detected_when_built() -> None:
    # A REAL, documented npm CVE end-to-end: st@0.2.4 path traversal (CVE-2014-3744).
    # Skips unless the operator has built the image (eval/corpus_apps/_cve/build.sh) —
    # so CI without Docker/npm/network is unaffected, but where it IS built this proves
    # CRUCIBLE confirms a real historical vulnerability with zero false positives.
    from pathlib import Path

    from framework.v2.eval.corpus_run import (
        CorpusApp,
        DockerLauncher,
        docker_available,
        run_corpus_app,
    )

    tag = "crucible-cve-st-2014-3744:local"
    if not docker_available():
        pytest.skip("docker not available")
    if not _image_present(tag):
        pytest.skip(f"{tag} not built (run eval/corpus_apps/_cve/build.sh)")

    desc = Path(__file__).resolve().parents[1] / "corpus_apps" / "cve-st-2014-3744.json"
    boards = run_corpus_app(CorpusApp.from_json(desc), launcher=DockerLauncher())
    assert len(boards) == 1
    board = boards[0].scoreboard
    assert board.tool == "crucible"
    assert board.true_positives == 1  # the real CVE traversal
    assert board.false_positives == 0  # zero-FP on a real package
    assert board.precision == 1.0


def test_load_corpus_apps_reads_shipped_descriptors() -> None:
    # the shipped descriptor directory must load and validate as CorpusApps.
    from pathlib import Path

    d = Path(__file__).resolve().parents[1] / "corpus_apps"
    if not d.is_dir():
        pytest.skip("no corpus_apps descriptors shipped yet")
    apps = load_corpus_apps(d)
    assert apps, "expected at least one shipped descriptor"
    assert all(a.container_port > 0 for a in apps)
