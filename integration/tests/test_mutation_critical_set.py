"""The mutation/fuzz critical set is a single source of truth, and the configs cannot drift from it
(W11-3, issue #484).

tools/mutation/critical-set.json enumerates the security-critical files subject to mutation testing
(mutmut / cosmic-ray) and coverage-guided fuzzing (cargo-fuzz + atheris). This guard makes that manifest
BINDING rather than advisory:

  * every path the manifest names actually exists (a rename that orphans an entry turns CI red);
  * the mutmut target list (repo-root pyproject.toml ``[tool.mutmut].paths_to_mutate``) and the cosmic-ray
    target list (tools/mutation/cosmic-ray.toml ``[cosmic-ray].module-path``) EQUAL, exactly, the set of
    files the manifest marks ``"mutation": true`` — so a critical file added to the manifest but not wired
    into an engine (or dropped from an engine but left in the manifest) fails the build; and
  * every declared fuzz target resolves to a real harness, a real committed & non-empty seed corpus, and a
    real fast required-job test.

WHY IT MATTERS. The whole value of a mutation programme is that the enumerated set is the set actually
mutated. Without this guard, ``critical-set.json`` could claim ``crypto.py`` is under mutation while the
mutmut config never lists it — a manifest that describes a discipline the build does not run. The negative
controls below prove the equality check has teeth: a config missing a manifest file, and a config naming a
file the manifest does not, are BOTH reported.

THE NAMED-MUTANT CORPUS. A hand-picked subset of the money/gate files mutmut cannot reach (``mutation: false``
— sovereign-leg ``apps/sigil`` files and engine gates; those flagged ``named_mutants: true``) is mutated instead
by ``tools/mutation/named-mutants.json``, run per plane by ``tools/mutation/named_mutants.py`` in the scheduled
workflow; the remaining ``mutation: false`` files are covered by their own suites alone. The guards below bind
that corpus too:
the manifest's ``named_mutants: true`` flags EQUAL the corpus files, every mutant still applies exactly once
and compiles and names a real test in its own plane (so a refactor that orphans a mutant turns the PR red,
not the next weekly run), the sovereign plane's PYTHONPATH never holds the engine, and the runner itself is
proven to tell KILLED (an assertion) from CRASHED (any other exception) from SURVIVED from ERROR (a mutant that
does not import, a collection error), and to restore the source, also after an interrupted run: through the CLI
the restore runs BEFORE the corpus is validated, only from a sidecar that verifies (written atomically, with the
sha256 of the original), and never while another run holds the tree.

STDLIB ONLY (``json`` + ``tomllib``, Python >=3.11) and framework-free, so it runs in the sovereign leg of
the required ``integration two-env boundary (P5)`` job over the whole ``integration/tests`` directory.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_MANIFEST = _REPO / "tools" / "mutation" / "critical-set.json"
_PYPROJECT = _REPO / "pyproject.toml"
_COSMIC = _REPO / "tools" / "mutation" / "cosmic-ray.toml"
_WORKFLOW = _REPO / ".github" / "workflows" / "mutation-fuzz.yml"
_CORPUS = _REPO / "tools" / "mutation" / "named-mutants.json"

sys.path.insert(0, str(_REPO / "tools" / "mutation"))
import named_mutants  # noqa: E402 — path is prepended just above (stdlib-only runner).


def _manifest() -> dict:
    assert _MANIFEST.is_file(), f"critical-set manifest missing: {_MANIFEST}"
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def _mutation_true_paths(man: dict) -> set[str]:
    return {e["path"] for e in man["critical_set"] if e.get("mutation") is True}


def _mutmut_paths() -> set[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return set(data["tool"]["mutmut"]["paths_to_mutate"])


def _cosmic_paths() -> set[str]:
    data = tomllib.loads(_COSMIC.read_text(encoding="utf-8"))
    mp = data["cosmic-ray"]["module-path"]
    return set(mp) if isinstance(mp, list) else {mp}


# --------------------------------------------------------------------------------------------------
# The manifest itself is well-formed and every path is real.
# --------------------------------------------------------------------------------------------------
def test_manifest_parses_and_is_for_this_issue():
    man = _manifest()
    assert man["issue"] == 484 and man["id"] == "W11-3"
    assert man["critical_set"], "the critical set must be non-empty"


def test_every_manifest_path_exists():
    man = _manifest()
    missing = [e["path"] for e in man["critical_set"] if not (_REPO / e["path"]).is_file()]
    assert not missing, f"critical-set entries name files that do not exist: {missing}"


def test_every_critical_entry_is_classified_and_reasoned():
    man = _manifest()
    allowed = {"gate", "oracle", "verifier", "signing", "parser"}
    for e in man["critical_set"]:
        assert e["category"] in allowed, f"{e['path']}: bad category {e['category']!r}"
        assert e.get("reason"), f"{e['path']}: every critical entry must carry a reason"
        assert e["lang"] in {"python", "rust"}
        assert isinstance(e.get("mutation"), bool), f"{e['path']}: mutation must be an explicit bool"
        if "named_mutants" in e:
            assert isinstance(e["named_mutants"], bool), f"{e['path']}: named_mutants must be a bool"


def test_the_security_critical_categories_are_all_represented():
    """The programme names gate/oracle/verifier/signing as the security-critical spine; a manifest that
    silently lost a whole category (e.g. no signing file) would be a coverage hole."""
    cats = {e["category"] for e in _manifest()["critical_set"]}
    for required in ("gate", "oracle", "verifier", "signing"):
        assert required in cats, f"the critical set names no {required!r} file"


# --------------------------------------------------------------------------------------------------
# The engines mutate EXACTLY the manifest's mutation=true set (no drift).
# --------------------------------------------------------------------------------------------------
def test_mutmut_targets_equal_the_manifest_mutation_set():
    want = _mutation_true_paths(_manifest())
    got = _mutmut_paths()
    assert got == want, (
        "pyproject [tool.mutmut].paths_to_mutate has drifted from critical-set.json (mutation=true):\n"
        f"  only in manifest: {sorted(want - got)}\n  only in mutmut:   {sorted(got - want)}"
    )


def test_cosmic_ray_targets_equal_the_manifest_mutation_set():
    want = _mutation_true_paths(_manifest())
    got = _cosmic_paths()
    assert got == want, (
        "tools/mutation/cosmic-ray.toml [cosmic-ray].module-path has drifted from critical-set.json "
        f"(mutation=true):\n  only in manifest: {sorted(want - got)}\n  only in cosmic:   {sorted(got - want)}"
    )


def test_mutation_true_files_are_python_only():
    """mutmut/cosmic-ray mutate Python; a rust file must be mutation=false (covered by cargo test/fuzz)."""
    for e in _manifest()["critical_set"]:
        if e.get("mutation") is True:
            assert e["lang"] == "python", f"{e['path']}: only python files can be mutation=true"


# --------------------------------------------------------------------------------------------------
# Every declared fuzz target is fully wired: harness, committed non-empty corpus, fast required test.
# --------------------------------------------------------------------------------------------------
def test_every_fuzz_target_is_fully_wired():
    man = _manifest()
    targets = man["fuzz_targets"]
    assert targets, "the manifest declares no fuzz targets"
    for name, ft in targets.items():
        assert (_REPO / ft["target"]).is_file(), f"{name}: fuzz target file missing: {ft['target']}"
        assert (_REPO / ft["harness"]).is_file(), f"{name}: fuzz harness missing: {ft['harness']}"
        assert (_REPO / ft["fast_required_test"]).is_file(), \
            f"{name}: fast required test missing: {ft['fast_required_test']}"
        corpus = _REPO / ft["corpus"]
        assert corpus.is_dir(), f"{name}: committed corpus dir missing: {ft['corpus']}"
        seeds = [p for p in corpus.iterdir() if p.is_file()]
        assert seeds, f"{name}: committed corpus {ft['corpus']} is empty"


def test_both_engine_families_are_present():
    engines = {ft["engine"].split()[0] for ft in _manifest()["fuzz_targets"].values()}
    assert "cargo-fuzz" in engines and "atheris" in engines, f"missing a fuzz engine family: {engines}"


# --------------------------------------------------------------------------------------------------
# The heavy runs are wired as a SCHEDULED workflow (honestly labelled), not claimed as a PR check.
# --------------------------------------------------------------------------------------------------
def test_scheduled_mutation_fuzz_workflow_exists_and_names_every_engine():
    assert _WORKFLOW.is_file(), f"scheduled mutation/fuzz workflow missing: {_WORKFLOW}"
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert "schedule:" in text, "the heavy run must be a scheduled workflow, not a required PR check"
    assert "mutmut" in text, "workflow must run mutmut"
    assert ("cargo-fuzz" in text or "cargo fuzz" in text), "workflow must run cargo-fuzz"
    assert "atheris" in text, "workflow must run atheris"


# --------------------------------------------------------------------------------------------------
# Negative controls — the equality check is not a no-op. A drifted config is REJECTED, in the same run.
# --------------------------------------------------------------------------------------------------
def _equal(config_set: set[str], manifest_set: set[str]) -> bool:
    """The exact predicate the two drift tests assert, factored out so the controls exercise it."""
    return config_set == manifest_set


def test_negative_control_a_config_missing_a_manifest_file_is_rejected():
    want = _mutation_true_paths(_manifest())
    assert want, "precondition: the manifest marks at least one file mutation=true"
    drifted = set(want)
    drifted.pop()  # a config that forgot to mutate one critical file
    assert not _equal(drifted, want), "a config missing a manifest file MUST be flagged as drift"


def test_negative_control_a_config_with_an_extra_file_is_rejected():
    want = _mutation_true_paths(_manifest())
    drifted = set(want) | {"packages/core/vigil_core/vigil_core/NOT_CRITICAL.py"}
    assert not _equal(drifted, want), "a config naming a non-manifest file MUST be flagged as drift"


def test_positive_control_the_live_configs_satisfy_the_predicate():
    """The control-for-the-controls: the real, shipped configs DO satisfy the equality the negatives break,
    so a later red from a drift test is caused by real drift, not by a broken predicate."""
    want = _mutation_true_paths(_manifest())
    assert _equal(_mutmut_paths(), want)
    assert _equal(_cosmic_paths(), want)


# --------------------------------------------------------------------------------------------------
# The named-mutant corpus — bound to the manifest, statically valid, plane-separated, and run on schedule.
# --------------------------------------------------------------------------------------------------
def _corpus() -> dict:
    assert _CORPUS.is_file(), f"named-mutant corpus missing: {_CORPUS}"
    return named_mutants.load_corpus(_CORPUS)


def test_named_mutant_corpus_validates():
    """Every mutant still applies EXACTLY once, compiles, states its guard and names a real test in its own
    plane. A refactor that moves a guard's text orphans its mutant here, on the PR, not in a weekly run."""
    problems = named_mutants.validate_corpus(_corpus(), _REPO)
    assert not problems, "named-mutant corpus does not validate:\n  " + "\n  ".join(problems)


def test_named_mutant_flags_equal_the_corpus_files():
    """critical-set.json ``named_mutants: true`` == the corpus file set (both directions), so the manifest can
    neither claim a corpus that does not exist nor leave a corpus file unrecorded."""
    flagged = {e["path"] for e in _manifest()["critical_set"] if e.get("named_mutants") is True}
    files = {f["path"] for f in _corpus()["files"]}
    assert flagged == files, (
        "critical-set.json named_mutants flags drifted from tools/mutation/named-mutants.json:\n"
        f"  flagged only: {sorted(flagged - files)}\n  corpus only:  {sorted(files - flagged)}"
    )


def test_named_mutant_corpus_runs_both_planes_on_the_money_chokepoint():
    by_plane: dict[str, set[str]] = {}
    for f in _corpus()["files"]:
        by_plane.setdefault(f["plane"], set()).add(f["path"])
    assert set(by_plane) == {"sovereign", "offense"}, by_plane
    assert "apps/sigil/sigil/ui/launch_gate.py" in by_plane["sovereign"], "the K4 money chokepoint must be mutated"
    assert all(p.startswith("engine/crucible/") for p in by_plane["offense"])
    assert not any(p.startswith("engine/") for p in by_plane["sovereign"])


def test_named_mutant_plane_paths_never_cross(tmp_path, monkeypatch):
    """FATAL-2: the sovereign children's PYTHONPATH (rebuilt from scratch, absolute) never holds the engine,
    and the offense children's never holds apps/sigil — whatever PYTHONPATH the runner itself inherited (here
    deliberately BOTH planes, so an inherit-and-append runner is caught)."""
    c = _corpus()
    engine, sigil = (_REPO / "engine" / "crucible").resolve(), (_REPO / "apps" / "sigil").resolve()
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(engine), str(sigil)]))
    for plane, forbidden in (("sovereign", engine), ("offense", sigil)):
        entries = named_mutants.plane_env(c, plane, _REPO, tmp_path / plane)["PYTHONPATH"].split(os.pathsep)
        assert entries and all(Path(p).is_absolute() for p in entries), entries
        assert not any(Path(p) == forbidden or forbidden in Path(p).parents for p in entries), (plane, entries)


def test_scheduled_workflow_runs_the_named_corpus_per_plane_and_does_not_swallow_a_survivor():
    text = _WORKFLOW.read_text(encoding="utf-8")
    for plane in named_mutants.PLANES:
        assert f"tools/mutation/named_mutants.py --plane {plane}" in text, f"workflow never runs the {plane} plane"
    job = text.split("  named-mutants:", 1)
    assert len(job) == 2, "the named-mutants job is missing from mutation-fuzz.yml"
    assert "|| true" not in job[1], "the named-mutant job must go red on a survivor, not swallow it"


def _perturbed(mutate) -> list[str]:
    c = copy.deepcopy(_corpus())
    mutate(c)
    return named_mutants.validate_corpus(c, _REPO)


def _first(c: dict, plane: str) -> dict:
    return next(f for f in c["files"] if f["plane"] == plane)


@pytest.mark.parametrize("perturb,expect", [
    (lambda c: _first(c, "sovereign")["mutants"][0].update(old="THIS TEXT IS NOT IN THE FILE"), "exactly once"),
    (lambda c: _first(c, "sovereign")["mutants"][0].update(
        old=_dup_line(_first(c, "sovereign")["path"])), "exactly once"),
    (lambda c: _first(c, "sovereign")["mutants"][0].update(new="def (:"), "does not compile"),
    (lambda c: _first(c, "sovereign")["mutants"][0].update(new=_first(c, "sovereign")["mutants"][0]["old"]),
     "must differ"),
    (lambda c: _first(c, "sovereign")["mutants"][0].update(tests=[]), "names no killing test"),
    (lambda c: _first(c, "sovereign")["mutants"][0].update(guard=""), "must state the guard"),
    (lambda c: _first(c, "sovereign")["mutants"][1].update(id=_first(c, "sovereign")["mutants"][0]["id"]),
     "duplicate mutant id"),
    (lambda c: _first(c, "sovereign")["mutants"][0].update(
        tests=[_first(c, "sovereign")["mutants"][0]["tests"][0].split("::")[0] + "::test_does_not_exist"]),
     "is not defined"),
    (lambda c: _first(c, "sovereign")["mutants"][0].update(tests=_first(c, "offense")["mutants"][0]["tests"]),
     "not under the sovereign plane's test_roots"),
    (lambda c: _first(c, "offense").update(plane="sovereign"), "not under the sovereign plane's source_roots"),
    (lambda c: c["files"].append({"path": "apps/sigil/sigil/obs.py", "plane": "sovereign", "mutants": []}),
     "not a python entry of tools/mutation/critical-set.json"),
    (lambda c: c["planes"]["sovereign"]["pythonpath"].append("engine/crucible"), "leaks a forbidden root"),
    (lambda c: c["planes"]["sovereign"].update(forbidden_pythonpath=[]), "forbidden_pythonpath"),
], ids=["stale-old", "ambiguous-old", "uncompilable", "no-op", "no-test", "no-guard", "dup-id",
        "unknown-test", "cross-plane-test", "cross-plane-file", "not-critical", "engine-on-sovereign-path",
        "no-forbidden-roots"])
def test_negative_control_a_broken_corpus_is_rejected(perturb, expect):
    problems = _perturbed(perturb)
    assert any(expect in p for p in problems), f"expected a {expect!r} problem, got: {problems}"


def _dup_line(rel: str) -> str:
    """A line that occurs MORE than once in ``rel`` — an ambiguous 'old' the validator must refuse."""
    text = (_REPO / rel).read_text(encoding="utf-8")
    return next(ln for ln in text.splitlines() if len(ln.strip()) > 8 and text.count(ln) > 1)


def _synthetic_plane(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "tests").mkdir()
    src = tmp_path / "pkg" / "gate.py"
    src.write_text("def admit(units):\n    return 1 <= units <= 10\n", encoding="utf-8")
    os.utime(src, ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))
    (tmp_path / "tests" / "test_gate.py").write_text(
        "import pytest\n\nfrom gate import admit\n\n\n"
        "def test_floor():\n    assert admit(1) and not admit(0)\n\n\n"
        "def test_floor_by_fail():\n    if admit(0):\n        pytest.fail('a 0-unit admit')\n\n\n"
        "def test_weak():\n    assert admit(5)\n\n\n"
        "@pytest.fixture\ndef floor_checked():\n    assert not admit(0)\n\n\n"
        "def test_floor_in_fixture(floor_checked):\n    pass\n", encoding="utf-8")
    (tmp_path / "tests" / "test_red.py").write_text("def test_red():\n    assert False\n", encoding="utf-8")
    return src, {"planes": {"sovereign": {"cwd": ".", "pythonpath": ["pkg"]}}}


def _mut(mid, tests, old="1 <= units", new="0 <= units"):
    nodes = [t if t.startswith("tests/") else f"tests/test_gate.py::{t}" for t in tests]
    return {"id": mid, "guard": "floor", "old": old, "new": new, "tests": nodes}


def test_named_mutant_runner_kills_only_on_an_assertion_and_restores(tmp_path):
    """The runner has teeth and no false kills, on a synthetic plane: an adequate test KILLS a boundary mutant
    (by assert, and by pytest.fail), a weak test lets the SAME mutant SURVIVE, a mutant that only fails its
    test by a NameError at call time is CRASHED and a fixture that fails in setup is CRASHED (neither is a
    kill), a mutant that breaks the module's import is ERROR before any test runs, one that breaks the test
    file's collection is ERROR, a red baseline scores nothing, and the source is restored byte- and mtime-exact."""
    src, corpus = _synthetic_plane(tmp_path)
    before, mtime = src.read_bytes(), src.stat().st_mtime_ns
    entry = {"path": "pkg/gate.py", "plane": "sovereign", "mutants": [
        _mut("strong", ["test_floor"]),
        _mut("strong-by-fail", ["test_floor_by_fail"]),
        _mut("weak", ["test_weak"]),
        _mut("name-error-at-call", ["test_floor"], old="    return 1 <= units <= 10",
             new="    return undefined_name or 1 <= units <= 10"),
        _mut("setup-error", ["test_floor_in_fixture"]),
        _mut("breaks-import", ["test_floor"], old="def admit(units):", new="raise ImportError('x')\ndef admit(units):"),
        _mut("breaks-import-file", ["tests/test_gate.py"], old="def admit(units):",
             new="raise ImportError('x')\ndef admit(units):"),
        _mut("breaks-test-collection", ["tests/test_gate.py"], old="def admit(units):", new="def admitted(units):"),
    ]}
    run = named_mutants.run_file(entry, corpus, tmp_path, timeout=120)
    assert run.baseline_ok, run.baseline_detail
    verdicts = {r.mutant: r.verdict for r in run.results}
    assert verdicts == {
        "strong": named_mutants.KILLED, "strong-by-fail": named_mutants.KILLED, "weak": named_mutants.SURVIVED,
        "name-error-at-call": named_mutants.CRASHED, "setup-error": named_mutants.CRASHED,
        "breaks-import": named_mutants.ERROR, "breaks-import-file": named_mutants.ERROR,
        "breaks-test-collection": named_mutants.ERROR,
    }, run.results
    detail = {r.mutant: r.detail for r in run.results}
    assert "NameError" in detail["name-error-at-call"] and "setup" in detail["setup-error"], detail
    assert "does not import" in detail["breaks-import"] and "does not import" in detail["breaks-import-file"]
    assert "rc=2" in detail["breaks-test-collection"], detail
    assert src.read_bytes() == before and src.stat().st_mtime_ns == mtime, "the source was not restored exactly"
    assert not named_mutants.sidecar(src).exists(), "the sidecar outlived the run"

    red = {"path": "pkg/gate.py", "plane": "sovereign", "mutants": [_mut("strong", ["test_floor", "tests/test_red.py"])]}
    run = named_mutants.run_file(red, corpus, tmp_path, timeout=120)
    assert not run.baseline_ok and [r.verdict for r in run.results] == [named_mutants.ERROR]
    assert "baseline not green" in run.results[0].detail
    assert src.read_bytes() == before


def test_named_mutant_runner_restores_a_source_an_interrupted_run_left_mutated(tmp_path):
    """A run killed mid-mutant (SIGKILL: no finally runs) leaves the mutant in the source and the original in
    the sidecar; the next run puts the original back before it reads anything, and scores against it."""
    src, corpus = _synthetic_plane(tmp_path)
    before, mtime = _left_by_a_sigkill(src, _mut("strong", ["test_floor"]))
    run = named_mutants.run_file({"path": "pkg/gate.py", "plane": "sovereign", "mutants": [_mut("strong", ["test_floor"])]},
                                 corpus, tmp_path, timeout=120)
    assert src.read_bytes() == before and src.stat().st_mtime_ns == mtime and not named_mutants.sidecar(src).exists()
    assert run.baseline_ok and [r.verdict for r in run.results] == [named_mutants.KILLED], run.results


def _left_by_a_sigkill(src: Path, mutant: dict) -> tuple[bytes, int]:
    """The tree exactly as run_file leaves it when SIGKILLed with a mutant applied (no ``finally`` ran): the
    sidecar written, then the mutant in the source. Returns the original bytes and mtime."""
    original, st = src.read_bytes(), src.stat()
    named_mutants.write_sidecar(src, original, st)
    src.write_bytes(original.decode("utf-8").replace(mutant["old"], mutant["new"], 1).encode("utf-8"))
    assert src.read_bytes() != original
    return original, st.st_mtime_ns


def _synthetic_tree(tmp_path) -> tuple[Path, dict]:
    """A whole synthetic repo the CLI can run on: _synthetic_plane's source and tests, both planes, a critical
    set naming the gate, the corpus, and a byte-for-byte copy of the runner under tools/mutation/ (so the copy's
    REPO is this tree, and it is the shipped runner code that runs)."""
    src, _ = _synthetic_plane(tmp_path)
    (tmp_path / "eng").mkdir()
    corpus = {
        "planes": {
            "sovereign": {"cwd": ".", "pythonpath": ["pkg"], "forbidden_pythonpath": ["eng"],
                          "source_roots": ["pkg/"], "test_roots": ["tests/"]},
            "offense": {"cwd": ".", "pythonpath": ["eng"], "forbidden_pythonpath": ["pkg"],
                        "source_roots": ["eng/"], "test_roots": ["eng/"]},
        },
        "files": [{"path": "pkg/gate.py", "plane": "sovereign", "mutants": [_mut("strong", ["test_floor"])]}],
    }
    tools = tmp_path / "tools" / "mutation"
    tools.mkdir(parents=True)
    (tools / "named-mutants.json").write_text(json.dumps(corpus), encoding="utf-8")
    (tools / "critical-set.json").write_text(json.dumps({"critical_set": [
        {"path": "pkg/gate.py", "lang": "python", "mutation": False, "named_mutants": True}]}), encoding="utf-8")
    shutil.copyfile(named_mutants.__file__, tools / "named_mutants.py")
    assert not named_mutants.validate_corpus(corpus, tmp_path), "precondition: the synthetic corpus validates"
    return src, corpus


def _cli(tree: Path, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTEST_ADDOPTS")}
    return subprocess.run([sys.executable, str(tree / "tools" / "mutation" / "named_mutants.py"), *args],
                          cwd=str(tree), env=env, capture_output=True, text=True, timeout=300)


def _sidecar_files(src: Path) -> list[Path]:
    """The sidecar and any temp file of one, next to ``src``."""
    return sorted(src.parent.glob(src.name + named_mutants.SIDECAR_SUFFIX + "*"))


def test_named_mutant_cli_restores_a_sigkilled_run_before_it_validates(tmp_path):
    """A run SIGKILLed with a mutant applied leaves the mutant in the source and the original in the sidecar. That
    mutant has removed its own 'old' text, so the corpus does not validate as left: the CLI restores every
    corpus file BEFORE it validates — the source byte- and mtime-exact, the sidecar gone — then scores against
    the original (exit 0: the one mutant is KILLED over a green baseline)."""
    src, corpus = _synthetic_tree(tmp_path)
    before, mtime = _left_by_a_sigkill(src, corpus["files"][0]["mutants"][0])
    problems = named_mutants.validate_corpus(corpus, tmp_path)
    assert any("found 0 (stale corpus?)" in p for p in problems), f"precondition: the corpus fails as left: {problems}"
    cp = _cli(tmp_path, "--plane", "sovereign")
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "restored pkg/gate.py from the sidecar an interrupted run left" in cp.stdout, cp.stdout
    assert "1/1 killed" in cp.stdout, cp.stdout
    assert src.read_bytes() == before and src.stat().st_mtime_ns == mtime, "the source was not restored exactly"
    assert not _sidecar_files(src), "the sidecar outlived the restore"


def test_named_mutant_cli_restores_every_corpus_file_whatever_plane_it_runs(tmp_path):
    """The startup restore covers every file the corpus names, not only the selected plane's (validation covers
    them all), and runs for --list too."""
    src, corpus = _synthetic_tree(tmp_path)
    before, mtime = _left_by_a_sigkill(src, corpus["files"][0]["mutants"][0])
    cp = _cli(tmp_path, "--plane", "offense", "--list")
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert src.read_bytes() == before and src.stat().st_mtime_ns == mtime and not _sidecar_files(src)


@pytest.mark.parametrize("damage", [
    lambda b: b[:-7],                              # cut short by a crash mid-write
    lambda b: b[:20],                              # cut short inside the header
    lambda b: b[:-1] + bytes([b[-1] ^ 1]),         # altered, same length
    lambda b: b.partition(b"\n")[2],               # no header: the bare original bytes
    lambda b: b"",                                 # empty
    lambda b: b.replace(named_mutants.SIDECAR_FORMAT.encode(), b"named-mutants-sidecar/0", 1),  # not this format
], ids=["cut-short", "cut-in-header", "altered", "no-header", "empty", "other-format"])
def test_named_mutant_sidecar_that_does_not_verify_is_refused_and_the_source_is_untouched(tmp_path, damage):
    """A sidecar whose bytes do not match the sha256 its header records is never copied over the source: the
    restore refuses loudly (SidecarError; through the CLI exit 3, before anything validates or runs) and the
    healthy source and the sidecar are left exactly as found."""
    src, _corpus = _synthetic_tree(tmp_path)
    side = named_mutants.write_sidecar(src, src.read_bytes(), src.stat())
    side.write_bytes(damage(side.read_bytes()))
    left_src, left_side, mtime = src.read_bytes(), side.read_bytes(), src.stat().st_mtime_ns
    with pytest.raises(named_mutants.SidecarError):
        named_mutants.restore_interrupted(src)
    assert src.read_bytes() == left_src and side.read_bytes() == left_side
    cp = _cli(tmp_path, "--plane", "sovereign")
    assert cp.returncode == 3, cp.stdout + cp.stderr
    assert "does not verify" in cp.stderr and "pkg/gate.py" in cp.stderr, cp.stderr
    assert "1/1 killed" not in cp.stdout, "a run went ahead over a sidecar that does not verify"
    assert src.read_bytes() == left_src and src.stat().st_mtime_ns == mtime and side.read_bytes() == left_side


def test_named_mutant_sidecar_is_written_atomically(tmp_path, monkeypatch):
    """The sidecar is written to a temp file in its own directory, flushed and fsynced there, and only then
    renamed into place, so a crash leaves no sidecar or a whole one, never one cut short. What lands verifies."""
    src, _ = _synthetic_plane(tmp_path)
    before, st = src.read_bytes(), src.stat()
    side = named_mutants.sidecar(src)
    events: list[tuple] = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        fs = os.fstat(fd)
        events.append(("fsync", fs.st_ino, fs.st_size, side.exists()))
        real_fsync(fd)

    def replace(a, b):
        events.append(("replace", Path(a), Path(b), os.stat(a).st_ino))
        real_replace(a, b)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    assert named_mutants.write_sidecar(src, before, st) == side
    renames = [e for e in events if e[0] == "replace"]
    assert len(renames) == 1, events
    _, tmp, dst, ino = renames[0]
    assert dst == side and tmp.parent == side.parent and tmp != side, renames
    synced = events[: events.index(renames[0])]
    assert ("fsync", ino, side.stat().st_size, False) in synced, f"the whole temp was not fsynced before the rename: {events}"
    assert named_mutants.read_sidecar(side) == (before, st.st_atime_ns, st.st_mtime_ns)

    side.unlink()

    def crash(a, b):
        raise KeyboardInterrupt("signal 15")

    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(KeyboardInterrupt):
        named_mutants.write_sidecar(src, before, st)
    assert not _sidecar_files(src), "an interrupted write left a sidecar (or its temp) behind"
    assert src.read_bytes() == before


def test_named_mutant_runner_keeps_the_sidecar_before_the_mutant_touches_the_source(tmp_path, monkeypatch):
    """run_file writes the sidecar while the source still holds the original, so a crash between the two leaves
    a healthy source (and at most a sidecar that restores it to itself), never a mutant with no sidecar."""
    src, corpus = _synthetic_plane(tmp_path)
    before = src.read_bytes()
    seen: list[bytes] = []
    real = named_mutants.write_sidecar

    def write_sidecar(s, original, st):
        seen.append(s.read_bytes())
        return real(s, original, st)

    monkeypatch.setattr(named_mutants, "write_sidecar", write_sidecar)
    run = named_mutants.run_file({"path": "pkg/gate.py", "plane": "sovereign", "mutants": [_mut("strong", ["test_floor"])]},
                                 corpus, tmp_path, timeout=120)
    assert [r.verdict for r in run.results] == [named_mutants.KILLED], run.results
    assert seen == [before], "the sidecar must be written while the source still holds the original"
    assert src.read_bytes() == before and not _sidecar_files(src)


def test_named_mutant_cli_refuses_a_tree_another_run_holds(tmp_path):
    """Two runs in one tree must not overlap: the second's startup restore would put back a mutant the first has
    applied, mid-test. While another run holds the tree the CLI touches nothing (exit 3), not even a sidecar
    that verifies (it may belong to that live run); once the holder is gone the restore goes ahead."""
    src, corpus = _synthetic_tree(tmp_path)
    before, mtime = _left_by_a_sigkill(src, corpus["files"][0]["mutants"][0])    # here: a LIVE run's mutant
    side = named_mutants.sidecar(src)
    left_src, left_side = src.read_bytes(), side.read_bytes()
    with named_mutants._tree_lock(tmp_path) as held:
        assert held
        cp = _cli(tmp_path, "--plane", "sovereign", "--list")
    assert cp.returncode == 3 and "another named-mutants run holds" in cp.stderr, cp.stdout + cp.stderr
    assert src.read_bytes() == left_src and side.read_bytes() == left_side
    cp = _cli(tmp_path, "--plane", "sovereign", "--list")
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert src.read_bytes() == before and src.stat().st_mtime_ns == mtime and not _sidecar_files(src)


@pytest.mark.parametrize("rc,rows,verdict", [
    (None, None, named_mutants.ERROR),
    (0, [], named_mutants.SURVIVED),
    (2, [], named_mutants.ERROR),
    (4, [], named_mutants.ERROR),
    (1, None, named_mutants.ERROR),
    (1, [], named_mutants.ERROR),
    (1, [{"when": "call", "type": "AssertionError", "assertion": True}], named_mutants.KILLED),
    (1, [{"when": "call", "type": "NameError", "assertion": False}], named_mutants.CRASHED),
    (1, [{"when": "setup", "type": "AssertionError", "assertion": True}], named_mutants.CRASHED),
    (1, [{"when": "call", "type": "ValidationError", "assertion": False},
         {"when": "call", "type": "Failed", "assertion": True}], named_mutants.KILLED),
], ids=["timeout", "pass", "rc2", "rc4", "no-probe", "no-rows", "assert", "name-error", "setup-assert",
        "one-assert-of-two"])
def test_named_mutant_classification_counts_only_assertions(rc, rows, verdict):
    assert named_mutants.classify(rc, rows, "tail")[0] == verdict


def test_named_mutant_runner_turns_term_hangup_and_quit_into_a_restoring_interrupt():
    """A CI cancel (SIGTERM), a closed terminal (SIGHUP) and SIGQUIT all become KeyboardInterrupt, so the restore
    in run_file's ``finally`` runs instead of the process dying with a mutant in the source."""
    import signal
    names = ("SIGTERM", "SIGHUP", "SIGQUIT")
    saved = {n: signal.getsignal(getattr(signal, n)) for n in names}
    try:
        named_mutants._install_signal_restore()
        for n in names:
            handler = signal.getsignal(getattr(signal, n))
            assert callable(handler), n
            with pytest.raises(KeyboardInterrupt):
                handler(getattr(signal, n), None)
    finally:
        for n, h in saved.items():
            signal.signal(getattr(signal, n), h)


def test_named_mutant_children_get_their_own_vigil_base_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", "/somewhere/shared")
    env = named_mutants.plane_env(_corpus(), "sovereign", _REPO, tmp_path / "m0")
    assert Path(env["VIGIL_BASE_DIR"]).is_relative_to(tmp_path) and Path(env["VIGIL_BASE_DIR"]).is_dir()


def test_named_mutant_kill_table_states_its_scope_and_skips_unselected_files():
    corpus = _corpus()
    uncovered = named_mutants.uncovered_files(corpus)
    man = _manifest()
    off = {e["path"] for e in man["critical_set"] if e.get("lang") == "python" and e.get("mutation") is False}
    assert set(uncovered) == off - {f["path"] for f in corpus["files"]} and uncovered, uncovered
    ran = named_mutants.FileRun(path="a.py", plane="sovereign", baseline_ok=True, baseline_detail="rc=0",
                                results=[named_mutants.Result("a.py", "m", "g", ["t"], named_mutants.KILLED)])
    idle = named_mutants.FileRun(path="idle.py", plane="sovereign", baseline_ok=True, baseline_detail="")
    table = named_mutants.kill_table([ran, idle], "sovereign", uncovered)
    assert "1/1 killed" in table and "idle.py" not in table
    assert f"{len(uncovered)} of those carry no named mutants" in table and uncovered[0] in table


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
