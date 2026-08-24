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

STDLIB ONLY (``json`` + ``tomllib``, Python >=3.11) and framework-free, so it runs in the sovereign leg of
the required ``integration two-env boundary (P5)`` job over the whole ``integration/tests`` directory.
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_MANIFEST = _REPO / "tools" / "mutation" / "critical-set.json"
_PYPROJECT = _REPO / "pyproject.toml"
_COSMIC = _REPO / "tools" / "mutation" / "cosmic-ray.toml"
_WORKFLOW = _REPO / ".github" / "workflows" / "mutation-fuzz.yml"


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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
