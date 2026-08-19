"""W2-2 (#419) — every package carries a ruff + mypy config that reaches its source AND its tests.

Before this slice, ruff ran on `apps/sigil/sigil` ONLY (and skipped its own `tests/`); `engine/crucible`
(~1000 modules), `integration/`, `gateway/` and `packages/core/vigil_core` had NO lint or type config at
all, and the sigil rule set was the narrow `E9,F,B`. This test pins the fix so it cannot silently regress:

  1. `test_every_package_has_ruff_and_mypy_config` — each covered package's pyproject declares a
     `[tool.ruff.lint].select` that is a STRICT superset of `{E9,F,B}` (the rule set is genuinely WIDER)
     and a `[tool.mypy]` table. This runs with no external tool and therefore FAILS on a tree without the
     fix (the four newly-covered packages have neither table; sigil's select is exactly `E9,F,B`).
  2. `test_test_directories_are_linted_not_excluded` — the package's tests live on disk, are NOT named in
     ruff `exclude`, and are reached by a `tests`-matching `per-file-ignores` key (linted-but-loosened, the
     opposite of excluded).
  3. `test_ruff_check_is_clean_on_covered_packages` — `ruff check` (auto-discovering the committed config)
     exits 0 over the package's source + tests. Requires ruff; skipped where it is not installed (e.g. the
     required `integration` CI job, which does not install it — the advisory `lint-config` workflow does).
  4. `test_negative_control_planted_violation_is_caught` — the gate is NOT a no-op: a deliberately bad
     input (a B006 mutable-default-argument, which is OUTSIDE ruff's default `E4,E7,E9,F` select and so
     only fires because THIS config's `B` family is active) is rejected under each package's own config,
     asserted in the same run, then removed. Proves the config actually reaches that tree.

The test is framework-free (pure file reads + a ruff subprocess), so it runs in the sovereign CI leg and
needs no entry on the offense-leg run-list.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# The rule set every covered package must EXCEED. `select` must be a strict superset of this.
_BASELINE = {"E9", "F", "B"}

# Each newly-covered / widened package: the pyproject that carries its [tool.ruff]/[tool.mypy], the source
# dir a planted violation is dropped into, the paths `ruff check` is run over, and the tests dir that must
# be linted (not excluded). `tests_glob` is how tests appear on disk (nested for the framework tree).
_PACKAGES = {
    "vigil_core": {
        "pyproject": "packages/core/vigil_core/pyproject.toml",
        "src": "packages/core/vigil_core/vigil_core",
        "lint": ["packages/core/vigil_core/vigil_core", "packages/core/vigil_core/tests"],
        "tests_glob": "tests",
    },
    "gateway": {
        "pyproject": "gateway/pyproject.toml",
        "src": "gateway/vigil_gateway",
        "lint": ["gateway/vigil_gateway", "gateway/tests", "gateway/conftest.py"],
        "tests_glob": "tests",
    },
    "integration": {
        "pyproject": "integration/pyproject.toml",
        "src": "integration/vigil_integration",
        "lint": ["integration/vigil_integration", "integration/tests", "integration/conftest.py"],
        "tests_glob": "tests",
    },
    "crucible": {
        "pyproject": "engine/crucible/pyproject.toml",
        "src": "engine/crucible/framework",
        "lint": ["engine/crucible/framework"],
        "tests_glob": "framework/v2/common/tests",  # one of ~40 nested tests dirs
    },
    "sigil": {
        "pyproject": "apps/sigil/pyproject.toml",
        "src": "apps/sigil/sigil",
        "lint": ["apps/sigil/sigil", "apps/sigil/tests"],
        "tests_glob": "tests",
    },
}


def _load(pyproject_rel: str) -> dict:
    return tomllib.loads((_REPO / pyproject_rel).read_text(encoding="utf-8"))


@pytest.mark.parametrize("pkg", sorted(_PACKAGES))
def test_every_package_has_ruff_and_mypy_config(pkg: str) -> None:
    """(1) Widened ruff select + a mypy table — fails on a tree without the fix (no external tool needed)."""
    cfg = _load(_PACKAGES[pkg]["pyproject"])
    tool = cfg.get("tool", {})
    select = set(tool.get("ruff", {}).get("lint", {}).get("select", []))
    assert select, f"{pkg}: no [tool.ruff.lint].select"
    assert select >= _BASELINE, f"{pkg}: select must retain the {sorted(_BASELINE)} real-bug baseline, got {sorted(select)}"
    assert select > _BASELINE, (
        f"{pkg}: select must be WIDER than the historical E9,F,B entry gate; got exactly {sorted(select)}"
    )
    assert "mypy" in tool, f"{pkg}: no [tool.mypy] table"


@pytest.mark.parametrize("pkg", sorted(_PACKAGES))
def test_test_directories_are_linted_not_excluded(pkg: str) -> None:
    """(2) The tests tree exists, is not in ruff `exclude`, and is reached by a tests per-file-ignore key."""
    meta = _PACKAGES[pkg]
    cfg = _load(meta["pyproject"])
    ruff = cfg.get("tool", {}).get("ruff", {})
    lint = ruff.get("lint", {})

    tests_path = _REPO / Path(meta["pyproject"]).parent / meta["tests_glob"]
    assert tests_path.is_dir(), f"{pkg}: expected a tests dir at {tests_path}"

    exclude = ruff.get("exclude", [])
    assert not any("test" in str(e).lower() for e in exclude), (
        f"{pkg}: tests must be LINTED, not excluded — ruff exclude={exclude}"
    )

    pfi_keys = list(lint.get("per-file-ignores", {}).keys())
    assert any("tests" in k or "test" in k for k in pfi_keys), (
        f"{pkg}: tests are loosened-not-excluded via a per-file-ignores key; keys={pfi_keys}"
    )


@pytest.mark.parametrize("pkg", sorted(_PACKAGES))
def test_ruff_check_is_clean_on_covered_packages(pkg: str) -> None:
    """(3) `ruff check` (auto-discovering the committed config) is CLEAN over the package source + tests."""
    ruff = shutil.which("ruff")
    if ruff is None:
        pytest.skip("ruff not installed in this job (runs in the advisory `lint-config` workflow)")
    paths = [str(_REPO / p) for p in _PACKAGES[pkg]["lint"]]
    proc = subprocess.run([ruff, "check", "--no-cache", *paths], capture_output=True, text=True)
    assert proc.returncode == 0, (
        f"{pkg}: ruff check is not clean on the current tree:\n{proc.stdout}\n{proc.stderr}"
    )


@pytest.mark.parametrize("pkg", sorted(_PACKAGES))
def test_negative_control_planted_violation_is_caught(pkg: str) -> None:
    """(4) NEGATIVE CONTROL — a planted B006 (outside ruff's default select) is caught under the package's
    OWN config, proving the config reaches the tree and the gate is not a no-op; then it is removed."""
    ruff = shutil.which("ruff")
    if ruff is None:
        pytest.skip("ruff not installed in this job (runs in the advisory `lint-config` workflow)")

    src = _REPO / _PACKAGES[pkg]["src"]
    assert src.is_dir(), f"{pkg}: source dir {src} missing"

    # Sanity: with NO project config (ruff defaults are E4,E7,E9,F), B006 must NOT fire — so a catch below
    # can only come from THIS package's `B` selection, not from a default rule.
    with tempfile.TemporaryDirectory() as td:
        probe = Path(td) / "probe.py"
        probe.write_text("def _f(x=[]):\n    return x\n", encoding="utf-8")
        default_run = subprocess.run(
            [ruff, "check", "--isolated", "--no-cache", str(probe)], capture_output=True, text=True
        )
    assert "B006" not in default_run.stdout, "B006 fired under ruff defaults — negative control is not specific"

    planted = src / "_w22_2_negctl.py"
    planted.write_text("def _w22_2_neg_ctl(x=[]):\n    return x\n", encoding="utf-8")
    try:
        proc = subprocess.run(
            [ruff, "check", "--no-cache", str(planted)], capture_output=True, text=True
        )
        assert proc.returncode != 0, f"{pkg}: planted B006 was NOT rejected — the gate reaches this tree as a no-op"
        assert "B006" in proc.stdout, f"{pkg}: expected B006, got:\n{proc.stdout}\n{proc.stderr}"
    finally:
        planted.unlink(missing_ok=True)

    # And, having removed it, the tree is clean again (the control is fully reverted).
    residual = subprocess.run(
        [ruff, "check", "--no-cache", str(src)], capture_output=True, text=True
    )
    assert residual.returncode == 0, f"{pkg}: source not clean after removing the planted violation:\n{residual.stdout}"


if __name__ == "__main__":  # pragma: no cover - manual runner
    sys.exit(pytest.main([__file__, "-v"]))
