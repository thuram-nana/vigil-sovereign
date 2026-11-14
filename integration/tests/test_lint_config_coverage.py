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
     exits 0 over the package's source + tests. It runs the ruff pinned in
     `infra/supply-chain/ci-tooling.lock.txt`, which both CI jobs that run this file install (the required
     `integration` job and the `lint-config` workflow): the interpreter's own ruff is preferred, then PATH,
     and a candidate is used only at the locked version — a different ruff applies a different rule set,
     so its verdict says nothing about the committed tree. No locked ruff: skipped locally (the reason names
     the versions found), FAILED in CI (`GITHUB_ACTIONS=true`).
  4. `test_negative_control_planted_violation_is_caught` — the gate is NOT a no-op: a deliberately bad
     input is rejected under each package's own config, asserted in the same run, then removed. The planted
     rule is the first candidate (B006 mutable-default-argument first) that the package SELECTS and that
     verifiably does NOT fire under ruff's built-in defaults (`--isolated`), so a catch can only come from
     THIS config. Ruff's defaults have widened across releases; if no candidate qualifies the control fails
     loudly instead of passing. Proves the config actually reaches that tree.

The test is framework-free (pure file reads + a ruff subprocess), so it runs in the sovereign CI leg and
needs no entry on the offense-leg run-list.
"""
from __future__ import annotations

import functools
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Callable, Optional

import pytest

_REPO = Path(__file__).resolve().parents[2]
_CI_TOOLING_LOCK = _REPO / "infra" / "supply-chain" / "ci-tooling.lock.txt"

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


# ---------------------------------------------------------------------------------------------------
# which ruff — the one the CI toolchain lock pins, never "whatever is first on PATH"
# ---------------------------------------------------------------------------------------------------


def _locked_ruff_version() -> str:
    m = re.search(r"^ruff==([^\s\\;]+)", _CI_TOOLING_LOCK.read_text(encoding="utf-8"), re.M)
    assert m, f"no `ruff==` pin in {_CI_TOOLING_LOCK}"
    return m.group(1)


def _ruff_version(cmd: list[str]) -> Optional[str]:
    try:
        proc = subprocess.run([*cmd, "--version"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    parts = proc.stdout.split()
    if proc.returncode != 0 or len(parts) < 2 or parts[0] != "ruff":
        return None
    return parts[1]


def _resolve_ruff(
    *, locked: str, has_module: bool, path_ruff: Optional[str],
    version_of: Callable[[list[str]], Optional[str]],
) -> tuple[Optional[list[str]], str]:
    """The first ruff AT THE LOCKED VERSION — the running interpreter's own package first (that is what the
    CI install of the ci-tooling lock provides), then PATH. Returns ``(argv_prefix, "")`` or ``(None, why)``,
    where ``why`` names every candidate and its version."""
    candidates: list[list[str]] = []
    if has_module:
        candidates.append([sys.executable, "-m", "ruff"])
    if path_ruff:
        candidates.append([path_ruff])
    if not candidates:
        return None, f"ruff is not installed (infra/supply-chain/ci-tooling.lock.txt pins ruff=={locked})"
    seen = []
    for cmd in candidates:
        version = version_of(cmd)
        if version == locked:
            return cmd, ""
        seen.append(f"`{' '.join(cmd)}` is {version or 'an unreadable version'}")
    return None, f"no ruff at the locked version {locked}: " + "; ".join(seen)


@functools.lru_cache(maxsize=1)
def _resolved_ruff() -> tuple[Optional[tuple[str, ...]], str]:
    cmd, why = _resolve_ruff(
        locked=_locked_ruff_version(),
        has_module=importlib.util.find_spec("ruff") is not None,
        path_ruff=shutil.which("ruff"),
        version_of=_ruff_version,
    )
    return (tuple(cmd) if cmd else None), why


def _ruff() -> list[str]:
    """The locked ruff's argv prefix. Without one: skip locally, FAIL in CI (which installs the lock)."""
    cmd, why = _resolved_ruff()
    if cmd is None:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            pytest.fail(f"{why} — CI installs infra/supply-chain/ci-tooling.lock.txt, so this check must run")
        pytest.skip(why)
    return list(cmd)


# Candidate planted violations, in preference order (B006 first, the historical control). Each must be
# SELECTED by the package's config and must NOT fire under ruff's built-in defaults, so that a catch can
# only come from the package's own selection. Ruff's default select has widened across releases (0.16
# added B006/B008/B015/PIE794 among others), hence a list rather than one fixed rule.
_PLANT_CANDIDATES: tuple[tuple[str, str], ...] = (
    ("B006", "def _w22_2_neg_ctl(x=[]):\n    return x\n"),
    ("B015", "def _w22_2_neg_ctl(x):\n    x == 1\n    return x\n"),
    ("PIE794", "class _W222NegCtl:\n    a = 1\n    a = 2\n"),
    ("C400", "def _w22_2_neg_ctl(y):\n    return list(v for v in y)\n"),
    ("T100", "def _w22_2_neg_ctl():\n    breakpoint()\n"),
    ("SLOT000", "class _W222NegCtl(str):\n    pass\n"),
    ("ISC001", '_W22_2_NEG_CTL = "a" "b"\n'),
)


def _selected(rule: str, lint_cfg: dict) -> bool:
    """Whether ``rule`` is active under a ``[tool.ruff.lint]`` table (prefix semantics, ``ALL`` honoured)."""
    def _hit(patterns: list) -> bool:
        return any(p == "ALL" or rule.startswith(p) for p in patterns)
    select = list(lint_cfg.get("select", [])) + list(lint_cfg.get("extend-select", []))
    ignore = list(lint_cfg.get("ignore", [])) + list(lint_cfg.get("extend-ignore", []))
    return _hit(select) and not _hit(ignore)


def _fires(ruff: list[str], rule: str, source: str, *extra: str) -> bool:
    with tempfile.TemporaryDirectory() as td:
        probe = Path(td) / "probe.py"
        probe.write_text(source, encoding="utf-8")
        run = subprocess.run(
            [*ruff, "check", "--isolated", "--no-cache", "--output-format", "concise", *extra, str(probe)],
            capture_output=True, text=True,
        )
    return re.search(rf"\b{re.escape(rule)}\b", run.stdout) is not None


def _pick_planted_rule(
    ruff: list[str], lint_cfg: dict, candidates: tuple[tuple[str, str], ...] = _PLANT_CANDIDATES,
) -> tuple[str, str]:
    """The first candidate the config selects, whose probe fires when that rule alone is selected, and which
    does NOT fire under ruff's defaults. None qualifies -> FAIL (a control that cannot be specific must not
    pass)."""
    for rule, source in candidates:
        if not _selected(rule, lint_cfg):
            continue
        if not _fires(ruff, rule, source, "--select", rule):
            continue  # the probe does not trigger its own rule under this ruff
        if _fires(ruff, rule, source):
            continue  # part of ruff's defaults -> a catch would not prove THIS config reaches the tree
        return rule, source
    pytest.fail(
        "no negative-control candidate is selected by this config AND outside ruff's default rules — "
        "extend _PLANT_CANDIDATES with a rule this config selects that the locked ruff does not enable by default"
    )


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
    ruff = _ruff()
    paths = [str(_REPO / p) for p in _PACKAGES[pkg]["lint"]]
    proc = subprocess.run([*ruff, "check", "--no-cache", *paths], capture_output=True, text=True)
    assert proc.returncode == 0, (
        f"{pkg}: ruff check is not clean on the current tree:\n{proc.stdout}\n{proc.stderr}"
    )


@pytest.mark.parametrize("pkg", sorted(_PACKAGES))
def test_negative_control_planted_violation_is_caught(pkg: str) -> None:
    """(4) NEGATIVE CONTROL — a planted violation (outside ruff's default select) is caught under the
    package's OWN config, proving the config reaches the tree and the gate is not a no-op; then removed."""
    ruff = _ruff()

    src = _REPO / _PACKAGES[pkg]["src"]
    assert src.is_dir(), f"{pkg}: source dir {src} missing"

    lint_cfg = _load(_PACKAGES[pkg]["pyproject"]).get("tool", {}).get("ruff", {}).get("lint", {})
    # Chosen so that, with NO project config, the rule does NOT fire — a catch below can only come from THIS
    # package's selection, not from a default rule.
    rule, source = _pick_planted_rule(ruff, lint_cfg)

    planted = src / "_w22_2_negctl.py"
    planted.write_text(source, encoding="utf-8")
    try:
        proc = subprocess.run(
            [*ruff, "check", "--no-cache", "--output-format", "concise", str(planted)],
            capture_output=True, text=True,
        )
        assert proc.returncode != 0, f"{pkg}: planted {rule} was NOT rejected — the gate reaches this tree as a no-op"
        assert rule in proc.stdout, f"{pkg}: expected {rule}, got:\n{proc.stdout}\n{proc.stderr}"
    finally:
        planted.unlink(missing_ok=True)

    # And, having removed it, the tree is clean again (the control is fully reverted).
    residual = subprocess.run(
        [*ruff, "check", "--no-cache", str(src)], capture_output=True, text=True
    )
    assert residual.returncode == 0, f"{pkg}: source not clean after removing the planted violation:\n{residual.stdout}"


# ---------------------------------------------------------------------------------------------------
# the resolution + candidate logic itself (pure, or a probe-only ruff run)
# ---------------------------------------------------------------------------------------------------


def _fake_versions(table: dict[str, Optional[str]]) -> Callable[[list[str]], Optional[str]]:
    return lambda cmd: table[cmd[-1]]


def _outcome(fn: Callable[[], object]) -> str:
    """'skip' / 'fail' / 'ran' — caught here, so a wrong outcome is an assertion failure in THIS test rather
    than an escaping Skipped that would turn the test itself into a skip."""
    try:
        fn()
    except pytest.skip.Exception:
        return "skip"
    except pytest.fail.Exception:
        return "fail"
    return "ran"


def test_the_locked_ruff_wins_over_a_newer_one_first_on_path() -> None:
    # module (interpreter) at the lock, PATH at a newer release -> the interpreter's ruff
    cmd, why = _resolve_ruff(locked="0.15.12", has_module=True, path_ruff="/home/u/.local/bin/ruff",
                             version_of=_fake_versions({"ruff": "0.15.12", "/home/u/.local/bin/ruff": "0.16.9"}))
    assert cmd == [sys.executable, "-m", "ruff"] and why == ""
    # interpreter at a different release, PATH at the lock -> PATH (the lock decides, not the order)
    cmd, _ = _resolve_ruff(locked="0.15.12", has_module=True, path_ruff="/usr/bin/ruff",
                           version_of=_fake_versions({"ruff": "0.16.9", "/usr/bin/ruff": "0.15.12"}))
    assert cmd == ["/usr/bin/ruff"]


def test_only_a_mismatched_ruff_skips_locally_and_fails_in_ci(monkeypatch) -> None:
    cmd, why = _resolve_ruff(locked="0.15.12", has_module=False, path_ruff="/home/u/.local/bin/ruff",
                             version_of=_fake_versions({"/home/u/.local/bin/ruff": "0.16.9"}))
    assert cmd is None and "0.15.12" in why and "0.16.9" in why   # the reason names both versions
    cmd, why = _resolve_ruff(locked="0.15.12", has_module=False, path_ruff=None, version_of=_fake_versions({}))
    assert cmd is None and "not installed" in why

    monkeypatch.setattr(sys.modules[__name__], "_resolved_ruff", lambda: (None, "no ruff at the locked version"))
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert _outcome(_ruff) == "skip"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert _outcome(_ruff) == "fail"


def test_the_lock_pins_a_ruff_version() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", _locked_ruff_version())


def test_rule_selection_honours_prefixes_and_ignores() -> None:
    cfg = {"select": ["E9", "F", "B", "PIE"], "ignore": ["B008", "B011"]}
    assert _selected("B006", cfg) and _selected("PIE794", cfg)
    assert not _selected("B008", cfg) and not _selected("C400", cfg)
    assert _selected("C400", {"select": ["ALL"]})


def test_a_control_that_cannot_be_specific_fails_loudly() -> None:
    ruff = _ruff()
    # every candidate fires under ruff's defaults (F401 is a default rule) -> FAIL, never a silent pass
    assert _outcome(lambda: _pick_planted_rule(ruff, {"select": ["F"]}, candidates=(("F401", "import os\n"),))) == "fail"
    # the only candidate is not selected by the config -> FAIL
    assert _outcome(lambda: _pick_planted_rule(
        ruff, {"select": ["B"], "ignore": ["B006"]}, candidates=_PLANT_CANDIDATES[:1])) == "fail"
    # and a qualifying candidate is chosen and verifiably outside the defaults
    rule, source = _pick_planted_rule(ruff, {"select": ["E9", "F", "B"]})
    assert rule.startswith("B") and not _fires(ruff, rule, source)


if __name__ == "__main__":  # pragma: no cover - manual runner
    sys.exit(pytest.main([__file__, "-v"]))
