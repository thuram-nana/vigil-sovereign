"""Guard: a test that needs a plane its home CI leg lacks RUNS somewhere — it cannot only ever skip.

WHY THIS EXISTS. Each test tree has a home leg that sees only part of the repository (the two-env
boundary): ``engine/crucible`` runs in "CRUCIBLE core on vigil_core" with no ``vigil_integration`` and
no ``vigil_gateway``; ``docs/tests`` runs with nothing but pytest; ``gateway/tests`` has no engine. A
test there that needs another plane guards itself with ``pytest.importorskip("<plane>…")`` and SKIPS
in its home leg, by design. The one process that has every plane is the offense leg of "integration
two-env boundary (P5)", which runs an EXPLICIT file list — so a cross-plane test that is not on that
list runs in NO leg, while every dashboard stays green.

That is where 21 engine test files were on 2026-11-11, including
``framework/v2/tests/test_engage_pause_halt.py`` and ``test_launch_lease_pause.py`` (the pause / halt
money path), plus ``console/tests/test_chat_inject.py`` (``--ignore``d in its home leg and listed
nowhere), ``docs/tests/test_verifier_provenance.py`` and the whole of ``range/tests`` (run by no job).
The sibling guard ``test_ci_framework_tests_run_in_offense_leg.py`` could not see any of them: it
scans ``integration/tests`` only.

So, from the committed files alone (pure file reads — this guard is framework-free and runs in the
SOVEREIGN leg; keep it out of any ``--ignore``, which the last test enforces):

  1. every test file OUTSIDE ``integration/tests`` that references a first-party plane its home leg
     does not have is on the run-list of a both-planes command (for ``strix``: a command that also has
     ``vendor/strix`` on its path);
  2. every single FILE ``--ignore``d in crucible-core is on such a run-list too;
  3. those commands load ``pytest_require_planes`` with ``VIGIL_REQUIRE_PLANES`` naming every plane on
     their path — the runtime half: in a process that HAS the plane, a skip for it is a failure, so a
     renamed module or a broken import cannot hide behind ``importorskip`` either.

KNOWN RESIDUE, stated rather than hidden. ``strix`` is a plane whose own THIRD-PARTY closure (its
separate lock: openai-agents, docker, pydantic-settings, …) no hash-locked CI environment installs, so:
  * ``strix`` is NOT in ``VIGIL_REQUIRE_PLANES`` — ``console/tests/test_strix_model_sovereignty.py`` has
    one test that importorskips ``strix.config.loader`` (needs ``pydantic_settings``) and still skips;
    every other strix-guarded engine test now runs, with ``vendor/strix`` on the path;
  * ``KNOWN_STRIX_RESIDUE`` below names the files that cannot run at all without that closure. It is
    checked in BOTH directions (an entry must still exist, still reference strix and still be unlisted),
    so it can only shrink deliberately and cannot grow without a reviewer reading a reason.

NEGATIVE CONTROLS. The checkers take their inputs as ARGUMENTS, so the perturbations (a file dropped
from the list, the plugin or the variable removed, a new cross-plane file) are exercised in-process.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_CI = _REPO / ".github" / "workflows" / "ci.yml"
_PLUGIN = _REPO / ".github" / "scripts" / "pytest_require_planes.py"

# The first-party planes, and the path entry that makes each importable.
PLANE_PATHS = {
    "vigil_integration": "integration",
    "framework": "engine/crucible",
    "vigil_gateway": "gateway",
    "strix": "vendor/strix",
    "sigil": "apps/sigil",
    "vigil_core": None,          # pip-installed (editable) in every leg that needs it
}
# The planes the both-planes commands must REQUIRE (see KNOWN RESIDUE for why strix is not one).
REQUIRED_PLANES = frozenset({"vigil_integration", "vigil_gateway", "framework", "vigil_core"})

# Test tree -> the planes its HOME leg can import. A tree that no job runs wholesale has none.
HOME_PLANES: dict[str, frozenset[str]] = {
    "engine/crucible": frozenset({"framework", "vigil_core"}),
    "apps/sigil": frozenset({"sigil", "vigil_integration", "vigil_core"}),
    "packages/core": frozenset({"vigil_core"}),
    # gateway/tests also reaches the engine: vigil_gateway.scope_source resolves engine/crucible from the
    # checkout itself, and test_scope_source.py's charter tests pass in the gateway job on that basis.
    "gateway": frozenset({"vigil_gateway", "vigil_core", "framework"}),
    "vendor/strix": frozenset({"strix"}),
    "vscp": frozenset({"vigil_core"}),
    "tools": frozenset({"framework", "vigil_core"}),
    "docs": frozenset(),
    "range": frozenset(),
    "tests": frozenset(),
}
# file -> why it runs in no leg today (see KNOWN RESIDUE in the module docstring).
KNOWN_STRIX_RESIDUE: dict[str, str] = {
    "gateway/tests/test_docker_caps.py": (
        "imports strix.runtime.docker_client, which needs strix's own runtime closure (openai-agents / "
        "docker); no hash-locked CI env installs it, so 4 of its 5 tests skip in every leg"),
}
_SKIP_DIRS = ("/.venv", "/node_modules/", "/site-packages/", "/corpus/", "/corpus_apps/", "/.git/")

_ALT = "|".join(sorted(PLANE_PATHS))
# An import-shaped reference: importorskip / find_spec / import_module of a plane, or a real import
# statement. A plane that is only NAMED in prose or a string is not a dependency.
_PLANE_REF = re.compile(
    rf"(?:importorskip|find_spec|import_module)\(\s*['\"]({_ALT})\b"
    rf"|^[ \t]*(?:from|import)[ \t]+({_ALT})\b", re.M)
_CRUCIBLE_IGNORE_FILE = re.compile(r"--ignore=(framework/v2/[A-Za-z0-9_./-]+\.py)")
_TOKEN = re.compile(r"(?<![\w./=-])((?:docs|engine|range|gateway|tools|tests|integration|apps|packages|vendor|vscp)"
                    r"/[A-Za-z0-9_./-]+)")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _tree_of(rel: str) -> str:
    parts = rel.split("/")
    two = "/".join(parts[:2])
    return two if two in HOME_PLANES else parts[0]


def cross_plane_files(repo: Path) -> dict[str, set[str]]:
    """repo-relative test file -> the planes it references that its home leg lacks."""
    out: dict[str, set[str]] = {}
    for f in sorted(repo.rglob("test_*.py")):
        rel = f.relative_to(repo).as_posix()
        if rel.startswith("integration/") or any(s in "/" + rel for s in _SKIP_DIRS):
            continue
        tree = _tree_of(rel)
        if tree not in HOME_PLANES:
            continue
        refs = {a or b for a, b in _PLANE_REF.findall(_read(f))}
        missing = refs - HOME_PLANES[tree]
        if missing:
            out[rel] = missing
    return out


def _job_block(ci_text: str, job: str) -> str:
    m = re.search(rf"^  {re.escape(job)}:\s*$", ci_text, re.M)
    if not m:
        return ""
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\s*$", ci_text[m.end():], re.M)
    return ci_text[m.end(): m.end() + nxt.start()] if nxt else ci_text[m.end():]


def pytest_commands(ci_text: str, job: str = "integration") -> list[str]:
    """Every ``python -m pytest`` command of a job as ONE logical line: comment lines dropped, then
    backslash continuations joined (a comment in the middle of a continued command does not end it)."""
    code = [ln for ln in _job_block(ci_text, job).splitlines() if not ln.lstrip().startswith("#")]
    commands, current = [], ""
    for ln in code:
        current += " " + ln.strip().removesuffix("\\").strip()
        if not ln.rstrip().endswith("\\"):
            if "python -m pytest" in current:
                commands.append(current.strip())
            current = ""
    return commands


def _pythonpath(command: str) -> list[str]:
    m = re.search(r"PYTHONPATH=(\S+)", command)
    return m.group(1).split(":") if m else []


def _required(command: str) -> frozenset[str]:
    m = re.search(r"VIGIL_REQUIRE_PLANES=(\S+)", command)
    return frozenset(p for p in (m.group(1).split(",") if m else []) if p)


def _has_planes(command: str, planes) -> bool:
    path = _pythonpath(command)
    return all(PLANE_PATHS[p] is None or PLANE_PATHS[p] in path for p in planes)


def both_planes_commands(ci_text: str) -> list[str]:
    """The P5 commands that can import the integration, engine AND gateway planes at once."""
    return [c for c in pytest_commands(ci_text) if _has_planes(c, REQUIRED_PLANES)]


def _listed(command: str) -> set[str]:
    return {t.rstrip("/") for t in _TOKEN.findall(command.split("python -m pytest", 1)[1])
            if "--ignore" not in t}


def _covers(listed: set[str], rel: str) -> bool:
    return rel in listed or any(rel.startswith(d + "/") for d in listed if not d.endswith(".py"))


def unlisted_cross_plane_files(ci_text: str, cross: dict[str, set[str]]) -> list[str]:
    """The cross-plane files that no command able to import their planes will run."""
    commands = both_planes_commands(ci_text)
    problems = []
    for rel, planes in sorted(cross.items()):
        if rel in KNOWN_STRIX_RESIDUE and planes == {"strix"}:
            continue
        if "sigil" in planes:
            problems.append(f"{rel}: needs `sigil` outside apps/sigil — no leg co-loads it (FATAL-2)")
            continue
        able = [c for c in commands if _has_planes(c, planes)]
        if not any(_covers(_listed(c), rel) for c in able):
            problems.append(f"{rel}: needs {sorted(planes)} which its home leg lacks, and is on no "
                            f"run-list of the P5 offense leg that has them — it SKIPS everywhere")
    return problems


def stale_residue(ci_text: str, cross: dict[str, set[str]]) -> list[str]:
    """KNOWN_STRIX_RESIDUE entries that no longer describe reality."""
    listed = set().union(*(_listed(c) for c in both_planes_commands(ci_text)), set())
    problems = []
    for rel in sorted(KNOWN_STRIX_RESIDUE):
        if cross.get(rel) != {"strix"}:
            problems.append(f"{rel}: is recorded as strix residue but no longer (only) references strix")
        elif _covers(listed, rel):
            problems.append(f"{rel}: is recorded as residue but is now on a run-list — remove the entry")
    return problems


def orphaned_crucible_ignores(ci_text: str) -> list[str]:
    """Single files ``--ignore``d in crucible-core that no both-planes command runs."""
    core = "\n".join(ln for ln in _job_block(ci_text, "crucible-core").splitlines()
                     if not ln.lstrip().startswith("#"))
    listed = set().union(*(_listed(c) for c in both_planes_commands(ci_text)), set())
    return sorted(f"engine/crucible/{rel}" for rel in _CRUCIBLE_IGNORE_FILE.findall(core)
                  if not _covers(listed, f"engine/crucible/{rel}"))


def enforcement_problems(ci_text: str) -> list[str]:
    """Why a both-planes command would let a missing-plane skip through ([] when none would)."""
    # A `--collect-only` command executes nothing, so nothing can skip in it.
    commands = [c for c in both_planes_commands(ci_text) if "--collect-only" not in c]
    if not commands:
        return ["no P5 pytest command has the integration, engine and gateway planes on its path"]
    problems = []
    for c in commands:
        head = c.split("python -m pytest", 1)
        what = f"the command starting `{head[1].split()[0:3]}`"
        if ".github/scripts" not in _pythonpath(c) or "-p pytest_require_planes" not in head[1]:
            problems.append(f"{what} does not load pytest_require_planes")
        missing = REQUIRED_PLANES - _required(c)
        if missing:
            problems.append(f"{what} does not REQUIRE {sorted(missing)} (VIGIL_REQUIRE_PLANES)")
        absent = [p for p in _required(c) if p in PLANE_PATHS and not _has_planes(c, [p])]
        if absent:
            problems.append(f"{what} requires {absent} but does not put it on PYTHONPATH")
    return problems


# ---------------------------------------------------------------------------------------------------
# the committed artifacts hold
# ---------------------------------------------------------------------------------------------------
def test_every_cross_plane_test_outside_integration_is_run_with_its_planes():
    cross = cross_plane_files(_REPO)
    assert cross, "expected to find cross-plane tests outside integration/tests; the detector may be broken"
    assert unlisted_cross_plane_files(_read(_CI), cross) == []
    assert stale_residue(_read(_CI), cross) == []


def test_every_file_ignored_in_crucible_core_runs_with_both_planes():
    assert orphaned_crucible_ignores(_read(_CI)) == []


def test_the_both_planes_commands_fail_on_a_missing_plane_skip():
    assert enforcement_problems(_read(_CI)) == []
    assert _PLUGIN.is_file(), "the pytest_require_planes plugin the commands load is missing"


def test_every_test_tree_has_a_declared_home_leg():
    """A new top-level test tree must be given its home planes here, or its cross-plane tests would be
    invisible to this guard."""
    unknown = set()
    for f in _REPO.rglob("test_*.py"):
        rel = f.relative_to(_REPO).as_posix()
        if rel.startswith("integration/") or any(s in "/" + rel for s in _SKIP_DIRS):
            continue
        if _tree_of(rel) not in HOME_PLANES:
            unknown.add(_tree_of(rel))
    assert sorted(unknown) == []


def test_this_guard_is_not_ignored_in_ci():
    name = Path(__file__).name
    assert [ln.strip() for ln in _read(_CI).splitlines()
            if "--ignore" in ln and name in ln and not ln.lstrip().startswith("#")] == []


# ---------------------------------------------------------------------------------------------------
# negative controls
# ---------------------------------------------------------------------------------------------------
_PAUSE_HALT = "engine/crucible/framework/v2/tests/test_engage_pause_halt.py"
_CHAT_INJECT = "engine/crucible/framework/v2/console/tests/test_chat_inject.py"


def _without(text: str, needle: str) -> str:
    assert needle in text, f"the negative control's anchor is gone from ci.yml: {needle!r}"
    out = "\n".join(ln for ln in text.splitlines() if needle not in ln or "--ignore" in ln)
    assert out != text
    return out


def test_negative_control_a_dropped_file_is_reported():
    ci = _without(_read(_CI), _PAUSE_HALT)
    assert any(_PAUSE_HALT in p for p in unlisted_cross_plane_files(ci, cross_plane_files(_REPO)))


def test_negative_control_a_new_cross_plane_file_is_reported():
    cross = {"engine/crucible/framework/v2/tests/test_brand_new.py": {"vigil_integration"},
             "docs/tests/test_brand_new.py": {"framework"},
             "engine/crucible/framework/v2/console/tests/test_new_strix.py": {"strix"},
             "gateway/tests/test_new_sigil.py": {"sigil"}}
    problems = unlisted_cross_plane_files(_read(_CI), cross)
    assert len(problems) == 4


def test_negative_control_a_strix_test_listed_without_strix_on_the_path_is_reported():
    ci = _read(_CI)
    assert ":vendor/strix:" in ci
    ci2 = ci.replace(":vendor/strix:", ":")
    assert any("test_tool_research.py" in p for p in unlisted_cross_plane_files(ci2, cross_plane_files(_REPO)))


def test_negative_control_residue_cannot_hide_a_file_that_needs_more_than_strix():
    rel = next(iter(KNOWN_STRIX_RESIDUE))
    cross = {rel: {"strix", "vigil_integration"}}
    assert any(rel in p for p in unlisted_cross_plane_files(_read(_CI), cross))
    assert any(rel in p for p in stale_residue(_read(_CI), cross))
    assert any(rel in p for p in stale_residue(_read(_CI), {}))


def test_negative_control_a_file_only_mentioned_in_a_comment_is_not_listed():
    ci = _without(_read(_CI), _PAUSE_HALT) + f"\n            # {_PAUSE_HALT} \\\n"
    assert any(_PAUSE_HALT in p for p in unlisted_cross_plane_files(ci, cross_plane_files(_REPO)))


def test_negative_control_an_orphaned_crucible_ignore_is_reported():
    assert orphaned_crucible_ignores(_without(_read(_CI), _CHAT_INJECT)) == [_CHAT_INJECT]


def test_negative_control_missing_enforcement_is_reported():
    ci = _read(_CI)
    for needle, expected in (("-p pytest_require_planes", "does not load"),
                             ("VIGIL_REQUIRE_PLANES=vigil_integration,vigil_gateway,framework,vigil_core",
                              "does not REQUIRE"),
                             (":.github/scripts", "does not load")):
        assert needle in ci
        perturbed = ci.replace(needle, "")
        assert any(expected in p for p in enforcement_problems(perturbed)), needle
    narrowed = ci.replace("VIGIL_REQUIRE_PLANES=vigil_integration,vigil_gateway,framework,vigil_core",
                          "VIGIL_REQUIRE_PLANES=framework,vigil_core")
    assert any("vigil_integration" in p for p in enforcement_problems(narrowed))


def test_negative_control_prose_that_names_a_plane_is_not_a_dependency():
    assert _PLANE_REF.findall('"""talks about vigil_integration and framework"""\nx = "vigil_gateway"\n') == []
    assert {a or b for a, b in _PLANE_REF.findall(
        "import os\n    from vigil_integration.live import x\npytest.importorskip('strix.config')\n")} == {
            "vigil_integration", "strix"}
