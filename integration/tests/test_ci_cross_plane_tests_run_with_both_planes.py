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

import ast
import re
import shlex
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

# Test tree -> the planes its HOME leg can import, read off how .github/workflows/ci.yml runs that tree
# (what is on PYTHONPATH and what is pip-installed). A tree that no job runs has none.
HOME_PLANES: dict[str, frozenset[str]] = {
    "engine/crucible": frozenset({"framework", "vigil_core"}),      # crucible-core: cwd engine/crucible
    "apps/sigil": frozenset({"sigil", "vigil_integration", "vigil_core"}),
    "packages/core": frozenset({"vigil_core"}),
    "gateway": frozenset({"vigil_gateway", "vigil_core"}),           # PYTHONPATH=gateway only
    "vendor/strix": frozenset({"strix"}),
    "vscp": frozenset({"vigil_core"}),
    "tools": frozenset({"vigil_core"}),                               # no PYTHONPATH; vigil_core installed
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

_IMPORT_CALLS = frozenset({"importorskip", "import_module", "find_spec", "__import__"})
_MODULE_NAME = re.compile(r"[A-Za-z_][\w]*(?:\.[\w]+)*\.?")
_CRUCIBLE_IGNORE_FILE = re.compile(r"--ignore=(framework/v2/[A-Za-z0-9_./-]+\.py)")
_PATH_PREFIXES = ("docs/", "engine/", "range/", "gateway/", "tools/", "tests/", "integration/", "apps/",
                  "packages/", "vendor/", "vscp/")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _tree_of(rel: str) -> str:
    parts = rel.split("/")
    two = "/".join(parts[:2])
    return two if two in HOME_PLANES else parts[0]


def _is_test_file(name: str) -> bool:
    """The files pytest's default `python_files` collects."""
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _callee(call: ast.Call) -> str:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _module_args(call: ast.Call) -> list[ast.expr]:
    """The argument(s) of an import-shaped call that name the module: the first positional, or the
    `modname=` / `name=` keyword. A `reason=` is never a module name."""
    out = list(call.args[:1])
    out += [k.value for k in call.keywords if k.arg in ("modname", "name")]
    return out


def plane_refs(source: str) -> "set[str] | None":
    """The planes a Python source DEPENDS on, read from its syntax tree (None if it does not parse):
      * every `import X` / `from X import …` anywhere in the file (inside functions, `try:`, comma lists);
      * the module named by an importorskip / import_module / find_spec / __import__ call — a literal, a
        module-level string constant, or the literal head of an f-string;
      * the same for calls to a LOCAL WRAPPER, i.e. a function in the file that passes one of its own
        parameters to one of those calls (`def _need(mod): return pytest.importorskip(mod)`).
    A plane that is only NAMED in prose, a docstring or an unrelated string is not a dependency."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    def plane_of(name: str) -> "str | None":
        if not _MODULE_NAME.fullmatch(name):
            return None
        head = name.split(".", 1)[0]
        return head if head in PLANE_PATHS else None

    consts = {t.id: n.value.value for n in tree.body if isinstance(n, ast.Assign)
              and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
              for t in n.targets if isinstance(t, ast.Name)}
    wrappers = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs}
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Call) and _callee(sub) in _IMPORT_CALLS and any(
                    isinstance(a, ast.Name) and a.id in params for a in _module_args(sub)):
                wrappers.add(fn.name)

    def literal(node: ast.expr) -> "str | None":
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return consts.get(node.id)
        if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
            return str(node.values[0].value)
        return None

    refs: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        elif isinstance(node, ast.Call) and (_callee(node) in _IMPORT_CALLS or _callee(node) in wrappers):
            names = [v for v in (literal(a) for a in _module_args(node)) if v]
        for name in names:
            plane = plane_of(name)
            if plane:
                refs.add(plane)
    return refs


def _scannable(rel: str) -> bool:
    return not rel.startswith("integration/") and not any(s in "/" + rel for s in _SKIP_DIRS)


_CROSS_CACHE: dict = {}


def cross_plane_files(repo: Path) -> dict[str, set[str]]:
    """Cached per repo root: the real tree is scanned once per test session (it is ~6,000 files)."""
    key = repo.resolve()
    if key not in _CROSS_CACHE:
        _CROSS_CACHE[key] = _cross_plane_files(repo)
    return {k: set(v) for k, v in _CROSS_CACHE[key].items()}


def _cross_plane_files(repo: Path) -> dict[str, set[str]]:
    """repo-relative test file -> the planes it depends on that its home leg lacks.

    A test file's dependencies include what its SUPPORT code imports, because a fixture that importorskips
    a plane skips the test that uses it: every `conftest.py` from the test's directory up to its tree's
    root, and every non-test `.py` helper beside it in the same directory. A file that does not parse is
    reported as depending on the sentinel plane `<unparseable>`, which no leg has."""
    refs_cache: dict[Path, set[str]] = {}

    def refs(f: Path) -> set[str]:
        if f not in refs_cache:
            r = plane_refs(_read(f))
            refs_cache[f] = {"<unparseable>"} if r is None else r
        return refs_cache[f]

    out: dict[str, set[str]] = {}
    for f in sorted(p for p in repo.rglob("*.py") if _is_test_file(p.name)):
        rel = f.relative_to(repo).as_posix()
        tree = _tree_of(rel)
        if not _scannable(rel) or tree not in HOME_PLANES:
            continue
        deps = set(refs(f))
        tree_root = repo / tree
        d = f.parent
        while True:
            if (d / "conftest.py").is_file():
                deps |= refs(d / "conftest.py")
            if d == tree_root or tree_root not in d.parents:
                break
            d = d.parent
        for helper in f.parent.glob("*.py"):
            if helper.name not in ("conftest.py", "__init__.py") and not _is_test_file(helper.name):
                deps |= refs(helper)
        missing = deps - HOME_PLANES[tree]
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
    return all(PLANE_PATHS.get(p, "<none>") is None or PLANE_PATHS.get(p, "<none>") in path for p in planes)


_NO_EXEC = re.compile(r"(?<!\S)(?:--collect-only|--co)(?!\S)")


def both_planes_commands(ci_text: str) -> list[str]:
    """The P5 commands that can import the integration, engine AND gateway planes at once AND execute
    tests (a --collect-only command runs nothing, so a file listed only there does not run)."""
    return [c for c in pytest_commands(ci_text) if _has_planes(c, REQUIRED_PLANES) and not _NO_EXEC.search(c)]


# What a both-planes command may contain after `python -m pytest`. Anything else — `-k`, `--deselect`,
# `--ignore`, `--rootdir`, `--cov`, a `path::node`, `|| true` — could narrow or swallow what runs without
# the file list changing, so it is a problem until this guard is taught what it means.
_FLAGS = frozenset({"-q", "-rs", "-rA", "-v", "-x", "--strict-markers"})
_VALUE_OPTS = {"-m": {"not volume"}, "-p": {"pytest_require_planes", "no:cacheprovider"}}
_VALUE_PREFIXES = ("--junit-xml=", "--junitxml=")


def parse_command(command: str) -> "tuple[set[str], list[str]]":
    """(the paths a both-planes command runs, the problems that make its run-list untrustworthy)."""
    tail = command.split("python -m pytest", 1)[1]
    try:
        tokens = shlex.split(tail)
    except ValueError as exc:
        return set(), [f"the command cannot be tokenised ({exc}); the guard cannot tell what it runs"]
    paths: set[str] = set()
    problems: list[str] = []
    it = iter(tokens)
    for tok in it:
        if tok in ("||", "|", "&&", ";", "&") or tok.endswith(";"):
            problems.append(f"`{tok}` after the pytest command: its exit status could be swallowed")
        elif tok in _FLAGS or tok.startswith(_VALUE_PREFIXES):
            continue
        elif tok in _VALUE_OPTS:
            val = next(it, "")
            if val not in _VALUE_OPTS[tok]:
                problems.append(f"`{tok} {val}` is not an option this guard allows in a both-planes command")
        elif tok.startswith("-"):
            problems.append(f"unrecognised pytest option `{tok}` in a both-planes command (teach this guard "
                            f"what it means: it may narrow what runs)")
        elif "::" in tok:
            problems.append(f"`{tok}` selects a single node, so the rest of its file does not run")
        elif tok.startswith(_PATH_PREFIXES):
            paths.add(tok.rstrip("/"))
        else:
            problems.append(f"unrecognised argument `{tok}` in a both-planes command")
    return paths, problems


def _listed(command: str) -> set[str]:
    return parse_command(command)[0]


def _covers(listed: set[str], rel: str) -> bool:
    return rel in listed or any(rel.startswith(d + "/") for d in listed if not d.endswith(".py"))


def unlisted_cross_plane_files(ci_text: str, cross: dict[str, set[str]]) -> list[str]:
    """The cross-plane files that no command able to import their planes will run."""
    commands = both_planes_commands(ci_text)
    problems = []
    for rel, planes in sorted(cross.items()):
        if rel in KNOWN_STRIX_RESIDUE and planes == {"strix"}:
            continue
        if "<unparseable>" in planes:
            problems.append(f"{rel} (or its conftest/helper) does not parse, so its plane dependencies are unknown")
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
    """Why a both-planes command would let a missing-plane skip, a narrowed run or a swallowed exit status
    through ([] when none would)."""
    commands = both_planes_commands(ci_text)
    if not commands:
        return ["no P5 pytest command has the integration, engine and gateway planes on its path"]
    problems = []
    for c in commands:
        head = c.split("python -m pytest", 1)
        what = f"the command starting `{head[1].split()[0:3]}`"
        if ".github/scripts" not in _pythonpath(c) or not re.search(r"(?<!\S)-p pytest_require_planes(?!\S)",
                                                                   head[1]):
            problems.append(f"{what} does not load pytest_require_planes")
        missing = REQUIRED_PLANES - _required(c)
        if missing:
            problems.append(f"{what} does not REQUIRE {sorted(missing)} (VIGIL_REQUIRE_PLANES)")
        absent = [p for p in _required(c) if p in PLANE_PATHS and not _has_planes(c, [p])]
        if absent:
            problems.append(f"{what} requires {absent} but does not put it on PYTHONPATH")
        problems += [f"{what}: {p}" for p in parse_command(c)[1]]
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
    for f in _REPO.rglob("*.py"):
        rel = f.relative_to(_REPO).as_posix()
        if not _is_test_file(f.name) or not _scannable(rel):
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
    """Commented out IN PLACE — mid-continuation, inside the integration job — not appended at the end."""
    ci = _read(_CI)
    line = next(ln for ln in ci.splitlines() if _PAUSE_HALT in ln and "--ignore" not in ln)
    perturbed = ci.replace(line, line.replace(_PAUSE_HALT, "# " + _PAUSE_HALT), 1)
    assert perturbed != ci
    assert any(_PAUSE_HALT in p for p in unlisted_cross_plane_files(perturbed, cross_plane_files(_REPO)))


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
    assert plane_refs('"""talks about vigil_integration and framework"""\nx = "vigil_gateway"\n'
                      'pytest.skip("framework.v2 not importable")\n'
                      'pytest.importorskip("anthropic", reason="vigil_gateway is irrelevant here")\n') == set()


def test_negative_control_every_import_shape_is_detected():
    shapes = {
        "import os, vigil_gateway\n": "vigil_gateway",
        "try: import vigil_gateway\nexcept ImportError: pass\n": "vigil_gateway",
        "def f():\n    from vigil_integration.live import x\n": "vigil_integration",
        "pytest.importorskip(modname='vigil_gateway.denylist')\n": "vigil_gateway",
        "MOD = 'vigil_integration.live.executor'\npytest.importorskip(MOD)\n": "vigil_integration",
        "x = 'live'\npytest.importorskip(f'vigil_integration.{x}')\n": "vigil_integration",
        "__import__('vigil_gateway')\n": "vigil_gateway",
        "importlib.util.find_spec('framework') is None\n": "framework",
        "def _need(mod):\n    return pytest.importorskip(mod, reason='x')\n_need('vigil_gateway.denylist')\n":
            "vigil_gateway",
    }
    for src, plane in shapes.items():
        assert plane_refs(src) == {plane}, src
    assert plane_refs("def broken(:\n") is None


def _mini_tree(root: Path, files: dict) -> Path:
    for rel, body in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body, encoding="utf-8")
    return root


def test_negative_control_support_code_dependencies_are_attributed(tmp_path):
    """A conftest fixture or a helper module that importorskips a plane makes the tests using it skip."""
    root = _mini_tree(tmp_path, {
        "engine/crucible/x/conftest.py": "import pytest\n@pytest.fixture\ndef gw():\n"
                                         "    return pytest.importorskip('vigil_gateway.denylist')\n",
        "engine/crucible/x/tests/test_uses_fixture.py": "def test_a(gw):\n    pass\n",
        "engine/crucible/y/tests/_floor.py": "import pytest\nGW = pytest.importorskip('vigil_integration.x')\n",
        "engine/crucible/y/tests/test_uses_helper.py": "from ._floor import GW\n",
        "engine/crucible/z/tests/floor_test.py": "import vigil_gateway\n",
        "engine/crucible/z/tests/test_clean.py": "import framework\n",
        "docs/tests/test_bad.py": "def broken(:\n",
    })
    cross = cross_plane_files(root)
    assert cross["engine/crucible/x/tests/test_uses_fixture.py"] == {"vigil_gateway"}
    assert cross["engine/crucible/y/tests/test_uses_helper.py"] == {"vigil_integration"}
    assert cross["engine/crucible/z/tests/floor_test.py"] == {"vigil_gateway"}
    assert "engine/crucible/z/tests/test_clean.py" not in cross
    assert cross["docs/tests/test_bad.py"] == {"<unparseable>"}
    assert any("does not parse" in p for p in unlisted_cross_plane_files(_read(_CI), cross))


def test_negative_control_narrowing_or_swallowing_options_are_reported():
    ci = _read(_CI)
    line = next(ln for ln in ci.splitlines() if _PAUSE_HALT in ln and "--ignore" not in ln)
    indent = line[: len(line) - len(line.lstrip())]
    for bad, expected in ((f"--deselect {_PAUSE_HALT}", "unrecognised pytest option `--deselect`"),
                          (f"--ignore {_PAUSE_HALT}", "unrecognised pytest option `--ignore`"),
                          ("-k not_pause", "unrecognised pytest option `-k`"),
                          ("--rootdir engine/crucible", "unrecognised pytest option `--rootdir`"),
                          (f"{_PAUSE_HALT}::test_one", "selects a single node"),
                          ("-p no:pytest_require_planes", "`-p no:pytest_require_planes`"),
                          ('-m "not volume and not slow"', "`-m not volume and not slow`")):
        perturbed = ci.replace(line, f"{indent}{bad} \\\n{line}", 1)
        assert perturbed != ci
        assert any(expected in p for p in enforcement_problems(perturbed)), bad
    swallowed = ci.replace('range/tests -q -m "not volume"', 'range/tests -q -m "not volume" || true', 1)
    assert swallowed != ci
    assert any("could be swallowed" in p for p in enforcement_problems(swallowed))


def test_negative_control_a_collect_only_command_does_not_count_as_running():
    """A file moved from the offense list onto a `--collect-only` command (inside the integration job)."""
    real = _read(_CI)
    anchor = "      - name: the two-env boundary proof MUST have actually executed"
    assert anchor in real
    collect = ("      - name: collect only\n        run: |\n"
               "          PYTHONPATH=integration:engine/crucible:gateway:.github/scripts python -m pytest \\\n"
               f"            {_PAUSE_HALT} --collect-only -q\n")
    perturbed = _without(real, _PAUSE_HALT).replace(anchor, collect + anchor, 1)
    assert any(_PAUSE_HALT in p for p in unlisted_cross_plane_files(perturbed, cross_plane_files(_REPO)))


def test_negative_control_the_gateway_home_leg_has_no_engine():
    ci = _without(_read(_CI), "gateway/tests/test_scope_source.py")
    assert any("test_scope_source.py" in p for p in unlisted_cross_plane_files(ci, cross_plane_files(_REPO)))
