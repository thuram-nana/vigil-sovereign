"""CI-leg guards: the sigil suite runs on the SOVEREIGN lock, it also runs with the fold cache ON, and a JS test
that executes node FAILS — never skips — in every ci.yml job that runs it.

(a) FOLD CACHE ON. Front C's verified fold cache (``VIGIL_FOLD_CACHE_ENABLED``, S0) is default-OFF, so the suite's
    default run exercises it only where a test switches it on for itself. Its production configuration — every
    request-path fold on the cache, for every test in the suite — ran in NO CI leg. The ``sigil-fold-cache-on`` job
    runs the WHOLE ``apps/sigil/tests/`` directory with the flag on. This fails if no ci.yml step does, if the value
    it sets is one the REAL flag reader (``sigil.config.fold_cache_enabled``) does not treat as ON, or if that leg
    ``--ignore``s a file the default leg runs.

(b) SOVEREIGN LOCK. The ``sigil-governor`` job installed the OFFENSE framework lock
    (engine/crucible/framework/v2/requirements.lock.txt), so the sovereign pins (mcp, onnxruntime, qdrant-client,
    tokenizers, huggingface-hub, kuzu, numpy …) never met the sigil suite in CI — their tests importorskip-SKIPPED.
    Every ci.yml job that runs apps/sigil/tests must install infra/supply-chain/sovereign.lock.txt under
    --require-hashes and must NOT install the offense lock: SIGIL does not ship it, and a second runtime install
    would mask a sovereign pin with an offense one on any shared package.

(c) NODE. Several tests execute shipped JS under node and used to SKIP (``skipif(... node ... is None)``) — or, in
    test_bridge_webapp.py, print "SKIP" and RETURN, i.e. PASS — where node is missing. Every such test file must
    route its node lookup through a ``_need_node()`` gate that FAILS when ``VIGIL_REQUIRE_NODE`` is set, and every
    ci.yml step that runs the file must set it. Which steps run which file is computed from ci.yml itself (the
    pytest targets, ``working-directory`` and ``--ignore``s of each step), so a node test that moves, or a new one,
    is covered without editing a list here — and one that no ci.yml step runs at all fails too.

Framework-free: pure file reads, plus executing each ``_need_node`` gate's OWN source in isolation (no engine
import), so it runs in the sovereign leg. Every checker takes its input as an argument, so the NEGATIVE CONTROLS
feed it the defect it exists to catch and assert that defect is reported.
"""
from __future__ import annotations

import ast
import os
import re
import shlex
import types
from pathlib import Path, PurePosixPath

import pytest

_ME = Path(__file__).name
_REPO = Path(__file__).resolve().parents[3]                # apps/sigil/tests -> apps/sigil -> apps -> repo
_CI = _REPO / ".github" / "workflows" / "ci.yml"

SUITE = "apps/sigil/tests"
SOVEREIGN_LOCK = "infra/supply-chain/sovereign.lock.txt"
OFFENSE_LOCK = "engine/crucible/framework/v2/requirements.lock.txt"
FOLD_FLAG = "VIGIL_FOLD_CACHE_ENABLED"
NODE_FLAG = "VIGIL_REQUIRE_NODE"
NODE_GATE = "_need_node"


# --------------------------------------------------------------------------------------------------------------
# A minimal reader for ci.yml's fixed shape (jobs at two spaces, `steps:` at four, a step starts `      - `).
# --------------------------------------------------------------------------------------------------------------
_JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
_STEPS_KEY = re.compile(r"^    steps:\s*$")
_STEP_START = re.compile(r"^      - ")
# pytest options that take their value as the NEXT token (so that token is not a run target)
_VALUE_OPTS = ("-m", "-k", "-p", "-c", "-o", "-W", "--rootdir", "--junit-xml", "--ignore", "--deselect",
               "--basetemp")


def _jobs(text: str) -> dict[str, tuple[list[str], list[list[str]]]]:
    """job key -> (job-level lines before ``steps:``, [lines of each step]). ``#`` comment lines are dropped, so
    a comment quoting a flag or a lock path can neither satisfy nor trip a check."""
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]
    start = next((i for i, ln in enumerate(lines) if ln.rstrip() == "jobs:"), None)
    assert start is not None, "no top-level `jobs:` in the workflow — the reader or the file changed shape"
    jobs: dict[str, tuple[list[str], list[list[str]]]] = {}
    key: str | None = None
    in_steps = False
    for ln in lines[start + 1:]:
        if re.match(r"^\S", ln):
            break
        m = _JOB_KEY.match(ln)
        if m:
            key, in_steps = m.group(1), False
            jobs[key] = ([], [])
            continue
        if key is None:
            continue
        head, steps = jobs[key]
        if _STEPS_KEY.match(ln):
            in_steps = True
        elif not in_steps:
            head.append(ln)
        elif _STEP_START.match(ln):
            steps.append([ln])
        elif steps:
            steps[-1].append(ln)
    return jobs


def _run_script(step: list[str]) -> list[str]:
    """The shell lines of a step's ``run:`` (inline, or the block scalar indented under it) — never its ``name:``,
    so a step titled "install pytest …" is not mistaken for a pytest invocation."""
    for i, ln in enumerate(step):
        m = re.match(r"^(\s+)(?:- )?run:\s*(.*?)\s*$", ln)
        if not m:
            continue
        if m.group(2)[:1] not in ("|", ">"):
            return [m.group(2)]
        indent = len(m.group(1))
        body: list[str] = []
        for nxt in step[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            body.append(nxt)
        return body
    return []


def _logical(lines: list[str]) -> list[str]:
    """Join shell continuation lines (a trailing backslash)."""
    out: list[str] = []
    buf = ""
    for ln in lines:
        s = ln.rstrip()
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        out.append(buf + s)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _yaml_env(lines: list[str], name: str) -> str | None:
    """The last ``NAME: value`` mapping entry in these lines (a job's or a step's ``env:``), unquoted."""
    vals = [m.group(1).strip().strip("\"'") for ln in lines
            for m in [re.match(rf"^\s+{re.escape(name)}:\s*(.*?)\s*$", ln)] if m]
    return vals[-1] if vals else None


def _inline_env(line: str, name: str) -> str | None:
    vals = re.findall(rf"(?:^|\s){re.escape(name)}=(\S*)", line)
    return vals[-1].strip("\"'") if vals else None


class Run:
    """One pytest invocation in one ci.yml step, with the environment that invocation actually sees."""

    def __init__(self, job: str, head: list[str], step: list[str], line: str, targets: list[str],
                 ignores: list[str]) -> None:
        self.job, self._head, self._step, self._line = job, head, step, line
        self.targets, self.ignores = targets, ignores

    def env(self, name: str) -> str | None:
        """Shell-inline beats the step's ``env:``, which beats the job's ``env:`` (GitHub's precedence)."""
        for v in (_inline_env(self._line, name), _yaml_env(self._step, name), _yaml_env(self._head, name)):
            if v is not None:
                return v
        return None


def _norm(rel: str, wd: str) -> str:
    p = PurePosixPath(os.path.normpath(str(PurePosixPath(wd) / rel.split("::", 1)[0])))
    return "" if str(p) == "." else str(p)


def _pytest_runs(text: str) -> list[Run]:
    """Every pytest invocation in the workflow that RUNS tests (``--collect-only`` does not), resolved to
    repo-relative targets and ``--ignore``s (``working-directory`` and ``$VAR`` from the step/job env applied)."""
    runs: list[Run] = []
    for job, (head, steps) in _jobs(text).items():
        for step in steps:
            wd = next((m.group(1).strip("\"'") for ln in step
                       for m in [re.match(r"^\s+working-directory:\s*(\S+)\s*$", ln)] if m), ".")
            for line in _logical(_run_script(step)):
                if "--collect-only" in line:
                    continue
                try:
                    toks = shlex.split(line)
                except ValueError:
                    continue
                at = next((i for i, t in enumerate(toks)
                           if t == "pytest" or (t == "-m" and i + 1 < len(toks) and toks[i + 1] == "pytest")), None)
                if at is None:
                    continue
                if toks[at] == "-m":
                    at += 1
                targets: list[str] = []
                ignores: list[str] = []
                rest = toks[at + 1:]
                skip_next = False
                for t in rest:
                    if skip_next:
                        skip_next = False
                        continue
                    if t in (";", "&&", "||", "|") or t.startswith(("2>", ">")):
                        break
                    if t.startswith("--ignore="):
                        ignores.append(_norm(t.split("=", 1)[1], wd))
                        continue
                    if t.startswith("-"):
                        skip_next = t in _VALUE_OPTS
                        continue
                    for word in _expand(t, head, step).split():
                        targets.append(_norm(word, wd))
                runs.append(Run(job, head, step, line, targets, ignores))
    return runs


def _expand(tok: str, head: list[str], step: list[str]) -> str:
    def sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        return _yaml_env(step, name) or _yaml_env(head, name) or ""
    return re.sub(r"\$\{(\w+)\}|\$(\w+)", sub, tok)


def _covers(path: str, roots: list[str]) -> bool:
    return any(r == "" or path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def _runs_suite_whole(run: Run) -> bool:
    return SUITE in run.targets


def _runs_any_of_suite(run: Run) -> bool:
    return any(t == SUITE or t.startswith(SUITE + "/") for t in run.targets)


def _job_installs(text: str, job: str) -> list[str]:
    _head, steps = _jobs(text)[job]
    return [ln for st in steps for ln in _logical(_run_script(st)) if "pip install" in ln]


_READER_FIXTURE = """\
on: [pull_request]
jobs:
  j:
    name: install pytest and friends
    env:
      SUITES: apps/sigil/tests/test_a.py apps/sigil/tests/test_b.py
      FLAG: "1"
    steps:
      - name: run pytest over everything (a step NAME, not a command)
        run: echo "unterminated
      - name: s1
        env:
          FLAG: "0"
        run: |
          python -m pytest -q apps/sigil/tests/ \\
            --ignore=apps/sigil/tests/test_x.py -m "not volume" 2>&1 | tee log
          pytest --collect-only apps/sigil/tests/
      - name: s2
        working-directory: engine/crucible
        run: >-
          FLAG=yes pytest framework/v2 --ignore=framework/v2/eval -p no:cacheprovider $SUITES ${SUITES}
      - run: pytest apps/sigil/tests/test_bridge_webapp.py::test_esc . \\
"""


def test_the_workflow_reader_resolves_what_each_pytest_step_runs():
    """The (a)/(b)/(c) checks stand on this reader, so every resolution rule it applies is pinned here: step
    names are not commands, an unparsable line is skipped, `--collect-only` runs nothing, continuations join,
    `--ignore=` / `working-directory` / `$VAR` / `${VAR}` / `::node-id` / `.` resolve, a pipe or redirect ends the
    argument list, and the env precedence is inline > step > job."""
    runs = _pytest_runs(_READER_FIXTURE)
    assert [r.targets for r in runs] == [
        [SUITE],
        ["engine/crucible/framework/v2", "engine/crucible/apps/sigil/tests/test_a.py",
         "engine/crucible/apps/sigil/tests/test_b.py", "engine/crucible/apps/sigil/tests/test_a.py",
         "engine/crucible/apps/sigil/tests/test_b.py"],
        ["apps/sigil/tests/test_bridge_webapp.py", ""],
    ], [r.targets for r in runs]
    assert [r.ignores for r in runs] == [["apps/sigil/tests/test_x.py"], ["engine/crucible/framework/v2/eval"], []]
    assert [r.env("FLAG") for r in runs] == ["0", "yes", "1"]
    assert _covers("range/tests/test_anything.py", runs[2].targets), "a `pytest .` target must cover every file"
    # each value-taking pytest option's separate VALUE is never mistaken for a run target (listed HERE, not read
    # back from _VALUE_OPTS, so dropping one from the reader is caught)
    for opt in ("-m", "-k", "-p", "-c", "-o", "-W", "--rootdir", "--junit-xml", "--ignore", "--deselect", "--basetemp"):
        got = _pytest_runs(f"jobs:\n  j:\n    steps:\n      - run: pytest {opt} VALUE {SUITE}/\n")
        assert [r.targets for r in got] == [[SUITE]], (opt, [r.targets for r in got])


# --------------------------------------------------------------------------------------------------------------
# (a) the fold cache ON leg
# --------------------------------------------------------------------------------------------------------------
def fold_cache_on_suite_runs(text: str, is_on) -> list[Run]:
    """The whole-suite runs that see an ON fold-cache flag, as judged by ``is_on(value)``."""
    return [r for r in _pytest_runs(text) if _runs_suite_whole(r) and is_on(r.env(FOLD_FLAG))]


@pytest.fixture
def real_fold_flag(monkeypatch):
    """``is_on(value)`` by the REAL reader: ``sigil.config.fold_cache_enabled`` under that environment value."""
    from sigil import config

    def is_on(value: str | None) -> bool:
        if value is None:
            monkeypatch.delenv(FOLD_FLAG, raising=False)
        else:
            monkeypatch.setenv(FOLD_FLAG, value)
        return config.fold_cache_enabled()
    return is_on


def test_some_ci_leg_runs_the_whole_sigil_suite_with_the_fold_cache_on(real_fold_flag):
    text = _CI.read_text(encoding="utf-8")
    on = fold_cache_on_suite_runs(text, real_fold_flag)
    assert on, (f"no ci.yml step runs the whole `{SUITE}/` directory with {FOLD_FLAG} set to a value "
                "sigil.config.fold_cache_enabled() treats as ON — the fold cache never runs in CI in its "
                "production configuration")
    off = [r for r in _pytest_runs(text) if _runs_suite_whole(r) and not real_fold_flag(r.env(FOLD_FLAG))]
    assert off, "the ON leg must be ADDITIVE: the default (flag-OFF) whole-suite run must still exist"
    for r in on:
        for base in off:
            assert set(r.ignores) == set(base.ignores), (
                f"the fold-cache-ON leg ({r.job}) --ignores {sorted(r.ignores)} but the default leg ({base.job}) "
                f"--ignores {sorted(base.ignores)}: the ON leg must cover exactly the suite the OFF leg covers")


def test_negative_control_fold_cache_leg_detector(real_fold_flag):
    text = _CI.read_text(encoding="utf-8")
    assert fold_cache_on_suite_runs(text, real_fold_flag), "precondition: the real ci.yml has an ON leg"
    gone = re.sub(rf"(?m)^.*\b{FOLD_FLAG}\b.*\n", "", text)
    assert not fold_cache_on_suite_runs(gone, real_fold_flag), "the detector did not notice the ON leg removed"
    zero = re.sub(rf"(?m)^(\s+{FOLD_FLAG}:\s*).*$", r'\1"0"', text)
    assert not fold_cache_on_suite_runs(zero, real_fold_flag), f"{FOLD_FLAG}: \"0\" was read as ON"
    # set on a DIFFERENT step of the job (not the one that runs the suite) -> not ON for the suite run
    misplaced = ("jobs:\n  j:\n    steps:\n      - name: a\n        env:\n"
                 f"          {FOLD_FLAG}: \"1\"\n        run: true\n      - name: b\n"
                 f"        run: python -m pytest {SUITE}/\n")
    assert not fold_cache_on_suite_runs(misplaced, real_fold_flag), "a flag on another step was credited"
    inline = (f"jobs:\n  j:\n    steps:\n      - run: {FOLD_FLAG}=1 python -m pytest {SUITE}/ -rs\n")
    assert fold_cache_on_suite_runs(inline, real_fold_flag), "an inline flag on the run line was not credited"


# --------------------------------------------------------------------------------------------------------------
# (b) the sigil suite installs the SOVEREIGN lock, never the offense lock
# --------------------------------------------------------------------------------------------------------------
def suite_lock_offenders(text: str) -> list[str]:
    jobs = sorted({r.job for r in _pytest_runs(text) if _runs_any_of_suite(r)})
    assert jobs, f"no ci.yml job runs {SUITE} — the reader broke, or the suite stopped running in CI"
    bad: list[str] = []
    for job in jobs:
        installs = _job_installs(text, job)
        if not any("--require-hashes" in ln and re.search(rf"-r\s+{re.escape(SOVEREIGN_LOCK)}\b", ln)
                   for ln in installs):
            bad.append(f"{job}: does not install {SOVEREIGN_LOCK} under --require-hashes")
        if any(OFFENSE_LOCK in ln for ln in installs):
            bad.append(f"{job}: installs the offense lock {OFFENSE_LOCK} (SIGIL does not ship it; it masks the "
                       "sovereign pins on every shared package)")
    return bad


def test_every_job_that_runs_the_sigil_suite_installs_the_sovereign_lock():
    bad = suite_lock_offenders(_CI.read_text(encoding="utf-8"))
    assert not bad, "the sigil suite must run on the lock SIGIL ships:\n  " + "\n  ".join(bad)


def test_negative_control_suite_lock_detector():
    text = _CI.read_text(encoding="utf-8")
    assert not suite_lock_offenders(text), "precondition: the real ci.yml is clean"
    reverted = text.replace(f"-r {SOVEREIGN_LOCK}", f"-r {OFFENSE_LOCK}")
    got = suite_lock_offenders(reverted)
    assert any("sigil-governor" in b and "does not install" in b for b in got), got
    assert any("sigil-governor" in b and "offense lock" in b for b in got), got
    # the sovereign lock still installed, but the offense lock layered after it: still an offender (masking)
    masked = text.replace(f"pip install --require-hashes -r {SOVEREIGN_LOCK}\n",
                          f"pip install --require-hashes -r {SOVEREIGN_LOCK}\n"
                          f"          pip install --require-hashes -r {OFFENSE_LOCK}\n", 1)
    assert any("offense lock" in b for b in suite_lock_offenders(masked)), "a layered offense lock was not caught"


# --------------------------------------------------------------------------------------------------------------
# (c) node-executed JS tests FAIL where CI runs them
# --------------------------------------------------------------------------------------------------------------
_EXECUTES_NODE = re.compile(r"""\bwhich\(\s*["']node["']\s*\)|\[\s*["']node["']\s*,""")
_SKIP_DIRS = {"node_modules", "__pycache__"}


def node_test_files(root: Path = _REPO) -> list[str]:
    """Every test_*.py in the repository that executes node, repo-relative (hidden dirs, node_modules skipped)."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.startswith("test_") and fn.endswith(".py") and fn != _ME:
                p = Path(dirpath) / fn
                if _EXECUTES_NODE.search(p.read_text(encoding="utf-8", errors="replace")):
                    out.append(p.relative_to(root).as_posix())
    return sorted(out)


def _is_node_which(node: ast.AST) -> bool:
    if not (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "node"):
        return False
    f = node.func
    return (isinstance(f, ast.Attribute) and f.attr == "which") or (isinstance(f, ast.Name) and f.id == "which")


def gate_violations(src: str) -> list[str]:
    """Every node lookup must sit inside the ``_need_node`` gate: a module-level ``skipif`` or an in-test
    ``if not which(node): return`` is exactly the silent skip/pass this guard exists to end."""
    tree = ast.parse(src)
    bad: list[str] = []

    def walk(node: ast.AST, fn: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            if _is_node_which(child) and fn != NODE_GATE:
                bad.append(f"line {child.lineno}: node lookup outside {NODE_GATE}() (in {fn or 'module scope'})")
            walk(child, inner)
    walk(tree, None)
    return bad


def gate_misbehaviours(src: str) -> list[str]:
    """Execute the file's OWN ``_need_node`` source in isolation (stub ``shutil.which``) and report every way it
    departs from: node missing + VIGIL_REQUIRE_NODE=1 -> FAIL; node missing, flag unset -> SKIP; node present ->
    returned, no skip, no fail."""
    tree = ast.parse(src)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == NODE_GATE), None)
    if fn is None:
        return [f"no module-level {NODE_GATE}() gate"]
    code = ast.get_source_segment(src, fn)
    assert code is not None
    problems: list[str] = []
    for found, flag, want in ((None, "1", "fail"), (None, None, "skip"), ("/usr/bin/node", "1", "return"),
                              ("/usr/bin/node", None, "return")):
        stub = types.SimpleNamespace(which=lambda name, _f=found: _f if name == "node" else None)
        env = dict(os.environ)
        env.pop(NODE_FLAG, None)
        if flag is not None:
            env[NODE_FLAG] = flag
        ns: dict[str, object] = {"shutil": stub, "which": stub.which, "pytest": pytest,
                                 "os": types.SimpleNamespace(environ=env)}
        exec(compile(code, NODE_GATE, "exec"), ns)  # the repo's OWN gate source, isolated: that is what is tested
        try:
            got = ns[NODE_GATE]()  # type: ignore[operator]
            outcome = "return" if got else "returned-falsy"
        except pytest.fail.Exception:
            outcome = "fail"
        except pytest.skip.Exception:
            outcome = "skip"
        if outcome != want:
            problems.append(f"node={'present' if found else 'missing'}, {NODE_FLAG}={flag!r}: {outcome}, want {want}")
    return problems


def node_ci_violations(text: str, files: list[str]) -> list[str]:
    runs = _pytest_runs(text)
    bad: list[str] = []
    for f in files:
        mine = [r for r in runs if _covers(f, r.targets) and not _covers(f, r.ignores)]
        if not mine:
            bad.append(f"{f}: no ci.yml step runs it — its JS is never executed in CI")
        for r in mine:
            v = r.env(NODE_FLAG)
            if (v or "").strip().lower() not in {"1", "true", "yes", "on"}:
                bad.append(f"{f}: run by job {r.job!r} without {NODE_FLAG}=1 (a missing node would SKIP there)")
    return bad


def test_the_node_test_detector_finds_the_known_js_tests():
    """Not vacuous: the detector finds the JS-executing files this guard was written against."""
    files = node_test_files()
    for known in ("apps/sigil/tests/test_js_untrusted_key_parsing.py", "apps/sigil/tests/test_customer_checkout_ui.py",
                  "apps/sigil/tests/test_bridge_webapp.py",
                  "engine/crucible/framework/v2/console/tests/test_s10_strix_control.py"):
        assert known in files, f"the node-test detector no longer finds {known} (found {files})"


@pytest.mark.parametrize("rel", node_test_files())
def test_node_test_routes_every_node_lookup_through_a_failing_gate(rel):
    src = (_REPO / rel).read_text(encoding="utf-8")
    assert not gate_violations(src), f"{rel}: " + "; ".join(gate_violations(src))
    if any(_is_node_which(n) for n in ast.walk(ast.parse(src))):
        assert not gate_misbehaviours(src), f"{rel}: {NODE_GATE}() " + "; ".join(gate_misbehaviours(src))


def test_every_ci_job_that_runs_a_node_test_requires_node():
    bad = node_ci_violations(_CI.read_text(encoding="utf-8"), node_test_files())
    assert not bad, "a missing node must FAIL the job that runs these JS tests:\n  " + "\n  ".join(bad)


def test_negative_control_node_guards():
    skipif = ("import shutil, pytest\n"
              "pytestmark = pytest.mark.skipif(shutil.which('node') is None, reason='node not installed')\n")
    assert gate_violations(skipif), "a module-level skipif on node was not flagged"
    silent_pass = ("import shutil\ndef test_x():\n    if not shutil.which('node'):\n        print('SKIP')\n"
                   "        return\n")
    assert gate_violations(silent_pass), "an in-test print-and-return on missing node was not flagged"
    always_skip = ("def _need_node():\n    node = shutil.which('node')\n    if node is None:\n"
                   "        pytest.skip('node not installed')\n    return node\n")
    assert not gate_violations(always_skip), "the lookup inside the gate itself must not be flagged"
    assert any("want fail" in p for p in gate_misbehaviours(always_skip)), "a gate that ignores the flag passed"
    text = _CI.read_text(encoding="utf-8")
    files = node_test_files()
    assert not node_ci_violations(text, files), "precondition: the real ci.yml is clean"
    stripped = re.sub(rf"(?m)^.*\b{NODE_FLAG}\b.*\n", "", text)
    got = node_ci_violations(stripped, files)
    assert {b.split(":", 1)[0] for b in got} == set(files), got
    assert any("'sigil-governor'" in b for b in got) and any("'crucible-core'" in b for b in got), got
    assert any("no ci.yml step runs it" in b for b in node_ci_violations(text, ["nowhere/tests/test_unrun.py"])), \
        "a node test that no ci.yml step runs was not flagged"
