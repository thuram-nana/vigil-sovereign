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
    Every job in EVERY workflow that runs apps/sigil/tests (through pytest, or through
    tools/flake/run_and_record.py --target) must install infra/supply-chain/sovereign.lock.txt under
    --require-hashes and must NOT install the offense lock (any ``pip``/``pip3``/``python -m pip`` spelling):
    SIGIL does not ship it, and a second runtime install would mask a sovereign pin with an offense one on any
    shared package.

(c) NODE. Several tests execute shipped JS under node and used to SKIP (``skipif(... node ... is None)``) — or, in
    test_bridge_webapp.py, print "SKIP" and RETURN, i.e. PASS — where node is missing. Every such test file must
    route its node lookup through a ``_need_node()`` gate that FAILS when ``VIGIL_REQUIRE_NODE`` is set, and every
    ci.yml step that runs the file must set it. Which steps run which file is computed from ci.yml itself (the
    pytest targets, ``working-directory`` and ``--ignore``s of each step), so a node test that moves, or a new one,
    is covered without editing a list here — and one that no ci.yml step runs at all fails too.

    A literal ``["node", …]`` argv bypasses the gate, and an ``except FileNotFoundError`` (or broader) handler
    that skips re-creates the silent skip: both are flagged. The gate is checked under a constructed
    environment, so it must also FAIL on a runner (``GITHUB_ACTIONS=true``) without node and return the path.

(d) WHOLE-SUITE LEGS. Both whole-suite runs (default and fold-cache ON) require the sovereign closure
    (``VIGIL_REQUIRE_SOVEREIGN_CLOSURE=1``, ``-p pytest_require_planes`` with ``VIGIL_REQUIRE_PLANES`` naming
    numpy/onnxruntime/tokenizers/huggingface_hub/mcp/qdrant_client, ``.github/scripts`` on PYTHONPATH), so a
    skip for a package the sovereign lock installs FAILS there. Nothing may mask either run: no shell operator
    after pytest (``||``, ``;``, ``&&``, ``|``, ``&``), no ``!``, no ``set +e``, no job- or step-level ``if:`` or
    ``continue-on-error``, and the fold flag only from ``env:`` or an inline prefix (never exported/unset in
    the shell). The two legs must use IDENTICAL selection options (``-k``, ``-m``, ``--deselect``, ``-p no:*``,
    ``--ignore``, ``-x``/``--maxfail``, …), and ``--co`` counts as collect-only, i.e. not a run.

    Each whole-suite leg also runs OFFLINE against a warmed, pinned model cache: an ``actions/cache`` step keyed
    on ``sigil/vectors/embed.py`` (which carries the model pins), then a step that calls
    ``sigil.vectors.embed.prefetch()`` with the same ``SIGIL_EMBED_CACHE_DIR``, then the suite with
    ``HF_HUB_OFFLINE=1`` — so the golden-embedding test runs on every PR and pytest never touches the network.

(e) NO BROAD SKIP. No apps/sigil test may turn ANY error into a skip (``except Exception`` / bare / BaseException
    whose body skips): a broken module or a bad model file must fail.

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
_WORKFLOWS = _REPO / ".github" / "workflows"

SUITE = "apps/sigil/tests"
SOVEREIGN_LOCK = "infra/supply-chain/sovereign.lock.txt"
OFFENSE_LOCK = "engine/crucible/framework/v2/requirements.lock.txt"
FOLD_FLAG = "VIGIL_FOLD_CACHE_ENABLED"
NODE_FLAG = "VIGIL_REQUIRE_NODE"
NODE_GATE = "_need_node"
CLOSURE_FLAG = "VIGIL_REQUIRE_SOVEREIGN_CLOSURE"
PLANES_VAR = "VIGIL_REQUIRE_PLANES"
PLANES_PLUGIN = "pytest_require_planes"
# The sovereign-lock packages the SIGIL suite guards with importorskip/find_spec. Where the sovereign lock is
# installed, a skip for one of them is a FAILURE (the plugin), so a broken pin cannot hide behind a skip.
SOVEREIGN_CLOSURE_PLANES = frozenset({"numpy", "onnxruntime", "tokenizers", "huggingface_hub", "mcp", "qdrant_client"})


# --------------------------------------------------------------------------------------------------------------
# A minimal reader for ci.yml's fixed shape (jobs at two spaces, `steps:` at four, a step starts `      - `).
# --------------------------------------------------------------------------------------------------------------
_JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
_STEPS_KEY = re.compile(r"^    steps:\s*$")
_STEP_START = re.compile(r"^      - ")
# pytest options that take their value as the NEXT token (so that token is not a run target)
_VALUE_OPTS = ("-m", "-k", "-p", "-c", "-o", "-W", "--rootdir", "--junit-xml", "--ignore", "--deselect",
               "--basetemp", "--maxfail", "--ignore-glob")
# The options that change WHICH tests run or how many: two legs that must cover the same suite must agree on
# every one of them (``-p no:<plugin>`` too — disabling a plugin can change collection).
_SELECTION_OPTS = frozenset({"-k", "-m", "--deselect", "--ignore", "--ignore-glob", "-x", "--exitfirst",
                             "--maxfail", "--lf", "--last-failed", "--ff", "--failed-first", "--sw", "--stepwise",
                             "--sw-skip", "--stepwise-skip", "--co", "--collect-only", "--pyargs"})
_COLLECT_ONLY = frozenset({"--co", "--collect-only"})
# Shell control operators. One AFTER a pytest command can mask its exit status (`|| true`, a pipe without
# pipefail, `; true`, `&& true` when it is not the step's last command, `&`): the step goes green whatever
# pytest said.
_CONTROL_OPS = frozenset({";", "&&", "||", "|", "|&", "&", ";;"})


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


def _yaml_scalar(raw: str) -> str:
    """A plain or quoted YAML scalar, without a trailing ``# comment``."""
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        end = raw.find(raw[0], 1)
        return raw[1:end] if end > 0 else raw[1:]
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def _yaml_env(lines: list[str], name: str) -> str | None:
    """The last ``NAME: value`` mapping entry in these lines (a job's or a step's ``env:``), unquoted."""
    vals = [_yaml_scalar(m.group(1)) for ln in lines
            for m in [re.match(rf"^\s+{re.escape(name)}:\s*(.*?)\s*$", ln)] if m]
    return vals[-1] if vals else None


def _inline_env(line: str, name: str) -> str | None:
    vals = re.findall(rf"(?:^|\s){re.escape(name)}=(\S*)", line)
    return vals[-1].strip("\"'") if vals else None


class Run:
    """One pytest invocation in one ci.yml step, with the environment that invocation actually sees."""

    def __init__(self, job: str, head: list[str], step: list[str], line: str, targets: list[str],
                 ignores: list[str], opts: list[tuple[str, str | None]] | None = None,
                 chain: list[str] | None = None, negated: bool = False) -> None:
        self.job, self._head, self._step, self._line = job, head, step, line
        self.targets, self.ignores = targets, ignores
        self.opts = opts or []           # every pytest option, in order, with its value (None for a flag)
        self.chain = chain or []         # shell control operators that FOLLOW this pytest command on its line
        self.negated = negated           # `! pytest …`

    @property
    def line(self) -> str:
        return self._line

    @property
    def head(self) -> list[str]:
        return self._head

    @property
    def step(self) -> list[str]:
        return self._step

    def selection(self) -> list[tuple[str, str | None]]:
        """The options that decide which tests run, sorted (``-p no:<plugin>`` included)."""
        sel = [(o, v) for o, v in self.opts if o in _SELECTION_OPTS]
        sel += [("-p", v) for o, v in self.opts if o == "-p" and (v or "").startswith("no:")]
        return sorted(sel, key=lambda ov: (ov[0], ov[1] or ""))

    def env(self, name: str) -> str | None:
        """Shell-inline beats the step's ``env:``, which beats the job's ``env:`` (GitHub's precedence)."""
        for v in (_inline_env(self._line, name), _yaml_env(self._step, name), _yaml_env(self._head, name)):
            if v is not None:
                return v
        return None


def _norm(rel: str, wd: str) -> str:
    p = PurePosixPath(os.path.normpath(str(PurePosixPath(wd) / rel.split("::", 1)[0])))
    return "" if str(p) == "." else str(p)


def _shell_tokens(line: str) -> list[str] | None:
    """Shell words with control/redirect operators split out as their own tokens (``-rs||true`` is three
    tokens, not one option). None for a line the shell lexer cannot parse."""
    lex = shlex.shlex(line, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return None


def _segments(toks: list[str]) -> list[tuple[list[str], list[str]]]:
    """Split a token list at control operators: [(segment tokens, the operators that FOLLOW it)]."""
    out: list[tuple[list[str], list[str]]] = []
    cur: list[str] = []
    for t in toks:
        if t in _CONTROL_OPS:
            out.append((cur, [t]))
            cur = []
        else:
            cur.append(t)
    out.append((cur, []))
    # every operator after a segment on the same line can mask it, not only the adjacent one
    for i in range(len(out)):
        out[i] = (out[i][0], [op for _seg, ops in out[i:] for op in ops])
    return out


def _pytest_runs(text: str) -> list[Run]:
    """Every pytest invocation in the workflow that RUNS tests (``--collect-only`` / ``--co`` do not), resolved
    to repo-relative targets and ``--ignore``s (``working-directory`` and ``$VAR`` from the step/job env
    applied), with its options and any shell operator that follows it on the line."""
    runs: list[Run] = []
    for job, (head, steps) in _jobs(text).items():
        for step in steps:
            wd = next((m.group(1).strip("\"'") for ln in step
                       for m in [re.match(r"^\s+working-directory:\s*(\S+)\s*$", ln)] if m), ".")
            for line in _logical(_run_script(step)):
                toks = _shell_tokens(line)
                if toks is None:
                    continue
                for seg, chain in _segments(toks):
                    at = next((i for i, t in enumerate(seg)
                               if t == "pytest" or (t == "-m" and i + 1 < len(seg) and seg[i + 1] == "pytest")),
                              None)
                    if at is None:
                        continue
                    negated = "!" in seg[:at]
                    if seg[at] == "-m":
                        at += 1
                    targets: list[str] = []
                    ignores: list[str] = []
                    opts: list[tuple[str, str | None]] = []
                    rest = seg[at + 1:]
                    i = 0
                    while i < len(rest):
                        t = rest[i]
                        i += 1
                        if set(t) <= set("<>&") and t:          # a redirect: drop it, its target and an fd number
                            if targets and targets[-1].isdigit():
                                targets.pop()
                            i += 1
                            continue
                        if t.startswith("-") and "=" in t and t.startswith("--"):
                            o, v = t.split("=", 1)
                            opts.append((o, v))
                            if o == "--ignore":
                                ignores.append(_norm(v, wd))
                            continue
                        if t.startswith("-"):
                            if t in _VALUE_OPTS and i < len(rest):
                                opts.append((t, rest[i]))
                                if t == "--ignore":
                                    ignores.append(_norm(rest[i], wd))
                                i += 1
                            else:
                                opts.append((t, None))
                            continue
                        for word in _expand(t, head, step).split():
                            targets.append(_norm(word, wd))
                    if any(o in _COLLECT_ONLY for o, _v in opts):
                        continue
                    runs.append(Run(job, head, step, line, targets, ignores, opts, chain, negated))
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


_PIP_INSTALL = re.compile(r"(?:^|[\s;&|(])(?:python3?(?:\.\d+)?\s+-m\s+)?pip3?(?:\.\d+)?\s+install\b")


def _job_installs(text: str, job: str) -> list[str]:
    _head, steps = _jobs(text)[job]
    return [ln for st in steps for ln in _logical(_run_script(st)) if _PIP_INSTALL.search(ln)]


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
    commented = _pytest_runs(f'jobs:\n  j:\n    env:\n      FLAG: "1"  # on\n      CACHE: /tmp/c   # where\n'
                             f"    steps:\n      - run: pytest {SUITE}/\n")
    assert commented[0].env("FLAG") == "1" and commented[0].env("CACHE") == "/tmp/c", "a trailing comment was read"
    assert _covers("range/tests/test_anything.py", runs[2].targets), "a `pytest .` target must cover every file"
    # each value-taking pytest option's separate VALUE is never mistaken for a run target (listed HERE, not read
    # back from _VALUE_OPTS, so dropping one from the reader is caught)
    for opt in ("-m", "-k", "-p", "-c", "-o", "-W", "--rootdir", "--junit-xml", "--ignore", "--deselect", "--basetemp",
                "--maxfail", "--ignore-glob"):
        got = _pytest_runs(f"jobs:\n  j:\n    steps:\n      - run: pytest {opt} VALUE {SUITE}/\n")
        assert [r.targets for r in got] == [[SUITE]], (opt, [r.targets for r in got])
    # options are recorded with their values; a redirect's fd and target are not run targets
    assert runs[0].opts == [("-q", None), ("--ignore", "apps/sigil/tests/test_x.py"), ("-m", "not volume")]
    # every shell control operator AFTER pytest on its line is recorded (it can mask pytest's exit status)
    assert runs[0].chain == ["|"] and runs[1].chain == [] and runs[2].chain == []

    def one(cmd: str) -> list[Run]:
        return _pytest_runs(f"jobs:\n  j:\n    steps:\n      - run: {cmd}\n")
    assert one(f"pytest {SUITE}/ -rs||true")[0].chain == ["||"], "an unspaced || must still split off"
    assert one(f"pytest {SUITE}/; true")[0].chain == [";"]
    assert one(f"pytest {SUITE}/ && echo ok")[0].chain == ["&&"]
    assert one(f"cd . && pytest {SUITE}/")[0].chain == [], "an operator BEFORE pytest does not mask it"
    assert one(f"! pytest {SUITE}/")[0].negated
    assert one(f"pytest a ; pytest {SUITE}/")[1].targets == [SUITE], "a second pytest on the line is read too"
    assert one(f"pytest {SUITE}/ > out.txt 2> err")[0].targets == [SUITE]
    # --co is --collect-only: it runs nothing
    assert one(f"pytest --co {SUITE}/") == [] and one(f"pytest --collect-only {SUITE}/") == []
    sel = one(f"pytest -p no:randomly -p {PLANES_PLUGIN} -k 'not slow' -x --deselect a::b {SUITE}/")[0].selection()
    assert sel == [("--deselect", "a::b"), ("-k", "not slow"), ("-p", "no:randomly"), ("-x", None)], sel


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
            assert r.selection() == base.selection(), (
                f"the fold-cache-ON leg ({r.job}) selects with {r.selection()} but the default leg ({base.job}) "
                f"with {base.selection()}: the ON leg must run exactly the tests the OFF leg runs")


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
_RECORDER_TARGET = re.compile(rf"run_and_record\.py\b.*--target[ =]+{re.escape(SUITE)}(?:/|\s|$)")


def _suite_jobs(text: str) -> list[str]:
    """Jobs that run apps/sigil/tests: through pytest, or through tools/flake/run_and_record.py --target."""
    jobs = {r.job for r in _pytest_runs(text) if _runs_any_of_suite(r)}
    for job, (_head, steps) in _jobs(text).items():
        if any(_RECORDER_TARGET.search(ln) for st in steps for ln in _logical(_run_script(st))):
            jobs.add(job)
    return sorted(jobs)


def suite_lock_offenders(text: str, *, require_some: bool = True) -> list[str]:
    jobs = _suite_jobs(text)
    if require_some:
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


def _workflow_texts() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(_WORKFLOWS.glob("*.y*ml"))}


def test_every_workflow_that_runs_sigil_tests_installs_the_sovereign_lock():
    """Not only ci.yml: a scheduled workflow that runs apps/sigil/tests on the offense lock tests a tree SIGIL
    does not ship, so a sovereign pin bump could break SIGIL with every nightly job green."""
    texts = _workflow_texts()
    running = {name for name, text in texts.items() if _suite_jobs(text)}
    assert {"ci.yml", "concurrency-race.yml", "scheduled-chaos-failover.yml", "upgrade-harness-soak.yml"} <= running, \
        f"the reader no longer finds the known workflows that run {SUITE}: {sorted(running)}"
    bad = [f"{name}: {b}" for name, text in texts.items() for b in suite_lock_offenders(text, require_some=False)]
    assert not bad, "every workflow that runs the sigil suite must install the sovereign lock:\n  " + "\n  ".join(bad)


def test_negative_control_scheduled_workflow_lock_detector():
    text = (_WORKFLOWS / "concurrency-race.yml").read_text(encoding="utf-8")
    assert not suite_lock_offenders(text), "precondition: the real workflow is clean"
    reverted = text.replace(f"-r {SOVEREIGN_LOCK}", f"-r {OFFENSE_LOCK}")
    got = suite_lock_offenders(reverted)
    assert any("does not install" in b for b in got) and any("offense lock" in b for b in got), got
    # pip3 / python3 -m pip spellings are installs too
    for spelling in ("pip3 install", "python3 -m pip install", "python -m pip install"):
        variant = reverted.replace("pip install --require-hashes -r " + OFFENSE_LOCK,
                                   f"{spelling} --require-hashes -r {OFFENSE_LOCK}")
        assert any("offense lock" in b for b in suite_lock_offenders(variant)), spelling


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


def _is_literal_node_argv(node: ast.AST) -> bool:
    return (isinstance(node, (ast.List, ast.Tuple)) and bool(node.elts) and isinstance(node.elts[0], ast.Constant)
            and node.elts[0].value == "node")


def _calls_skip(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Call) and (
        (isinstance(n.func, ast.Attribute) and n.func.attr == "skip")
        or (isinstance(n.func, ast.Name) and n.func.id == "skip")) for n in ast.walk(node))


def _catches(handler: ast.ExceptHandler, names: set[str]) -> bool:
    t = handler.type
    if t is None:
        return True
    elts = t.elts if isinstance(t, ast.Tuple) else [t]
    return any(isinstance(e, ast.Name) and e.id in names or isinstance(e, ast.Attribute) and e.attr in names
               for e in elts)


def gate_violations(src: str) -> list[str]:
    """Every node lookup must sit inside the ``_need_node`` gate: a module-level ``skipif`` or an in-test
    ``if not which(node): return`` is exactly the silent skip/pass this guard exists to end. A literal
    ``["node", …]`` argv bypasses the gate (a missing node then raises FileNotFoundError, which a handler can
    turn into a skip), so node must be invoked by the gate's returned path, and no ``except FileNotFoundError``
    (or broader) handler may skip."""
    tree = ast.parse(src)
    bad: list[str] = []

    def walk(node: ast.AST, fn: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn
            if _is_node_which(child) and fn != NODE_GATE:
                bad.append(f"line {child.lineno}: node lookup outside {NODE_GATE}() (in {fn or 'module scope'})")
            if _is_literal_node_argv(child):
                bad.append(f"line {child.lineno}: a literal ['node', ...] argv — run node by {NODE_GATE}()'s path")
            if (isinstance(child, ast.ExceptHandler)
                    and _catches(child, {"FileNotFoundError", "OSError", "Exception", "BaseException"})
                    and _calls_skip(child)):
                bad.append(f"line {child.lineno}: an except handler that SKIPS (a missing node must fail in CI)")
            walk(child, inner)
    walk(tree, None)
    return bad


def gate_misbehaviours(src: str) -> list[str]:
    """Execute the file's OWN ``_need_node`` source in isolation (stub ``shutil.which``, an environment built
    here — ``GITHUB_ACTIONS`` and ``VIGIL_REQUIRE_NODE`` removed, then set per case, so the verdict is the same
    on a laptop and on a runner) and report every way it departs from: node missing + VIGIL_REQUIRE_NODE=1 ->
    FAIL; node missing + GITHUB_ACTIONS=true -> FAIL; node missing, neither set -> SKIP; node present -> its path
    returned, no skip, no fail."""
    tree = ast.parse(src)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == NODE_GATE), None)
    if fn is None:
        return [f"no module-level {NODE_GATE}() gate"]
    code = ast.get_source_segment(src, fn)
    assert code is not None
    problems: list[str] = []
    for found, flag, gha, want in ((None, "1", None, "fail"), (None, None, "true", "fail"),
                                   (None, None, None, "skip"), ("/usr/bin/node", "1", None, "return"),
                                   ("/usr/bin/node", None, "true", "return"), ("/usr/bin/node", None, None, "return")):
        stub = types.SimpleNamespace(which=lambda name, _f=found: _f if name == "node" else None)
        env = dict(os.environ)
        env.pop(NODE_FLAG, None)
        env.pop("GITHUB_ACTIONS", None)
        if flag is not None:
            env[NODE_FLAG] = flag
        if gha is not None:
            env["GITHUB_ACTIONS"] = gha
        ns: dict[str, object] = {"shutil": stub, "which": stub.which, "pytest": pytest,
                                 "os": types.SimpleNamespace(environ=env)}
        exec(compile(code, NODE_GATE, "exec"), ns)  # the repo's OWN gate source, isolated: that is what is tested
        try:
            got = ns[NODE_GATE]()  # type: ignore[operator]
            outcome = "return" if got == found else f"returned {got!r}"
        except pytest.fail.Exception:
            outcome = "fail"
        except pytest.skip.Exception:
            outcome = "skip"
        if outcome != want:
            problems.append(f"node={'present' if found else 'missing'}, {NODE_FLAG}={flag!r}, "
                            f"GITHUB_ACTIONS={gha!r}: {outcome}, want {want}")
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
    literal_argv = ("import subprocess\ndef test_x():\n    subprocess.run(['node', '-e', '1'], check=True)\n")
    assert any("literal" in v for v in gate_violations(literal_argv)), "a literal ['node', ...] argv was not flagged"
    assert any("literal" in v for v in gate_violations("ARGV = ('node', '--check', 'app.js')\n")), \
        "a literal ('node', ...) tuple was not flagged"
    fnf_skip = ("import subprocess, pytest\ndef test_x():\n    try:\n        subprocess.run([NODE, '-e', '1'])\n"
                "    except FileNotFoundError:\n        pytest.skip('no node')\n")
    assert any("SKIPS" in v for v in gate_violations(fnf_skip)), "except FileNotFoundError -> skip was not flagged"
    assert not gate_violations("def f():\n    try:\n        g()\n    except FileNotFoundError:\n        raise\n"), \
        "a handler that does not skip must not be flagged"
    assert any("want fail" in p for p in gate_misbehaviours(always_skip)), "a gate that ignores the flag passed"
    flag_only = ("def _need_node():\n    node = shutil.which('node')\n    if node is None:\n"
                 "        if os.environ.get('VIGIL_REQUIRE_NODE') == '1':\n            pytest.fail('need node')\n"
                 "        pytest.skip('node not installed')\n    return node\n")
    assert any("GITHUB_ACTIONS='true'" in p and "want fail" in p for p in gate_misbehaviours(flag_only)), \
        "a gate that skips on a CI runner (GITHUB_ACTIONS) without node was not flagged"
    returns_none = ("def _need_node():\n    if shutil.which('node') is None:\n        pytest.skip('no node')\n")
    assert any("want return" in p for p in gate_misbehaviours(returns_none)), \
        "a gate that does not return the node path (callers use it as argv[0]) was not flagged"
    text = _CI.read_text(encoding="utf-8")
    files = node_test_files()
    assert not node_ci_violations(text, files), "precondition: the real ci.yml is clean"
    stripped = re.sub(rf"(?m)^.*\b{NODE_FLAG}\b.*\n", "", text)
    got = node_ci_violations(stripped, files)
    assert {b.split(":", 1)[0] for b in got} == set(files), got
    assert any("'sigil-governor'" in b for b in got) and any("'crucible-core'" in b for b in got), got
    assert any("no ci.yml step runs it" in b for b in node_ci_violations(text, ["nowhere/tests/test_unrun.py"])), \
        "a node test that no ci.yml step runs was not flagged"


# --------------------------------------------------------------------------------------------------------------
# (d) every whole-suite leg (default and fold-cache ON) runs the suite as the sovereign tree, and its verdict
#     can be neither masked by the shell nor switched off by a condition
# --------------------------------------------------------------------------------------------------------------
_JOB_COND = re.compile(r"^    (if|continue-on-error):")
_STEP_COND = re.compile(r"^      (?:- |  )(if|continue-on-error):")
_ERREXIT_OFF = re.compile(r"\bset\s+(?:\+[A-Za-z]*e|\+o\s+errexit)\b")


def whole_suite_runs(text: str) -> list[Run]:
    return [r for r in _pytest_runs(text) if _runs_suite_whole(r)]


def closure_violations(run: Run) -> list[str]:
    """The sovereign closure is installed on every whole-suite leg, so a skip for it must FAIL there."""
    bad: list[str] = []
    if run.env(CLOSURE_FLAG) != "1":
        bad.append(f"{run.job}: {CLOSURE_FLAG} is not 1 on the whole-suite run")
    if ("-p", PLANES_PLUGIN) not in run.opts:
        bad.append(f"{run.job}: the whole-suite run does not load -p {PLANES_PLUGIN}")
    planes = {p.strip() for p in (run.env(PLANES_VAR) or "").split(",") if p.strip()}
    if not SOVEREIGN_CLOSURE_PLANES <= planes:
        bad.append(f"{run.job}: {PLANES_VAR} lacks {sorted(SOVEREIGN_CLOSURE_PLANES - planes)}")
    if ".github/scripts" not in (run.env("PYTHONPATH") or "").split(":"):
        bad.append(f"{run.job}: .github/scripts (where {PLANES_PLUGIN} lives) is not on PYTHONPATH")
    return bad


def leg_integrity_violations(run: Run) -> list[str]:
    """Nothing may mask or skip the whole-suite pytest: no control operator after it, no negation, no errexit
    switched off before it, no job/step ``if:`` or ``continue-on-error``, and no in-shell override of the fold
    flag (the flag may only come from ``env:`` or an inline prefix on the pytest command)."""
    bad: list[str] = []
    if run.chain:
        bad.append(f"{run.job}: shell operator(s) {run.chain} after the whole-suite pytest can mask its status")
    if run.negated:
        bad.append(f"{run.job}: the whole-suite pytest is negated with `!`")
    for ln in run.head:
        m = _JOB_COND.match(ln)
        if m:
            bad.append(f"{run.job}: job-level `{m.group(1)}:` on a whole-suite leg")
    for ln in run.step:
        m = _STEP_COND.match(ln)
        if m:
            bad.append(f"{run.job}: step-level `{m.group(1)}:` on the whole-suite step")
    script = _logical(_run_script(run.step))
    upto = script[:script.index(run.line) + 1] if run.line in script else script
    if any(_ERREXIT_OFF.search(ln) for ln in upto):
        bad.append(f"{run.job}: `set +e` before the whole-suite pytest lets a failure fall through")
    for ln in script:
        if FOLD_FLAG not in ln:
            continue
        if ln != run.line or re.search(rf"(?:\bunset\s+|\bexport\s+|-u\s*){FOLD_FLAG}\b|\benv\s+-i\b", ln):
            bad.append(f"{run.job}: the step's shell sets/unsets {FOLD_FLAG} ({ln.strip()!r}) — set it in env:")
    return bad


def test_every_whole_suite_leg_requires_the_sovereign_closure():
    runs = whole_suite_runs(_CI.read_text(encoding="utf-8"))
    assert {r.job for r in runs} >= {"sigil-governor", "sigil-fold-cache-on"}, [r.job for r in runs]
    bad = [b for r in runs for b in closure_violations(r)]
    assert not bad, "a whole-suite sigil leg must fail, not skip, on a missing sovereign package:\n  " + "\n  ".join(bad)


def test_no_whole_suite_leg_can_be_masked_or_skipped():
    runs = whole_suite_runs(_CI.read_text(encoding="utf-8"))
    bad = [b for r in runs for b in leg_integrity_violations(r)]
    assert not bad, "\n  ".join(bad)


def _perturb_job(text: str, job: str, old: str, new: str) -> str:
    """Apply one textual change inside ONE job's block only."""
    start = text.index(f"\n  {job}:\n")
    nxt = re.search(r"\n  [A-Za-z0-9_-]+:\n", text[start + 1:])
    end = start + 1 + nxt.start() if nxt else len(text)
    block = text[start:end]
    assert old in block, (job, old)
    return text[:start] + block.replace(old, new, 1) + text[end:]


def _perturb_on_leg(text: str, old: str, new: str) -> str:
    return _perturb_job(text, "sigil-fold-cache-on", old, new)


_ON_PYTEST = "python -m pytest -p pytest_require_planes"
_ON_STEP = "      - name: the whole apps/sigil/tests suite with VIGIL_FOLD_CACHE_ENABLED=1\n"
_ON_LINE = "          PYTHONPATH=apps/sigil:integration:.github/scripts python -m pytest"


def test_negative_controls_whole_suite_legs(real_fold_flag):
    text = _CI.read_text(encoding="utf-8")

    def on_runs(t: str) -> list[Run]:
        return fold_cache_on_suite_runs(t, real_fold_flag)

    def integrity(t: str) -> list[str]:
        return [b for r in on_runs(t) for b in leg_integrity_violations(r)]

    def closure(t: str) -> list[str]:
        return [b for r in whole_suite_runs(t) for b in closure_violations(r)]

    assert on_runs(text) and not integrity(text) and not closure(text), "precondition: the real ci.yml is clean"
    # --co on the ON leg: it no longer RUNS the suite
    assert not on_runs(_perturb_on_leg(text, _ON_PYTEST, _ON_PYTEST + " --co")), "--co was credited as a run"
    # a selection option on the ON leg only: the legs no longer run the same tests
    narrowed = _perturb_on_leg(text, _ON_PYTEST, _ON_PYTEST + " -k 'not slow'")
    off = [r for r in whole_suite_runs(narrowed) if not real_fold_flag(r.env(FOLD_FLAG))]
    assert any(r.selection() != b.selection() for r in on_runs(narrowed) for b in off), "-k on the ON leg unseen"
    # || true after the ON pytest; continue-on-error; step-level if:; job-level if:
    assert any("operator" in b for b in integrity(_perturb_on_leg(text, "apps/sigil/tests/ -rs", "apps/sigil/tests/ -rs || true")))
    assert any("operator" in b for b in integrity(_perturb_on_leg(text, "apps/sigil/tests/ -rs", "apps/sigil/tests/ -rs; true")))
    assert any("continue-on-error" in b for b in integrity(_perturb_on_leg(
        text, "    timeout-minutes: 30\n", "    timeout-minutes: 30\n    continue-on-error: true\n")))
    assert any("job-level `if:`" in b for b in integrity(_perturb_on_leg(
        text, "    timeout-minutes: 30\n", "    timeout-minutes: 30\n    if: false\n")))
    assert any("step-level `if:`" in b for b in integrity(_perturb_on_leg(text, _ON_STEP, _ON_STEP + "        if: false\n")))
    assert any("set +e" in b for b in integrity(_perturb_on_leg(text, _ON_LINE, "          set +e\n" + _ON_LINE)))
    # an in-shell export / unset of the fold flag before pytest
    for override in (f"export {FOLD_FLAG}=0", f"unset {FOLD_FLAG}", f"{FOLD_FLAG}=0"):
        got = integrity(_perturb_on_leg(text, _ON_LINE, f"          {override}\n" + _ON_LINE))
        assert any("sets/unsets" in b for b in got), (override, got)
    # the closure requirement dropped from the governor job, the plugin dropped, the planes narrowed
    gov = "sigil-governor"
    assert any(gov in b and CLOSURE_FLAG in b for b in closure(
        _perturb_job(text, gov, f'          {CLOSURE_FLAG}: "1"\n', "")))
    assert any(gov in b and PLANES_PLUGIN in b for b in closure(
        _perturb_job(text, gov, f"-p {PLANES_PLUGIN} ", "")))
    assert any(gov in b and "lacks" in b for b in closure(_perturb_job(text, gov, ",qdrant_client\n", "\n")))
    assert any(gov in b and ".github/scripts" in b for b in closure(
        _perturb_job(text, gov, "integration:.github/scripts ", "integration ")))


# --------------------------------------------------------------------------------------------------------------
# (e) a sovereign-closure test may not swallow ANY error into a skip
# --------------------------------------------------------------------------------------------------------------
def broad_except_skips(src: str) -> list[str]:
    """``except Exception`` (or bare / BaseException) whose body skips turns ANY failure — a broken module, a
    raising import, a bad model file — into a green skip. Narrow it to the availability error instead."""
    out: list[str] = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.ExceptHandler) and _catches(node, {"Exception", "BaseException"}) and _calls_skip(node):
            out.append(f"line {node.lineno}: a broad except handler that skips")
    return out


def test_no_sigil_test_turns_any_error_into_a_skip():
    here = _REPO / SUITE
    bad = [f"{p.relative_to(_REPO).as_posix()}: {v}" for p in sorted(here.rglob("*.py")) if p.name != _ME
           for v in broad_except_skips(p.read_text(encoding="utf-8"))]
    assert not bad, "\n  ".join(bad)


def test_negative_control_broad_except_skip_detector():
    broad = "import pytest\ntry:\n    import x\nexcept Exception as e:\n    pytest.skip(str(e))\n"
    assert broad_except_skips(broad)
    assert broad_except_skips("import pytest\ntry:\n    import x\nexcept:\n    pytest.skip('x')\n")
    assert broad_except_skips("import pytest\ntry:\n    f()\nexcept (ValueError, Exception):\n    pytest.skip('x')\n")
    assert not broad_except_skips("import pytest\ntry:\n    import x\nexcept ImportError:\n    pytest.skip('x')\n")


# --------------------------------------------------------------------------------------------------------------
# (f) the golden-embedding test runs offline against a warmed, pinned model cache on every whole-suite leg
# --------------------------------------------------------------------------------------------------------------
_EMBED_SRC = "apps/sigil/sigil/vectors/embed.py"
_EMBED_CACHE_ENV = "SIGIL_EMBED_CACHE_DIR"


def _step_env(head: list[str], step: list[str], name: str) -> str | None:
    v = _yaml_env(step, name)
    return v if v is not None else _yaml_env(head, name)


def model_cache_violations(text: str, run: Run) -> list[str]:
    bad: list[str] = []
    if run.env("HF_HUB_OFFLINE") != "1":
        bad.append(f"{run.job}: the whole-suite run is not HF_HUB_OFFLINE=1 (pytest could reach the network)")
    cache = run.env(_EMBED_CACHE_ENV)
    if not cache:
        bad.append(f"{run.job}: no {_EMBED_CACHE_ENV} on the whole-suite run")
        return bad
    head, steps = _jobs(text)[run.job]
    here = steps.index(run.step) if run.step in steps else len(steps)
    before = steps[:here]
    prefetch = [i for i, st in enumerate(before)
                if any("sigil.vectors.embed" in ln and "prefetch(" in ln for ln in _logical(_run_script(st)))]
    if not prefetch:
        bad.append(f"{run.job}: no step before the suite calls sigil.vectors.embed.prefetch()")
    elif _step_env(head, before[prefetch[-1]], _EMBED_CACHE_ENV) != cache:
        bad.append(f"{run.job}: the prefetch step warms a different {_EMBED_CACHE_ENV} than the suite reads")
    elif _step_env(head, before[prefetch[-1]], "HF_HUB_OFFLINE") == "1":
        bad.append(f"{run.job}: the prefetch step is offline, so it can never fetch")
    cached = [i for i, st in enumerate(before)
              if any(re.search(r"uses:\s*actions/cache@", ln) for ln in st)
              and _yaml_env(st, "path") == cache
              and f"hashFiles('{_EMBED_SRC}')" in (_yaml_env(st, "key") or "")]
    if not cached or (prefetch and cached[-1] > prefetch[-1]):
        bad.append(f"{run.job}: no actions/cache of {cache} keyed on {_EMBED_SRC} before the prefetch step")
    return bad


def test_every_whole_suite_leg_runs_the_embedding_test_offline_on_a_warmed_cache():
    text = _CI.read_text(encoding="utf-8")
    runs = whole_suite_runs(text)
    assert {r.job for r in runs} >= {"sigil-governor", "sigil-fold-cache-on"}
    bad = [b for r in runs for b in model_cache_violations(text, r)]
    assert not bad, "\n  ".join(bad)


def test_negative_controls_model_cache():
    text = _CI.read_text(encoding="utf-8")

    def bad(t: str) -> list[str]:
        return [b for r in whole_suite_runs(t) for b in model_cache_violations(t, r)]

    assert not bad(text), "precondition: the real ci.yml is clean"
    on = "sigil-fold-cache-on"
    no_offline = _perturb_job(text, on, '          HF_HUB_OFFLINE: "1"\n', "")
    assert any(on in b and "HF_HUB_OFFLINE" in b for b in bad(no_offline))
    no_prefetch = _perturb_job(text, on, "from sigil.vectors.embed import prefetch; print(prefetch())", "print(1)")
    assert any(on in b and "prefetch()" in b for b in bad(no_prefetch))
    gov = "sigil-governor"
    no_cache = _perturb_job(text, gov, f"key: bge-onnx-${{{{ hashFiles('{_EMBED_SRC}') }}}}", "key: bge-onnx-static")
    assert any(gov in b and "actions/cache" in b for b in bad(no_cache))
    elsewhere = _perturb_job(text, gov, f"      {_EMBED_CACHE_ENV}: /tmp/sigil-embed-cache\n",
                             f"      {_EMBED_CACHE_ENV}: /tmp/elsewhere\n")
    assert any(gov in b for b in bad(elsewhere)), "a suite reading a cache the cache step does not persist passed"

