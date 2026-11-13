"""The NAMED-MUTANT corpus runner — a deterministic, bounded, per-plane kill table for a hand-picked subset
of the money/gate files.

WHY THIS EXISTS (W11-3, issue #484). mutmut / cosmic-ray (the scheduled kill-suite) mutate only the
vigil_core-scoped ``mutation: true`` files: their single runner command cannot load ``framework`` beside the
sovereign-purity asserts, so the K4 money/gate files under ``apps/sigil`` and the engine gates under
``engine/crucible`` are ``mutation: false`` in ``critical-set.json``. Their mutation evidence lived only in
PR bodies, with nothing in the repo that re-runs it. This runner re-runs it for the files flagged
``named_mutants: true`` — a SUBSET of the ``mutation: false`` python files (``uncovered_files`` lists the
rest, which stay covered only by their own suites), and for each flagged file only the guards its corpus
entry names, not every mutant a PR body may have reported:

  * the corpus (``tools/mutation/named-mutants.json``) names, per file, a FIXED list of mutants — each an
    exact ``old`` -> ``new`` source replacement for ONE guard, plus the test node(s) that must kill it;
  * a run is ONE plane in its own process tree: the sovereign plane runs with a PYTHONPATH built from
    scratch that never contains ``engine/crucible`` (FATAL-2), and the offense plane runs from
    ``engine/crucible`` without ``apps/sigil`` — so the two planes never share an interpreter;
  * per file it first runs the union of the named tests on the UNMUTATED source (the baseline must be
    green, else a "kill" means nothing), then applies each mutant, runs only that mutant's named tests,
    and ALWAYS restores the original bytes (and mtime) before the next mutant;
  * before any test runs, the (mutated or original) module is IMPORTED on its own in the plane's
    environment: a mutant that does not import is ERROR, never a kill;
  * a mutant is KILLED only when pytest exits 1 AND a named test failed by an ASSERTION (an
    ``AssertionError`` or a ``pytest.fail``, ``DID NOT RAISE`` included), recorded by a probe plugin in
    the child. A test that fails by any other exception (a ``NameError`` the mutant introduced, a
    ``ValidationError`` from code past the broken guard), or that fails in its setup or teardown phase
    (an assertion in a fixture included), is CRASHED: reported, and never a kill. Exit 0 is SURVIVED;
    anything else (collection/usage error, no tests, timeout, a mutant that does not compile) is ERROR.
    So a broken mutant can never pad the score;
  * the original bytes are also kept in a sidecar (``<file>.named-mutant.orig``) while a mutant is
    applied. It is written ATOMICALLY before the mutant touches the source (a temp file in the same
    directory, fsynced, then renamed into place) and its header records the sha256 of the original;
  * at startup, BEFORE the corpus is validated, the sidecar of every file the corpus names is restored
    (a mutant a killed run left applied has removed its own ``old`` text, so the corpus would not validate
    first). Only a sidecar that verifies is restored from; one that does not is refused, and the source
    and the sidecar are left exactly as found. One run at a time holds the tree (an exclusive ``flock``),
    so that restore never reverts a mutant a live run has applied.

The output is a Markdown kill table (optionally appended to ``$GITHUB_STEP_SUMMARY``) and a JSON record.
Exit status: 0 iff every selected mutant was KILLED over a green baseline; 1 otherwise; 2 if the corpus
itself does not validate (a stale ``old`` string, an unknown test, a plane leak, ...); 3 if the runner
refuses to touch the tree (another run holds it, or a sidecar an interrupted run left does not verify:
nothing is restored, validated or run, and the source and the sidecar are left as found). The same
``validate_corpus`` runs on every PR in integration/tests/test_mutation_critical_set.py, so the corpus
cannot silently rot between scheduled runs.

STDLIB ONLY. It imports nothing from either plane; it only spawns ``python -m pytest`` children.

Usage (repo root):
    python tools/mutation/named_mutants.py --plane sovereign
    python tools/mutation/named_mutants.py --plane offense --file engine/crucible/framework/v2/kernel/routing.py
    python tools/mutation/named_mutants.py --plane sovereign --list
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover — no flock on this platform: runs are not serialised
    fcntl = None  # type: ignore[assignment]

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "tools" / "mutation" / "named-mutants.json"
CRITICAL_SET = REPO / "tools" / "mutation" / "critical-set.json"

PLANES = ("sovereign", "offense")
KILLED = "KILLED"
SURVIVED = "SURVIVED"
CRASHED = "CRASHED"     # tests failed, but by an exception other than an assertion: never a kill
ERROR = "ERROR"

SIDECAR_SUFFIX = ".named-mutant.orig"
SIDECAR_FORMAT = "named-mutants-sidecar/1"
PROBE_MODULE = "_named_mutants_probe"
# Loaded into every pytest child (-p): records, per failed test phase, whether it failed by an ASSERTION.
PROBE_SOURCE = '''"""named_mutants probe: per failed test phase, the exception type and whether it is an assertion."""
import json
import os

import pytest

_ROWS = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.failed:
        exc = call.excinfo
        value = exc.value if exc is not None else None
        assertion = rep.when == "call" and isinstance(value, (AssertionError, pytest.fail.Exception))
        _ROWS.append({"nodeid": item.nodeid, "when": rep.when, "type": exc.typename if exc else "",
                      "assertion": bool(assertion)})


def pytest_sessionfinish(session, exitstatus):
    with open(os.environ["NAMED_MUTANTS_PROBE_OUT"], "w", encoding="utf-8") as fh:
        json.dump(_ROWS, fh)
'''

DEFAULT_TIMEOUT_S = 600.0


# --------------------------------------------------------------------------------------------------
# Corpus loading + validation (pure, stdlib — the per-PR guard calls validate_corpus directly).
# --------------------------------------------------------------------------------------------------
def load_corpus(path: Path = CORPUS) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def critical_python_paths(path: Path = CRITICAL_SET) -> set[str]:
    man = json.loads(Path(path).read_text(encoding="utf-8"))
    return {e["path"] for e in man["critical_set"] if e.get("lang") == "python"}


def uncovered_files(corpus: dict, path: Path = CRITICAL_SET) -> list[str]:
    """The ``mutation: false`` python files of critical-set.json that the corpus does NOT mutate (covered only
    by their own suites and the per-slice mutation-verify), sorted."""
    man = json.loads(Path(path).read_text(encoding="utf-8"))
    off = {e["path"] for e in man["critical_set"] if e.get("lang") == "python" and e.get("mutation") is False}
    return sorted(off - {f["path"] for f in corpus.get("files") or []})


def module_name(rel: str, pythonpath: list[str]) -> str:
    """The dotted module ``rel`` imports as under the plane's pythonpath (the deepest root that holds it), or ""."""
    roots = sorted((r.rstrip("/") for r in pythonpath if r.strip("/") and _under(rel, [r])), key=len, reverse=True)
    if not roots or not rel.endswith(".py"):
        return ""
    parts = rel[len(roots[0]) + 1 : -3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts and all(p.isidentifier() for p in parts) else ""


def _under(rel: str, roots: list[str]) -> bool:
    return any(rel == r.rstrip("/") or rel.startswith(r.rstrip("/") + "/") for r in roots)


def _test_defined(test_file: Path, qual: str) -> bool:
    """True iff ``qual`` (``func`` or ``Class::method``; a ``[param]`` suffix is ignored) is defined in the file."""
    parts = qual.split("[", 1)[0].split("::")
    try:
        tree = ast.parse(test_file.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return False
    body: list[ast.stmt] = tree.body
    for i, name in enumerate(parts):
        last = i == len(parts) - 1
        found: Optional[ast.stmt] = None
        for node in body:
            if last and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                found = node
            elif not last and isinstance(node, ast.ClassDef) and node.name == name:
                found = node
        if found is None:
            return False
        if not last:
            body = found.body  # type: ignore[attr-defined]
    return True


def validate_corpus(corpus: dict, repo: Path = REPO, critical: Optional[set[str]] = None) -> list[str]:
    """Every problem that would make a run meaningless or a kill un-attributable. Empty list == valid."""
    problems: list[str] = []
    crit = critical if critical is not None else critical_python_paths(repo / "tools" / "mutation" / "critical-set.json")
    planes = corpus.get("planes") or {}
    if set(planes) != set(PLANES):
        problems.append(f"planes must be exactly {sorted(PLANES)}, got {sorted(planes)}")
    for name, pl in planes.items():
        cwd = repo / pl.get("cwd", "")
        if not cwd.is_dir():
            problems.append(f"plane {name}: cwd {pl.get('cwd')!r} is not a directory")
        pp = pl.get("pythonpath") or []
        if not pp:
            problems.append(f"plane {name}: empty pythonpath")
        for p in pp:
            if not (repo / p).is_dir():
                problems.append(f"plane {name}: pythonpath entry {p!r} is not a directory")
        forbidden = pl.get("forbidden_pythonpath") or []
        if not forbidden:
            problems.append(f"plane {name}: must name the other plane's roots in forbidden_pythonpath")
        for p in pp:
            if _under(p, forbidden) or any(_under(f, [p]) for f in forbidden):
                problems.append(f"plane {name}: pythonpath entry {p!r} leaks a forbidden root {forbidden}")
        for key in ("source_roots", "test_roots"):
            if not pl.get(key):
                problems.append(f"plane {name}: missing {key}")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    files = corpus.get("files") or []
    if not files:
        problems.append("the corpus names no files")
    for entry in files:
        rel = entry.get("path", "")
        plane = entry.get("plane")
        where = f"{rel} [{plane}]"
        if rel in seen_paths:
            problems.append(f"{where}: file listed twice")
        seen_paths.add(rel)
        if plane not in planes:
            problems.append(f"{where}: unknown plane {plane!r}")
            continue
        pl = planes[plane]
        src_path = repo / rel
        if not src_path.is_file():
            problems.append(f"{where}: source file does not exist")
            continue
        if rel not in crit:
            problems.append(f"{where}: not a python entry of tools/mutation/critical-set.json")
        if not _under(rel, pl.get("source_roots") or []):
            problems.append(f"{where}: not under the {plane} plane's source_roots {pl.get('source_roots')}")
        if _under(rel, pl.get("forbidden_pythonpath") or []):
            problems.append(f"{where}: lives under a root the {plane} plane forbids")
        if not module_name(rel, pl.get("pythonpath") or []):
            problems.append(f"{where}: is not an importable module under the {plane} plane's pythonpath")
        text = src_path.read_text(encoding="utf-8")
        mutants = entry.get("mutants") or []
        if not mutants:
            problems.append(f"{where}: no mutants")
        for m in mutants:
            mid = m.get("id", "")
            tag = f"{where} mutant {mid!r}"
            if not mid:
                problems.append(f"{where}: a mutant has no id")
            elif mid in seen_ids:
                problems.append(f"{tag}: duplicate mutant id")
            seen_ids.add(mid)
            if not m.get("guard"):
                problems.append(f"{tag}: must state the guard it breaks")
            old, new = m.get("old", ""), m.get("new")
            if not old:
                problems.append(f"{tag}: empty 'old'")
                continue
            if new is None or new == old:
                problems.append(f"{tag}: 'new' must differ from 'old'")
                continue
            n = text.count(old)
            if n != 1:
                problems.append(f"{tag}: 'old' must occur exactly once in {rel}, found {n} (stale corpus?)")
                continue
            try:
                compile(text.replace(old, new, 1), str(src_path), "exec", dont_inherit=True)
            except SyntaxError as e:
                problems.append(f"{tag}: the mutant does not compile ({e.msg}, line {e.lineno})")
            tests = m.get("tests") or []
            if not tests:
                problems.append(f"{tag}: names no killing test")
            for node in tests:
                tpath, _, qual = node.partition("::")
                if not _under(tpath, pl.get("test_roots") or []):
                    problems.append(f"{tag}: test {node!r} is not under the {plane} plane's test_roots")
                if _under(tpath, pl.get("forbidden_pythonpath") or []):
                    problems.append(f"{tag}: test {node!r} lives under a root the {plane} plane forbids")
                tf = repo / tpath
                if not tf.is_file():
                    problems.append(f"{tag}: test file {tpath!r} does not exist")
                elif qual and not _test_defined(tf, qual):
                    problems.append(f"{tag}: test {qual!r} is not defined in {tpath}")
    return problems


# --------------------------------------------------------------------------------------------------
# Execution.
# --------------------------------------------------------------------------------------------------
@dataclass
class Result:
    path: str
    mutant: str
    guard: str
    tests: list[str]
    verdict: str
    detail: str = ""
    seconds: float = 0.0


@dataclass
class FileRun:
    path: str
    plane: str
    baseline_ok: bool
    baseline_detail: str
    baseline_seconds: float = 0.0
    results: list[Result] = field(default_factory=list)


def plane_env(corpus: dict, plane: str, repo: Path, scratch: Path) -> dict[str, str]:
    """The child environment for ONE plane: PYTHONPATH rebuilt from scratch (absolute, never inherited),
    a fresh SIGIL_HOME and VIGIL_BASE_DIR, and a private bytecode cache so a stale .pyc can never stand in for
    a mutant (or for the restored original)."""
    pl = corpus["planes"][plane]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str((repo / p).resolve()) for p in pl["pythonpath"])
    home = scratch / "sigil-home"
    home.mkdir(parents=True, exist_ok=True)
    env["SIGIL_HOME"] = str(home)
    base = scratch / "vigil-base"
    base.mkdir(parents=True, exist_ok=True)
    env["VIGIL_BASE_DIR"] = str(base)
    pyc = scratch / "pycache"
    pyc.mkdir(parents=True, exist_ok=True)
    env["PYTHONPYCACHEPREFIX"] = str(pyc)
    env.pop("PYTEST_ADDOPTS", None)
    return env


def _run_pytest(tests: list[str], cwd: Path, env: dict[str, str], python: str, timeout: float,
                stop_first: bool) -> tuple[Optional[int], str, float, Optional[list[dict]]]:
    """(returncode | None on timeout, tail of output, seconds, the probe's failure rows | None if unread)."""
    probe_dir = Path(env["SIGIL_HOME"]).parent / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    (probe_dir / f"{PROBE_MODULE}.py").write_text(PROBE_SOURCE, encoding="utf-8")
    out_path = probe_dir / "rows.json"
    out_path.unlink(missing_ok=True)
    env = dict(env)
    env["PYTHONPATH"] = os.pathsep.join([str(probe_dir), env["PYTHONPATH"]])
    env["NAMED_MUTANTS_PROBE_OUT"] = str(out_path)
    cmd = [python, "-m", "pytest", "-p", "no:cacheprovider", "-p", PROBE_MODULE]
    if stop_first:
        cmd.append("-x")
    cmd += tests
    t0 = time.monotonic()
    try:
        cp = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timeout after {timeout:.0f}s", time.monotonic() - t0, None
    out = (cp.stdout or "") + (cp.stderr or "")
    tail = " | ".join(line.strip() for line in out.strip().splitlines()[-3:])
    try:
        rows = json.loads(out_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        rows = None
    return cp.returncode, tail, time.monotonic() - t0, rows


def _imports(module: str, cwd: Path, env: dict[str, str], python: str, timeout: float) -> tuple[bool, str]:
    """Does ``module`` import on its own in this plane's environment? (ok, last line of the error)."""
    try:
        cp = subprocess.run([python, "-c", "import importlib, sys; importlib.import_module(sys.argv[1])", module],
                            cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"import timed out after {timeout:.0f}s"
    err = (cp.stderr or "").strip().splitlines()
    return cp.returncode == 0, (err[-1] if err else f"rc={cp.returncode}")


def classify(rc: Optional[int], rows: Optional[list[dict]], tail: str) -> tuple[str, str]:
    """(verdict, detail) for one mutant's test run. KILLED needs pytest rc 1 AND a test that failed by an
    assertion in its call phase; a failure by any other exception is CRASHED; everything else is not a kill."""
    if rc is None:
        return ERROR, f"timed out (not a kill): {tail}"
    if rc == 0:
        return SURVIVED, "the named tests PASS on the mutant: " + tail
    if rc != 1:
        return ERROR, f"rc={rc} (not a kill): {tail}"
    if rows is None:
        return ERROR, f"rc=1 but the failure probe recorded nothing (not a kill): {tail}"
    if any(r.get("assertion") and r.get("when") == "call" for r in rows):
        return KILLED, tail
    if rows:
        kinds = sorted({f"{r.get('type') or '?'} in {r.get('when')}" for r in rows})
        return CRASHED, "failed by an exception, not an assertion (not a kill): " + ", ".join(kinds)
    return ERROR, f"rc=1 with no failed test recorded (not a kill): {tail}"


class SidecarError(RuntimeError):
    """A sidecar that does not verify: nothing is restored from it, and the source and the sidecar stay as found."""


def sidecar(src: Path) -> Path:
    return src.with_name(src.name + SIDECAR_SUFFIX)


def _fsync_dir(d: Path) -> None:
    """Make a rename in ``d`` durable (where a directory can be opened and fsynced at all)."""
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:  # pragma: no cover — a platform that cannot open a directory
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover — a filesystem that cannot fsync a directory
        pass
    finally:
        os.close(fd)


def write_sidecar(src: Path, original: bytes, st: os.stat_result) -> Path:
    """Keep ``original`` (what ``src`` holds before a mutant is applied) in its sidecar, ATOMICALLY: a one-line
    JSON header recording the sha256 of the original (and its atime/mtime), then the original bytes, written to
    a temp file in the sidecar's own directory, fsynced, and only then renamed into place. A crash at any point
    leaves no sidecar or a whole one; run_file applies the mutant only after this returns."""
    side = sidecar(src)
    head = json.dumps({"format": SIDECAR_FORMAT, "sha256": _sha(original),
                       "atime_ns": st.st_atime_ns, "mtime_ns": st.st_mtime_ns}, sort_keys=True)
    fd, tmp = tempfile.mkstemp(prefix=side.name + ".", suffix=".tmp", dir=side.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(head.encode("ascii") + b"\n" + original)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, side)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    _fsync_dir(side.parent)
    return side


def read_sidecar(side: Path) -> tuple[bytes, int, int]:
    """(original bytes, atime_ns, mtime_ns) from a sidecar whose header records the sha256 of exactly the bytes
    that follow it. Anything else (cut short by a crash, altered, not this format) raises SidecarError."""
    head, sep, body = side.read_bytes().partition(b"\n")
    try:
        meta = json.loads(head.decode("ascii")) if sep else None
    except ValueError:
        meta = None
    if not isinstance(meta, dict) or meta.get("format") != SIDECAR_FORMAT:
        raise SidecarError(f"{side}: not a {SIDECAR_FORMAT} sidecar (no valid header)")
    atime_ns, mtime_ns = meta.get("atime_ns"), meta.get("mtime_ns")
    if meta.get("sha256") != _sha(body) or not isinstance(atime_ns, int) or not isinstance(mtime_ns, int):
        raise SidecarError(f"{side}: the {len(body)} bytes it holds do not match the sha256 its header records "
                           "(cut short or altered)")
    return body, atime_ns, mtime_ns


def restore_interrupted(src: Path) -> bool:
    """If an interrupted run left ``src`` mutated, its sidecar holds the original: put it back (bytes and
    mtime). True if restored. Only a sidecar that VERIFIES is restored from: one that does not raises
    SidecarError and leaves the source and the sidecar exactly as found, for a hand to inspect. The sidecar is
    removed only once the source holds the original again."""
    side = sidecar(src)
    if not side.is_file():
        return False
    original, atime_ns, mtime_ns = read_sidecar(side)
    with open(src, "wb") as fh:
        fh.write(original)
        fh.flush()
        os.fsync(fh.fileno())
    os.utime(src, ns=(atime_ns, mtime_ns))
    if _sha(src.read_bytes()) != _sha(original):  # pragma: no cover — a restore that did not land
        raise SidecarError(f"FAILED TO RESTORE {src} from {side} (the sidecar is kept)")
    side.unlink()
    return True


def restore_interrupted_files(corpus: dict, repo: Path) -> tuple[list[str], list[str]]:
    """The interrupted-run restore for EVERY file the corpus names (both planes), run before the corpus is
    validated or any source is read: a mutant a killed run left applied has removed its own ``old`` text, so
    validating first would refuse the corpus as stale and leave the mutated source and its sidecar in place.
    (restored paths, refusals); a refused file's source and sidecar are left as found."""
    restored: list[str] = []
    refused: list[str] = []
    for entry in corpus.get("files") or []:
        rel = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(rel, str) or not rel:
            continue  # validate_corpus reports it
        try:
            if restore_interrupted(repo / rel):
                restored.append(rel)
        except (SidecarError, OSError) as e:
            refused.append(f"{rel}: {e}")
    return restored, refused


@contextlib.contextmanager
def _tree_lock(repo: Path) -> Iterator[bool]:
    """An exclusive, non-blocking ``flock`` on the tree's root directory for the life of the run: True if this
    run holds the tree, False if another run does (two runs in one tree would otherwise revert each other's
    applied mutants at startup). The kernel drops it when the process dies, SIGKILL included."""
    if fcntl is None:  # pragma: no cover
        yield True
        return
    fd = os.open(repo, os.O_RDONLY)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


def _abs_tests(nodes: list[str], repo: Path) -> list[str]:
    out = []
    for node in nodes:
        tpath, sep, qual = node.partition("::")
        out.append(str((repo / tpath).resolve()) + (sep + qual if sep else ""))
    return out


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run_file(entry: dict, corpus: dict, repo: Path, *, python: str = sys.executable,
             timeout: float = DEFAULT_TIMEOUT_S, only: Optional[set[str]] = None) -> FileRun:
    plane = entry["plane"]
    cwd = repo / corpus["planes"][plane]["cwd"]
    src = repo / entry["path"]
    if restore_interrupted(src):
        print(f"[named-mutants] restored {entry['path']} from the sidecar an interrupted run left", flush=True)
    module = module_name(entry["path"], corpus["planes"][plane]["pythonpath"])
    original = src.read_bytes()
    st = src.stat()
    text = original.decode("utf-8")
    mutants = [m for m in entry["mutants"] if only is None or m["id"] in only]
    union: list[str] = []
    for m in mutants:
        for t in m["tests"]:
            if t not in union:
                union.append(t)
    run = FileRun(path=entry["path"], plane=plane, baseline_ok=False, baseline_detail="")
    if not mutants:
        run.baseline_ok = True
        return run
    with tempfile.TemporaryDirectory(prefix="named-mutants-") as td:
        scratch = Path(td)
        base_env = plane_env(corpus, plane, repo, scratch / "base")
        imported, why = _imports(module, cwd, base_env, python, timeout) if module else (False, "no module name")
        if not imported:
            run.baseline_detail = f"the unmutated module {module or entry['path']} does not import: {why}"
        else:
            rc, tail, secs, _rows = _run_pytest(_abs_tests(union, repo), cwd, base_env, python, timeout,
                                                stop_first=False)
            run.baseline_ok = rc == 0
            run.baseline_detail = ("timed out" if rc is None else f"rc={rc}") + f": {tail}"
            run.baseline_seconds = round(secs, 2)
        for i, m in enumerate(mutants):
            res = Result(path=entry["path"], mutant=m["id"], guard=m["guard"], tests=list(m["tests"]),
                         verdict=ERROR)
            if not run.baseline_ok:
                res.detail = f"baseline not green, nothing scored: {run.baseline_detail}"
                run.results.append(res)
                continue
            if text.count(m["old"]) != 1:
                res.detail = "stale: 'old' no longer occurs exactly once"
                run.results.append(res)
                continue
            mutated = text.replace(m["old"], m["new"], 1)
            try:
                compile(mutated, str(src), "exec", dont_inherit=True)
            except SyntaxError as e:
                res.detail = f"mutant does not compile: {e.msg}"
                run.results.append(res)
                continue
            env = plane_env(corpus, plane, repo, scratch / f"m{i}")
            try:
                write_sidecar(src, original, st)
                src.write_bytes(mutated.encode("utf-8"))
                imported, why = _imports(module, cwd, env, python, timeout)
                if imported:
                    rc, tail, secs, rows = _run_pytest(_abs_tests(m["tests"], repo), cwd, env, python, timeout,
                                                       stop_first=True)
            finally:
                src.write_bytes(original)
                os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))
                sidecar(src).unlink(missing_ok=True)
            if _sha(src.read_bytes()) != _sha(original):  # pragma: no cover — a restore that did not land
                raise RuntimeError(f"FAILED TO RESTORE {src} — fix the tree before anything else")
            if not imported:
                res.detail = f"the mutant does not import (not a kill): {why}"
            else:
                res.seconds = round(secs, 2)
                res.verdict, res.detail = classify(rc, rows, tail)
            run.results.append(res)
            shutil.rmtree(scratch / f"m{i}", ignore_errors=True)
    return run


def kill_table(runs: list[FileRun], plane: str, uncovered: Optional[list[str]] = None) -> str:
    runs = [fr for fr in runs if fr.results]           # a file with no selected mutant ran nothing: no row
    rows = [r for fr in runs for r in fr.results]
    killed = sum(1 for r in rows if r.verdict == KILLED)
    lines = [f"### Named-mutant kill table — {plane} plane: {killed}/{len(rows)} killed", ""]
    if uncovered is not None:
        lines += [f"Scope: the corpus mutates the files flagged `named_mutants: true`, a hand-picked subset of the "
                  f"`mutation: false` python files; {len(uncovered)} of those carry no named mutants and are "
                  "covered only by their own suites: " + ", ".join(f"`{u}`" for u in uncovered), ""]
    for fr in runs:
        state = "green" if fr.baseline_ok else f"NOT GREEN ({fr.baseline_detail})"
        lines.append(f"- baseline (unmutated) `{fr.path}`: {state}, {fr.baseline_seconds}s")
    lines += ["", "| file | mutant | guard broken | killed by | verdict | s |", "|---|---|---|---|---|---|"]
    for r in rows:
        tests = "<br>".join(f"`{t.split('/')[-1]}`" for t in r.tests)
        lines.append(f"| `{r.path.split('/')[-1]}` | `{r.mutant}` | {r.guard} | {tests} | **{r.verdict}** | {r.seconds} |")
    bad = [r for r in rows if r.verdict != KILLED]
    if bad:
        lines += ["", "Not killed:"]
        lines += [f"- `{r.mutant}`: {r.verdict} — {r.detail}" for r in bad]
    return "\n".join(lines) + "\n"


def _install_signal_restore() -> None:
    """SIGTERM (a CI cancel), SIGHUP (a closed terminal) and SIGQUIT become KeyboardInterrupt, so the
    ``finally`` restore in run_file runs; a SIGKILL is covered by the sidecar the next run restores."""
    def _raise(signum: int, frame: Any) -> None:  # noqa: ARG001
        raise KeyboardInterrupt(f"signal {signum}")
    for name in ("SIGTERM", "SIGHUP", "SIGQUIT"):
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, _raise)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--plane", required=True, choices=PLANES, help="run ONE plane per process")
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--file", action="append", default=[], help="repo-relative source file (repeatable)")
    ap.add_argument("--mutant", action="append", default=[], help="mutant id (repeatable)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="per-pytest-run timeout (s)")
    ap.add_argument("--python", default=sys.executable, help="interpreter for the pytest children")
    ap.add_argument("--json", dest="json_out", default="", help="write the results as JSON here")
    ap.add_argument("--summary-md", default="", help="append the Markdown kill table here")
    ap.add_argument("--list", action="store_true", help="list the selected mutants and exit")
    args = ap.parse_args(argv)

    with _tree_lock(REPO) as held:
        if not held:
            print(f"another named-mutants run holds {REPO}: refusing to touch its sources", file=sys.stderr)
            return 3
        return _run(args)


def _run(args: argparse.Namespace) -> int:
    corpus = load_corpus(Path(args.corpus))
    restored, refused = restore_interrupted_files(corpus, REPO)
    for rel in restored:
        print(f"[named-mutants] restored {rel} from the sidecar an interrupted run left", flush=True)
    if refused:
        print("named-mutants: a sidecar an interrupted run left does not verify, so nothing was restored from "
              "it and nothing ran; the source and the sidecar are left as found, for a hand to inspect:",
              file=sys.stderr)
        for why in refused:
            print(f"  - {why}", file=sys.stderr)
        return 3
    problems = validate_corpus(corpus, REPO)
    if problems:
        print("named-mutant corpus does not validate:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2
    entries = [e for e in corpus["files"] if e["plane"] == args.plane and (not args.file or e["path"] in args.file)]
    only = set(args.mutant) or None
    if args.file and len(entries) != len(set(args.file)):
        print(f"--file names a path that is not a {args.plane}-plane corpus entry: {args.file}", file=sys.stderr)
        return 2
    if only:
        known = {m["id"] for e in entries for m in e["mutants"]}
        if only - known:
            print(f"unknown mutant id(s) for this selection: {sorted(only - known)}", file=sys.stderr)
            return 2
        entries = [e for e in entries if any(m["id"] in only for m in e["mutants"])]
    if args.list:
        for e in entries:
            for m in e["mutants"]:
                if only is None or m["id"] in only:
                    print(f"{e['path']}\t{m['id']}\t{m['guard']}\t{' '.join(m['tests'])}")
        return 0
    if not entries:
        print(f"no {args.plane}-plane entries selected", file=sys.stderr)
        return 2

    _install_signal_restore()
    pp = corpus["planes"][args.plane]["pythonpath"]
    print(f"[named-mutants] plane={args.plane} PYTHONPATH={':'.join(pp)} cwd={corpus['planes'][args.plane]['cwd']} "
          f"python={args.python}", flush=True)
    runs: list[FileRun] = []
    t0 = time.monotonic()
    for e in entries:
        fr = run_file(e, corpus, REPO, python=args.python, timeout=args.timeout, only=only)
        runs.append(fr)
        for r in fr.results:
            print(f"[named-mutants] {r.verdict:8s} {r.mutant}  ({r.seconds}s)", flush=True)
    table = kill_table(runs, args.plane, uncovered_files(corpus))
    print(table)
    print(f"[named-mutants] wall time {time.monotonic() - t0:.1f}s")
    if args.summary_md:
        with open(args.summary_md, "a", encoding="utf-8") as fh:
            fh.write(table + "\n")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"plane": args.plane, "runs": [asdict(fr) for fr in runs]},
                                                  indent=2) + "\n", encoding="utf-8")
    ok = all(fr.baseline_ok for fr in runs) and all(r.verdict == KILLED for fr in runs for r in fr.results)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
