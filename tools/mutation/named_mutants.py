"""The NAMED-MUTANT corpus runner — a deterministic, bounded, per-plane kill table for the money/gate files.

WHY THIS EXISTS (W11-3, issue #484). mutmut / cosmic-ray (the scheduled kill-suite) mutate only the
vigil_core-scoped ``mutation: true`` files: their single runner command cannot load ``framework`` beside the
sovereign-purity asserts, so the K4 money/gate files under ``apps/sigil`` and the engine gates under
``engine/crucible`` are ``mutation: false`` in ``critical-set.json``. Their mutation evidence lived only in
PR bodies ("8/8 killed"), with nothing in the repo that re-runs it. This runner closes that gap:

  * the corpus (``tools/mutation/named-mutants.json``) names, per file, a FIXED list of mutants — each an
    exact ``old`` -> ``new`` source replacement for ONE guard, plus the test node(s) that must kill it;
  * a run is ONE plane in its own process tree: the sovereign plane runs with a PYTHONPATH built from
    scratch that never contains ``engine/crucible`` (FATAL-2), and the offense plane runs from
    ``engine/crucible`` without ``apps/sigil`` — so the two planes never share an interpreter;
  * per file it first runs the union of the named tests on the UNMUTATED source (the baseline must be
    green, else a "kill" means nothing), then applies each mutant, runs only that mutant's named tests,
    and ALWAYS restores the original bytes (and mtime) before the next mutant;
  * a mutant is KILLED only when pytest exits 1 (tests ran and failed). Exit 0 is SURVIVED. Anything
    else — collection/usage error, no tests collected, timeout, or a mutant that does not compile — is
    ERROR, never a kill, so a broken mutant can never pad the score.

The output is a Markdown kill table (optionally appended to ``$GITHUB_STEP_SUMMARY``) and a JSON record.
Exit status: 0 iff every selected mutant was KILLED over a green baseline; 1 otherwise; 2 if the corpus
itself does not validate (a stale ``old`` string, an unknown test, a plane leak, ...). The same
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
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "tools" / "mutation" / "named-mutants.json"
CRITICAL_SET = REPO / "tools" / "mutation" / "critical-set.json"

PLANES = ("sovereign", "offense")
KILLED = "KILLED"
SURVIVED = "SURVIVED"
ERROR = "ERROR"

DEFAULT_TIMEOUT_S = 600.0


# --------------------------------------------------------------------------------------------------
# Corpus loading + validation (pure, stdlib — the per-PR guard calls validate_corpus directly).
# --------------------------------------------------------------------------------------------------
def load_corpus(path: Path = CORPUS) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def critical_python_paths(path: Path = CRITICAL_SET) -> set[str]:
    man = json.loads(Path(path).read_text(encoding="utf-8"))
    return {e["path"] for e in man["critical_set"] if e.get("lang") == "python"}


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
    a fresh SIGIL_HOME, and a private bytecode cache so a stale .pyc can never stand in for a mutant (or for
    the restored original)."""
    pl = corpus["planes"][plane]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str((repo / p).resolve()) for p in pl["pythonpath"])
    home = scratch / "sigil-home"
    home.mkdir(parents=True, exist_ok=True)
    env["SIGIL_HOME"] = str(home)
    pyc = scratch / "pycache"
    pyc.mkdir(parents=True, exist_ok=True)
    env["PYTHONPYCACHEPREFIX"] = str(pyc)
    env.pop("PYTEST_ADDOPTS", None)
    return env


def _run_pytest(tests: list[str], cwd: Path, env: dict[str, str], python: str, timeout: float,
                stop_first: bool) -> tuple[Optional[int], str, float]:
    """(returncode | None on timeout, tail of output, seconds)."""
    cmd = [python, "-m", "pytest", "-p", "no:cacheprovider"]
    if stop_first:
        cmd.append("-x")
    cmd += tests
    t0 = time.monotonic()
    try:
        cp = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timeout after {timeout:.0f}s", time.monotonic() - t0
    out = (cp.stdout or "") + (cp.stderr or "")
    tail = " | ".join(line.strip() for line in out.strip().splitlines()[-3:])
    return cp.returncode, tail, time.monotonic() - t0


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
        rc, tail, secs = _run_pytest(_abs_tests(union, repo), cwd, plane_env(corpus, plane, repo, scratch / "base"),
                                     python, timeout, stop_first=False)
        run.baseline_ok = rc == 0
        run.baseline_detail = f"rc={rc}: {tail}"
        run.baseline_seconds = round(secs, 2)
        for i, m in enumerate(mutants):
            res = Result(path=entry["path"], mutant=m["id"], guard=m["guard"], tests=list(m["tests"]),
                         verdict=ERROR)
            if not run.baseline_ok:
                res.detail = "baseline red: the unmutated source fails its named tests"
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
            try:
                src.write_bytes(mutated.encode("utf-8"))
                rc, tail, secs = _run_pytest(_abs_tests(m["tests"], repo), cwd,
                                             plane_env(corpus, plane, repo, scratch / f"m{i}"),
                                             python, timeout, stop_first=True)
            finally:
                src.write_bytes(original)
                os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))
            if _sha(src.read_bytes()) != _sha(original):  # pragma: no cover — a restore that did not land
                raise RuntimeError(f"FAILED TO RESTORE {src} — fix the tree before anything else")
            res.seconds = round(secs, 2)
            if rc == 1:
                res.verdict, res.detail = KILLED, tail
            elif rc == 0:
                res.verdict, res.detail = SURVIVED, "the named tests PASS on the mutant: " + tail
            else:
                res.verdict, res.detail = ERROR, f"rc={rc} (not a kill): {tail}"
            run.results.append(res)
            shutil.rmtree(scratch / f"m{i}", ignore_errors=True)
    return run


def kill_table(runs: list[FileRun], plane: str) -> str:
    rows = [r for fr in runs for r in fr.results]
    killed = sum(1 for r in rows if r.verdict == KILLED)
    lines = [f"### Named-mutant kill table — {plane} plane: {killed}/{len(rows)} killed", ""]
    for fr in runs:
        state = "green" if fr.baseline_ok else f"RED ({fr.baseline_detail})"
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
    """SIGTERM (a CI cancel) becomes KeyboardInterrupt, so the ``finally`` restore in run_file runs."""
    def _raise(signum: int, frame: Any) -> None:  # noqa: ARG001
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, _raise)


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

    corpus = load_corpus(Path(args.corpus))
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
    table = kill_table(runs, args.plane)
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
