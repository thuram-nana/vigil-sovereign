"""
analysis.analyzers.joern — adapter over Joern (CPG inter-procedural dataflow).

Joern builds a Code Property Graph and runs whole-program, inter-procedural
taint queries (`reachableByFlows`). Its edge over semgrep's taint mode is
deeper cross-function/cross-file analysis, arbitrary graph queries, and
languages semgrep handles poorly — C/C++ and binaries via its frontends.

Honest note: for typical Python *web* source, semgrep's taint mode is
already competitive (it does limited inter-procedural analysis), so Joern
is most valuable on harder targets (native code, large cross-file flows,
custom queries), not as a strict upgrade on every codebase.

MEASURED LIMITATION — one language per run, and that language is Python.
``importCode`` auto-detects a single frontend for the tree and imports only
that language. Verified against the range fixture: on a tree holding
``app/*.py``, ``web/server.js`` and ``native/parse.c``, the CPG contained
the three ``.py`` files and nothing else — the C and JS files were never
parsed. The source/sink model below is Python-web-shaped as well
(``request.args.get`` sources; ``subprocess`` / ``execute`` / ``open``
sinks), so it would not describe C or JS even if they were imported.

So the C/C++ reach named above is Joern's capability, NOT this adapter's
today. Delivering it is real work, not a flag: it needs a per-language
``importCode`` pass plus a distinct source/sink model per frontend
(argv/``gets``/``strcpy``/``system`` for C; ``req.query``/``exec``/``eval``
for JS). Until that exists, treat this adapter as a Python inter-procedural
taint backend, and do not read a clean Joern result as evidence about the
C or JS in a mixed tree.

Heavy and not pip-installable (~2 GB, JVM, slow cold start). The framework
does not install it; a deployment provisions Joern and points the adapter
at it via `CRUCIBLE_JOERN_HOME` or `joern` on PATH. Absent → skipped
gracefully, like the semgrep adapter.

The adapter renders a CPGQL dataflow script with the target/output paths
embedded, runs `joern --script`, and parses the JSON-lines the script
writes. No shell; bounded by a timeout.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ...common.errors import BackendError, BackendUnavailable
from ..models import AnalysisFinding, AnalysisTarget

# CPGQL dataflow script. The `__INPUT__` / `__OUTPUT__` tokens are substituted
# at runtime (deliberately NOT str.format: the script is dense in Scala braces,
# and one un-doubled brace would silently break the whole query).
#
# Sources: common web-request entry points. Sinks: the injection/SSRF/
# traversal/exec/template points. Each flow's sink node yields a finding
# with file + line, written as JSON lines for the adapter to parse.
#
# BARRIERS (sanitizer modelling). Joern's OSS dataflow reports reachability;
# it does not model validation, so a *correctly guarded* path read reaches
# `open()` exactly like an unguarded one and is reported identically. That is
# a false positive, and it made the range's clean negative control report two
# HIGH path-traversal findings. Every serious taint engine models sanitizers
# for this reason (semgrep `pattern-sanitizer`, CodeQL barriers), so the query
# now models one — narrowly, and only in its SOUND form:
#
#   * scope — the barrier applies ONLY to the path-traversal sink class
#     (`open(`). Path containment says nothing about shell metacharacters, so
#     it must never suppress a command-injection or eval flow.
#   * soundness — only *canonicalise-then-contain* is recognised: a fully
#     resolving call (`os.path.realpath` / `.resolve(`) must appear ON THE
#     FLOW PATH, and a containment predicate (`commonpath` / `relpath` /
#     `is_relative_to`) must appear in the sink's enclosing method. Both, or
#     the flow is reported.
#
# Deliberately NOT treated as barriers, because they do not actually sanitize
# and accepting them would buy a quiet control with false negatives:
#   * `str.startswith(root)` — the classic bypassable prefix check.
#   * `os.path.abspath` — normalises `..` but does not resolve symlinks, so an
#     abspath+commonpath guard is still traversable via a symlink and stays
#     reported.
_SCRIPT_TEMPLATE = r'''
importCode(inputPath="__INPUT__", projectName="daa-joern")
val sourceRe = ".*request\\.(args|form|values|GET|POST)\\.get.*|.*request\\.get_json.*"
val sinkRe = ".*os\\.system.*|.*os\\.popen.*|.*subprocess\\.(call|run|Popen|check_output).*|" +
             ".*\\.execute\\(.*|.*\\beval\\(.*|.*\\bexec\\(.*|.*requests\\.(get|post|request).*|" +
             ".*urlopen.*|.*render_template_string.*|.*\\bopen\\(.*"
// (?s) so `.` spans the newlines Joern's lowered `code` fragments contain.
val pathSinkRe = "(?s).*\\bopen\\(.*"
val canonRe    = "(?s).*(os\\.path\\.realpath|\\.resolve\\().*"
val containRe  = "(?s).*(os\\.path\\.commonpath|os\\.path\\.relpath|is_relative_to).*"

val sources = cpg.call.code(sourceRe)
val sinks = cpg.call.code(sinkRe)
val flows = sinks.reachableByFlows(sources).l

// Does the sink's enclosing method contain a containment predicate?
def containmentChecked(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Boolean =
  n.start.repeat(_.astParent)(_.until(_.isMethod))
    .collectAll[io.shiftleft.codepropertygraph.generated.nodes.Method]
    .l.headOption.exists(m => m.ast.isCall.code.l.exists(_.matches(containRe)))

val kept = flows.filter { f =>
  f.elements.lastOption.exists { sink =>
    if (!sink.code.matches(pathSinkRe)) true
    else !(f.elements.exists(_.code.matches(canonRe)) && containmentChecked(sink))
  }
}

// One record per (file, line): Joern emits both `open(x)` and its lowered
// `manager_tmp0 = open(x)` for the same sink. Keep the shortest (the
// un-lowered) form — the orchestrator dedups on path:line:rule_id anyway,
// so this only removes a confusing duplicate, it never drops a distinct sink.
val recs = kept.flatMap { f =>
  f.elements.lastOption.map { n =>
    val fn = n.location.filename
    val ln = n.location.lineNumber.getOrElse(0)
    val code = n.code.replace("\"", "'").replace("\n", " ").take(160)
    (fn, ln, code)
  }
}
val lines = recs.groupBy(r => (r._1, r._2)).values.map(_.minBy(_._3.length)).toList
  .sortBy(r => (r._1, r._2))
  .map(r => s"""{"file":"${r._1}","line":${r._2},"sink":"${r._3}"}""")

java.nio.file.Files.write(
  java.nio.file.Paths.get("__OUTPUT__"),
  lines.mkString("\n").getBytes("UTF-8")
)
'''

# Map a sink code fragment to a bug class / CWE for the normalized finding.
_SINK_CLASS: tuple[tuple[str, str, str], ...] = (
    ("os.system", "OS Command Injection", "CWE-78"),
    ("os.popen", "OS Command Injection", "CWE-78"),
    ("subprocess", "OS Command Injection", "CWE-78"),
    (".execute(", "SQL Injection", "CWE-89"),
    ("eval(", "Code Injection", "CWE-95"),
    ("exec(", "Code Injection", "CWE-95"),
    ("requests.", "SSRF", "CWE-918"),
    ("urlopen", "SSRF", "CWE-918"),
    ("render_template_string", "Server-Side Template Injection", "CWE-1336"),
    ("open(", "Path Traversal", "CWE-22"),
)


def _classify(sink_code: str) -> tuple[str, str]:
    for needle, _cls, cwe in _SINK_CLASS:
        if needle in sink_code:
            return _cls, cwe
    return "Tainted Dataflow", ""


def _joern_binary() -> str | None:
    home = os.environ.get("CRUCIBLE_JOERN_HOME")
    if home:
        cand = Path(home).expanduser() / "joern"
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which("joern")


class JoernAnalyzer:
    """Adapter over the `joern` CLI for CPG inter-procedural dataflow."""

    name = "joern"

    def __init__(self, timeout_s: int = 600) -> None:
        self._timeout_s = timeout_s

    def is_available(self) -> tuple[bool, str]:
        binary = _joern_binary()
        if binary is None:
            return False, (
                "joern not found (set CRUCIBLE_JOERN_HOME or put joern on PATH; "
                "~2 GB, JVM — provisioned per analysis host, not installed by the framework)"
            )
        return True, f"joern at {binary}"

    def analyze(self, target: AnalysisTarget) -> list[AnalysisFinding]:
        binary = _joern_binary()
        if binary is None:
            raise BackendUnavailable("joern not found")

        # Absolute path: the script runs with cwd set to a temp dir (so
        # Joern's workspace/ output lands there, not in the repo), so a
        # relative target would not resolve.
        root = Path(target.root).expanduser().resolve()
        if not root.exists():
            raise BackendError(f"target path does not exist: {root}")
        # The path is interpolated into a Scala string literal. A quote,
        # backslash or newline in it would terminate that literal and turn
        # the rest of the query into arbitrary Scala, so refuse rather than
        # emit a script we cannot reason about.
        if any(c in str(root) for c in '"\\\n\r'):
            raise BackendError(f"unsupported character in target path: {root!r}")
        with tempfile.TemporaryDirectory() as td:
            out_path = Path(td) / "joern-flows.jsonl"
            script_path = Path(td) / "taint.sc"
            script_path.write_text(
                _SCRIPT_TEMPLATE.replace("__INPUT__", str(root)).replace(
                    "__OUTPUT__", str(out_path)),
                encoding="utf-8",
            )
            try:
                proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                    [binary, "--script", str(script_path)],
                    capture_output=True, text=True, timeout=self._timeout_s, check=False,
                    # Run in the temp dir so Joern's `workspace/` output
                    # lands there, never polluting the repo / engagement CWD.
                    cwd=td,
                )
            except subprocess.TimeoutExpired as e:
                raise BackendError(f"joern timed out after {self._timeout_s}s") from e
            except OSError as e:
                raise BackendError(f"joern failed to launch: {e}") from e

            if not out_path.is_file():
                raise BackendError(
                    f"joern produced no output (exit {proc.returncode}): "
                    f"{proc.stderr.strip()[:300]}"
                )
            return self._parse(out_path, root)

    def _parse(self, out_path: Path, root: Path) -> list[AnalysisFinding]:
        findings: list[AnalysisFinding] = []
        for line in out_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            raw_path = str(rec.get("file", ""))
            try:
                rel = str(Path(raw_path).relative_to(root)) if root.is_dir() else Path(raw_path).name
            except ValueError:
                rel = raw_path
            sink_code = str(rec.get("sink", ""))
            bug_class, cwe = _classify(sink_code)
            findings.append(AnalysisFinding(
                analyzer=self.name,
                rule_id="joern-taint",
                severity="high",
                path=rel,
                line=int(rec.get("line", 0) or 0),
                message=f"Inter-procedural taint reaches sink ({bug_class}): {sink_code[:120]}",
                snippet=sink_code[:200],
                cwe=cwe,
            ))
        findings.sort(key=lambda f: (f.path, f.line))
        return findings
