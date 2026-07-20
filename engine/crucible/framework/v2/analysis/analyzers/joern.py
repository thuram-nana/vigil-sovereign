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

# CPGQL dataflow script. `{input}` / `{output}` are filled at runtime.
# Sources: common web-request entry points. Sinks: the injection/SSRF/
# traversal/exec/template points. Each flow's sink node yields a finding
# with file + line, written as JSON lines for the adapter to parse.
_SCRIPT_TEMPLATE = r'''
importCode(inputPath="{input}", projectName="daa-joern")
val sourceRe = ".*request\\.(args|form|values|GET|POST)\\.get.*|.*request\\.get_json.*"
val sinkRe = ".*os\\.system.*|.*os\\.popen.*|.*subprocess\\.(call|run|Popen|check_output).*|" +
             ".*\\.execute\\(.*|.*\\beval\\(.*|.*\\bexec\\(.*|.*requests\\.(get|post|request).*|" +
             ".*urlopen.*|.*render_template_string.*|.*\\bopen\\(.*"
val sources = cpg.call.code(sourceRe)
val sinks = cpg.call.code(sinkRe)
val flows = sinks.reachableByFlows(sources).l
val lines = flows.flatMap {{ f =>
  f.elements.lastOption.map {{ n =>
    val fn = n.location.filename
    val ln = n.location.lineNumber.getOrElse(0)
    val code = n.code.replace("\"", "'").replace("\n", " ").take(160)
    s"""{{"file":"$fn","line":$ln,"sink":"$code"}}"""
  }}
}}.distinct
java.nio.file.Files.write(
  java.nio.file.Paths.get("{output}"),
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
        with tempfile.TemporaryDirectory() as td:
            out_path = Path(td) / "joern-flows.jsonl"
            script_path = Path(td) / "taint.sc"
            script_path.write_text(
                _SCRIPT_TEMPLATE.format(input=str(root), output=str(out_path)),
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
